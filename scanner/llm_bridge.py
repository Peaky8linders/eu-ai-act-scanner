"""Claude Max bridge for the scanner's optional LLM calls.

Routes the scanner's optional semantic-analysis calls through a *local*
Claude-Code wrapper (Anthropic-compatible ``/v1/messages`` + ``/health``)
that authenticates via the Claude Code CLI subscription instead of a metered
API key. The wrapper runs at ``http://127.0.0.1:8000`` by default and is also
reachable through a Cloudflare tunnel.

Because the wrapper speaks the Anthropic API, the existing optional
``anthropic`` SDK dependency routes through it transparently:
``anthropic.Anthropic(base_url=..., api_key=...)``.

Everything here is *graceful*: a missing SDK, an unreachable wrapper, a
malformed response, or any other failure degrades to an :class:`LLMResult`
carrying an ``error`` string. :func:`complete` never raises.

Ported from ``regenold-eu-ai-act-rag`` (``app/engines/graph_rag.py``):

* the multi-strategy JSON extractor
  (direct parse -> fenced ```` ```json ```` block -> balanced-brace span), and
* the structural-truncation heuristic (an answer that ends mid-clause without
  terminal punctuation, after peeling closing wrappers).

Env config (read at call time via :func:`os.getenv`):

* ``EU_AI_ACT_SCANNER_LLM`` — enable flag (``true``/``1``/``yes``).
* ``EU_AI_ACT_SCANNER_LLM_BASE_URL`` — wrapper base URL.
* ``EU_AI_ACT_SCANNER_LLM_API_KEY`` — passed to the SDK; ``"not-needed"`` when unset.
* ``EU_AI_ACT_SCANNER_LLM_MODEL`` — model id (defaults to a Haiku for back-compat).
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

# ─── Env defaults ───────────────────────────────────────────────────────

_DEFAULT_BASE_URL = "http://127.0.0.1:8000"
_DEFAULT_MODEL = "claude-haiku-4-5-20251001"
_DEFAULT_API_KEY = "not-needed"

# ─── JSON-extraction helpers (ported from graph_rag.py) ─────────────────

_JSON_FENCE_RE = re.compile(
    r"```(?:json5?|jsonc)?\s*\n?(.*?)\n?```",
    re.IGNORECASE | re.DOTALL,
)
_TRAILING_COMMA_RE = re.compile(r",\s*(?=[}\]])")


class LLMResult(BaseModel):
    """Outcome of a single bridge completion call.

    ``error`` is ``None`` on success and a short human-readable string on any
    failure (SDK missing, wrapper unreachable, malformed response, ...). The
    other fields are best-effort and may stay at their defaults on error.
    """

    text: str = ""
    model: str = ""
    truncated: bool = False
    raw_json: dict | None = None
    error: str | None = None


def is_enabled() -> bool:
    """Return ``True`` when the LLM bridge is enabled via env var.

    Reads ``EU_AI_ACT_SCANNER_LLM`` at call time so a late env rebind (e.g. a
    test monkeypatch) takes effect without a module reload. Disabled by default.
    """
    return os.getenv("EU_AI_ACT_SCANNER_LLM", "false").strip().lower() in ("true", "1", "yes")


def _base_url() -> str:
    """Resolve the wrapper base URL from env (default local wrapper)."""
    return os.getenv("EU_AI_ACT_SCANNER_LLM_BASE_URL", _DEFAULT_BASE_URL).rstrip("/")


def _model() -> str:
    """Resolve the model id from env (Haiku default for back-compat)."""
    return os.getenv("EU_AI_ACT_SCANNER_LLM_MODEL", _DEFAULT_MODEL)


def _api_key() -> tuple[str, str]:
    """Resolve the API key and its source.

    Returns ``(key, source)`` where ``source`` is ``"env"`` when the user set
    ``EU_AI_ACT_SCANNER_LLM_API_KEY`` and ``"default"`` when we fell back to the
    ``"not-needed"`` sentinel the local subscription wrapper accepts.
    """
    raw = os.getenv("EU_AI_ACT_SCANNER_LLM_API_KEY")
    if raw:
        return raw, "env"
    return _DEFAULT_API_KEY, "default"


def bridge_config() -> dict:
    """Return the resolved bridge configuration for diagnostics.

    The key *value* is never included — only its source (``"env"`` vs
    ``"default"``) — so this dict is safe to log or surface in a report.
    """
    _, source = _api_key()
    return {
        "base_url": _base_url(),
        "model": _model(),
        "api_key_source": source,
        "enabled": is_enabled(),
    }


# ─── JSON extraction (ported) ────────────────────────────────────────────


def _strip_trailing_commas(text: str) -> str:
    """Strip ``,}`` / ``,]`` an LLM sometimes emits despite a strict-JSON ask."""
    return _TRAILING_COMMA_RE.sub("", text)


def _try_parse(candidate: str) -> dict | None:
    """Best-effort ``json.loads``; return ``None`` on any failure (or non-dict)."""
    candidate = candidate.strip()
    if not candidate:
        return None
    try:
        result = json.loads(candidate)
    except (ValueError, TypeError):
        try:
            result = json.loads(_strip_trailing_commas(candidate))
        except (ValueError, TypeError):
            return None
    return result if isinstance(result, dict) else None


def _balanced_brace_spans(text: str) -> list[str]:
    """Yield every balanced ``{...}`` span in document order.

    Walks the string with a depth counter so a stray ``{placeholder}`` in the
    prose around the real JSON doesn't poison the match the way a greedy
    ``{.*}`` regex does (which spans the first ``{`` to the last ``}`` and
    fails to parse when there are multiple top-level objects). O(n) walk,
    bounded by the string length.
    """
    spans: list[str] = []
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    spans.append(text[start:i + 1])
                    start = -1
    return spans


def extract_json_object(text: str) -> dict | None:
    """Extract a parseable JSON object from an arbitrary LLM response.

    Three strategies, in order of strictness:

    1. **Direct parse** — the response is already valid JSON (hot path).
    2. **Fenced-block extraction** — walk every ```` ``` ```` fenced span
       (optional ``json``/``json5``/``jsonc`` tag) and return the *last* that
       parses to a dict (an LLM may ship a worked-example fence before the real
       answer, so the later span wins — mirroring strategy 3 and the regenold
       original's example-then-answer handling).
    3. **Balanced-brace fallback** — when no fence parses, walk every balanced
       ``{...}`` span and return the *last* one that parses (LLMs ship the real
       answer after any example/reasoning).

    Returns the parsed dict, or ``None`` when every strategy fails.
    """
    if not text:
        return None
    cleaned = text.strip()

    # 1. Direct parse — strict JSON response (hot path).
    direct = _try_parse(cleaned)
    if direct is not None:
        return direct

    # 2. Fenced-block extraction — last parsable fence wins (answer after example).
    chosen: dict | None = None
    for match in _JSON_FENCE_RE.finditer(cleaned):
        result = _try_parse(match.group(1))
        if result is not None:
            chosen = result
    if chosen is not None:
        return chosen

    # 3. Balanced-brace fallback — last parsable span wins (answer after prose).
    for span in _balanced_brace_spans(cleaned):
        result = _try_parse(span)
        if result is not None:
            chosen = result
    return chosen


def looks_structurally_truncated(text: str) -> bool:
    """Heuristic: does ``text`` look cut mid-clause (no natural ending)?

    A completed answer ends with sentence-terminal punctuation
    (``.``/``!``/``?``/``…``), optionally wrapped by closing quotes, parens or
    brackets. Anything else — a trailing letter, digit, comma, colon, dash — is
    treated as the model stopping mid-clause.

    Conservative: only fires on non-empty text whose stripped tail (after
    peeling closing wrappers) is not terminal punctuation, so it never
    false-positives on a complete sentence. Empty/whitespace text returns
    ``False``.
    """
    if not text:
        return False
    stripped = text.rstrip()
    if not stripped:
        return False
    # Peel trailing closing wrappers a complete sentence may carry after its
    # terminator (e.g. ``…Annex IV.)`` ends ``)`` → peel to reach the ``.``).
    tail = stripped
    while tail and tail[-1] in ")]}\"”’'":
        tail = tail[:-1].rstrip()
    if not tail:
        return False
    return tail[-1] not in ".!?…"


# ─── Completion ──────────────────────────────────────────────────────────


def complete(
    system: str,
    user: str,
    *,
    model: str | None = None,
    max_tokens: int = 800,
) -> LLMResult:
    """Run one completion through the Claude Max wrapper.

    Builds an :class:`anthropic.Anthropic` client pointed at the local wrapper
    (``base_url`` + ``api_key`` from env) and issues a single ``messages``
    call. Fully graceful — a missing ``anthropic`` SDK, an unreachable wrapper,
    or any other exception is caught and returned as an :class:`LLMResult` with
    a populated ``error``. **Never raises.**

    ``truncated`` is set from :func:`looks_structurally_truncated` on the
    returned text.
    """
    chosen_model = model or _model()
    try:
        import anthropic
    except ImportError:
        return LLMResult(model=chosen_model, error="anthropic SDK not installed")

    try:
        key, _ = _api_key()
        client = anthropic.Anthropic(base_url=_base_url(), api_key=key)
        response = client.messages.create(
            model=chosen_model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = _extract_response_text(response)
        return LLMResult(
            text=text,
            model=chosen_model,
            truncated=looks_structurally_truncated(text),
        )
    except Exception as exc:  # noqa: BLE001 — best-effort bridge, never blocks the scan
        logger.warning("llm_bridge_complete_failed", error=str(exc)[:120])
        return LLMResult(model=chosen_model, error=f"LLM call failed: {str(exc)[:120]}")


def _extract_response_text(response: object) -> str:
    """Pull the first text block out of an Anthropic ``messages`` response.

    Tolerant of both real SDK objects (``response.content[0].text``) and the
    minimal fakes used in tests. Returns ``""`` when no text block is present.
    """
    content = getattr(response, "content", None)
    if not content:
        return ""
    first = content[0]
    return getattr(first, "text", "") or ""


def complete_json(system: str, user: str, **kw: object) -> tuple[dict | None, LLMResult]:
    """Run :func:`complete`, then extract a JSON object from the text.

    Returns ``(parsed_or_None, result)``. The :class:`LLMResult` is always
    returned (even on error) so the caller can inspect ``error``/``truncated``;
    the dict is ``None`` when the call failed or no JSON could be extracted.
    """
    result = complete(system, user, **kw)  # type: ignore[arg-type]
    if result.error is not None:
        return None, result
    parsed = extract_json_object(result.text)
    result.raw_json = parsed
    return parsed, result


# ─── Health ──────────────────────────────────────────────────────────────


def bridge_health(timeout: float = 4.0) -> dict:
    """Probe the wrapper's ``/health`` endpoint over HTTP.

    Issues a ``GET {base_url}/health`` via :mod:`urllib.request`. On success
    returns ``{"reachable": True, "status": <status string>, "claude_max":
    <bool>}``; on *any* error (connection refused, timeout, malformed body,
    ...) returns ``{"reachable": False, "status": None, "claude_max": False}``.
    Never raises.
    """
    url = f"{_base_url()}/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 — fixed local/tunnel host, GET only
            body = resp.read().decode("utf-8", errors="replace")
        payload = json.loads(body) if body.strip() else {}
        if not isinstance(payload, dict):
            payload = {}
        # The local subscription wrapper carries no explicit ``claude_max`` flag
        # on ``/health`` but advertises itself via its ``service`` name
        # ("claude-code-openai-wrapper"); treat either an explicit flag or that
        # service signal as proof the endpoint is the Claude Max bridge.
        claude_max = bool(payload.get("claude_max")) or (
            "claude-code" in str(payload.get("service", "")).lower()
        )
        return {
            "reachable": True,
            "status": str(payload.get("status")) if payload.get("status") is not None else None,
            "claude_max": claude_max,
        }
    except (urllib.error.URLError, OSError, ValueError, TypeError) as exc:
        logger.debug("llm_bridge_health_unreachable", error=str(exc)[:120])
        return {"reachable": False, "status": None, "claude_max": False}
    except Exception as exc:  # noqa: BLE001 — health probe must never raise
        logger.debug("llm_bridge_health_error", error=str(exc)[:120])
        return {"reachable": False, "status": None, "claude_max": False}


# ─── Extensive Semantic Analysis (Subscription-Powered) ────────────────────


class SemanticFinding(BaseModel):
    """A semantically verified compliance gap or risk in audited code."""

    id: str
    dimension: str
    article: str
    file_path: str
    line_number: int | None = None
    severity: str = "high"  # critical | high | medium | low
    title: str
    description: str
    evidence_excerpt: str = ""
    remediation_advice: str = ""
    mitigated: bool = False


class SemanticAuditResult(BaseModel):
    """Outcome of an extensive semantic compliance audit."""

    project_name: str
    mode: str = "assisted"
    total_findings: int = 0
    findings: list[SemanticFinding] = Field(default_factory=list)
    cleared_false_positives: list[str] = Field(default_factory=list)
    summary: str = ""
    error: str | None = None


def semantic_audit_project(
    root: Path | str,
    scan_result: Any,
    sample_files: dict[str, str] | None = None,
    max_files: int = 5,
) -> SemanticAuditResult:
    """Run an extensive semantic compliance audit on a project using Claude / Codex.

    Leverages the user's active Claude Code or Codex subscription (via local wrapper
    or bridge) to perform deep semantic code inspection that static regex cannot do:
    - Verifies human oversight gates (Art. 14) are real and non-bypassable.
    - Inspects Art. 50 disclosure messages and C2PA synthetic media marking.
    - Detects prohibited practices (Art. 5(1)(a)-(h) and Reg 2026/1744 (ba)/(bb)).
    - Audits multi-agent tool execution bounds and lethal trifecta risks.
    - Identifies and eliminates static false positives where custom code already complies.
    """
    project_name = getattr(scan_result, "project_name", "Project")
    if not is_enabled():
        return SemanticAuditResult(
            project_name=project_name,
            summary="Deterministic static scan baseline. Enable assisted mode with /ai-act-settings to activate subscription-powered semantic audit.",
            error="LLM bridge is disabled",
        )

    # Collect key files to audit
    files_to_send: dict[str, str] = {}
    if sample_files:
        files_to_send = dict(list(sample_files.items())[:max_files])
    else:
        root_path = Path(root).resolve()
        # Pick top files from findings or python/ts files
        file_candidates: list[str] = []
        file_findings = getattr(scan_result, "file_findings", [])
        for ff in file_findings:
            if getattr(ff, "status", "") in ("gap", "partial"):
                file_candidates.append(ff.file_path)

        for rel_path in file_candidates[:max_files]:
            fp = root_path / rel_path
            if fp.is_file():
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    if len(content) < 50_000:
                        files_to_send[rel_path] = content
                except OSError:
                    continue

    if not files_to_send:
        return SemanticAuditResult(
            project_name=project_name,
            summary="No candidate source files found for semantic review.",
        )

    system_prompt = (
        "You are an expert EU AI Act compliance auditor and AI safety engineer. "
        "Analyze the provided source code for regulatory compliance under Regulation (EU) 2024/1689 "
        "and Regulation (EU) 2026/1744 (Digital Omnibus on AI). "
        "Evaluate specifically: \n"
        "1. Article 14 Human Oversight: Are human intervention and kill-switch capabilities operational?\n"
        "2. Article 50 Transparency: Are AI interaction disclosures and synthetic content markings real?\n"
        "3. Article 5 Prohibited Practices: Are there manipulative patterns, biometric profiling, or NCII/CSAM generation?\n"
        "4. Article 12 Logging: Are prompts, responses, and session trace IDs logged with audit retention?\n"
        "Return a strictly valid JSON object with keys: \n"
        "- 'summary': brief overview of the semantic findings\n"
        "- 'cleared_false_positives': list of file paths where static gaps were false alarms\n"
        "- 'findings': list of objects each with {'id', 'dimension', 'article', 'file_path', 'line_number', 'severity', 'title', 'description', 'evidence_excerpt', 'remediation_advice'}"
    )

    user_prompt = (
        f"Project: {project_name}\n"
        f"Scanned files to audit:\n\n"
        + "\n\n".join(
            f"--- File: {path} ---\n{content[:6000]}"
            for path, content in files_to_send.items()
        )
    )

    parsed_json, result = complete_json(system_prompt, user_prompt, max_tokens=2000)
    if not parsed_json or result.error:
        return SemanticAuditResult(
            project_name=project_name,
            summary="Semantic review could not complete cleanly.",
            error=result.error or "JSON parse failed",
        )

    findings: list[SemanticFinding] = []
    for f in parsed_json.get("findings", []):
        if isinstance(f, dict):
            findings.append(
                SemanticFinding(
                    id=str(f.get("id", f"sem-{len(findings)+1}")),
                    dimension=str(f.get("dimension", "risk_mgmt")),
                    article=str(f.get("article", "Art. 9")),
                    file_path=str(f.get("file_path", "")),
                    line_number=f.get("line_number"),
                    severity=str(f.get("severity", "high")),
                    title=str(f.get("title", "Semantic Compliance Finding")),
                    description=str(f.get("description", "")),
                    evidence_excerpt=str(f.get("evidence_excerpt", "")),
                    remediation_advice=str(f.get("remediation_advice", "")),
                )
            )

    return SemanticAuditResult(
        project_name=project_name,
        total_findings=len(findings),
        findings=findings,
        cleared_false_positives=parsed_json.get("cleared_false_positives", []),
        summary=str(parsed_json.get("summary", "Extensive semantic audit complete.")),
    )


def semantic_draft_remediation(
    dim_id: str,
    gap_title: str,
    file_path: str,
    existing_code: str,
    grounded_obligation: str = "",
) -> dict:
    """Use Claude or Codex to draft a context-aware remediation patch for a specific file.

    Returns a dict with {'patch_code': str, 'explanation': str, 'test_code': str}.
    """
    if not is_enabled():
        return {
            "patch_code": "",
            "explanation": "LLM bridge disabled.",
            "test_code": "",
        }

    system_prompt = (
        "You are an expert AI engineer remediating EU AI Act compliance gaps. "
        "Given the existing code and an identified compliance gap, output a production-ready "
        "patch that directly solves the gap without breaking existing functionality. "
        "Return a strictly valid JSON object with keys: "
        "- 'patch_code': the code to insert or replace\n"
        "- 'explanation': why this satisfies the EU AI Act obligation\n"
        "- 'test_code': a pytest test function verifying this compliance control"
    )

    user_prompt = (
        f"Dimension: {dim_id}\n"
        f"Gap Title: {gap_title}\n"
        f"File Path: {file_path}\n"
        f"Grounded Obligation:\n{grounded_obligation}\n\n"
        f"Existing Code:\n{existing_code[:8000]}\n"
    )

    parsed_json, _ = complete_json(system_prompt, user_prompt, max_tokens=1500)
    return parsed_json or {
        "patch_code": "",
        "explanation": "Could not generate patch.",
        "test_code": "",
    }

