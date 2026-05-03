"""Privilege Minimization Analyzer — Art. 15(4) / prEN 18282 controls outside the model.

Implements the "privilege minimization outside the generative model"
controls from Nannini et al. (2026) §6.1 (paper lines 672-773). The
core architectural point: a system prompt saying "do not delete files"
is **not** a security control — Article 15(4) compliance for agentic
systems requires the **inability** to perform a restricted action be
enforced at the API level, where the model's tool interface simply
does not expose the restricted capability.

What this analyzer flags:

1. **Restrictive-language-as-control antipattern**: tool definitions
   paired with prompt-level "do not", "never", "you are forbidden"
   instead of architecturally scoped tools.
2. **`subprocess.run(model_output, shell=True)` / `eval(llm_output)` /
   `exec(llm_output)`** — open-ended code execution from an LLM
   string. Paper line 728: prEN 18282 explicitly flags this.
3. **Long-lived service-account credentials** attached to LLM-touching
   modules — the NHI thesis. Paper lines 760-770: agents hold
   credentials for CRM+email+cloud+payments simultaneously, which
   cannot be governed by static-policy IAM.
4. **Confused-deputy / actor-spoof** signal: writes to an audit log
   without distinguishing user-initiated from AI-initiated actions
   (paper line 738).
5. **OAuth scope overgrant**: a scope claimed in config but no
   matching call-site (the prEN 18282 example at lines 334-336 — an
   email agent tasked with summarising needs read-only, not send/delete).

Maps to KB dimensions: tool_governance, security, access_control.

References:
- Paper §6.1 (lines 672-773)
- Paper Conclusion 7 (line 2469) — interleaved cybersecurity tracks
"""

from __future__ import annotations

import re

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    has_file,
    search_files,
)

# ─── 1. Restrictive-language-as-control antipattern ──────────────────────
# Strings inside an LLM prompt that try to constrain behaviour rather
# than enforcing the constraint architecturally.

_PROMPT_CONSTRAINT_LANGUAGE = [
    r"do\s+not\s+(delete|drop|remove|truncate|send|email|charge)",
    r"never\s+(delete|drop|truncate|send|email|charge|execute)",
    r"you\s+are\s+forbidden\s+to",
    r"you\s+must\s+not\s+(delete|drop|send|charge|email)",
    r"do\s+not\s+output\s+(secrets?|api[_\s]?keys?|tokens?)",
]

# ─── 2. LLM output → arbitrary code execution ────────────────────────────

_OPEN_ENDED_EXEC = [
    # subprocess with shell=True near LLM output is the canonical pattern
    r"subprocess\.(run|Popen|call|check_output)\([^)]*shell\s*=\s*True",
    # eval/exec on a variable that came back from an LLM call
    r"\beval\s*\(\s*[a-zA-Z_]+\s*\)",
    r"\bexec\s*\(\s*[a-zA-Z_]+\s*\)",
    # Python's `os.system` is the same risk class
    r"\bos\.system\s*\(",
]

# ─── 3. Long-lived service-account credentials in LLM-touching modules ───
# Treat as risky when paired with an LLM SDK in the same file.

_LLM_SDK_HINTS = (
    r"\b(openai|anthropic|mistralai|cohere|google\.generativeai)\b"
)

_LONG_LIVED_CRED_HINTS = (
    r"(access[_-]?key|secret[_-]?key|service[_-]?account|client[_-]?secret|admin[_-]?token)"
    r"\s*=\s*[\"'][A-Za-z0-9_+\-/=]{20,}"
)

# ─── 4. Audit-log writes that lack actor_kind/actor_type distinction ─────

_AUDIT_WRITE_HINTS = [
    r"audit_log\.(write|info|record)",
    r"evidence_store\.record",
    r"insert_audit\b",
]

_ACTOR_DISTINCTION_HINTS = [
    r"actor_kind\s*=\s*",
    r"actor_type\s*=\s*",
    r"is_ai\s*[:=]",
    r"initiated_by\s*=\s*",
    r"caller_role\s*=\s*",
]

# ─── 5. OAuth scope vs call-site cross-check ─────────────────────────────
# A pragmatic best-effort: if scope X is declared but no obvious call to X,
# flag the overgrant. Conservative on false-positives.

_OAUTH_SCOPE_PATTERNS: list[tuple[str, str, str]] = [
    # (scope token, expected-call-site signature, friendly label)
    (r"https?://www\.googleapis\.com/auth/gmail\.send", r"\.send_message\(|sendgrid", "gmail.send"),
    (r"https?://www\.googleapis\.com/auth/gmail\.modify", r"\.batchModify\(|\.modify\(", "gmail.modify"),
    (r"https?://www\.googleapis\.com/auth/calendar(\b|\.events)", r"events\(\)\.insert\(|events\(\)\.delete\(", "calendar"),
    (r"\brepo\b\s*[\"']\s*,", r"\.create_pull\(|\.merge_pull\(|\.delete_repo\(", "github repo write"),
]


def _files_with_pattern(ctx: AnalyzerContext, pattern: str) -> dict[str, str]:
    """Return {file_path: matched_line} for files matching pattern."""
    return {p: line for p, line in search_files(ctx, pattern)}


def analyze_privilege_minimization(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    # Files that touch an LLM SDK — used to scope some checks.
    llm_files = set(_files_with_pattern(ctx, _LLM_SDK_HINTS))

    # ── 1. Restrictive-language-as-control antipattern ─────────────────
    for pattern in _PROMPT_CONSTRAINT_LANGUAGE:
        for path, line in search_files(ctx, pattern):
            evidence_files.add(path)
            findings.append(Finding(
                id="pm-prompt-as-control", category="privilege_minimization",
                title="Prompt-level restriction used as a security control",
                description=(
                    "Detected restrictive language ('do not / never / forbidden') in what looks "
                    "like an LLM system prompt. Per prEN 18282 / Art. 15(4) this is not a security "
                    "control — it is a natural-language suggestion. Enforce the restriction at the "
                    "API level by simply not exposing the capability."
                ),
                file_path=path, confidence=0.7,
                compliance_impact="gap",
                compliance_dimensions=["tool_governance", "security"],
                evidence_snippet=line,
                kb_question_ids=["tg-1", "sc-3"], suggested_answer="no",
            ))
            break  # one finding per pattern is enough

    # ── 2. Open-ended exec from LLM output ──────────────────────────────
    for pattern in _OPEN_ENDED_EXEC:
        for path, line in search_files(ctx, pattern):
            # Only count if the file also touches an LLM SDK or this is a known
            # agent module (otherwise it's just a normal subprocess call).
            if path in llm_files or "agent" in path.lower() or "tool" in path.lower():
                evidence_files.add(path)
                findings.append(Finding(
                    id="pm-open-exec", category="privilege_minimization",
                    title="LLM-driven open-ended code execution",
                    description=(
                        "Detected `subprocess`/`eval`/`exec`/`os.system` near an LLM SDK or in an "
                        "agent/tool module. prEN 18282 explicitly flags open-ended code execution "
                        "as a high-risk pattern under Art. 15(4). Replace with a bounded sandbox or "
                        "an explicit allow-listed action set."
                    ),
                    file_path=path, confidence=0.85,
                    compliance_impact="gap",
                    compliance_dimensions=["tool_governance", "security", "access_control"],
                    evidence_snippet=line,
                    kb_question_ids=["tg-2"], suggested_answer="no",
                ))
                break  # one finding per pattern across the project

    # ── 3. Long-lived creds in LLM-touching files (NHI antipattern) ─────
    cred_finding_emitted = False
    for path in llm_files:
        content = ctx.files.get(path, "")
        # Case-insensitive match — codebases often write `ACCESS_KEY` in upper case.
        if re.search(_LONG_LIVED_CRED_HINTS, content, re.IGNORECASE):
            if not cred_finding_emitted:
                evidence_files.add(path)
                # Pick the first matching line for the snippet.
                snippet = ""
                for line in content.split("\n"):
                    if re.search(_LONG_LIVED_CRED_HINTS, line, re.IGNORECASE):
                        snippet = line.strip()[:180]
                        break
                findings.append(Finding(
                    id="pm-long-lived-cred", category="privilege_minimization",
                    title="Long-lived credential in LLM-touching module",
                    description=(
                        "A static, long-lived credential (access_key/secret_key/service_account/admin_token) "
                        "appears in a file that imports an LLM SDK. Per the NHI thesis in Nannini et al. §6.1 "
                        "(line 760), agents holding credentials for CRM+email+cloud+payments simultaneously "
                        "cannot be governed by static-policy IAM. Migrate to just-in-time per-action "
                        "credential provisioning with short TTLs."
                    ),
                    file_path=path, confidence=0.7,
                    compliance_impact="gap",
                    compliance_dimensions=["tool_governance", "access_control"],
                    evidence_snippet=snippet,
                    kb_question_ids=["tg-3", "ac-2"], suggested_answer="no",
                ))
                cred_finding_emitted = True

    # ── 4. Audit-log writes without actor_kind distinction ──────────────
    audit_files: set[str] = set()
    for hint in _AUDIT_WRITE_HINTS:
        for path, _ in search_files(ctx, hint):
            audit_files.add(path)
    has_actor_distinction = any(
        search_files(ctx, hint) for hint in _ACTOR_DISTINCTION_HINTS
    )
    if audit_files and not has_actor_distinction:
        first = sorted(audit_files)[0]
        evidence_files.add(first)
        findings.append(Finding(
            id="pm-no-actor-kind", category="privilege_minimization",
            title="Audit log lacks user-vs-AI actor distinction",
            description=(
                "Audit-log writes detected, but no field signal (`actor_kind`, `actor_type`, "
                "`is_ai`, `initiated_by`, `caller_role`) distinguishes user-initiated from "
                "AI-initiated actions. Paper §6.1 (line 738) requires this distinction for "
                "Art. 15(4) compliance. Add an actor-classification field at the audit-write call site."
            ),
            file_path=first, confidence=0.6,
            compliance_impact="gap",
            compliance_dimensions=["tool_governance", "logging"],
            evidence_snippet="",
            kb_question_ids=["tg-4"], suggested_answer="no",
        ))

    # ── 5. OAuth scope overgrant ────────────────────────────────────────
    for scope_pattern, callsite_pattern, scope_label in _OAUTH_SCOPE_PATTERNS:
        scope_hits = search_files(ctx, scope_pattern)
        if not scope_hits:
            continue
        callsite_hits = search_files(ctx, callsite_pattern)
        if not callsite_hits:
            evidence_files.add(scope_hits[0][0])
            findings.append(Finding(
                id=f"pm-overgrant-{scope_label.replace('.', '-').replace(' ', '-')}",
                category="privilege_minimization",
                title=f"OAuth scope `{scope_label}` declared without matching call-site",
                description=(
                    f"OAuth scope `{scope_label}` is requested in config, but no call to the "
                    "matching API method appears in the codebase. The agent is asking for more "
                    "privilege than its code visibly uses. Per the prEN 18282 example "
                    "(read-only summarisation agent does not need `gmail.send`), tighten the "
                    "scope to the smallest set the agent actually invokes."
                ),
                file_path=scope_hits[0][0], confidence=0.55,
                compliance_impact="gap",
                compliance_dimensions=["tool_governance", "access_control"],
                evidence_snippet=scope_hits[0][1],
                kb_question_ids=["tg-3"], suggested_answer="no",
            ))

    # ── 6. Positive evidence: tool-permission registry in repo ──────────
    # Filename-based detection (registry files), plus decorator-based
    # detection at the call-site level via search_files.
    registry_files = (
        has_file(ctx, r"tool[s]?[-_]permissions?\.(yaml|yml|json)$")
        or has_file(ctx, r"agent[-_]?policy\.(yaml|yml|json)$")
    )
    decorator_hits = search_files(ctx, r"@require[_-]?scope\b|@scope[_-]?required\b")
    if registry_files or decorator_hits:
        evidence_path = registry_files[0] if registry_files else decorator_hits[0][0]
        evidence_line = "" if registry_files else decorator_hits[0][1]
        evidence_files.add(evidence_path)
        findings.append(Finding(
            id="pm-permission-registry", category="privilege_minimization",
            title="Tool-permission registry detected",
            description=(
                "A tool-permission registry / agent-policy file / scope-decorator was detected. "
                "This is the architectural posture prEN 18282 requires."
            ),
            file_path=evidence_path, confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["tool_governance", "access_control"],
            evidence_snippet=evidence_line,
            kb_question_ids=["tg-1"], suggested_answer="yes",
        ))

    # ── Score ───────────────────────────────────────────────────────────
    if not findings:
        score = 75.0  # not applicable
    else:
        positives = sum(1 for f in findings if f.compliance_impact == "positive")
        gaps = sum(1 for f in findings if f.compliance_impact == "gap")
        if not gaps and positives:
            score = 88.0
        elif gaps and positives:
            score = max(35.0, 68.0 - gaps * 10 + positives * 6)
        elif gaps:
            score = max(15.0, 55.0 - gaps * 10)
        else:
            score = 60.0

    return AnalyzerResult(
        analyzer_id="privilege_minimization",
        label="Privilege Minimization (prEN 18282)",
        findings=findings,
        score=round(score, 1),
        file_count=len(evidence_files),
        graph_node_type="security",
        graph_icon="🛡",
        connected_categories=["agent_inventory", "agent_cascade", "security_controls"],
        metadata={
            "llm_files_count": len(llm_files),
            "audit_files_count": len(audit_files),
        },
    )
