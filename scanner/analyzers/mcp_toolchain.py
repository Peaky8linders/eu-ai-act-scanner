"""MCP Tool-Chain Security Analyzer — agentic supply-chain & OWASP MCP Top 10 detector.

Detects Model Context Protocol (MCP) tool-chain security risks:
* **MCP01 (Token Mismanagement & Secret Exposure)** — hardcoded API tokens /
  secrets inside ``.mcp.json`` / ``mcpServers.*.env`` blocks.
* **MCP03 / MCP06 (Tool Poisoning & Prompt Injection)** — instruction-like
  injection or hidden/bidi unicode smuggled into tool descriptions (MCPTox).
* **MCP04 (Supply Chain & Dependency Tampering)** — unpinned / rug-pullable
  MCP server references with no version pin or integrity hash.
* **MCP05 / MCP02 (SSRF / Execution Abuse)** — HTTP fetch sinks driven by
  unvalidated tool arguments without host allow-listing.
* **MCP07 (Insufficient Authentication & Authorization)** — internet-facing
  HTTP/SSE MCP servers without OAuth / RFC-9728 protected-resource metadata.

Grounds to Art. 15(4)-(5) (accuracy/robustness/cybersecurity of tool execution),
the ``tool_governance``, ``supply_chain``, ``security``, and ``access_control``
KB dimensions, and the four-axis agentic compound-risk taxonomy ``cascading`` axis.

Every finding requires an MCP surface signal in the same file (a tool definition,
an MCP server, or an MCP config) so repos with no MCP surface return a neutral
``80.0`` score with zero findings.
"""

from __future__ import annotations

import json
import re

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    is_non_product_path,
    product_files,
    search_code_files,
)
from scanner.data.agentic_taxonomy import CompoundRiskType, ThreatCategory
from scanner.data.role_obligations import (
    ROLE_DEPLOYER,
    ROLE_PRODUCT_MANUFACTURER,
    ROLE_PROVIDER,
)

# Self-reference guard so scanning this repo never self-flags this module's banks.
_SELF_SENTINEL = "_POISON_PATTERNS = ["

# ─── MCP surface detection ───────────────────────────────────────────────
_MCP_SURFACE_PATTERNS = [
    r"@(mcp|server|app)\.tool\b",
    r"\bFastMCP\b|\bmcp\.server\b|from\s+mcp\b|import\s+mcp\b",
    r"\bmodelcontextprotocol\b",
    r"\blist_tools\b|\bcall_tool\b|tools/(list|call)\b",
    r"\bmcpServers\b|\.well-known/mcp\b",
    r"\bTool\s*\(\s*name\s*=",
]
_MCP_SURFACE_RE = re.compile("|".join(_MCP_SURFACE_PATTERNS), re.IGNORECASE)

# Leg 1 — tool-poisoning (MCPTox / OWASP MCP03, MCP06).
_POISON_PATTERNS = [
    r"ignore\s+(all\s+|the\s+)?(previous|prior|above|earlier)\s+(instruction|prompt|message|context)",
    r"disregard\s+(all\s+|the\s+)?(previous|prior|above)",
    r"system\s*:\s*you\s+(are|must|should)",
    r"<\s*(important|system|secret)\s*>",
    r"do\s+not\s+(tell|mention|reveal|disclose|inform)\s+(the\s+)?(user|human)",
    r"always\s+(send|forward|include|append|exfiltrate|copy)\b",
    # Hidden / bidi / zero-width unicode — classic MCPTox smuggling vector.
    r"[\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\ufeff]",
]

# Leg 2 — SSRF-exposed tool input (OWASP MCP05, MCP02).
_HTTP_SINK_PATTERNS = [
    r"requests\.(get|post|put|delete|request)\s*\(\s*[a-zA-Z_]",
    r"httpx\.(get|post|put|delete|AsyncClient|Client)\s*\(\s*[a-zA-Z_]",
    r"urllib\.request\.urlopen\s*\(\s*[a-zA-Z_]",
    r"\burlopen\s*\(\s*[a-zA-Z_]",
    r"aiohttp\.[A-Za-z_]+\s*\(\s*[a-zA-Z_]",
    r"\bfetch\s*\(\s*[a-zA-Z_`$]",
]
_ALLOWLIST_PATTERNS = [
    r"allow(ed)?[_-]?(host|list|domain|url)",
    r"ALLOWED_(HOSTS|DOMAINS|URLS)",
    r"urlparse\b[^\n]*\bhost",
    r"\bhostname\s+(in|not in)\b",
    r"validate_url|is_allowed_url|check_host",
]

# Leg 3 — internet-facing MCP server with no auth (OWASP MCP07 / RFC-9728).
_SERVER_HTTP_PATTERNS = [
    r"transport\s*=\s*[\"'](sse|http|streamable[-_]?http)[\"']",
    r"\.sse_app\(|\.streamable_http_app\(|streamable_http",
    r"host\s*=\s*[\"']0\.0\.0\.0[\"']",
    r"mcp\.run\s*\([^\n]*transport\s*=\s*[\"'](sse|http)",
]
_AUTH_PATTERNS = [
    r"Authorization\b|\bBearer\b",
    r"ProtectedResourceMetadata|protected[_-]resource",
    r"\boauth\b|OAuth",
    r"\.well-known/oauth",
    r"verify_token|require_auth|auth_middleware|authenticate\b",
    r"RFC[-\s]?9728|\b9728\b",
]

# Leg 4 — unpinned / rug-pullable MCP server refs (OWASP MCP04).
_SERVER_REF_PATTERNS = [
    r"\"?command\"?\s*:\s*\"?(npx|uvx|uv|node|python)",
    r"\"?url\"?\s*:\s*\"?https?://",
    r"npx\s+-y\b",
]
_PINNED_PATTERNS = [
    r"@\d+\.\d+\.\d+",
    r"@sha256:",
    r"\"integrity\"\s*:",
    r"\bintegrity=|sha256[-:]|checksum",
    r"\bcommit\s*[:=]\s*[0-9a-f]{7,40}",
]

# Leg 5 — hardcoded secrets in MCP config env blocks (OWASP MCP01).
_ENV_VAR_REF_RE = re.compile(r"^\$\{?[A-Za-z_][\w:.-]*\}?$")
_SECRET_PREFIX_RE = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{10,}|gho_[A-Za-z0-9]{10,}"
    r"|glpat-[A-Za-z0-9_-]{10,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,})"
)
_SECRET_KEY_NAME_RE = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|auth[_-]?key|credential|bearer|private[_-]?key)",
    re.IGNORECASE,
)
_PLACEHOLDER_VAL_RE = re.compile(
    r"^(your[-_]|replace[-_]|changeme|example|dummy|placeholder|xxx+|todo|none|null|<[^>]+>)",
    re.IGNORECASE,
)

# Positive — tool allow-list, signed registry, pinned versions, or OAuth metadata.
_POSITIVE_PATTERNS = [
    r"allow(ed)?[_-]?(host|list|domain|tool)",
    r"tool[_-]?allow(list)?|signed[_-]?tool|tool[_-]?registry",
    r"sigstore|cosign|@sha256:|\"integrity\"\s*:",
    r"ProtectedResourceMetadata|\.well-known/oauth|\boauth\b",
    r"@\d+\.\d+\.\d+",
]

_MAX_MCP_FINDINGS = 25
_ROLES = [ROLE_PROVIDER, ROLE_PRODUCT_MANUFACTURER, ROLE_DEPLOYER]


def _first_match(content: str, patterns: list[str]) -> tuple[bool, str]:
    """Return (matched?, first_matching_line) for the first pattern that hits."""
    for pattern in patterns:
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue
        match = compiled.search(content)
        if match:
            start = content.rfind("\n", 0, match.start()) + 1
            end = content.find("\n", match.end())
            line = content[start : end if end != -1 else len(content)].strip()
            return True, line[:200]
    return False, ""


def _any_match(content: str, patterns: list[str]) -> bool:
    ok, _ = _first_match(content, patterns)
    return ok


def _is_mcp_config(path: str) -> bool:
    """True for a file conventionally used as an MCP client configuration.

    Content-only matching treated README examples and the vendored incident
    corpus as live client configs whenever they mentioned ``mcpServers``.
    """
    p = path.lower().replace("\\", "/")
    name = p.rsplit("/", 1)[-1]
    return name in {
        ".mcp.json", "mcp.json", "mcp.yaml", "mcp.yml", "mcp.config.json",
        "claude_desktop_config.json",
    } or ".well-known/mcp" in p


def _find_hardcoded_env_secret(content: str) -> str | None:
    """Return the offending env key name if an MCP config hardcodes a secret in ``env``."""
    try:
        parsed = json.loads(content)
    except (ValueError, TypeError):
        parsed = None

    if isinstance(parsed, dict):
        server_maps: list[dict] = []
        for container_key in ("mcpServers", "servers"):
            candidate = parsed.get(container_key)
            if isinstance(candidate, dict):
                server_maps.append(candidate)
        for servers in server_maps:
            for server_cfg in servers.values():
                if not isinstance(server_cfg, dict):
                    continue
                env_block = server_cfg.get("env")
                if not isinstance(env_block, dict):
                    continue
                for env_key, env_val in env_block.items():
                    if not isinstance(env_val, str):
                        continue
                    stripped = env_val.strip()
                    if not stripped or _ENV_VAR_REF_RE.match(stripped):
                        continue
                    if _PLACEHOLDER_VAL_RE.match(stripped):
                        continue
                    if _SECRET_PREFIX_RE.search(stripped):
                        return str(env_key)
                    if _SECRET_KEY_NAME_RE.search(str(env_key)) and len(stripped) >= 8:
                        return str(env_key)
        return None

    # Fallback for non-JSON / JSONC MCP config files: look for known token prefixes inside an env block.
    if re.search(r"\"?env\"?\s*:", content, re.IGNORECASE):
        if _SECRET_PREFIX_RE.search(content):
            return "env_secret"
    return None


def _candidate_files(ctx: AnalyzerContext) -> list[tuple[str, str]]:
    """Combine product files and agent config files, deduped by path."""
    merged: dict[str, str] = {}
    for path, content in product_files(ctx):
        merged[path] = content
    for path, content in ctx.agent_config_files.items():
        if not is_non_product_path(path):
            merged[path] = content
    return list(merged.items())


def analyze_mcp_toolchain(ctx: AnalyzerContext) -> AnalyzerResult:
    """Detect MCP tool-chain security gaps (MCP01–MCP07 / MCPTox / rug-pull / SSRF)."""
    findings: list[Finding] = []
    positives: list[Finding] = []
    mcp_files: set[str] = set()
    # Match MCP surfaces in live code only. Literal examples in a benchmark,
    # docs, comments, or detector table must not turn their file into a server.
    active_surface_paths = {
        path for path, _line in search_code_files(ctx, _MCP_SURFACE_RE.pattern)
    }

    for path, content in _candidate_files(ctx):
        if _SELF_SENTINEL in content:
            continue
        is_cfg = _is_mcp_config(path)
        is_mcp = is_cfg or path in active_surface_paths
        if not is_mcp:
            continue
        mcp_files.add(path)
        file_had_gap = False

        # Leg 1 — tool-description poisoning (MCPTox / OWASP MCP03, MCP06).
        ok, line = _first_match(content, _POISON_PATTERNS)
        if ok:
            file_had_gap = True
            findings.append(Finding(
                id="mcp-tool-poisoning",
                category="mcp_toolchain",
                title="MCP tool description carries injection / hidden-unicode payload",
                description=(
                    "[OWASP MCP03: Tool Poisoning / MCP06: Prompt Injection] "
                    "An MCP tool or skill description contains instruction-like text "
                    "or hidden/bidi unicode — the MCPTox tool-poisoning vector. "
                    "A poisoned description is executed as trusted context on every "
                    "invocation, cascading across the tool-call chain. Art. 15(4) "
                    "robustness + prEN 18282 tool governance require validating tool "
                    "metadata before load."
                ),
                file_path=path, confidence=0.7,
                compliance_impact="gap",
                compliance_dimensions=["tool_governance", "security"],
                evidence_snippet=line,
                kb_question_ids=["tg-1", "sc-3"], suggested_answer="no",
                article_paragraphs=["15(4)"],
                matched_pattern="mcp_tool_poisoning",
                compound_risk_type=CompoundRiskType.cascading.value,
                threat_categories=[
                    ThreatCategory.prompt_injection.value,
                    ThreatCategory.tool_misuse_privilege_escalation.value,
                ],
                applicable_roles=_ROLES,
            ))

        # Leg 2 — SSRF-exposed tool input (OWASP MCP05, MCP02).
        ok, line = _first_match(content, _HTTP_SINK_PATTERNS)
        if ok and not _any_match(content, _ALLOWLIST_PATTERNS):
            file_had_gap = True
            findings.append(Finding(
                id="mcp-tool-ssrf",
                category="mcp_toolchain",
                title="MCP tool passes an unvalidated input into an HTTP fetch (SSRF)",
                description=(
                    "[OWASP MCP05: Execution Abuse / MCP02: Privilege Escalation] "
                    "A tool handler forwards a variable URL into an HTTP client with "
                    "no host allow-list — a server-side request forgery vector when the "
                    "URL originates from an agent-controlled tool argument. Add host "
                    "allow-listing / URL validation before the fetch. Art. 15(4)-(5) "
                    "cybersecurity."
                ),
                file_path=path, confidence=0.65,
                compliance_impact="gap",
                compliance_dimensions=["security"],
                evidence_snippet=line,
                kb_question_ids=["sc-3", "sc-2"], suggested_answer="no",
                article_paragraphs=["15(4)", "15(5)"],
                matched_pattern="mcp_tool_ssrf",
                compound_risk_type=CompoundRiskType.cascading.value,
                threat_categories=[
                    ThreatCategory.autonomous_cyber_exploit.value,
                    ThreatCategory.tool_misuse_privilege_escalation.value,
                ],
                applicable_roles=_ROLES,
            ))

        # Leg 3 — internet-facing MCP server with no auth (OWASP MCP07 / RFC-9728).
        ok, line = _first_match(content, _SERVER_HTTP_PATTERNS)
        if ok and not _any_match(content, _AUTH_PATTERNS):
            file_had_gap = True
            findings.append(Finding(
                id="mcp-server-no-auth",
                category="mcp_toolchain",
                title="Internet-facing MCP server exposes tools with no OAuth / protected-resource metadata",
                description=(
                    "[OWASP MCP07: Insufficient Authentication & Authorization] "
                    "An MCP server binds an http/sse transport (or 0.0.0.0) with no "
                    "OAuth / RFC-9728 protected-resource metadata — its tools are "
                    "reachable without authentication. Publish protected-resource "
                    "metadata and require a bearer token. Art. 15(4) + prEN 18282 "
                    "API-level tool-permission enforcement."
                ),
                file_path=path, confidence=0.6,
                compliance_impact="gap",
                compliance_dimensions=["tool_governance", "access_control"],
                evidence_snippet=line,
                kb_question_ids=["tg-3", "tg-1"], suggested_answer="no",
                article_paragraphs=["15(4)"],
                matched_pattern="mcp_server_no_auth",
                compound_risk_type=CompoundRiskType.cascading.value,
                threat_categories=[ThreatCategory.tool_misuse_privilege_escalation.value],
                applicable_roles=_ROLES,
            ))

        # Leg 4 — unpinned / rug-pullable MCP server ref in config (OWASP MCP04).
        if is_cfg:
            ok, line = _first_match(content, _SERVER_REF_PATTERNS)
            if ok and not _any_match(content, _PINNED_PATTERNS):
                file_had_gap = True
                findings.append(Finding(
                    id="mcp-unpinned-server",
                    category="mcp_toolchain",
                    title="MCP server pulled without a version pin or integrity hash (rug-pull surface)",
                    description=(
                        "[OWASP MCP04: Software Supply Chain Attacks & Dependency Tampering] "
                        "An MCP config references a server by command/registry/URL with "
                        "no pinned version or integrity hash — a rug-pull surface where "
                        "the upstream can silently swap the tool behind the agent's back. "
                        "Pin the server version (or an integrity hash) and pull only from "
                        "an allow-listed registry. Art. 15 supply-chain / NIST SP 800-161."
                    ),
                    file_path=path, confidence=0.65,
                    compliance_impact="gap",
                    compliance_dimensions=["supply_chain"],
                    evidence_snippet=line,
                    kb_question_ids=["sp-1", "sp-2"], suggested_answer="no",
                    article_paragraphs=["15"],
                    matched_pattern="mcp_unpinned_server",
                    compound_risk_type=CompoundRiskType.cascading.value,
                    threat_categories=[ThreatCategory.tool_misuse_privilege_escalation.value],
                    applicable_roles=_ROLES,
                ))

            # Leg 5 — hardcoded secret / token in MCP server env block (OWASP MCP01).
            leaked_key = _find_hardcoded_env_secret(content)
            if leaked_key:
                file_had_gap = True
                findings.append(Finding(
                    id="mcp-hardcoded-env-secret",
                    category="mcp_toolchain",
                    title=f"Hardcoded secret in MCP server env configuration ({leaked_key})",
                    description=(
                        "[OWASP MCP01: Token Mismanagement & Secret Exposure] "
                        f"MCP server configuration defines a literal secret under env key "
                        f"`{leaked_key}` instead of an environment reference (`${{VAR}}`). "
                        "Committed MCP configs leak long-lived credentials to every developer "
                        "and CI runner with repo read access. Replace literal credentials with "
                        "environment variable interpolation or a secrets manager. Art. 15(4)."
                    ),
                    file_path=path, confidence=0.85,
                    compliance_impact="gap",
                    compliance_dimensions=["security", "access_control"],
                    evidence_snippet=f"[redacted — hardcoded credential in MCP env key '{leaked_key}']",
                    kb_question_ids=["ac-2", "sc-2"], suggested_answer="no",
                    article_paragraphs=["15(4)"],
                    matched_pattern="mcp_hardcoded_env_secret",
                    compound_risk_type=CompoundRiskType.cascading.value,
                    threat_categories=[
                        ThreatCategory.autonomous_cyber_exploit.value,
                        ThreatCategory.tool_misuse_privilege_escalation.value,
                    ],
                    applicable_roles=_ROLES,
                ))

        # Positive — a governance control is present in a file with no detected gap.
        if not file_had_gap:
            ok, line = _first_match(content, _POSITIVE_PATTERNS)
            if ok:
                positives.append(Finding(
                    id="mcp-tool-control",
                    category="mcp_toolchain",
                    title="MCP tool-chain control present (allow-list / signing / pin / OAuth)",
                    description=(
                        "[OWASP MCP04 / MCP07 Control] "
                        "A tool allow-list, signed tool registry, pinned server version, "
                        "or OAuth protected-resource metadata is present — the tool chain "
                        "is governed rather than dynamically rug-pullable. Mitigates the "
                        "MCPTox / rug-pull surface (Art. 15(4) + prEN 18282)."
                    ),
                    file_path=path, confidence=0.65,
                    compliance_impact="positive",
                    compliance_dimensions=["tool_governance", "supply_chain"],
                    evidence_snippet=line,
                    kb_question_ids=["tg-1", "sp-1"], suggested_answer="yes",
                    article_paragraphs=["15(4)"],
                    matched_pattern="mcp_tool_control",
                    compound_risk_type=CompoundRiskType.cascading.value,
                    threat_categories=[ThreatCategory.tool_misuse_privilege_escalation.value],
                ))

    findings = (findings + positives)[:_MAX_MCP_FINDINGS]

    if not mcp_files:
        score = 80.0
    else:
        gaps = [f for f in findings if f.compliance_impact == "gap"]
        pos = [f for f in findings if f.compliance_impact == "positive"]
        if gaps and not pos:
            score = max(15.0, 50.0 - len(gaps) * 20)
        elif gaps and pos:
            score = max(35.0, 65.0 - len(gaps) * 15 + len(pos) * 5)
        elif pos:
            score = min(95.0, 80.0 + len(pos) * 5)
        else:
            score = 75.0

    score = max(0.0, min(100.0, score))
    return AnalyzerResult(
        analyzer_id="mcp_toolchain",
        label="MCP Tool-Chain Security",
        findings=findings,
        score=round(score, 1),
        file_count=len(mcp_files),
        graph_node_type="control",
        graph_icon="🔌",
        connected_categories=[
            "privilege_minimization",
            "agent_inventory",
            "security_controls",
        ],
    )
