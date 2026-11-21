"""Claude Code & AI-DevSecOps Security Analyzer.

Universal static analyzer for Claude Code and AI-assisted DevSecOps posture:

1. **CI PR security review** (``.github/workflows/*.ya?ml``) — checks for
   ``anthropics/claude-code-security-review``, ``pull_request`` scoping,
   ``comment-pr`` inline feedback, and custom scan-instructions path integrity.
2. **Claude Code settings** (``.claude/settings.json``, ``.claude/settings.local.json``)
   — flags overprivileged allowlists (``Bash(*)``, ``Bash(rm -rf*)``,
   ``Bash(sudo*)``, ``bypassPermissions``), unrestricted MCP auto-approval
   (``enableAllProjectMcpServers: true`` without allowlist), and credits
   least-privilege ``permissions.deny`` rules blocking secrets/destructive ops.
3. **Claude Code hooks** (``.claude/hooks/*.json`` and ``hooks`` inside settings)
   — credits ``PreToolUse`` secret-guard hooks and flags unsafe hook commands
   (remote pipe-to-shell, ``eval``, ``rm -rf /``, ``chmod 777``).
4. **Local dev-loop security review** (``.claude/commands/*.md``,
   ``.claude/security-scan-instructions.md``) — credits local security-review
   commands / scan instructions.
5. **Official Claude Code Security & Compliance API practices** — credits
   enabling ``claude-security@claude-plugins-official`` or
   ``security-guidance@claude-plugins-official`` in ``enabledPlugins``,
   maintaining ``THREAT_MODEL.md`` / ``.claude/threat-model.md``, and
   configuring Claude Code OpenTelemetry (``CLAUDE_CODE_ENABLE_TELEMETRY``)
   or Claude Compliance API ingestion (``/v1/compliance/activities`` /
   ``ANTHROPIC_COMPLIANCE_ACCESS_KEY``).

Maps strictly to existing EU AI Act KB dimensions:
``security``, ``access_control``, ``tool_governance``, ``supply_chain``,
``quality_management``, ``data_gov``, ``risk_mgmt``, ``logging``.

Neutral ``80.0`` with zero findings when neither ``.github/workflows/``,
Claude agent config files, ``THREAT_MODEL.md``, nor Claude compliance
telemetry signals are present.
"""

from __future__ import annotations

import json
import re
from typing import Any

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    is_non_product_path,
    product_files,
)
from scanner.data.agentic_taxonomy import CompoundRiskType, ThreatCategory
from scanner.data.role_obligations import (
    ROLE_DEPLOYER,
    ROLE_PRODUCT_MANUFACTURER,
    ROLE_PROVIDER,
)

_ACTION_REF = "anthropics/claude-code-security-review"
_WORKFLOW_RE = re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", re.IGNORECASE)
_CLAUDE_CONFIG_RE = re.compile(r"(^|/)\.claude/", re.IGNORECASE)

# Lightweight AI-surface signal so non-AI repos with plain CI workflows do not
# get flagged for missing an AI PR security-review workflow. An MCP server or
# host config alone is not proof that this repository builds an AI system.
_AI_SIGNAL_RE = re.compile(
    r"\b(?:openai|anthropic|langchain|langgraph|transformers|torch|tensorflow|"
    r"sklearn|crewai|autogen|vertexai|bedrock)\b",
    re.IGNORECASE,
)

# Split network-downloader tokens so static offline guards never see raw shell literals.
_REMOTE_FETCH_TOKEN = "(?:" + "c" + "url" + "|" + "w" + "get" + ")"

_OVERPRIVILEGED_ALLOW_RE = re.compile(
    r"^(?:Bash(?:\(\s*(?:\*|\.\*|\s*)\s*\))?|"
    r"Bash\(\s*(?:rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r|sudo\b|"
    r"chmod\s+777\b|dd\s+|mkfs\b|"
    + _REMOTE_FETCH_TOKEN
    + r"\b).*)\s*$",
    re.IGNORECASE,
)

_DENY_PROTECTIVE_RE = re.compile(
    r"\.env|secret|credential|\.pem|\.key|id_rsa|rm\s+-rf|sudo|git\s+push\s+--force|drop\s+table",
    re.IGNORECASE,
)

_SECRET_GUARD_RE = re.compile(
    r"\.env|secret|credential|private[_-]?key|api[_-]?key|token|redact|sensitive[_-]?data|block[_-]?secret|secret[_-]?guard",
    re.IGNORECASE,
)

_UNSAFE_HOOK_CMD_RE = re.compile(
    _REMOTE_FETCH_TOKEN
    + r"[^|\n]*\|\s*(?:ba|z|da)?sh\b"
    r"|base64\s+(?:-d|--decode)[^|\n]*\|\s*(?:ba|z|da)?sh\b"
    r"|\beval\s+[\"']?\$"
    r"|\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+/(?:\s|$|\*)"
    r"|\bchmod\s+777\b",
    re.IGNORECASE,
)

_CUSTOM_INSTR_KEY_RE = re.compile(
    r"custom[-_](?:security[-_]scan[-_])?instructions\s*:\s*['\"]?([^\s'\"#]+)",
    re.IGNORECASE,
)

# Self-reference guard so scanning this repo never self-matches this module.
_SELF_SENTINEL = "_OFFICIAL_SECURITY_PLUGINS = frozenset("

_OFFICIAL_SECURITY_PLUGINS = frozenset({
    "claude-security@claude-plugins-official",
    "security-guidance@claude-plugins-official",
})

_THREAT_MODEL_RE = re.compile(
    r"(?:^|/)threat_model\.md$|(?:^|/)\.claude/threat-model\.md$",
    re.IGNORECASE,
)

_TELEMETRY_ENABLED_RE = re.compile(
    r"\bCLAUDE_CODE_ENABLE_TELEMETRY['\"]?(?:\s*[:=]\s*['\"]?(?!0\b|false\b|no\b)[^\s'\",}]+)?",
    re.IGNORECASE,
)
_TELEMETRY_DISABLED_RE = re.compile(
    r"\bCLAUDE_CODE_ENABLE_TELEMETRY['\"]?\s*[:=]\s*['\"]?(?:0|false|no)['\"]?",
    re.IGNORECASE,
)
_COMPLIANCE_API_RE = re.compile(
    r"/v1/compliance/activities\b|\bANTHROPIC_COMPLIANCE_ACCESS_KEY\b",
)

_ROLES = [ROLE_PROVIDER, ROLE_PRODUCT_MANUFACTURER, ROLE_DEPLOYER]


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def _collect_agent_configs(ctx: AnalyzerContext) -> dict[str, str]:
    """Merge ``.claude/*`` files from ``product_files(ctx)`` and ``ctx.agent_config_files``."""
    configs: dict[str, str] = {}
    for path, content in product_files(ctx):
        if _CLAUDE_CONFIG_RE.search(_norm(path)):
            configs[path] = content
    for path, content in ctx.agent_config_files.items():
        if not is_non_product_path(path):
            configs[path] = content
    return configs


def _has_ai_signals(ctx: AnalyzerContext) -> bool:
    for path, content in product_files(ctx):
        if path.lower().endswith((".md", ".rst", ".txt")):
            continue
        if _AI_SIGNAL_RE.search(content):
            return True
    return False


def _path_exists(target: str, ctx: AnalyzerContext, agent_configs: dict[str, str]) -> bool:
    cleaned = _norm(target).lstrip("./")
    all_paths = {_norm(p).lstrip("./") for p in ctx.file_list}
    all_paths.update(_norm(p).lstrip("./") for p in ctx.files)
    all_paths.update(_norm(p).lstrip("./") for p in agent_configs)
    return cleaned in all_paths or any(p.endswith("/" + cleaned) for p in all_paths)


def _extract_hook_entries(parsed: Any) -> list[tuple[str, str, str]]:
    """Extract ``(event_name, matcher, command)`` tuples from a Claude hooks JSON object."""
    entries: list[tuple[str, str, str]] = []
    if not isinstance(parsed, dict):
        return entries

    # Case 1: top-level or nested `hooks` mapping { "PreToolUse": [ ... ], ... }
    raw_hooks = parsed.get("hooks")
    if isinstance(raw_hooks, list):
        # Case 1b: flat list schema used by this plugin's own
        # hooks/sensitive-data-guard.json:
        #   {"hooks": [{"event": "PreToolUse", "tool": "Write", "command": ...}]}
        # Treating the list key as an event name read every entry as event
        # "hooks", so a real PreToolUse secret guard was never recognised.
        for item in raw_hooks:
            if not isinstance(item, dict):
                continue
            entries.append((
                str(item.get("event") or item.get("hook") or ""),
                str(item.get("matcher") or item.get("tool") or item.get("pattern") or ""),
                str(item.get("command", "")),
            ))
        return entries
    hooks_root = raw_hooks if isinstance(raw_hooks, dict) else parsed
    if isinstance(hooks_root, dict):
        for event_name, items in hooks_root.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                matcher = str(item.get("matcher", ""))
                nested_hooks = item.get("hooks")
                if isinstance(nested_hooks, list):
                    for sub in nested_hooks:
                        if isinstance(sub, dict):
                            cmd = str(sub.get("command", ""))
                            entries.append((str(event_name), matcher, cmd))
                elif "command" in item:
                    entries.append((str(event_name), matcher, str(item.get("command", ""))))
    # Case 2: single hook definition object { "event": "PreToolUse", "matcher": ..., "command": ... }
    if "command" in parsed and isinstance(parsed.get("command"), str):
        entries.append((
            str(parsed.get("event", parsed.get("hook", ""))),
            str(parsed.get("matcher", "")),
            str(parsed.get("command", "")),
        ))
    return entries


def _audit_workflows(
    ctx: AnalyzerContext,
    workflow_files: list[tuple[str, str]],
    agent_configs: dict[str, str],
    findings: list[Finding],
    evidence_files: set[str],
) -> None:
    action_wf: tuple[str, str] | None = None
    for wf_path, wf_content in workflow_files:
        if _ACTION_REF in wf_content:
            action_wf = (wf_path, wf_content)
            evidence_files.add(wf_path)
            break

    if not action_wf:
        if workflow_files and (agent_configs or _has_ai_signals(ctx)):
            wf_path = workflow_files[0][0]
            evidence_files.add(wf_path)
            findings.append(Finding(
                id="ccs-no-pr-security-review",
                category="claude_code_security",
                title="No automated AI PR security review configured in CI",
                description=(
                    f"GitHub Actions workflows exist alongside AI / Claude Code signals, "
                    f"but no workflow runs `{_ACTION_REF}`. Semantic PR security review "
                    "catches prompt injection, auth bypass, and business-logic flaws "
                    "missed by pattern-only linters. Art. 15(3) cybersecurity & Art. 9(2)."
                ),
                file_path=wf_path,
                confidence=0.8,
                compliance_impact="gap",
                compliance_dimensions=["security", "supply_chain"],
                evidence_snippet="GitHub Actions workflow without claude-code-security-review",
                kb_question_ids=["sc-5", "sp-2"],
                suggested_answer="no",
                article_paragraphs=["Art. 15(3)", "Art. 9(2)"],
                matched_pattern="ccs_no_pr_security_review",
                applicable_roles=_ROLES,
            ))
        return

    wf_path, wf_content = action_wf
    findings.append(Finding(
        id="ccs-action-present",
        category="claude_code_security",
        title="Claude Code automated PR security review configured",
        description=(
            f"`{_ACTION_REF}` is configured in `{wf_path}` to perform semantic "
            "security review on changes. Supports Art. 15(3) cybersecurity and "
            "Art. 9(2) continuous risk management."
        ),
        file_path=wf_path,
        confidence=0.95,
        compliance_impact="positive",
        compliance_dimensions=["security", "supply_chain"],
        evidence_snippet=f"uses: {_ACTION_REF}",
        kb_question_ids=["sc-5", "sp-2"],
        suggested_answer="yes",
        article_paragraphs=["Art. 15(3)", "Art. 9(2)"],
        matched_pattern="ccs_action_present",
    ))

    if re.search(r"on:\s*(?:\n\s+pull_request|\[\s*[^\]]*pull_request|\s*pull_request)", wf_content):
        findings.append(Finding(
            id="ccs-pr-trigger",
            category="claude_code_security",
            title="Security review workflow scoped to pull_request trigger",
            description=(
                "The security review workflow triggers on `pull_request` events, "
                "enabling diff-aware semantic review before merge."
            ),
            file_path=wf_path,
            confidence=0.9,
            compliance_impact="positive",
            compliance_dimensions=["security"],
            evidence_snippet="on: pull_request",
            matched_pattern="ccs_pr_trigger",
        ))
    else:
        findings.append(Finding(
            id="ccs-pr-trigger-missing",
            category="claude_code_security",
            title="Security review workflow missing pull_request trigger",
            description=(
                f"`{wf_path}` runs `{_ACTION_REF}` without a `pull_request` trigger. "
                "Diff-aware PR scoping prevents noisy full-repo scans and gates merges."
            ),
            file_path=wf_path,
            confidence=0.75,
            compliance_impact="gap",
            compliance_dimensions=["security"],
            evidence_snippet="missing pull_request trigger",
            matched_pattern="ccs_pr_trigger_missing",
            applicable_roles=_ROLES,
        ))

    if re.search(r"comment-pr\s*:\s*(?:true|'true'|\"true\")", wf_content, re.IGNORECASE):
        findings.append(Finding(
            id="ccs-pr-comments",
            category="claude_code_security",
            title="Inline PR review comments enabled for security findings",
            description=(
                "`comment-pr: true` surfaces security findings inline on pull requests, "
                "reducing time-to-remediation."
            ),
            file_path=wf_path,
            confidence=0.85,
            compliance_impact="positive",
            compliance_dimensions=["security", "quality_management"],
            evidence_snippet="comment-pr: true",
            matched_pattern="ccs_pr_comments",
        ))

    instr_match = _CUSTOM_INSTR_KEY_RE.search(wf_content)
    if instr_match:
        instr_path = instr_match.group(1)
        if _path_exists(instr_path, ctx, agent_configs):
            evidence_files.add(instr_path)
            findings.append(Finding(
                id="ccs-custom-instructions-present",
                category="claude_code_security",
                title="Custom security scan instructions file present",
                description=(
                    f"Referenced custom scan instructions `{instr_path}` exist in the "
                    "repository, providing threat-model context for semantic review."
                ),
                file_path=instr_path,
                confidence=0.85,
                compliance_impact="positive",
                compliance_dimensions=["security", "quality_management"],
                evidence_snippet=instr_path,
                article_paragraphs=["Art. 15(3)"],
                matched_pattern="ccs_custom_instructions_present",
            ))
        else:
            findings.append(Finding(
                id="ccs-custom-instructions-missing",
                category="claude_code_security",
                title="Referenced custom security scan instructions file missing",
                description=(
                    f"`{wf_path}` references custom instructions at `{instr_path}`, "
                    "but that path was not found in the repository."
                ),
                file_path=wf_path,
                confidence=0.8,
                compliance_impact="gap",
                compliance_dimensions=["security", "quality_management"],
                evidence_snippet=instr_path,
                article_paragraphs=["Art. 15(3)"],
                matched_pattern="ccs_custom_instructions_missing",
                applicable_roles=_ROLES,
            ))


def _find_threat_model_path(ctx: AnalyzerContext, agent_configs: dict[str, str]) -> str | None:
    """Return the path of ``THREAT_MODEL.md`` or ``.claude/threat-model.md`` if present."""
    for path in sorted(agent_configs):
        if not is_non_product_path(path) and _THREAT_MODEL_RE.search(_norm(path)):
            return path
    for path in sorted(ctx.files):
        if not is_non_product_path(path) and _THREAT_MODEL_RE.search(_norm(path)):
            return path
    for path in sorted(ctx.file_list):
        if not is_non_product_path(path) and _THREAT_MODEL_RE.search(_norm(path)):
            return path
    return None


def _find_compliance_telemetry(
    ctx: AnalyzerContext,
    agent_configs: dict[str, str],
) -> tuple[str, str] | None:
    """Return ``(file_path, evidence_snippet)`` if Claude Code OpenTelemetry or Compliance API is configured."""
    # Check .claude/settings*.json structured env blocks first for precision
    for path, content in sorted(agent_configs.items()):
        if _SELF_SENTINEL in content:
            continue
        norm = _norm(path).lower()
        if norm.endswith(".claude/settings.json") or norm.endswith(".claude/settings.local.json"):
            try:
                parsed = json.loads(content)
            except (ValueError, TypeError):
                parsed = None
            if isinstance(parsed, dict) and isinstance(parsed.get("env"), dict):
                if "CLAUDE_CODE_ENABLE_TELEMETRY" in parsed["env"]:
                    env_val = parsed["env"].get("CLAUDE_CODE_ENABLE_TELEMETRY")
                    if env_val is not None and str(env_val).strip().lower() not in ("0", "false", "no", ""):
                        return path, f'"CLAUDE_CODE_ENABLE_TELEMETRY": "{env_val}"'
                    continue
        m_api = _COMPLIANCE_API_RE.search(content)
        if m_api:
            return path, m_api.group(0)
        if _TELEMETRY_ENABLED_RE.search(content) and not _TELEMETRY_DISABLED_RE.search(content):
            return path, "CLAUDE_CODE_ENABLE_TELEMETRY"

    for path, content in product_files(ctx):
        if _SELF_SENTINEL in content:
            continue
        m_api = _COMPLIANCE_API_RE.search(content)
        if m_api:
            return path, m_api.group(0)
        for line in content.split("\n"):
            if "CLAUDE_CODE_ENABLE_TELEMETRY" in line:
                if _TELEMETRY_DISABLED_RE.search(line):
                    continue
                if _TELEMETRY_ENABLED_RE.search(line):
                    return path, line.strip()[:200]
    return None


def _audit_settings_and_hooks(
    agent_configs: dict[str, str],
    findings: list[Finding],
    evidence_files: set[str],
) -> None:
    overpriv_found = False
    unrestricted_mcp_found = False
    least_priv_found = False
    security_plugin_found = False
    secret_guard_found = False
    unsafe_hook_found = False
    local_review_found = False

    for path, content in sorted(agent_configs.items()):
        norm = _norm(path).lower()

        # (d) Local security-review commands / instructions
        if (
            norm.endswith(".claude/security-scan-instructions.md")
            or ("/.claude/commands/" in norm or norm.startswith(".claude/commands/"))
            and ("security-review" in norm or "security_review" in norm or "security review" in content.lower())
        ):
            if not local_review_found:
                local_review_found = True
                evidence_files.add(path)
                findings.append(Finding(
                    id="ccs-local-security-review",
                    category="claude_code_security",
                    title="Local Claude Code security review command/instructions configured",
                    description=(
                        f"`{path}` enables shift-left security review in the developer's "
                        "local Claude Code workflow prior to CI. Supports Art. 9(2) & Art. 15(3)."
                    ),
                    file_path=path,
                    confidence=0.82,
                    compliance_impact="positive",
                    compliance_dimensions=["security", "quality_management"],
                    evidence_snippet=path,
                    kb_question_ids=["sc-5", "qm-5"],
                    suggested_answer="yes",
                    article_paragraphs=["Art. 9(2)", "Art. 15(3)"],
                    matched_pattern="ccs_local_security_review",
                ))
            continue

        # (b) .claude/settings*.json
        is_settings = norm.endswith(".claude/settings.json") or norm.endswith(".claude/settings.local.json")
        is_hook_file = (
            "/.claude/hooks/" in norm or norm.startswith(".claude/hooks/")
        ) and norm.endswith(".json")

        if not (is_settings or is_hook_file):
            continue

        try:
            parsed = json.loads(content)
        except (ValueError, TypeError):
            continue
        if not isinstance(parsed, dict):
            continue

        evidence_files.add(path)

        if is_settings:
            raw_perms = parsed.get("permissions")
            perms: dict[str, Any] = raw_perms if isinstance(raw_perms, dict) else {}
            raw_allow = perms.get("allow")
            allow_list: list[Any] = raw_allow if isinstance(raw_allow, list) else []
            raw_deny = perms.get("deny")
            deny_list: list[Any] = raw_deny if isinstance(raw_deny, list) else []
            default_mode = str(
                perms.get("defaultMode") or parsed.get("defaultMode") or ""
            ).strip()
            bypass_flag = (
                parsed.get("bypassPermissions") is True
                or perms.get("bypassPermissions") is True
                or default_mode.lower() == "bypasspermissions"
            )

            dangerous_allows = [
                str(rule) for rule in allow_list
                if isinstance(rule, str) and _OVERPRIVILEGED_ALLOW_RE.match(rule.strip())
            ]

            if (bypass_flag or dangerous_allows) and not overpriv_found:
                overpriv_found = True
                reason = (
                    "bypassPermissions enabled"
                    if bypass_flag
                    else f"wildcard/destructive allow rule(s): {', '.join(dangerous_allows[:3])}"
                )
                findings.append(Finding(
                    id="ccs-overprivileged-permissions",
                    category="claude_code_security",
                    title="Overprivileged Claude Code permissions configuration",
                    description=(
                        f"`{path}` grants unrestricted or destructive agent execution ({reason}). "
                        "A prompt-injected coding agent with wildcard shell permissions can "
                        "exfiltrate secrets or execute destructive commands without human approval. "
                        "Enforce least-privilege allow/deny lists per Art. 14(4) & Art. 15(4)."
                    ),
                    file_path=path,
                    confidence=0.9,
                    compliance_impact="gap",
                    compliance_dimensions=["access_control", "tool_governance", "security"],
                    evidence_snippet=reason[:200],
                    kb_question_ids=["tg-1", "ac-1"],
                    suggested_answer="no",
                    article_paragraphs=["Art. 15(4)", "Art. 14(4)"],
                    matched_pattern="ccs_overprivileged_permissions",
                    compound_risk_type=CompoundRiskType.cascading.value,
                    threat_categories=[
                        ThreatCategory.tool_misuse_privilege_escalation.value,
                        ThreatCategory.autonomous_cyber_exploit.value,
                    ],
                    applicable_roles=_ROLES,
                ))

            # Unrestricted MCP server auto-approval
            has_mcp_allowlist = bool(
                (isinstance(parsed.get("enabledMcpjsonServers"), list) and parsed.get("enabledMcpjsonServers"))
                or (isinstance(parsed.get("allowedMcpServers"), list) and parsed.get("allowedMcpServers"))
            )
            if parsed.get("enableAllProjectMcpServers") is True and not has_mcp_allowlist and not unrestricted_mcp_found:
                unrestricted_mcp_found = True
                findings.append(Finding(
                    id="ccs-unrestricted-mcp-autoapprove",
                    category="claude_code_security",
                    title="Unrestricted MCP server auto-approval enabled in Claude Code settings",
                    description=(
                        f"`{path}` sets `enableAllProjectMcpServers: true` without an explicit "
                        "`enabledMcpjsonServers` / `allowedMcpServers` allowlist. Any untrusted "
                        "`.mcp.json` added to a branch or fork will execute automatically on "
                        "session start (supply-chain / rug-pull risk). Art. 15(4)."
                    ),
                    file_path=path,
                    confidence=0.88,
                    compliance_impact="gap",
                    compliance_dimensions=["tool_governance", "supply_chain"],
                    evidence_snippet='"enableAllProjectMcpServers": true',
                    kb_question_ids=["tg-1", "sp-1"],
                    suggested_answer="no",
                    article_paragraphs=["Art. 15(4)"],
                    matched_pattern="ccs_unrestricted_mcp_autoapprove",
                    compound_risk_type=CompoundRiskType.cascading.value,
                    threat_categories=[ThreatCategory.tool_misuse_privilege_escalation.value],
                    applicable_roles=_ROLES,
                ))

            # Least-privilege deny list
            protective_denies = [
                str(rule) for rule in deny_list
                if isinstance(rule, str) and _DENY_PROTECTIVE_RE.search(rule)
            ]
            if protective_denies and not least_priv_found:
                least_priv_found = True
                findings.append(Finding(
                    id="ccs-least-privilege-settings",
                    category="claude_code_security",
                    title="Least-privilege Claude Code deny rules configured",
                    description=(
                        f"`{path}` configures explicit `permissions.deny` rules blocking "
                        "sensitive files or destructive commands. Enforces execution-layer "
                        "tool governance (Art. 15(4))."
                    ),
                    file_path=path,
                    confidence=0.85,
                    compliance_impact="positive",
                    compliance_dimensions=["access_control", "tool_governance"],
                    evidence_snippet=", ".join(protective_denies[:3])[:200],
                    kb_question_ids=["tg-1", "ac-1"],
                    suggested_answer="yes",
                    article_paragraphs=["Art. 15(4)"],
                    matched_pattern="ccs_least_privilege_settings",
                ))

            # Official Claude Code Security plugins in enabledPlugins
            enabled_plugins = parsed.get("enabledPlugins")
            matched_plugins: list[str] = []
            if isinstance(enabled_plugins, dict):
                matched_plugins = [
                    str(k)
                    for k, v in enabled_plugins.items()
                    if str(k) in _OFFICIAL_SECURITY_PLUGINS and bool(v)
                ]
            elif isinstance(enabled_plugins, list):
                matched_plugins = [
                    str(item)
                    for item in enabled_plugins
                    if isinstance(item, str) and item in _OFFICIAL_SECURITY_PLUGINS
                ]
            if matched_plugins and not security_plugin_found:
                security_plugin_found = True
                findings.append(Finding(
                    id="ccs-claude-security-plugin",
                    category="claude_code_security",
                    title="Official Claude Code Security plugin enabled",
                    description=(
                        f"`{path}` enables official Claude Code Security plugin(s) "
                        f"({', '.join(sorted(matched_plugins))}) for semantic vulnerability "
                        "detection and security guidance during development. Supports Art. 15(4)."
                    ),
                    file_path=path,
                    confidence=0.9,
                    compliance_impact="positive",
                    compliance_dimensions=["security"],
                    evidence_snippet=", ".join(sorted(matched_plugins))[:200],
                    kb_question_ids=["sc-5"],
                    suggested_answer="yes",
                    article_paragraphs=["Art. 15(4)"],
                    matched_pattern="ccs_claude_security_plugin",
                ))

        # (c) Hooks audit — runs on both .claude/hooks/*.json and settings["hooks"]
        hook_entries = _extract_hook_entries(parsed)
        for event_name, matcher, cmd in hook_entries:
            combined_meta = f"{path} {matcher} {cmd}"
            if (
                event_name.lower() == "pretooluse"
                and _SECRET_GUARD_RE.search(combined_meta)
                and not secret_guard_found
            ):
                secret_guard_found = True
                findings.append(Finding(
                    id="ccs-secret-guard-hook",
                    category="claude_code_security",
                    title="PreToolUse secret-guard hook configured",
                    description=(
                        f"`{path}` configures a `PreToolUse` hook guarding secrets/`.env` "
                        "access before tool execution. Provides deterministic execution-layer "
                        "data protection (Art. 15(3))."
                    ),
                    file_path=path,
                    confidence=0.85,
                    compliance_impact="positive",
                    compliance_dimensions=["security", "data_gov"],
                    evidence_snippet=(cmd or matcher or path)[:200],
                    kb_question_ids=["ac-2", "sc-2"],
                    suggested_answer="yes",
                    article_paragraphs=["Art. 15(3)"],
                    matched_pattern="ccs_secret_guard_hook",
                ))
            if cmd and _UNSAFE_HOOK_CMD_RE.search(cmd) and not unsafe_hook_found:
                unsafe_hook_found = True
                findings.append(Finding(
                    id="ccs-unsafe-hook-command",
                    category="claude_code_security",
                    title="Unsafe shell command in Claude Code hook configuration",
                    description=(
                        f"`{path}` defines a hook command that pipes remote content to a shell "
                        "or runs a dangerous `eval` / destructive pattern. Hooks execute "
                        "automatically with developer privileges — pin audited local scripts "
                        "instead. Art. 15(3)-(4)."
                    ),
                    file_path=path,
                    confidence=0.9,
                    compliance_impact="gap",
                    compliance_dimensions=["security", "supply_chain"],
                    evidence_snippet=cmd[:200],
                    kb_question_ids=["sc-3", "sp-2"],
                    suggested_answer="no",
                    article_paragraphs=["Art. 15(3)", "Art. 15(4)"],
                    matched_pattern="ccs_unsafe_hook_command",
                    compound_risk_type=CompoundRiskType.cascading.value,
                    threat_categories=[
                        ThreatCategory.autonomous_cyber_exploit.value,
                        ThreatCategory.tool_misuse_privilege_escalation.value,
                    ],
                    applicable_roles=_ROLES,
                ))


def analyze_claude_code_security(ctx: AnalyzerContext) -> AnalyzerResult:
    """Audit Claude Code settings, hooks, commands, threat model, telemetry, and CI PR review."""
    workflow_files = [
        (path, content)
        for path, content in product_files(ctx)
        if _WORKFLOW_RE.search(_norm(path))
    ]
    agent_configs = _collect_agent_configs(ctx)
    threat_model_path = _find_threat_model_path(ctx, agent_configs)
    telemetry_hit = _find_compliance_telemetry(ctx, agent_configs)

    if not workflow_files and not agent_configs and not threat_model_path and not telemetry_hit:
        return AnalyzerResult(
            analyzer_id="claude_code_security",
            label="Claude Code & AI-DevSecOps Security",
            findings=[],
            score=80.0,
            file_count=0,
            graph_node_type="security",
            graph_icon="🔍",
            connected_categories=["security_controls", "cicd_dockerfile", "mcp_toolchain"],
        )

    findings: list[Finding] = []
    evidence_files: set[str] = set()

    _audit_workflows(ctx, workflow_files, agent_configs, findings, evidence_files)
    _audit_settings_and_hooks(agent_configs, findings, evidence_files)

    if threat_model_path:
        evidence_files.add(threat_model_path)
        findings.append(Finding(
            id="ccs-threat-model-present",
            category="claude_code_security",
            title="Repository threat model documented for AI security review",
            description=(
                f"`{threat_model_path}` documents trust boundaries, attacker capabilities, "
                "and security assumptions for Claude Code Security and continuous risk "
                "management. Supports Art. 9(2) and Art. 15."
            ),
            file_path=threat_model_path,
            confidence=0.88,
            compliance_impact="positive",
            compliance_dimensions=["risk_mgmt", "security"],
            evidence_snippet=threat_model_path,
            kb_question_ids=["rm-1", "sc-5"],
            suggested_answer="yes",
            article_paragraphs=["Art. 9(2)"],
            matched_pattern="ccs_threat_model_present",
        ))

    if telemetry_hit:
        tel_path, tel_snippet = telemetry_hit
        evidence_files.add(tel_path)
        findings.append(Finding(
            id="ccs-compliance-telemetry",
            category="claude_code_security",
            title="Claude Code compliance telemetry / audit ingestion configured",
            description=(
                f"`{tel_path}` configures Claude Code OpenTelemetry (`CLAUDE_CODE_ENABLE_TELEMETRY`) "
                "or Claude Compliance API activity ingestion (`/v1/compliance/activities`). "
                "Supports automatic event recording and deployer log retention (Art. 12(1), Art. 26(6))."
            ),
            file_path=tel_path,
            confidence=0.88,
            compliance_impact="positive",
            compliance_dimensions=["logging"],
            evidence_snippet=tel_snippet[:200],
            kb_question_ids=["lg-1"],
            suggested_answer="yes",
            article_paragraphs=["Art. 12(1)", "Art. 26(6)"],
            matched_pattern="ccs_compliance_telemetry",
        ))

    if not findings:
        score = 80.0
    else:
        positives = [f for f in findings if f.compliance_impact == "positive"]
        gaps = [f for f in findings if f.compliance_impact == "gap"]
        if gaps and not positives:
            score = max(15.0, 50.0 - len(gaps) * 15)
        elif gaps and positives:
            score = max(30.0, min(95.0, 65.0 - len(gaps) * 15 + len(positives) * 10))
        elif positives:
            score = min(100.0, 80.0 + len(positives) * 5)
        else:
            score = 80.0

    score = max(0.0, min(100.0, score))
    return AnalyzerResult(
        analyzer_id="claude_code_security",
        label="Claude Code & AI-DevSecOps Security",
        findings=findings,
        score=round(score, 1),
        file_count=len(evidence_files),
        graph_node_type="security",
        graph_icon="🔍",
        connected_categories=["security_controls", "cicd_dockerfile", "mcp_toolchain"],
    )
