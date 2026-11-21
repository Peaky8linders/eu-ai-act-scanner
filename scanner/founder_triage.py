"""Founder & startup plain-English compliance triage engine.

Translates a technical :class:`scanner.models.ScanResult` into three actionable,
jargon-free priority buckets tuned for early-stage AI teams:

1. ``ship_now`` — live obligations (Art. 50 transparency since 2 Aug 2026) and
   immediate exploit vectors (MCP tool poisoning / SSRF / no-auth / hardcoded
   secrets, dangerous `.claude/settings.json` permissions, lethal trifecta,
   code execution, unbounded subagent loops).
2. ``enterprise_deals`` — gaps that stall enterprise security questionnaires,
   SOC 2 Type II, GDPR, and OWASP reviews, paired with the top 3 "Satisfy Once,
   Comply Everywhere" cross-framework levers and a deployer vendor-contract
   checklist.
3. ``later_2027`` — Annex III high-risk governance & documentation items
   deferred by Digital Omnibus (Regulation (EU) 2026/1744) to **2 Dec 2027**
   (and Annex I safety-component products to **2 Aug 2028**).

Pure deterministic, 100% offline, zero outbound calls, zero remote URLs.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field

from scanner.cross_framework import CrossFrameworkScanProjection, project_scan_to_frameworks
from scanner.data.frameworks import FRAMEWORK_LABELS
from scanner.kb import DIMENSIONS
from scanner.models import DiscoveredComponent, ScanResult

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_URL_RE = re.compile(r"https?://[^\s\"'<>()]+")

_ROLE_PLAIN_ENGLISH: dict[str, str] = {
    "deployer": (
        "You integrate third-party AI APIs/models -> you are a deployer under Art. 26/50 "
        "unless you substantially fine-tune a model or rebrand a high-risk AI system under "
        "your own name (Art. 25(1))."
    ),
    "provider": (
        "You build, train, or ship an AI system under your own name -> you are a provider "
        "under Art. 3(3): Art. 50 transparency applies today, and Annex III high-risk duties "
        "(Art. 9-15, 17, 43) apply from 2 Dec 2027."
    ),
    "gpai_provider": (
        "You train or place a general-purpose AI model on the EU market -> Art. 53 GPAI "
        "obligations have applied since 2 Aug 2025 (pre-existing models have until 2 Aug 2027 "
        "under Art. 111(3))."
    ),
    "gpai_systemic_provider": (
        "Your GPAI model crosses systemic-risk thresholds (Art. 51/55) -> adversarial testing, "
        "incident reporting, and cybersecurity duties apply now."
    ),
    "product_manufacturer": (
        "You embed AI as a safety component in a regulated product under your own brand -> "
        "you inherit provider duties (Art. 25(3)); Annex I deadline is 2 Aug 2028 under "
        "Digital Omnibus (Reg. 2026/1744)."
    ),
    "importer": (
        "You place a non-EU provider's AI system on the EU market under their name -> "
        "verify provider conformity docs and CE marking before release (Art. 23)."
    ),
    "distributor": (
        "You resell or distribute an AI system in the EU without modifying it -> "
        "verify required instructions and CE marking accompany the system (Art. 24)."
    ),
    "authorized_representative": (
        "You act under written EU mandate for a non-EU provider -> verify technical "
        "documentation and serve as the EU contact for authorities (Art. 22)."
    ),
    "extraterritorial_non_eu": (
        "Your company is outside the EU but your AI outputs are used in the EU (Art. 2(1)(c)) -> "
        "EU AI Act duties still apply, and high-risk providers need an EU authorized "
        "representative (Art. 22)."
    ),
}

_DEPLOYER_VENDOR_CONTRACT_CHECKLIST: tuple[str, ...] = (
    (
        "No silent provider flip (Art. 25(1)): confirm your AI vendor retains provider "
        "obligations and does not shift EU AI Act compliance onto you 'as-is'."
    ),
    (
        "Instructions for use + 6-month audit logs (Art. 26(1), 26(6)): require written "
        "usage guidelines and 6-month accessible logs (or retain prompt/output logs yourself)."
    ),
    (
        "AI-ready DPA & incident notice (GDPR Art. 28, AI Act Art. 4a / Art. 73): verify zero-training / data "
        "safeguards in the DPA and prompt vendor notification of model or security incidents."
    ),
)

_HIGH_RISK_VERTICAL_KEYWORDS: dict[str, str] = {
    "hiring": "Employment / HR (Annex III(4))",
    "recruit": "Employment / HR (Annex III(4))",
    "resume": "Employment / HR (Annex III(4))",
    "cv_screen": "Employment / HR (Annex III(4))",
    "credit_scor": "Creditworthiness / Finance (Annex III(5)(b))",
    "loan_approv": "Creditworthiness / Finance (Annex III(5)(b))",
    "underwrit": "Insurance / Credit Risk (Annex III(5))",
    "biometric": "Biometrics (Annex III(1))",
    "facial_recogn": "Biometrics (Annex III(1))",
    "medical": "Healthcare / Clinical (Annex I / III)",
    "clinical": "Healthcare / Clinical (Annex I / III)",
    "diagnos": "Healthcare / Clinical (Annex I / III)",
    "triage": "Healthcare / Emergency (Annex III(5)(d))",
    "student_grad": "Education / Assessment (Annex III(3))",
    "exam_proctor": "Education / Assessment (Annex III(3))",
    "law_enforce": "Law Enforcement (Annex III(6))",
    "asylum": "Migration / Border Control (Annex III(7))",
    "critical_infra": "Critical Infrastructure (Annex III(2))",
}

_SHIP_NOW_KEYWORDS: tuple[str, ...] = (
    "tool poisoning",
    "mcp poisoning",
    "poisoned",
    "ssrf",
    "no-auth",
    "no auth",
    "unauthenticated",
    ".mcp.json",
    "bypasspermissions",
    "bypass_permissions",
    "bash(*)",
    "unsafe hook",
    "dangerous hook",
    "over-privileged",
    "lethal trifecta",
    "hardcoded secret",
    "hardcoded credential",
    "hardcoded api",
    "hardcoded key",
    "exposed secret",
    "api_key",
    "api key",
    "private key",
    "eval(",
    "exec(",
    "shell=true",
    "command injection",
    "sql injection",
    "remote code execution",
    "rce",
    "path traversal",
    "xxe",
    "auth bypass",
    "csrf",
    "prompt injection",
    "code execution",
    "insecure deserialization",
    "pickle",
    "yaml.load",
    "unbounded",
    "infinite loop",
    "subagent loop",
    "runaway loop",
    "cascade",
)

_ENTERPRISE_DEAL_KEYWORDS: tuple[str, ...] = (
    "pr security review",
    "security review",
    "claude-code-security-review",
    "unpinned",
    "floating version",
    "npx -y",
    "uvx",
    "latest tag",
    "dockerfile",
    "ci/cd",
    "github action",
    "structured logging",
    "audit trail",
    "audit log",
    "correlation",
    "fairness",
    "bias test",
    "adversarial",
    "red team",
    "access control",
    "rbac",
    "rate limit",
    "least privilege",
    "privilege",
    "supply chain",
    "sbom",
    "dependency",
)

_ENTERPRISE_DEAL_COMPONENTS = frozenset(
    {
        "logging_monitoring",
        "fairness_testing",
        "adversarial_robustness",
        "test_suite",
        "cicd_dockerfile",
        "terraform",
        "cloudformation_k8s",
        "cloud_deployment",
        "configuration",
        "privilege_minimization",
        "security_controls",
        "external_security_sarif",
        "runtime_drift",
    }
)

_LATER_2027_DIMENSIONS = frozenset(
    {
        "risk_mgmt",
        "data_gov",
        "tech_docs",
        "human_oversight",
        "quality_management",
        "deployer_obligations",
        "conformity_assessment",
        "agent_inventory",
        "regulatory_perimeter",
        "decision_governance",
        "voluntary_codes",
        "ai_literacy",
    }
)


class TriageItem(BaseModel):
    """A single founder-friendly compliance or security action item."""

    id: str
    title: str
    bucket: Literal["ship_now", "enterprise_deals", "later_2027"]
    what_is_wrong: str
    why_it_matters_now: str
    effort_estimate: str
    suggested_pr_title: str
    file_path: str = ""
    line_number: int | None = None
    articles: list[str] = Field(default_factory=list)
    dimensions: list[str] = Field(default_factory=list)
    fix_hint: str = ""


class QuickWinLever(BaseModel):
    """A high-leverage 'Satisfy Once, Comply Everywhere' control."""

    control: str
    frameworks_unlocked: list[str] = Field(default_factory=list)
    why_it_matters: str


class FounderTriage(BaseModel):
    """Complete plain-English founder triage report."""

    is_ai_system: bool
    headline: str
    operator_role: str
    role_plain_english: str
    ship_now: list[TriageItem] = Field(default_factory=list)
    enterprise_deals: list[TriageItem] = Field(default_factory=list)
    later_2027: list[TriageItem] = Field(default_factory=list)
    top_cross_framework_levers: list[QuickWinLever] = Field(default_factory=list)
    vendor_contract_checklist: list[str] = Field(default_factory=list)
    summary_counts: dict[str, int] = Field(default_factory=dict)
    brief_markdown: str = ""


def _clean_text(text: str) -> str:
    return _URL_RE.sub("[redacted-url]", text or "").strip()


def _slug(text: str, *, max_len: int = 40) -> str:
    s = _SLUG_RE.sub("-", text.lower()).strip("-")
    return (s[:max_len].rstrip("-")) or "item"


def _extract_line_number(comp: DiscoveredComponent) -> int | None:
    line = getattr(comp, "line_number", None)
    if line is None and isinstance(comp.details, dict):
        line = comp.details.get("line_number")
        if line is None:
            line = comp.details.get("line")
    if isinstance(line, int) and not isinstance(line, bool) and line >= 1:
        return line
    return None


def _articles_for_component(comp: DiscoveredComponent) -> list[str]:
    articles: list[str] = []
    seen: set[str] = set()
    if isinstance(comp.details, dict):
        raw = comp.details.get("article_paragraphs") or comp.details.get("articles") or []
        if isinstance(raw, str):
            raw = [raw]
        for a in raw:
            if isinstance(a, str) and a.strip() and a.strip() not in seen:
                seen.add(a.strip())
                articles.append(a.strip())
    for dim_id in comp.compliance_dimensions:
        dim = DIMENSIONS.get(dim_id)
        if dim and dim.article and dim.article not in seen:
            seen.add(dim.article)
            articles.append(dim.article)
    return articles


def _detect_high_risk_verticals(result: ScanResult) -> list[str]:
    """Detect whether repo signals hint at an EU AI Act Annex III high-risk domain."""
    corpus_parts = [
        result.project_name,
        " ".join(result.ai_system_signals),
        " ".join(result.risk_indicators),
        " ".join(c.name for c in result.components),
        " ".join(c.file_path for c in result.components),
    ]
    haystack = " ".join(corpus_parts).lower()
    detected: list[str] = []
    seen: set[str] = set()
    for kw, label in _HIGH_RISK_VERTICAL_KEYWORDS.items():
        if kw in haystack and label not in seen:
            seen.add(label)
            detected.append(label)
    return detected


def _classify_component_bucket(comp: DiscoveredComponent) -> Literal["ship_now", "enterprise_deals", "later_2027"]:
    """Assign a gap component to one of the three founder triage buckets."""
    comp_type = comp.component_type.lower()
    name_lower = comp.name.lower()
    evidence_lower = ""
    severity = ""
    if isinstance(comp.details, dict):
        evidence_lower = str(comp.details.get("evidence", "")).lower()
        severity = str(comp.details.get("severity", "")).lower()
    haystack = f"{comp_type} {name_lower} {evidence_lower}"
    dims = set(comp.compliance_dimensions)

    # 1. Missing PR security review workflow is an enterprise deal blocker, not an active exploit
    if comp_type == "claude_code_security" and (
        "pr security review" in haystack
        or "security review" in haystack
        or "workflow" in haystack
        or "missing review" in haystack
    ) and not any(tok in haystack for tok in ("bypasspermissions", "bash(*)", "unsafe hook", "secret")):
        return "enterprise_deals"

    # 2. Unpinned MCP servers go to enterprise_deals unless paired with poisoning/SSRF/no-auth/secrets
    if comp_type == "mcp_toolchain" and any(
        tok in haystack for tok in ("unpinned", "floating", "npx -y", "uvx", "version pin")
    ) and not any(
        tok in haystack for tok in ("poison", "ssrf", "no-auth", "no auth", "unauthenticated", "secret", "key", "token")
    ):
        return "enterprise_deals"

    # 2b. Generic heuristic 'lacks prompt injection guards' (adversarial_robustness)
    # is an enterprise hardening item unless paired with an active exploit/trifecta.
    if comp_type == "adversarial_robustness" and "lacks prompt injection guards" in name_lower:
        return "enterprise_deals"

    # 3. Bucket 1: ship_now (live Art. 50 + immediate security/agent exploits)
    if comp_type == "article_50_transparency":
        return "ship_now"
    if dims & {"transparency", "content_transparency"} and any(
        tok in haystack
        for tok in ("art. 50", "art 50", "50(", "disclosure", "chatbot", "watermark", "c2pa", "deepfake", "synthetic", "label")
    ):
        return "ship_now"
    if severity == "critical":
        return "ship_now"
    if comp_type in {"claude_security_plugin", "external_security_sarif"} and severity in {"critical", "high"}:
        return "ship_now"
    if comp_type in {"mcp_toolchain", "claude_code_security", "lethal_trifecta", "agent_cascade"}:
        return "ship_now"
    if any(kw in haystack for kw in _SHIP_NOW_KEYWORDS):
        return "ship_now"
    if comp_type == "security_controls" and (severity == "high" or comp.confidence >= 0.85):
        return "ship_now"

    # 4. Bucket 2: enterprise_deals (unblocks SOC 2 / GDPR / enterprise security questionnaires)
    if comp_type in _ENTERPRISE_DEAL_COMPONENTS:
        return "enterprise_deals"
    if any(kw in haystack for kw in _ENTERPRISE_DEAL_KEYWORDS):
        return "enterprise_deals"
    if dims & {"security", "access_control", "infra_mlops", "supply_chain", "logging", "tool_governance"}:
        return "enterprise_deals"

    # 5. Bucket 3: later_2027 (Annex III governance & documentation)
    return "later_2027"


def _describe_component(
    comp: DiscoveredComponent,
    bucket: Literal["ship_now", "enterprise_deals", "later_2027"],
    high_risk_verticals: list[str],
) -> tuple[str, str, str, str, str]:
    """Return (what_is_wrong, why_it_matters_now, effort_estimate, suggested_pr_title, fix_hint)."""
    name_clean = _clean_text(comp.name)
    name_lower = name_clean.lower()
    comp_type = comp.component_type.lower()
    dims = set(comp.compliance_dimensions)
    loc = f" in `{comp.file_path}`" if comp.file_path else ""

    if bucket == "ship_now":
        if comp_type == "article_50_transparency" or dims & {"transparency", "content_transparency"}:
            return (
                f"{name_clean}{loc}: users or generated outputs lack required AI disclosure or content marking.",
                "EU AI Act Art. 50 transparency obligations have been live since 2 Aug 2026 — applies today to customer-facing AI and synthetic content.",
                "30 min",
                "feat(transparency): add Art. 50 AI disclosure and content marking",
                "Add a clear UI/API notice ('You are interacting with an AI assistant') and machine-readable C2PA / watermark metadata for generated media.",
            )
        if comp_type == "mcp_toolchain" or "mcp" in name_lower:
            return (
                f"{name_clean}{loc}: MCP server configuration exposes your agent to tool poisoning, credential theft, or unauthorized remote calls.",
                "Live exploit risk today — a single compromised MCP tool or leaked `.mcp.json` secret can exfiltrate customer data or hijack sessions.",
                "30-60 min",
                "fix(security): harden MCP server config and remove exposed secrets",
                "Move credentials to environment variables, require auth/localhost binding on MCP endpoints, pin package versions, and audit tool descriptions.",
            )
        if comp_type == "claude_code_security" or any(
            k in name_lower for k in ("bypasspermissions", "bash(*)", "unsafe hook", ".claude/settings")
        ):
            return (
                f"{name_clean}{loc}: Claude Code settings grant unrestricted shell/tool permissions or run unreviewed hooks.",
                "Over-privileged AI coding settings can run arbitrary shell commands or leak secrets during everyday development.",
                "15 min",
                "chore(security): tighten .claude/settings.json to least privilege",
                "Remove `bypassPermissions` and `Bash(*)`; allowlist only the specific test/lint commands your repo needs.",
            )
        if comp_type == "lethal_trifecta" or "lethal trifecta" in name_lower:
            return (
                f"{name_clean}{loc}: your agent combines private data access, untrusted external input, and outbound action tools without an isolation boundary.",
                "This is the #1 real-world agentic exploit chain (indirect prompt injection -> silent data exfiltration).",
                "1-2 hours",
                "fix(agent): add human approval gate and isolate untrusted tool input",
                "Break the trifecta: require explicit human approval before outbound writes/sends, or strip untrusted content from privileged tool contexts.",
            )
        if any(k in name_lower for k in ("secret", "credential", "api key", "api_key", "password", "token", "private key")):
            return (
                f"{name_clean}{loc}: a secret or credential appears hardcoded in source or config.",
                "Immediate breach risk — leaked keys are scraped within minutes and fail every customer security check.",
                "15 min",
                "fix(security): remove hardcoded secret and load from environment",
                "Rotate the exposed key immediately, load it via environment variables/secrets manager, and install `hooks/sensitive-data-guard.json`.",
            )
        if comp_type == "agent_cascade" or any(k in name_lower for k in ("unbounded", "loop", "cascade")):
            return (
                f"{name_clean}{loc}: an agent or subagent loop lacks a hard iteration/token budget cap.",
                "Runaway agent loops cause sudden API bill spikes, DoS outages, and cascading bad actions in production.",
                "30 min",
                "fix(agent): enforce max_iterations and cost budget on agent loops",
                "Add an explicit `max_iterations` / `max_steps` ceiling, timeout, and circuit-breaker stop condition on every agent loop.",
            )
        return (
            f"{name_clean}{loc}: high-severity runtime security gap in an AI code path.",
            "Exploitable in production today and mapped to EU AI Act Art. 15(4) cybersecurity resilience.",
            "1-2 hours",
            f"fix(security): resolve {_slug(name_clean, max_len=36)}",
            "Replace unsafe dynamic execution (`eval`/`exec`/`shell=True`/`pickle`) with validated inputs, parameterized calls, and strict allowlists.",
        )

    if bucket == "enterprise_deals":
        if "timeout" in name_lower and ("http" in name_lower or "request" in name_lower):
            return (
                f"{name_clean}{loc}: outbound HTTP requests lack an explicit `timeout=` parameter.",
                "Hung upstream API calls exhaust worker threads and cause cascading production outages (Art. 15 resilience).",
                "15 min",
                "fix(resilience): add explicit timeout= to outbound HTTP calls",
                "Pass an explicit `timeout=` (e.g. `timeout=10`) on every outbound `requests`/`httpx` HTTP call.",
            )
        if "substantial" in name_lower and "modification" in name_lower:
            return (
                f"{name_clean}{loc}: no documented procedure for detecting substantial modifications (Art. 3(23) / Art. 25).",
                "Enterprise buyers ask how you control fine-tunes, model swaps, and intended-purpose changes before release.",
                "30 min",
                "docs(governance): document Art. 25 substantial-modification change-control procedure",
                "Document a change-control checklist (fine-tuning, model swap, or purpose change triggers Art. 25 re-assessment).",
            )
        if "prompt injection" in name_lower:
            return (
                f"{name_clean}{loc}: LLM prompts lack explicit input/output guardrails against prompt injection.",
                "Enterprise security teams test for prompt injection resilience and system/user prompt separation before onboarding.",
                "1-2 hours",
                "fix(ai-safety): add prompt injection guards and prompt boundaries",
                "Add system/user prompt boundaries and input/output guardrails around untrusted user text passed to LLMs.",
            )
        if "rate limit" in name_lower:
            return (
                f"{name_clean}{loc}: AI endpoints lack explicit rate limiting or quota controls.",
                "Unthrottled LLM endpoints expose startups to sudden API bill spikes and denial-of-service abuse (Art. 15).",
                "30-60 min",
                "feat(security): add rate limiting and token budgets on AI endpoints",
                "Add per-user/IP rate limiting and token budgets on AI endpoints to prevent abuse and DoS (Art. 15).",
            )
        if "input validation" in name_lower:
            return (
                f"{name_clean}{loc}: external request payloads are not validated with strict schemas before hitting models or tools.",
                "Strict input validation prevents injection, malformed tool arguments, and unexpected runtime failures.",
                "30-60 min",
                "feat(security): validate external AI inputs with strict schemas",
                "Validate all external request payloads with strict schemas (e.g., Pydantic/Zod) before passing to models or tools.",
            )
        if comp_type == "claude_code_security" or "security review" in name_lower:
            return (
                f"{name_clean}{loc}: no automated PR security review workflow is configured for AI/agent code changes.",
                "Enterprise security questionnaires routinely ask for documented automated security review on every pull request.",
                "30 min",
                "ci(security): add PR security review workflow",
                "Wire `/ai-act-security-review` or `anthropics/claude-code-security-review` into pull requests using `templates/security-scan-instructions.md`.",
            )
        if any(k in name_lower for k in ("unpinned", "floating", "latest", "npx -y", "uvx", "dockerfile", "supply chain")) or comp_type == "cicd_dockerfile":
            return (
                f"{name_clean}{loc}: dependencies, MCP servers, base images, or CI actions are unpinned.",
                "Unpinned supply chains fail SOC 2 CC8.1 change-management checks and expose builds to upstream hijacking.",
                "30 min",
                "chore(supply-chain): pin MCP servers, Docker base images, and CI actions",
                "Pin exact versions or SHA digests in `.mcp.json`, `Dockerfile`, lockfiles, and GitHub Actions workflows.",
            )
        if comp_type == "logging_monitoring" or "logging" in dims or "log" in name_lower:
            return (
                f"{name_clean}{loc}: AI inference calls lack structured audit logging with correlation IDs.",
                "Unblocks enterprise auditability questionnaires (SOC 2 CC7.2, ISO 27002 8.15) and EU AI Act Art. 12 record-keeping.",
                "1-2 hours",
                "feat(logging): add structured audit logging with request correlation IDs",
                "Emit structured JSON logs (`structlog` or stdlib logger) with request/session ID, model version, and timestamp on every AI call.",
            )
        if comp_type in {"fairness_testing", "adversarial_robustness", "test_suite"}:
            return (
                f"{name_clean}{loc}: automated robustness, prompt-injection, or bias regression tests are missing.",
                "Enterprise buyers ask for pre-release AI safety/evaluation test evidence before signing annual contracts.",
                "Half day",
                "test(ai-safety): add prompt-injection and evaluation regression suite",
                "Add a `tests/` suite covering prompt-injection refusal, schema validation, and domain accuracy/bias checks in CI.",
            )
        return (
            f"{name_clean}{loc}: access-control, privilege, or infrastructure hardening gap.",
            "Enterprise buyers check least-privilege auth, tenant isolation, and cloud hardening during SOC 2 / GDPR security reviews.",
            "1-2 hours",
            f"fix(hardening): tighten {_slug(name_clean, max_len=36)}",
            "Add authentication/RBAC checks, narrow tool/IAM permissions to least privilege, and validate external inputs at API boundaries.",
        )

    # Bucket 3: later_2027
    vertical_note = (
        f" Detected potential Annex III high-risk signals ({', '.join(high_risk_verticals[:2])}) — plan ahead."
        if high_risk_verticals
        else " Unless your product enters an Annex III high-risk vertical, keep this lightweight until closer to the deadline."
    )
    if "dataset versioning" in name_lower or "versioning" in name_lower and "data_gov" in dims:
        return (
            f"{name_clean}{loc}: data pipeline lacks dataset versioning or lineage tracking (Art. 10(2)).",
            f"Digital Omnibus (Reg. 2026/1744) deferred Annex III Art. 10 duties to 2 Dec 2027.{vertical_note}",
            "1-2 hours",
            "chore(data): add dataset versioning and lineage manifest",
            "Pin dataset versions and checksums (e.g., DVC, LakeFS, or SHA-256 manifest) for Art. 10(2) lineage.",
        )
    if "data quality" in name_lower or ("quality" in name_lower and "data_gov" in dims):
        return (
            f"{name_clean}{loc}: data pipeline lacks automated data quality / schema checks (Art. 10(3)).",
            f"Digital Omnibus (Reg. 2026/1744) deferred Annex III Art. 10 duties to 2 Dec 2027.{vertical_note}",
            "1-2 hours",
            "feat(data): add automated dataset schema and quality validation",
            "Add automated schema/null/drift validation (e.g., Great Expectations, Pandera, or Pydantic) before training/inference.",
        )
    return (
        f"{name_clean}{loc}: governance or compliance documentation gap.",
        (
            "Digital Omnibus (Reg. 2026/1744) deferred Annex III high-risk obligations (Art. 9-15, 17, 26, 27) "
            f"to 2 Dec 2027 (and Annex I safety-component products to 2 Aug 2028).{vertical_note}"
        ),
        "Half day",
        f"docs(ai-act): add {_slug(name_clean, max_len=36)} documentation",
        "Keep a lightweight living doc (`MODEL_CARD.md`, `DATA_CARD.md`, or risk register) and refresh it quarterly as your product matures.",
    )


def _extract_top_levers(
    result: ScanResult,
    cross_framework: dict[str, Any] | CrossFrameworkScanProjection | None,
) -> list[QuickWinLever]:
    """Build up to 3 'Satisfy Once, Comply Everywhere' founder levers."""
    raw_levers: list[dict[str, Any]] = []

    if isinstance(cross_framework, CrossFrameworkScanProjection):
        raw_levers = [lever.model_dump() for lever in cross_framework.satisfy_once_levers]
    elif isinstance(cross_framework, dict):
        maybe = cross_framework.get("satisfy_once_levers")
        if isinstance(maybe, list):
            raw_levers = [item for item in maybe if isinstance(item, dict)]
    elif result.compliance_scores:
        proj = project_scan_to_frameworks(result)
        raw_levers = [lever.model_dump() for lever in proj.satisfy_once_levers]

    levers: list[QuickWinLever] = []
    for item in raw_levers[:3]:
        dim_id = str(item.get("dimension_id", ""))
        label = str(item.get("dimension_label") or (DIMENSIONS[dim_id].label if dim_id in DIMENSIONS else dim_id))
        fws_raw = item.get("frameworks_helped") or []
        fw_labels = [FRAMEWORK_LABELS.get(str(fw), str(fw)) for fw in fws_raw]
        controls_closed = int(item.get("controls_closed_count", 0) or 0)
        summary = _clean_text(str(item.get("impact_summary", "")))
        if not summary:
            summary = (
                f"One engineering fix closes {controls_closed} controls across "
                f"{len(fw_labels)} frameworks at once."
            )
        levers.append(
            QuickWinLever(
                control=label,
                frameworks_unlocked=fw_labels,
                why_it_matters=summary,
            )
        )
    return levers


def _synthesize_dimension_items(
    result: ScanResult,
    ship_now: list[TriageItem],
    enterprise_deals: list[TriageItem],
    later_2027: list[TriageItem],
    high_risk_verticals: list[str],
) -> None:
    """Back-fill critical missing dimensions from compliance_scores when no explicit gap component exists."""
    covered_dims: set[str] = set()
    for bucket_items in (ship_now, enterprise_deals, later_2027):
        for item in bucket_items:
            covered_dims.update(item.dimensions)

    # Art. 50 live transparency check
    for dim_id in ("transparency", "content_transparency"):
        score = result.compliance_scores.get(dim_id)
        if score is not None and score < 30.0 and dim_id not in covered_dims:
            dim = DIMENSIONS.get(dim_id)
            ship_now.append(
                TriageItem(
                    id=f"ship-now-dim-{dim_id}",
                    title=f"Missing {dim.label if dim else dim_id} disclosure (Art. 50)",
                    bucket="ship_now",
                    what_is_wrong=(
                        f"Low evidence ({score:.0f}%) for {dim.label if dim else dim_id}: no clear user-facing AI disclosure "
                        "or synthetic-content marking was detected."
                    ),
                    why_it_matters_now=(
                        "EU AI Act Art. 50 transparency obligations have been live since 2 Aug 2026 — "
                        "shipping a visible disclosure banner or metadata tag takes minutes."
                    ),
                    effort_estimate="30 min",
                    suggested_pr_title="feat(transparency): add Art. 50 AI interaction disclosure",
                    articles=[dim.article] if dim else ["Art. 50"],
                    dimensions=[dim_id],
                    fix_hint="Add a concise 'Powered by AI' notice in your UI/API response and mark synthetic media with C2PA/watermark metadata.",
                )
            )
            covered_dims.add(dim_id)
            break  # One combined Art. 50 prompt is enough if both are low

    # Enterprise deal blockers from low scores
    enterprise_candidates = (
        ("logging", "Add structured AI audit logging", "feat(logging): add structured audit logs for AI calls", "1-2 hours"),
        ("security", "Strengthen AI endpoint security controls", "fix(security): add input validation and auth guards on AI routes", "1-2 hours"),
        ("access_control", "Enforce RBAC / auth on AI endpoints", "fix(auth): enforce role-based access control on AI endpoints", "1-2 hours"),
    )
    for dim_id, title, pr_title, effort in enterprise_candidates:
        score = result.compliance_scores.get(dim_id)
        if score is not None and score < 30.0 and dim_id not in covered_dims:
            dim = DIMENSIONS.get(dim_id)
            enterprise_deals.append(
                TriageItem(
                    id=f"enterprise-dim-{dim_id}",
                    title=title,
                    bucket="enterprise_deals",
                    what_is_wrong=f"Low evidence ({score:.0f}%) for {dim.label if dim else dim_id}.",
                    why_it_matters_now=(
                        "Shows up on nearly every enterprise security questionnaire, SOC 2 Type II audit, and GDPR review."
                    ),
                    effort_estimate=effort,
                    suggested_pr_title=pr_title,
                    articles=[dim.article] if dim else ["Art. 15"],
                    dimensions=[dim_id],
                    fix_hint="Implement minimal production-grade logging, auth middleware, and input validation around AI calls.",
                )
            )
            covered_dims.add(dim_id)

    # Roadmap 2027 items from low governance/doc scores (cap at 3 if none present)
    if not later_2027:
        roadmap_dims = (
            "risk_mgmt",
            "tech_docs",
            "human_oversight",
            "data_gov",
            "quality_management",
            "deployer_obligations",
        )
        added = 0
        vertical_note = (
            f" High-risk vertical signals detected ({', '.join(high_risk_verticals[:2])})."
            if high_risk_verticals
            else " Track on roadmap unless you enter an Annex III high-risk vertical."
        )
        for dim_id in roadmap_dims:
            score = result.compliance_scores.get(dim_id)
            if score is not None and score < 30.0 and dim_id not in covered_dims:
                dim = DIMENSIONS.get(dim_id)
                label = dim.label if dim else dim_id
                later_2027.append(
                    TriageItem(
                        id=f"later-2027-dim-{dim_id}",
                        title=f"Document {label} ({dim.article if dim else 'EU AI Act'})",
                        bucket="later_2027",
                        what_is_wrong=f"No code-observable evidence ({score:.0f}%) for {label}.",
                        why_it_matters_now=(
                            "Digital Omnibus (Reg. 2026/1744) deferred Annex III high-risk obligations to "
                            f"2 Dec 2027 (and Annex I products to 2 Aug 2028).{vertical_note}"
                        ),
                        effort_estimate="Half day",
                        suggested_pr_title=f"docs(ai-act): add {dim_id} starter documentation",
                        articles=[dim.article] if dim else [],
                        dimensions=[dim_id],
                        fix_hint="Start with a lightweight markdown template (`MODEL_CARD.md`, `DATA_CARD.md`, or risk register) and expand before 2 Dec 2027.",
                    )
                )
                covered_dims.add(dim_id)
                added += 1
                if added >= 3:
                    break


def format_founder_brief(triage: FounderTriage) -> str:
    """Render a crisp, <50-line jargon-free Markdown brief for founders.

    Safe to paste directly into a customer security questionnaire, investor
    memo, or GitHub/Linear issue. Contains zero remote URLs.
    """
    if not triage.is_ai_system:
        out_of_scope = [
            "# Founder AI Compliance Brief",
            "",
            f"**Status:** {triage.headline}",
            "",
            triage.role_plain_english,
            "",
            "_No EU AI Act action items apply until AI/ML or agent components are added._",
        ]
        return "\n".join(out_of_scope)

    counts = triage.summary_counts
    lines: list[str] = [
        "# Founder AI Compliance Brief",
        "",
        f"**Headline:** {triage.headline}",
        f"**Your Role (`{triage.operator_role}`):** {triage.role_plain_english}",
        (
            f"**Action Summary:** {counts.get('ship_now', len(triage.ship_now))} fix before shipping | "
            f"{counts.get('enterprise_deals', len(triage.enterprise_deals))} enterprise deal blockers | "
            f"{counts.get('later_2027', len(triage.later_2027))} roadmap (2 Dec 2027)"
        ),
    ]

    def _append_bucket(heading: str, items: list[TriageItem], limit: int) -> None:
        lines.append("")
        lines.append(f"## {heading}")
        if not items:
            lines.append("- None detected.")
            return
        for item in items[:limit]:
            fp = (item.file_path or "").strip()
            loc = f" (`{fp}`)" if fp and fp.lower() not in {"(no file)", "project", "n/a"} else ""
            lines.append(f"- **{item.title}**{loc} — _{item.effort_estimate}_. {item.fix_hint or item.what_is_wrong}")
        if len(items) > limit:
            lines.append(f"- _+{len(items) - limit} additional item(s) in full JSON triage._")

    _append_bucket("1. Fix Before Shipping (Live Today)", triage.ship_now, 3)
    _append_bucket("2. Unblock Enterprise Deals (SOC 2 / GDPR / OWASP)", triage.enterprise_deals, 3)
    _append_bucket("3. Roadmap (2 Dec 2027 — Digital Omnibus)", triage.later_2027, 2)

    if triage.top_cross_framework_levers:
        lines.append("")
        lines.append("## Satisfy Once, Comply Everywhere")
        for lever in triage.top_cross_framework_levers[:3]:
            fws = ", ".join(lever.frameworks_unlocked[:4])
            lines.append(f"- **{lever.control}** -> unlocks {fws}")

    if triage.vendor_contract_checklist:
        lines.append("")
        lines.append("## Vendor Contract Checklist (Deployer)")
        for item in triage.vendor_contract_checklist[:3]:
            lines.append(f"- {item}")

    lines.append("")
    lines.append(
        "_Key dates (Reg. 2024/1689 & Digital Omnibus Reg. 2026/1744): "
        "Art. 50 transparency live 2 Aug 2026 | EN 18286:2026 QMS Oct 2026 | "
        "Annex III high-risk 2 Dec 2027 | Annex I products 2 Aug 2028._"
    )

    # Guarantee strictly < 50 lines
    if len(lines) >= 50:
        lines = lines[:48] + ["_Truncated to stay concise; inspect JSON triage for full list._"]

    return "\n".join(lines)


def build_founder_triage(
    result: ScanResult,
    cross_framework: dict[str, Any] | CrossFrameworkScanProjection | None = None,
) -> FounderTriage:
    """Build a deterministic, founder-friendly 3-bucket compliance triage from a ``ScanResult``."""
    if not result.is_ai_system:
        triage = FounderTriage(
            is_ai_system=False,
            headline="No AI/ML system detected — EU AI Act obligations do not appear to apply to this repository.",
            operator_role="out_of_scope",
            role_plain_english=(
                "No AI/ML framework, model, or agent runtime was detected, so EU AI Act "
                "obligations under Art. 3(1) do not appear to apply to this repository."
            ),
            ship_now=[],
            enterprise_deals=[],
            later_2027=[],
            top_cross_framework_levers=[],
            vendor_contract_checklist=[],
            summary_counts={
                "ship_now": 0,
                "enterprise_deals": 0,
                "later_2027": 0,
                "total_gaps": 0,
            },
        )
        triage.brief_markdown = format_founder_brief(triage)
        return triage

    operator_role = result.active_role or (result.inferred_roles[0] if result.inferred_roles else "deployer")
    role_plain = _ROLE_PLAIN_ENGLISH.get(operator_role, _ROLE_PLAIN_ENGLISH["deployer"])
    high_risk_verticals = _detect_high_risk_verticals(result)

    ship_now: list[TriageItem] = []
    enterprise_deals: list[TriageItem] = []
    later_2027: list[TriageItem] = []

    gap_components = [c for c in result.components if c.compliance_impact == "gap"]
    for idx, comp in enumerate(gap_components, start=1):
        bucket = _classify_component_bucket(comp)
        what_wrong, why_now, effort, pr_title, fix_hint = _describe_component(
            comp, bucket, high_risk_verticals
        )
        item = TriageItem(
            id=f"{bucket.replace('_', '-')}-{_slug(comp.component_type, max_len=20)}-{idx}",
            title=_clean_text(comp.name),
            bucket=bucket,
            what_is_wrong=what_wrong,
            why_it_matters_now=why_now,
            effort_estimate=effort,
            suggested_pr_title=pr_title,
            file_path=_clean_text(comp.file_path),
            line_number=_extract_line_number(comp),
            articles=_articles_for_component(comp),
            dimensions=list(comp.compliance_dimensions),
            fix_hint=fix_hint,
        )
        if bucket == "ship_now":
            ship_now.append(item)
        elif bucket == "enterprise_deals":
            enterprise_deals.append(item)
        else:
            later_2027.append(item)

    _synthesize_dimension_items(result, ship_now, enterprise_deals, later_2027, high_risk_verticals)

    top_levers = _extract_top_levers(result, cross_framework)
    vendor_checklist = list(_DEPLOYER_VENDOR_CONTRACT_CHECKLIST) if operator_role == "deployer" else []

    summary_counts = {
        "ship_now": len(ship_now),
        "enterprise_deals": len(enterprise_deals),
        "later_2027": len(later_2027),
        "total_gaps": len(ship_now) + len(enterprise_deals) + len(later_2027),
    }

    if ship_now:
        headline = (
            f"{result.project_name}: fix {len(ship_now)} ship-blocker(s) first "
            f"(live Art. 50 / security risks), then {len(enterprise_deals)} enterprise deal item(s)."
        )
    elif enterprise_deals:
        headline = (
            f"{result.project_name}: no immediate ship-blockers — tackle {len(enterprise_deals)} "
            "enterprise security/compliance item(s) to speed up customer deals."
        )
    elif later_2027:
        headline = (
            f"{result.project_name}: ready to ship today — track {len(later_2027)} roadmap item(s) "
            "ahead of the 2 Dec 2027 Digital Omnibus deadline."
        )
    else:
        headline = (
            f"{result.project_name}: clean baseline ({result.overall_compliance_pct:.1f}% evidence score) — "
            "no open compliance or security gaps detected."
        )

    triage = FounderTriage(
        is_ai_system=True,
        headline=headline,
        operator_role=operator_role,
        role_plain_english=role_plain,
        ship_now=ship_now,
        enterprise_deals=enterprise_deals,
        later_2027=later_2027,
        top_cross_framework_levers=top_levers,
        vendor_contract_checklist=vendor_checklist,
        summary_counts=summary_counts,
    )
    triage.brief_markdown = format_founder_brief(triage)
    return triage


__all__ = [
    "TriageItem",
    "QuickWinLever",
    "FounderTriage",
    "build_founder_triage",
    "format_founder_brief",
]
