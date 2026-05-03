"""AEPD Lethal-Trifecta Analyzer — agentic-AI rule-of-2 detector.

Detects code paths where an agent simultaneously combines all three of:
  (a) processing untrusted input,
  (b) accessing sensitive data, and
  (c) taking autonomous state-changing action.

…without a human-oversight gate. This is the *rule of 2* the Spanish DPA
(AEPD) introduced on 18 February 2026 in its 71-page agentic-AI
guidance (paper lines 1175-1183), aligning with Simon Willison's
"lethal trifecta" framing and Meta's 31 October 2025 framework that
replaces "external communication" with "changing state."

The AEPD is the **first EU supervisory authority to treat the agentic
architecture as the primary object of data-protection analysis**
(paper line 1156). The detection grounds to Art. 14 (human oversight
commensurateness) + GDPR Art. 5(1)(a)(b)(c) + the four-axis taxonomy
``cascading`` axis (an attacker who controls one of the three legs
cascades into the other two).

Heuristics — intentionally conservative to keep false-positive rate
low. A finding fires only when ALL three legs are observed in the
same file or two-file slice AND no oversight gate (approval prompt,
confidence threshold, kill switch) is present in the same scope.
"""

from __future__ import annotations

import re

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
)
from scanner.data.agentic_taxonomy import CompoundRiskType, ThreatCategory
from scanner.data.role_obligations import (
    ROLE_DEPLOYER,
    ROLE_PRODUCT_MANUFACTURER,
    ROLE_PROVIDER,
)

# ─── Trifecta legs — pattern banks ───────────────────────────────────────

# Leg A — untrusted input. Anything that crosses the trust boundary into
# the agent: HTTP requests, webhooks, RSS, scraped pages, user uploads,
# email inbox, vector-db search results (RAG indirect injection vector).
_UNTRUSTED_INPUT_PATTERNS = [
    r"request\.(json|form|args|files|data)",
    r"@app\.(post|put|patch)\b",
    r"@router\.(post|put|patch)\b",
    r"flask\.request|fastapi.*Request|starlette.*Request",
    r"webhook|incoming.?email|imap\.|imaplib|email_inbox",
    r"feedparser|rss\.parse|scrap(e|ing)|crawl(er)?",
    r"vector(_)?store\.(similarity_)?search|retriever\.(invoke|get_relevant_documents)",
    r"slack.?(events|message)|discord.*on_message",
]

# Leg B — sensitive data access. Anything reading from a privileged
# data store: secrets manager, prod DB, document store with personal
# data, payment / health / KYC data.
_SENSITIVE_DATA_PATTERNS = [
    r"\b(boto3|aws).*?secrets?manager|secrets?_manager|get_secret_value",
    r"hashicorp.*vault|vault\.(read|kv)|hvac\.",
    r"environ\[[\"']?(.*?(SECRET|API_KEY|PASSWORD|TOKEN)).*?[\"']?\]",
    r"customer(s)?\.(find|get|fetch|all)|patient(s)?\.|payment(s)?\.|kyc\.|pii\.",
    r"prisma\.(user|customer|patient|order|payment)|psycopg2|asyncpg|sqlalchemy.*?session",
    r"models\.(User|Customer|Patient|Order|Payment)\.objects\.",
    r"GDPR|personal.?data|sensitive.?data|special.?category",
]

# Leg C — autonomous state-changing action. The agent (not the human)
# is making the call to a side-effecting tool: external email send,
# wire/payment, file delete, infra mutation, social-media post.
_AUTONOMOUS_ACTION_PATTERNS = [
    r"smtp(lib)?\.|email\.send|sendgrid\.send|resend\.send|ses\.send_email",
    r"slack.*?(post_message|chat\.postMessage)|discord.*?send",
    r"twilio.*?messages\.create|sms\.send",
    r"stripe.*?(charges|refunds|transfers)\.create|paypal.*?payments",
    r"\.delete\(|\.drop\(|os\.remove|shutil\.rmtree|rm\s+-rf",
    r"git.*?(push|force.?push|reset.*?--hard)",
    r"kubectl.*?(apply|delete|scale)|helm.*?(install|upgrade|uninstall)",
    r"terraform.*?(apply|destroy)|cdk.*?(deploy|destroy)",
    r"gh.*?(pr|issue|release).*?(create|merge|close)",
    r"webhook.*?notify|callback.*?execute",
]

# Oversight gate signals — if any of these are in the same file/scope
# we treat the trifecta as mitigated.
_OVERSIGHT_GATE_PATTERNS = [
    r"approve|approval|require_human|confirm_with_user|need_confirmation",
    r"input\(.*?(approve|confirm|y/n)|prompt_user|HITL|human_in_the_loop",
    r"confidence.*?(threshold|>=|>)|score.*?(threshold|>=|>)",
    r"escalate.*?human|escalation_queue|review_queue",
    r"kill_switch|emergency_stop|halt\b|abort\b",
    r"@require_(approval|confirmation|review)",
]


def _has_match(content: str, patterns: list[str]) -> tuple[bool, str]:
    """Return (matched?, first_matching_line)."""
    for pattern in patterns:
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue
        match = compiled.search(content)
        if match:
            # extract the line for evidence_snippet
            start = content.rfind("\n", 0, match.start()) + 1
            end = content.find("\n", match.end())
            line = content[start : end if end != -1 else len(content)].strip()
            return True, line[:200]
    return False, ""


def analyze_lethal_trifecta(ctx: AnalyzerContext) -> AnalyzerResult:
    """Detect AEPD-style lethal-trifecta agent invocation paths.

    Iterates every text file looking for the simultaneous co-occurrence
    of all three legs, then checks for an oversight gate in the same
    file. A trifecta with no gate is the ``aepd_lethal_trifecta``
    finding.
    """
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    trifecta_paths: list[tuple[str, str, str, str]] = []

    for path, content in ctx.files.items():
        # Quick skip — most files won't have an LLM SDK or agent symbol.
        if not re.search(
            r"\b(agent|llm|openai|anthropic|claude|gpt|langchain|crewai|autogen|invoke|run|complete|chat)\b",
            content,
            flags=re.IGNORECASE,
        ):
            continue

        a_match, a_line = _has_match(content, _UNTRUSTED_INPUT_PATTERNS)
        b_match, b_line = _has_match(content, _SENSITIVE_DATA_PATTERNS)
        c_match, c_line = _has_match(content, _AUTONOMOUS_ACTION_PATTERNS)

        # Need all three legs present in the same file.
        if not (a_match and b_match and c_match):
            continue

        # Oversight gate present? If yes, classify as positive (mitigated).
        gate_match, gate_line = _has_match(content, _OVERSIGHT_GATE_PATTERNS)
        evidence_files.add(path)

        if gate_match:
            findings.append(Finding(
                id="lt-trifecta-with-gate",
                category="lethal_trifecta",
                title="Lethal-trifecta path with human-oversight gate",
                description=(
                    "All three trifecta legs (untrusted input, sensitive data, autonomous "
                    "state-change) co-occur with an oversight gate (approval / threshold / "
                    "kill-switch). AEPD rule-of-2 satisfied via human-in-the-loop."
                ),
                file_path=path, confidence=0.7,
                compliance_impact="positive",
                compliance_dimensions=["human_oversight", "decision_governance"],
                evidence_snippet=gate_line,
                kb_question_ids=["ho-1"], suggested_answer="partial",
                article_paragraphs=["14(4)"],
                compound_risk_type=CompoundRiskType.cascading.value,
                threat_categories=[ThreatCategory.aepd_lethal_trifecta.value],
                applicable_roles=[ROLE_PROVIDER, ROLE_PRODUCT_MANUFACTURER, ROLE_DEPLOYER],
            ))
        else:
            trifecta_paths.append((path, a_line, b_line, c_line))

    if trifecta_paths:
        path, a_line, b_line, c_line = trifecta_paths[0]
        findings.append(Finding(
            id="lt-trifecta-violation",
            category="lethal_trifecta",
            title="AEPD lethal-trifecta: untrusted input + sensitive data + autonomous action without oversight",
            description=(
                "Agent path simultaneously processes untrusted input, accesses sensitive "
                "data, AND takes an autonomous state-changing action — with no oversight "
                "gate detected in the same scope. AEPD rule-of-2 (18 Feb 2026) requires "
                "removing one of the three legs OR adding a human-in-the-loop gate. "
                "Art. 14 oversight commensurateness + GDPR Art. 5(1)(a)(b)(c). "
                f"Untrusted-input signal: `{a_line}` · Sensitive-data signal: `{b_line}` · "
                f"Autonomous-action signal: `{c_line}`."
            ),
            file_path=path, confidence=0.75,
            compliance_impact="gap",
            compliance_dimensions=[
                "human_oversight", "decision_governance", "security",
            ],
            evidence_snippet=f"trifecta in {path}",
            kb_question_ids=["ho-1"], suggested_answer="no",
            article_paragraphs=["14(1)", "14(4)"],
            compound_risk_type=CompoundRiskType.cascading.value,
            threat_categories=[
                ThreatCategory.aepd_lethal_trifecta.value,
                ThreatCategory.governance_autonomy.value,
                ThreatCategory.tool_misuse_privilege_escalation.value,
            ],
            applicable_roles=[ROLE_PROVIDER, ROLE_PRODUCT_MANUFACTURER, ROLE_DEPLOYER],
        ))

    # Score — gap-only path drops hard; gate-present path stays neutral; nothing detected stays neutral.
    if not findings:
        score = 80.0
    else:
        gaps = [f for f in findings if f.compliance_impact == "gap"]
        positives = [f for f in findings if f.compliance_impact == "positive"]
        if gaps and not positives:
            score = max(15.0, 50.0 - len(gaps) * 25)
        elif gaps and positives:
            score = max(35.0, 65.0 - len(gaps) * 15 + len(positives) * 5)
        elif positives:
            score = min(95.0, 80.0 + len(positives) * 5)
        else:
            score = 70.0

    return AnalyzerResult(
        analyzer_id="lethal_trifecta",
        label="AEPD Lethal-Trifecta (Rule of 2)",
        findings=findings,
        score=round(score, 1),
        file_count=len(evidence_files),
        graph_node_type="control",
        graph_icon="⚠",
        connected_categories=["agent_cascade", "human_oversight", "security_controls"],
    )
