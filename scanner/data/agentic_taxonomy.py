"""Agentic-AI Compound-Risk Taxonomy — EU AI Act grounding.

This module is the canonical implementation of the four-axis compound-risk
taxonomy proposed by *AI Agents Under EU Law* (Working Paper, 7 April 2026)
section 10.4. The paper observes that no current EU instrument provides a
risk taxonomy for compound AI systems — Recital 116 only mandates a taxonomy
for GPAI systemic risk, and ISO/IEC 42005 + 23894 manage organisational
risk to the organisation rather than Article 9's external-rights scope.

The taxonomy captures:
  (i)   cascading risks — error/bias propagation across orchestrated sub-agents
  (ii)  emergent risks — unsafe collective behaviour from individually safe agents
  (iii) attribution risks — multi-provider value-chain obscuring responsibility
  (iv)  temporal risks — long-running state drift outside the conformity envelope

Each compound-risk type is grounded to specific EU AI Act articles, KB
maturity dimensions, threat-category cross-walks (Kim et al., Hammond et al.,
OWASP Top-10 Agentic, AEPD rule-of-2 / lethal trifecta), and required
evidence artifacts. Agent archetypes describe the architecture shape
(single-agent, orchestrator+sub-agents, GPAI-with-tools, etc.) so detectors
can map findings to the correct compound-risk profile.

This module is data-only — pure constants and pure helpers. No I/O, no
mutable state, deterministic for the same inputs. Engines reference this
module the same way they reference :mod:`scanner.kb` (single source of
truth; never inline literals in engine code).

Citation line numbers refer to *AI Agents Under EU Law* (Working Paper,
7 April 2026).

Wording convention: a control or artefact the Regulation itself requires is
stated with its article and nothing else. Guidance that comes from the paper
rather than from the Act is marked "the paper recommends" / "the paper notes",
and carries the paper line reference. The two are never merged into one claim:
the Act requires written Art. 25(4) agreements only from the provider of a
high-risk system toward suppliers of integrated AI systems, models, tools,
services or components (FOSS tools carved out, GPAI models not), which is a
narrower duty than the paper's suggested catalogue-wide governance.

Structurally, every mitigation and evidence item carries a provenance tag:
``act_required`` means the item states a control or artifact the Act requires
and ``ref`` cites the provision; ``paper_suggested`` means the paper
recommends it beyond the Act and ``ref`` cites the paper. The legacy
``mitigation_pattern`` / ``evidence_required`` string lists are derived from
the tagged ``recommendations`` field, never maintained by hand.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TypedDict

# Paper edition (2026.04.27) plus the taxonomy-content revision suffix. Bump
# the suffix when the shipped structure or guidance changes, not when the
# paper is re-read.
TAXONOMY_VERSION = "2026.04.27.v2"


class CompoundRiskType(StrEnum):
    """Four-axis compound-risk taxonomy from working-paper §10.4 lines 2227-2245."""

    cascading = "cascading"
    emergent = "emergent"
    attribution = "attribution"
    temporal = "temporal"


class ThreatCategory(StrEnum):
    """Threat categories cross-walked from agentic-AI literature.

    Sources:
      * Kim et al. USENIX 2026 — 5 categories (line 1428-1432).
      * Hammond et al. multi-agent failure modes — 3 modes (line 814-816, 2223-2225).
      * OWASP Top 10 for Agentic Applications — Dec 2025 (line 749-751).
      * AEPD rule-of-2 / lethal trifecta (Spanish DPA, 18 Feb 2026) — line 1175-1183.
    """

    # Kim et al.
    prompt_injection = "prompt_injection"
    autonomous_cyber_exploit = "autonomous_cyber_exploit"
    multi_agent_protocol = "multi_agent_protocol"
    interface_environment = "interface_environment"
    governance_autonomy = "governance_autonomy"
    # Hammond et al. multi-agent
    miscoordination = "miscoordination"
    conflict = "conflict"
    collusion = "collusion"
    # OWASP Top-10 Agentic — overarching
    tool_misuse_privilege_escalation = "tool_misuse_privilege_escalation"
    # AEPD-derived
    aepd_lethal_trifecta = "aepd_lethal_trifecta"


class AgentArchetype(StrEnum):
    """Architecture shapes — what the system *is*, not what it *does*."""

    single_agent = "single_agent"
    orchestrator_subagents = "orchestrator_subagents"
    multi_agent_swarm = "multi_agent_swarm"
    gpai_with_tools = "gpai_with_tools"
    rag_grounded_agent = "rag_grounded_agent"
    dynamic_tool_discovery = "dynamic_tool_discovery"
    continuously_learning = "continuously_learning"


class RecommendationSource(StrEnum):
    """Provenance of a taxonomy recommendation.

    ``act_required`` — the Act imposes the control or artifact in substance;
    ``ref`` cites the provision. ``paper_suggested`` — the working paper
    recommends it beyond the Act; ``ref`` cites the paper.
    """

    act_required = "act_required"
    paper_suggested = "paper_suggested"


SOURCE_LABELS: dict[str, str] = {
    RecommendationSource.act_required.value: "Act-required",
    RecommendationSource.paper_suggested.value: "Paper-suggested",
}


class RecommendationKind(StrEnum):
    """What the recommendation asks for: a control or an evidence artifact."""

    mitigation = "mitigation"
    evidence = "evidence"


class Recommendation(TypedDict):
    """One tagged mitigation or evidence item within a compound risk."""

    text: str
    kind: str
    source: str
    ref: str


class TaggedRecommendation(TypedDict):
    """A recommendation flattened out of its compound-risk entry."""

    risk_id: str
    risk_label: str
    text: str
    kind: str
    source: str
    ref: str


class CompoundRiskEntry(TypedDict, total=False):
    """One row in :data:`COMPOUND_RISK_TYPES`.

    ``recommendations`` is the single source of truth. ``mitigation_pattern``
    and ``evidence_required`` are derived from it at import time for backward
    compatibility with consumers that expect plain strings.
    """

    id: str
    label: str
    summary: str
    paper_section: str
    paper_lines: str
    article_refs: list[str]
    kb_dimensions: list[str]
    failure_modes: list[str]
    recommendations: list[Recommendation]
    mitigation_pattern: list[str]
    evidence_required: list[str]
    threat_categories: list[str]


class ThreatCategoryEntry(TypedDict, total=False):
    """One row in :data:`THREAT_CATEGORIES`."""

    id: str
    label: str
    source: str
    paper_lines: str
    article_refs: list[str]
    kb_dimensions: list[str]
    description: str


class AgentArchetypeEntry(TypedDict, total=False):
    """One row in :data:`AGENT_ARCHETYPES`."""

    id: str
    label: str
    description: str
    typical_compound_risks: list[str]
    typical_threats: list[str]
    paper_lines: str


def _act_required(
    text: str,
    ref: str,
    *,
    kind: str = RecommendationKind.mitigation.value,
) -> Recommendation:
    """Tag *text* as implementing an EU AI Act duty cited by *ref*."""
    return {
        "text": text,
        "kind": kind,
        "source": RecommendationSource.act_required.value,
        "ref": ref,
    }


def _paper_suggested(
    text: str,
    ref: str,
    *,
    kind: str = RecommendationKind.mitigation.value,
) -> Recommendation:
    """Tag *text* as paper guidance beyond the Act, cited by *ref*."""
    return {
        "text": text,
        "kind": kind,
        "source": RecommendationSource.paper_suggested.value,
        "ref": ref,
    }


def _derive_recommendation_lists(entry: CompoundRiskEntry) -> CompoundRiskEntry:
    """Add the legacy flat string lists derived from ``recommendations``.

    Kept for consumers that expect ``mitigation_pattern`` / ``evidence_required``
    as strings. Deriving them here keeps the provenance-tagged structure the
    only hand-maintained source, so the two views cannot drift.
    """
    recs = entry.get("recommendations", [])
    return {
        **entry,
        "mitigation_pattern": [
            rec["text"]
            for rec in recs
            if rec["kind"] == RecommendationKind.mitigation.value
        ],
        "evidence_required": [
            rec["text"]
            for rec in recs
            if rec["kind"] == RecommendationKind.evidence.value
        ],
    }


# ─── Compound-risk taxonomy (the four axes) ──────────────────────────────


_RAW_COMPOUND_RISK_TYPES: list[CompoundRiskEntry] = [
    {
        "id": CompoundRiskType.cascading.value,
        "label": "Cascading Risk",
        "summary": (
            "An error or bias in one agent's output propagates through "
            "orchestrated sub-agents, contaminating downstream actions."
        ),
        "paper_section": "10.4",
        "paper_lines": "2227-2229",
        "article_refs": ["Art. 9", "Art. 10", "Art. 15", "Art. 25(4)"],
        "kb_dimensions": ["risk_mgmt", "data_gov", "security", "decision_governance"],
        "failure_modes": [
            "Cross-tool propagation: a compromise in one tool interface cascades through the action chain (Kim et al., line 739).",
            "Authority escalation through legitimately granted scopes — agent acts harmfully using only permitted privileges (line 740-741).",
            "RAG caching staleness delivered as current data — financial advisory loss (Table 5, lines 1331-1334).",
        ],
        "recommendations": [
            _paper_suggested(
                "API-level least-privilege per tool with per-action scope.",
                "paper §10.4",
            ),
            _paper_suggested(
                "Dynamic privilege restriction based on input trust level.",
                "paper §10.4",
            ),
            _act_required(
                "Audit logging that distinguishes user-initiated vs AI-initiated actions.",
                "Art. 12(1)",
            ),
            _paper_suggested(
                "Inter-agent enforcement at the communication layer, not via per-agent prompts (Schroeder de Witt; Ji et al. SEAgent — lines 721-726, 768-770).",
                "paper lines 721-726, 768-770",
            ),
            _act_required(
                "Action-level audit log distinguishing user vs AI initiator.",
                "Art. 12(3)",
                kind=RecommendationKind.evidence.value,
            ),
            _paper_suggested(
                "Per-tool permission scope manifest.",
                "paper §10.4",
                kind=RecommendationKind.evidence.value,
            ),
            _paper_suggested(
                "Static dependency graph between sub-agents.",
                "paper §10.4",
                kind=RecommendationKind.evidence.value,
            ),
            _act_required(
                "Reproducible test that an injection on tool A does not exfiltrate via tool B.",
                "Art. 15(4)",
                kind=RecommendationKind.evidence.value,
            ),
        ],
        "threat_categories": [
            ThreatCategory.prompt_injection.value,
            ThreatCategory.autonomous_cyber_exploit.value,
            ThreatCategory.tool_misuse_privilege_escalation.value,
        ],
    },
    {
        "id": CompoundRiskType.emergent.value,
        "label": "Emergent Risk",
        "summary": (
            "Individually safe agents produce unsafe collective behaviour "
            "through interaction effects — miscoordination, conflict, collusion."
        ),
        "paper_section": "10.4",
        "paper_lines": "2229-2230",
        "article_refs": ["Art. 9", "Art. 14", "Art. 15(4)", "Art. 51(2)", "Art. 55"],
        "kb_dimensions": [
            "risk_mgmt",
            "human_oversight",
            "security",
            "gpai_systemic_risk",
            "decision_governance",
        ],
        "failure_modes": [
            "Hammond et al. — miscoordination, conflict, collusion across seven risk factors (line 814-816, 2223-2225).",
            "Darius et al. scenario-based risks: feedback loops, shared signals, coordination patterns (line 2237-2241).",
            "Schroeder de Witt — cascading jailbreaks across agent boundaries, steganographic collusion channels (line 721-724).",
            "Cross-agent propagation of unsafe practices — one compromised agent teaches others to bypass safety (Shapira et al., line 818-821).",
        ],
        "recommendations": [
            _paper_suggested(
                "Treat the agent collective — not the individual agent — as the unit of risk analysis (Riedl, footnote 44, line 2189-2194).",
                "paper lines 2189-2194",
            ),
            _paper_suggested(
                "Enforcement at the inter-agent communication layer (lines 725-726).",
                "paper lines 725-726",
            ),
            _paper_suggested(
                "External constraints, not internal instructions (lines 791, 2113-2115).",
                "paper lines 791, 2113-2115",
            ),
            _paper_suggested(
                "Documented inter-agent message-passing schema with policy enforcement at the broker.",
                "paper §10.4",
                kind=RecommendationKind.evidence.value,
            ),
            _paper_suggested(
                "Ablation tests showing each sub-agent stays within bounds AND the orchestrator stays within bounds.",
                "paper §10.4",
                kind=RecommendationKind.evidence.value,
            ),
            _paper_suggested(
                "Cross-agent jailbreak red-team campaigns recorded in the post-market monitoring file (Art. 72).",
                "paper §10.4; cf. Art. 72(1)",
                kind=RecommendationKind.evidence.value,
            ),
        ],
        "threat_categories": [
            ThreatCategory.multi_agent_protocol.value,
            ThreatCategory.miscoordination.value,
            ThreatCategory.conflict.value,
            ThreatCategory.collusion.value,
        ],
    },
    {
        "id": CompoundRiskType.attribution.value,
        "label": "Attribution Risk",
        "summary": (
            "The multi-provider value chain obscures responsibility in ways "
            "the New Legislative Framework (provider/auth-rep/importer/distributor) "
            "was not designed to handle."
        ),
        "paper_section": "10.4",
        "paper_lines": "2230-2232",
        "article_refs": [
            "Art. 3(23)",
            "Art. 25",
            "Art. 25(4)",
            "Art. 74",
            "Art. 53",
        ],
        "kb_dimensions": [
            "supply_chain",
            "quality_management",
            "tech_docs",
            "deployer_obligations",
        ],
        "failure_modes": [
            "Orchestrator + 3 sub-agents: 'could constitute one system or four' depending on placement on market (lines 1599-1601).",
            "Multi-layer assembly chain — Article 25 substantial-modification + own-name triggers may apply at multiple layers simultaneously (footnote 33, lines 1606-1611).",
            "Dynamic tool discovery — agents select tools at runtime not part of original conformity assessment (lines 1881-1890).",
            "Runtime-discovered tools have no supplier to contract with, so an Art. 25(4) written agreement cannot be obtained for them; the paper notes that Recital 88 only encourages tool-supplier cooperation (line 1886).",
        ],
        "recommendations": [
            _act_required(
                "Designated EU authorised representative where the provider is established outside the Union (Art. 22(1)); the paper frames this as a 'responsible person' in the EU per MSR Article 4 (line 1064).",
                "Art. 22(1)",
            ),
            _act_required(
                "Written Art. 25(4) agreements with the suppliers of AI systems, models, tools, services or components integrated into a high-risk system, covering information, capabilities, technical access and assistance. Publicly available FOSS tools, services and components are carved out; general-purpose AI models are not.",
                "Art. 25(4)",
            ),
            _paper_suggested(
                "The paper recommends extending that written record across the whole static tool catalogue (lines 1881-1883) — governance beyond the Act's supplier-only duty.",
                "paper lines 1881-1883",
            ),
            _paper_suggested(
                "Declared external-action inventory — Step 9 of the compliance sequence (line 1729).",
                "paper line 1729",
            ),
            _paper_suggested(
                "Contractual + technical exclusion of high-risk deployments where the platform cannot predict use (line 357).",
                "paper line 357",
            ),
            _act_required(
                "Art. 25(4) written agreements on file for each integrated third-party AI component.",
                "Art. 25(4)",
                kind=RecommendationKind.evidence.value,
            ),
            _paper_suggested(
                "Declared static tool catalogue with provider attestation — the paper's broader recommendation, not an Act requirement (lines 1881-1883).",
                "paper lines 1881-1883",
                kind=RecommendationKind.evidence.value,
            ),
            _paper_suggested(
                "Classification reasoning documented per system per Step 2 (lines 1626-1634).",
                "paper lines 1626-1634",
                kind=RecommendationKind.evidence.value,
            ),
            _act_required(
                "EU declaration of conformity naming the responsible person.",
                "Art. 47",
                kind=RecommendationKind.evidence.value,
            ),
        ],
        "threat_categories": [
            ThreatCategory.governance_autonomy.value,
        ],
    },
    {
        "id": CompoundRiskType.temporal.value,
        "label": "Temporal Risk (Runtime Drift)",
        "summary": (
            "Long-running agent processes accumulate state modifications "
            "that are individually minor but collectively constitute a shift "
            "outside the conformity-assessed envelope (Art. 3(23) substantial "
            "modification)."
        ),
        "paper_section": "10.4",
        "paper_lines": "2232-2233",
        "article_refs": [
            "Art. 3(23)",
            "Art. 12",
            "Art. 14",
            "Art. 15",
            "Art. 43",
            "Art. 72",
            "Art. 73",
        ],
        "kb_dimensions": [
            "logging",
            "human_oversight",
            "security",
            "conformity_assessment",
            "decision_governance",
        ],
        "failure_modes": [
            "Discovery of novel tool-use patterns not anticipated by the provider (line 930).",
            "Persistent cross-session memory shifting operational profile (line 931).",
            "Scope extension via tool composition (line 932).",
            "Oversight-evasion strategies (line 933).",
            "Specification gaming + memory poisoning (Kim et al., line 936-938).",
            "Three drift manifestations — semantic, coordination, behavioural (Rath ASI, line 940-943).",
        ],
        "recommendations": [
            _paper_suggested(
                "Treat runtime state as versioned architecture (line 945-947).",
                "paper lines 945-947",
            ),
            _paper_suggested(
                "Versioned snapshots of tool catalogue, memory state, policy bindings.",
                "paper lines 945-947",
            ),
            _act_required(
                "Continuous behavioural-metric monitoring against the conformity-assessment baseline.",
                "Art. 72(1); Art. 26(5)",
            ),
            _paper_suggested(
                "Automated drift detection beyond defined thresholds.",
                "paper §10.4",
            ),
            _act_required(
                "Documented internal procedure for the Article 3(23) determination (lines 954-958).",
                "Art. 3(23); Art. 43",
            ),
            _paper_suggested(
                "Version IDs on every snapshot.",
                "paper §10.4",
                kind=RecommendationKind.evidence.value,
            ),
            _paper_suggested(
                "Baseline behavioural metrics filed with the conformity assessment.",
                "paper §10.4",
                kind=RecommendationKind.evidence.value,
            ),
            _paper_suggested(
                "Alerting + change-management ticket each time a drift threshold is crossed.",
                "paper §10.4",
                kind=RecommendationKind.evidence.value,
            ),
            _act_required(
                "Article 3(23) determination memo per detected drift.",
                "Art. 3(23); Art. 43",
                kind=RecommendationKind.evidence.value,
            ),
            _act_required(
                "Article 73 serious-incident reports where applicable.",
                "Art. 73",
                kind=RecommendationKind.evidence.value,
            ),
        ],
        "threat_categories": [
            ThreatCategory.governance_autonomy.value,
            ThreatCategory.aepd_lethal_trifecta.value,
        ],
    },
]


# Public view: the same entries plus the legacy flat lists derived from the
# tagged recommendations, so existing consumers keep working while the
# machine-readable provenance lives on the structured field.
COMPOUND_RISK_TYPES: list[CompoundRiskEntry] = [
    _derive_recommendation_lists(entry) for entry in _RAW_COMPOUND_RISK_TYPES
]


# ─── Threat-category cross-walks ─────────────────────────────────────────


THREAT_CATEGORIES: list[ThreatCategoryEntry] = [
    # Kim et al. (USENIX Security 2026 survey).
    {
        "id": ThreatCategory.prompt_injection.value,
        "label": "Prompt Injection and Jailbreaks",
        "source": "Kim et al. USENIX 2026",
        "paper_lines": "1429",
        "article_refs": ["Art. 5(1)(a)", "Art. 5(1)(b)", "Art. 15(4)"],
        "kb_dimensions": ["security", "risk_mgmt"],
        "description": "Direct and indirect prompt manipulation. Particularly relevant for agents per AI Office guidance (line 402-404).",
    },
    {
        "id": ThreatCategory.autonomous_cyber_exploit.value,
        "label": "Autonomous Cyber-Exploitation and Tool Abuse",
        "source": "Kim et al. USENIX 2026",
        "paper_lines": "1430",
        "article_refs": ["Art. 14", "Art. 15(4)", "Art. 25(4)"],
        "kb_dimensions": ["security", "human_oversight", "supply_chain"],
        "description": "Privilege escalation through allowed scopes; agents performing harmful actions using only legitimately granted permissions (line 740).",
    },
    {
        "id": ThreatCategory.multi_agent_protocol.value,
        "label": "Multi-Agent and Protocol-Level Threats",
        "source": "Kim et al. USENIX 2026",
        "paper_lines": "1430",
        "article_refs": ["Art. 9", "Art. 14", "Art. 51(2)"],
        "kb_dimensions": ["risk_mgmt", "human_oversight", "gpai_systemic_risk"],
        "description": "Inter-agent communication exploits, steganographic channels, coordination attacks (Schroeder de Witt, lines 721-724).",
    },
    {
        "id": ThreatCategory.interface_environment.value,
        "label": "Interface and Environment Risks",
        "source": "Kim et al. USENIX 2026",
        "paper_lines": "1430",
        "article_refs": ["Art. 13", "Art. 50"],
        "kb_dimensions": ["transparency", "content_transparency"],
        "description": "Risks from the operating environment (sandbox escape, container break-out, network exfiltration) plus interface manipulation (CRA Annex I overlap).",
    },
    {
        "id": ThreatCategory.governance_autonomy.value,
        "label": "Governance and Autonomy Concerns",
        "source": "Kim et al. USENIX 2026",
        "paper_lines": "1431, 936-938",
        "article_refs": ["Art. 3(23)", "Art. 14", "Art. 72"],
        "kb_dimensions": ["human_oversight", "decision_governance", "logging"],
        "description": "Specification gaming, memory poisoning, latent drift only manifest under specific triggers (Kim et al., lines 936-938).",
    },
    # Hammond et al. multi-agent failure modes.
    {
        "id": ThreatCategory.miscoordination.value,
        "label": "Miscoordination",
        "source": "Hammond et al. multi-agent risks",
        "paper_lines": "814-816",
        "article_refs": ["Art. 9", "Art. 14"],
        "kb_dimensions": ["risk_mgmt", "human_oversight"],
        "description": "Individually-aligned agents converge on a system-level outcome no individual agent intended.",
    },
    {
        "id": ThreatCategory.conflict.value,
        "label": "Conflict",
        "source": "Hammond et al. multi-agent risks",
        "paper_lines": "814-816",
        "article_refs": ["Art. 9", "Art. 15", "Art. 51(2)"],
        "kb_dimensions": ["risk_mgmt", "security", "gpai_systemic_risk"],
        "description": "Agents pursuing inconsistent goals produce harmful interaction (markets, allocation, escalation).",
    },
    {
        "id": ThreatCategory.collusion.value,
        "label": "Collusion",
        "source": "Hammond et al. multi-agent risks",
        "paper_lines": "814-816",
        "article_refs": ["Art. 5(1)(a)", "Art. 5(1)(b)", "Art. 15(4)", "Art. 55"],
        "kb_dimensions": ["security", "gpai_systemic_risk"],
        "description": "Agents coordinate (possibly via steganographic channels per Schroeder de Witt) to reach outcomes the principal would refuse.",
    },
    # OWASP Top 10 Agentic.
    {
        "id": ThreatCategory.tool_misuse_privilege_escalation.value,
        "label": "Tool Misuse and Privilege Escalation",
        "source": "OWASP Top 10 for Agentic Applications (Dec 2025)",
        "paper_lines": "749-751",
        "article_refs": ["Art. 15(4)", "Art. 14"],
        "kb_dimensions": ["security", "access_control", "human_oversight"],
        "description": "Most frequently reported agentic threat; mitigation requires controls at the execution layer rather than the model layer (line 750-752).",
    },
    # AEPD rule-of-2 / lethal trifecta.
    {
        "id": ThreatCategory.aepd_lethal_trifecta.value,
        "label": "AEPD Rule-of-2 / Lethal Trifecta",
        "source": "Spanish DPA (AEPD) 18 February 2026 + Simon Willison + Meta 31 Oct 2025",
        "paper_lines": "1175-1183",
        "article_refs": ["Art. 14"],
        "kb_dimensions": ["human_oversight", "security", "decision_governance"],
        "description": (
            "Agent must NOT simultaneously combine all three of (a) processing untrusted input, "
            "(b) accessing sensitive data, and (c) taking autonomous state-changing action — "
            "without a human-oversight gate. First EU supervisory authority to treat the agentic "
            "architecture as the primary object of data-protection analysis (line 1156)."
        ),
    },
]


# ─── Agent archetypes ────────────────────────────────────────────────────


AGENT_ARCHETYPES: list[AgentArchetypeEntry] = [
    {
        "id": AgentArchetype.single_agent.value,
        "label": "Single Agent",
        "description": "One LLM call wrapped in a tool-invocation loop. Default architecture.",
        "typical_compound_risks": [CompoundRiskType.temporal.value],
        "typical_threats": [
            ThreatCategory.prompt_injection.value,
            ThreatCategory.tool_misuse_privilege_escalation.value,
        ],
        "paper_lines": "1595-1605",
    },
    {
        "id": AgentArchetype.orchestrator_subagents.value,
        "label": "Orchestrator + Sub-Agents",
        "description": "A coordinating agent delegates to specialised sub-agents that may themselves invoke tools.",
        "typical_compound_risks": [
            CompoundRiskType.cascading.value,
            CompoundRiskType.attribution.value,
            CompoundRiskType.emergent.value,
        ],
        "typical_threats": [
            ThreatCategory.multi_agent_protocol.value,
            ThreatCategory.miscoordination.value,
            ThreatCategory.tool_misuse_privilege_escalation.value,
        ],
        "paper_lines": "1599-1611",
    },
    {
        "id": AgentArchetype.multi_agent_swarm.value,
        "label": "Multi-Agent Swarm",
        "description": "Peer agents coordinate without a privileged orchestrator (CrewAI, AutoGen, swarm patterns).",
        "typical_compound_risks": [
            CompoundRiskType.emergent.value,
            CompoundRiskType.attribution.value,
        ],
        "typical_threats": [
            ThreatCategory.miscoordination.value,
            ThreatCategory.conflict.value,
            ThreatCategory.collusion.value,
            ThreatCategory.multi_agent_protocol.value,
        ],
        "paper_lines": "2237-2245",
    },
    {
        "id": AgentArchetype.gpai_with_tools.value,
        "label": "GPAI Model with Tools",
        "description": "A general-purpose AI model invoked with tool-calling capabilities; downstream provider may flip provider status under Art. 25 if >1/3 of original training compute is added (lines 455-457).",
        "typical_compound_risks": [
            CompoundRiskType.attribution.value,
            CompoundRiskType.cascading.value,
        ],
        "typical_threats": [
            ThreatCategory.governance_autonomy.value,
            ThreatCategory.tool_misuse_privilege_escalation.value,
        ],
        "paper_lines": "433-462, 1621-1624",
    },
    {
        "id": AgentArchetype.rag_grounded_agent.value,
        "label": "RAG-Grounded Agent",
        "description": "Agent grounds responses in retrieved documents from a knowledge store. Subject to caching-staleness + indirect-prompt-injection risk.",
        "typical_compound_risks": [
            CompoundRiskType.cascading.value,
            CompoundRiskType.temporal.value,
        ],
        "typical_threats": [
            ThreatCategory.prompt_injection.value,
            ThreatCategory.governance_autonomy.value,
        ],
        "paper_lines": "1331-1334",
    },
    {
        "id": AgentArchetype.dynamic_tool_discovery.value,
        "label": "Dynamic Tool Discovery",
        "description": "Tools are selected at runtime — typically via MCP or registry lookups — and were not part of the original conformity assessment. Art. 25(4)'s written-agreement route presupposes an identified supplier, so runtime-discovered tools may fall outside it; control the integration point instead (Art. 9 risk management, Art. 15 robustness) (lines 1874-1890).",
        "typical_compound_risks": [
            CompoundRiskType.attribution.value,
            CompoundRiskType.temporal.value,
        ],
        "typical_threats": [
            ThreatCategory.tool_misuse_privilege_escalation.value,
            ThreatCategory.governance_autonomy.value,
        ],
        "paper_lines": "1874-1890",
    },
    {
        "id": AgentArchetype.continuously_learning.value,
        "label": "Continuously Learning System",
        "description": "Online learning, fine-tuning on user interactions, decision-boundary modifications post-deployment. Candidate for Art. 3(23) substantial modification.",
        "typical_compound_risks": [
            CompoundRiskType.temporal.value,
            CompoundRiskType.cascading.value,
        ],
        "typical_threats": [
            ThreatCategory.governance_autonomy.value,
        ],
        "paper_lines": "909-933",
    },
]


# ─── Fast lookups (built once at import) ─────────────────────────────────


COMPOUND_RISK_BY_ID: dict[str, CompoundRiskEntry] = {
    entry["id"]: entry for entry in COMPOUND_RISK_TYPES
}

THREAT_CATEGORY_BY_ID: dict[str, ThreatCategoryEntry] = {
    entry["id"]: entry for entry in THREAT_CATEGORIES
}

AGENT_ARCHETYPE_BY_ID: dict[str, AgentArchetypeEntry] = {
    entry["id"]: entry for entry in AGENT_ARCHETYPES
}


# ─── Helpers ─────────────────────────────────────────────────────────────


def get_compound_risk(risk_id: str) -> CompoundRiskEntry | None:
    """Return the compound-risk entry by its ID, or ``None`` if unknown."""
    return COMPOUND_RISK_BY_ID.get(risk_id)


def get_threat_category(threat_id: str) -> ThreatCategoryEntry | None:
    """Return the threat-category entry by its ID, or ``None`` if unknown."""
    return THREAT_CATEGORY_BY_ID.get(threat_id)


def get_agent_archetype(archetype_id: str) -> AgentArchetypeEntry | None:
    """Return the agent-archetype entry by its ID, or ``None`` if unknown."""
    return AGENT_ARCHETYPE_BY_ID.get(archetype_id)


def compound_risks_for_kb_dimension(dimension_id: str) -> list[CompoundRiskEntry]:
    """Return all compound-risk entries that mention ``dimension_id`` in their KB dims."""
    return [
        entry
        for entry in COMPOUND_RISK_TYPES
        if dimension_id in entry.get("kb_dimensions", [])
    ]


def compound_risks_for_article(article_ref: str) -> list[CompoundRiskEntry]:
    """Return all compound-risk entries that ground to ``article_ref``.

    Matches on prefix so ``Art. 9`` matches both ``Art. 9`` and ``Art. 9(2)(a)``.
    """
    return [
        entry
        for entry in COMPOUND_RISK_TYPES
        if any(ref.startswith(article_ref) or article_ref.startswith(ref) for ref in entry.get("article_refs", []))
    ]


def threat_categories_for_compound_risk(risk_id: str) -> list[ThreatCategoryEntry]:
    """Return the threat-category entries linked from a compound-risk entry."""
    risk = COMPOUND_RISK_BY_ID.get(risk_id)
    if not risk:
        return []
    return [
        THREAT_CATEGORY_BY_ID[threat_id]
        for threat_id in risk.get("threat_categories", [])
        if threat_id in THREAT_CATEGORY_BY_ID
    ]


def all_recommendations() -> list[TaggedRecommendation]:
    """Flatten every mitigation/evidence item, tagged with its source risk.

    Deterministic order: taxonomy entry order, then the order within the entry.
    """
    return [
        {
            "risk_id": entry["id"],
            "risk_label": entry.get("label", entry["id"]),
            "text": rec["text"],
            "kind": rec["kind"],
            "source": rec["source"],
            "ref": rec["ref"],
        }
        for entry in COMPOUND_RISK_TYPES
        for rec in entry.get("recommendations", [])
    ]


def recommendations_for_risk(risk_id: str) -> list[TaggedRecommendation]:
    """Return the tagged recommendations for one compound-risk entry."""
    return [rec for rec in all_recommendations() if rec["risk_id"] == risk_id]


def recommendations_for_source(
    source: RecommendationSource | str,
) -> list[TaggedRecommendation]:
    """Return every recommendation carrying *source* (``act_required`` or
    ``paper_suggested``). Unknown values yield an empty list."""
    value = source.value if isinstance(source, RecommendationSource) else str(source)
    return [rec for rec in all_recommendations() if rec["source"] == value]


def recommendation_provenance_summary() -> dict[str, int]:
    """Count recommendations per provenance tag, keyed by source value."""
    counts = {source.value: 0 for source in RecommendationSource}
    for rec in all_recommendations():
        counts[rec["source"]] += 1
    return counts


__all__ = [
    "TAXONOMY_VERSION",
    "SOURCE_LABELS",
    "CompoundRiskType",
    "ThreatCategory",
    "AgentArchetype",
    "RecommendationSource",
    "RecommendationKind",
    "Recommendation",
    "TaggedRecommendation",
    "CompoundRiskEntry",
    "ThreatCategoryEntry",
    "AgentArchetypeEntry",
    "COMPOUND_RISK_TYPES",
    "THREAT_CATEGORIES",
    "AGENT_ARCHETYPES",
    "COMPOUND_RISK_BY_ID",
    "THREAT_CATEGORY_BY_ID",
    "AGENT_ARCHETYPE_BY_ID",
    "get_compound_risk",
    "get_threat_category",
    "get_agent_archetype",
    "compound_risks_for_kb_dimension",
    "compound_risks_for_article",
    "threat_categories_for_compound_risk",
    "all_recommendations",
    "recommendations_for_risk",
    "recommendations_for_source",
    "recommendation_provenance_summary",
]
