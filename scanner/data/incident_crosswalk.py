"""Crosswalk: scanner threat categories + KB dimensions -> incident taxonomy.

This module is the bridge between what the scanner *finds in your code* and
what has *actually gone wrong in the wild*. The scanner's findings already
carry an agentic compound-risk axis, threat categories
(:mod:`scanner.data.agentic_taxonomy`), and EU AI Act article references. The
open GenAI & Agentic AI Security Incidents dataset
(``emmanuelgjr/genai-incidents``, CC-BY-4.0) tags every real-world incident
with OWASP Top 10 for LLM Applications (2025), OWASP Agentic AI (ASI) Top 10,
NIST AI RMF, and MITRE ATLAS. This module maps between the two vocabularies so
a gap can be grounded in the documented incidents that exploited that gap
class.

Data-only + pure helpers: no I/O, no mutable state, deterministic for the same
inputs. Both :mod:`scanner.incident_grounding` (runtime grounding) and
``scripts/sync_incident_corpus.py`` (corpus regeneration) consume these tables,
so the curated snapshot and the runtime lookup always agree on what "relevant"
means.

The match logic leans on the dataset's strongest signals — ``attack_vector``
and ``owasp_llm`` (well-defined, high-population columns) — and uses
``owasp_asi`` presence and selected MITRE ATLAS techniques as agentic boosters.
"""

from __future__ import annotations

from dataclasses import dataclass, field

CROSSWALK_VERSION = "2026.06.04.v1"


# ─── Display labels (best-effort; unknown codes fall back to the raw code) ──
# Only labels we can state with confidence are included. The scanner's ethos is
# citation rigour: we do not fabricate a taxonomy title we are unsure of.

OWASP_LLM_LABELS: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# MITRE ATLAS technique titles — only the techniques we are confident about.
MITRE_ATLAS_LABELS: dict[str, str] = {
    "AML.T0010": "ML Supply Chain Compromise",
    "AML.T0020": "Poison Training Data",
    "AML.T0024": "Exfiltration via ML Inference API",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0049": "Exploit Public-Facing Application",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0057": "LLM Data Leakage",
}


def owasp_llm_label(code: str) -> str:
    """Return ``CODE - Title`` for an OWASP LLM code, or the bare code."""
    title = OWASP_LLM_LABELS.get(code)
    return f"{code} - {title}" if title else code


def mitre_atlas_label(code: str) -> str:
    """Return ``CODE - Title`` for a MITRE ATLAS technique, or the bare code."""
    title = MITRE_ATLAS_LABELS.get(code)
    return f"{code} - {title}" if title else code


# ─── Match specification ─────────────────────────────────────────────────


@dataclass(frozen=True)
class MatchSpec:
    """A crosswalk target: which incident tags make an incident relevant.

    An incident matches if it overlaps on any populated facet. The scalar
    ``attack_vector`` is matched by membership; the list facets
    (``owasp_llm``, ``mitre_atlas``) by intersection. ``owasp_asi_any`` is an
    agentic booster — it scores when the incident carries *any* OWASP ASI tag.
    """

    owasp_llm: frozenset[str] = field(default_factory=frozenset)
    attack_vectors: frozenset[str] = field(default_factory=frozenset)
    mitre_atlas: frozenset[str] = field(default_factory=frozenset)
    owasp_asi_any: bool = False


@dataclass(frozen=True)
class IncidentTags:
    """The subset of an incident's taxonomy used for matching."""

    owasp_llm: frozenset[str] = field(default_factory=frozenset)
    owasp_asi: frozenset[str] = field(default_factory=frozenset)
    attack_vector: str = ""
    mitre_atlas: frozenset[str] = field(default_factory=frozenset)


def match_score(tags: IncidentTags, spec: MatchSpec) -> int:
    """Score how strongly an incident matches a crosswalk target.

    0 means no match. Higher is more relevant. Weights favour the precise
    signals (attack_vector, OWASP LLM, MITRE technique) over the agentic
    booster so a directly-on-point incident always outranks a merely-agentic
    one.
    """
    score = 0
    if spec.owasp_llm and (tags.owasp_llm & spec.owasp_llm):
        score += 2 * len(tags.owasp_llm & spec.owasp_llm)
    if spec.attack_vectors and tags.attack_vector in spec.attack_vectors:
        score += 3
    if spec.mitre_atlas and (tags.mitre_atlas & spec.mitre_atlas):
        score += 2 * len(tags.mitre_atlas & spec.mitre_atlas)
    if spec.owasp_asi_any and tags.owasp_asi:
        score += 1
    return score


# ─── Threat-category -> incident taxonomy ────────────────────────────────
# Keys are :class:`scanner.data.agentic_taxonomy.ThreatCategory` values.

THREAT_TO_SPEC: dict[str, MatchSpec] = {
    "prompt_injection": MatchSpec(
        owasp_llm=frozenset({"LLM01", "LLM07"}),
        attack_vectors=frozenset({"prompt-injection", "jailbreak"}),
        mitre_atlas=frozenset({"AML.T0051", "AML.T0051.000", "AML.T0051.001", "AML.T0054"}),
    ),
    "autonomous_cyber_exploit": MatchSpec(
        owasp_llm=frozenset({"LLM05"}),
        attack_vectors=frozenset({
            "rce", "command-injection", "ssrf", "path-traversal",
            "deserialization", "sql-injection",
        }),
        mitre_atlas=frozenset({"AML.T0049"}),
    ),
    "multi_agent_protocol": MatchSpec(
        owasp_llm=frozenset({"LLM06"}),
        attack_vectors=frozenset({"tool-abuse"}),
        owasp_asi_any=True,
    ),
    "interface_environment": MatchSpec(
        owasp_llm=frozenset({"LLM05"}),
        attack_vectors=frozenset({"xss", "ssrf", "path-traversal", "info-disclosure"}),
    ),
    "governance_autonomy": MatchSpec(
        owasp_llm=frozenset({"LLM06"}),
        attack_vectors=frozenset({"tool-abuse", "unsafe-advice"}),
        owasp_asi_any=True,
    ),
    "miscoordination": MatchSpec(
        owasp_llm=frozenset({"LLM06"}),
        owasp_asi_any=True,
    ),
    "conflict": MatchSpec(
        owasp_llm=frozenset({"LLM06"}),
        owasp_asi_any=True,
    ),
    "collusion": MatchSpec(
        owasp_llm=frozenset({"LLM06"}),
        owasp_asi_any=True,
    ),
    "tool_misuse_privilege_escalation": MatchSpec(
        owasp_llm=frozenset({"LLM06"}),
        attack_vectors=frozenset({
            "tool-abuse", "command-injection", "rce", "auth-bypass", "ssrf",
        }),
        owasp_asi_any=True,
    ),
    "aepd_lethal_trifecta": MatchSpec(
        owasp_llm=frozenset({"LLM01", "LLM02", "LLM06"}),
        attack_vectors=frozenset({
            "data-exfiltration", "tool-abuse", "prompt-injection", "privacy-violation",
        }),
        owasp_asi_any=True,
    ),
}


# ─── KB dimension -> incident taxonomy ───────────────────────────────────
# Keys are :data:`scanner.kb.DIMENSIONS` ids.

DIMENSION_TO_SPEC: dict[str, MatchSpec] = {
    "security": MatchSpec(
        owasp_llm=frozenset({"LLM01", "LLM05"}),
        attack_vectors=frozenset({
            "rce", "prompt-injection", "jailbreak", "command-injection",
            "ssrf", "xss", "auth-bypass", "adversarial-input",
            "data-exfiltration", "deserialization", "sql-injection",
        }),
        mitre_atlas=frozenset({"AML.T0051", "AML.T0054", "AML.T0043", "AML.T0049"}),
    ),
    "data_gov": MatchSpec(
        owasp_llm=frozenset({"LLM04", "LLM08"}),
        attack_vectors=frozenset({"algorithmic-bias", "privacy-violation"}),
        mitre_atlas=frozenset({"AML.T0020"}),
    ),
    "transparency": MatchSpec(
        owasp_llm=frozenset({"LLM09"}),
        attack_vectors=frozenset({"misinformation", "hallucination", "unsafe-advice"}),
    ),
    "content_transparency": MatchSpec(
        owasp_llm=frozenset({"LLM09"}),
        attack_vectors=frozenset({"deepfake", "misinformation", "csam-generation"}),
    ),
    "human_oversight": MatchSpec(
        owasp_llm=frozenset({"LLM06"}),
        attack_vectors=frozenset({"tool-abuse", "unsafe-advice"}),
        owasp_asi_any=True,
    ),
    "logging": MatchSpec(
        owasp_llm=frozenset({"LLM06"}),
        attack_vectors=frozenset({"info-disclosure"}),
        owasp_asi_any=True,
    ),
    "supply_chain": MatchSpec(
        owasp_llm=frozenset({"LLM03"}),
        attack_vectors=frozenset({"supply-chain", "backdoor", "deserialization"}),
        mitre_atlas=frozenset({"AML.T0010"}),
    ),
    "access_control": MatchSpec(
        attack_vectors=frozenset({"auth-bypass", "info-disclosure", "privacy-violation"}),
    ),
    "infra_mlops": MatchSpec(
        owasp_llm=frozenset({"LLM05"}),
        attack_vectors=frozenset({
            "rce", "ssrf", "command-injection", "deserialization", "path-traversal",
        }),
        mitre_atlas=frozenset({"AML.T0049"}),
    ),
    "tech_docs": MatchSpec(owasp_asi_any=True),
    "agent_inventory": MatchSpec(
        attack_vectors=frozenset({"tool-abuse"}),
        owasp_asi_any=True,
    ),
    "tool_governance": MatchSpec(
        owasp_llm=frozenset({"LLM06"}),
        attack_vectors=frozenset({"tool-abuse", "command-injection", "auth-bypass"}),
        owasp_asi_any=True,
    ),
    "regulatory_perimeter": MatchSpec(
        attack_vectors=frozenset({"supply-chain", "tool-abuse"}),
        owasp_asi_any=True,
    ),
    "runtime_drift": MatchSpec(
        owasp_llm=frozenset({"LLM06"}),
        owasp_asi_any=True,
    ),
    "decision_governance": MatchSpec(
        owasp_llm=frozenset({"LLM06"}),
        attack_vectors=frozenset({"tool-abuse", "unsafe-advice", "algorithmic-bias"}),
        owasp_asi_any=True,
    ),
    "deployer_obligations": MatchSpec(
        owasp_llm=frozenset({"LLM09"}),
        attack_vectors=frozenset({"unsafe-advice", "algorithmic-bias", "misinformation"}),
    ),
    "gpai": MatchSpec(
        owasp_llm=frozenset({"LLM04", "LLM03"}),
        attack_vectors=frozenset({"backdoor", "supply-chain"}),
        owasp_asi_any=True,
    ),
    "gpai_systemic_risk": MatchSpec(
        owasp_llm=frozenset({"LLM04"}),
        attack_vectors=frozenset({"jailbreak", "adversarial-input"}),
        owasp_asi_any=True,
    ),
}


def spec_for_threat(threat_id: str) -> MatchSpec | None:
    """Return the crosswalk MatchSpec for a ThreatCategory id, or None."""
    return THREAT_TO_SPEC.get(threat_id)


def spec_for_dimension(dim_id: str) -> MatchSpec | None:
    """Return the crosswalk MatchSpec for a KB dimension id, or None."""
    return DIMENSION_TO_SPEC.get(dim_id)


# Every dimension/threat that has a crosswalk target — used by the sync
# script to guarantee the bundled corpus covers every lookup key.
ALL_SPEC_KEYS: tuple[tuple[str, MatchSpec], ...] = tuple(
    [(f"threat:{k}", v) for k, v in THREAT_TO_SPEC.items()]
    + [(f"dim:{k}", v) for k, v in DIMENSION_TO_SPEC.items()]
)


__all__ = [
    "CROSSWALK_VERSION",
    "OWASP_LLM_LABELS",
    "MITRE_ATLAS_LABELS",
    "owasp_llm_label",
    "mitre_atlas_label",
    "MatchSpec",
    "IncidentTags",
    "match_score",
    "THREAT_TO_SPEC",
    "DIMENSION_TO_SPEC",
    "spec_for_threat",
    "spec_for_dimension",
    "ALL_SPEC_KEYS",
]
