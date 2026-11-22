"""Cross-framework catalog and canonical crosswalk for EU AI Act compliance.

Maps EU AI Act compliance dimensions and articles to global AI governance,
security, and risk standards:
- NIST AI Risk Management Framework (NIST AI RMF 1.0 / AI 100-1)
- ISO/IEC 42001:2023 (Artificial Intelligence Management System)
- OWASP Top 10 for LLM Applications (2025 edition)
- OWASP Top 10 for Agentic Applications (ASI01-ASI10)
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems) — technique IDs
  (``AML.T####``) that the mapped control mitigates; not a control catalogue.
- NIST AI 600-1 (Generative AI Profile)
- CSA AI Controls Matrix (AICM v1.0)
- GDPR (General Data Protection Regulation EU 2016/679)
- SOC 2 Trust Services Criteria
- ISO/IEC 27002:2022 (Information Security Controls)
- NIST SP 800-53 Rev. 5
- CEN-CENELEC JTC 21 Harmonised Standards (EN 18286:2026 OJ-cited 14 Oct 2026
  for Art. 17(1) and the first sentence of Art. 11(1) only; prEN drafts carry
  no Art. 40 presumption of conformity until OJ citation)

Provides the "Satisfy Once, Comply Everywhere" foundation so teams can prove
compliance across multiple international regulatory frameworks from a single scan.
"""

from __future__ import annotations

from typing import Final

from pydantic import BaseModel, Field

# 2026.11.v1: ISO/IEC 42001 references corrected. Clause 8 ends at 8.4 and each
# Annex A "x.1" is a control objective, not a control, so 8.5, A.6.3, A.7.1,
# A.8.1, A.9.1 and A.10.1 were replaced, and topics realigned (Art. 10 data ->
# A.7 "Data for AI systems"; transparency -> A.8 "Information for interested
# parties"; Art. 15 -> A.6.2.4 verification and validation / A.6.2.6 operation
# and monitoring). Plus legal force per framework (scanner.data.normative_force).
# 2026.11.v2: 208 article-level control IDs ported from the legit-ai parent
# project (SOC 2, ISO/IEC 27002, NIST SP 800-53, NIST AI RMF, ATLAS techniques,
# OWASP, GDPR, NIST AI 600-1 actions), normalised to published IDs; non-existent
# ISO 42001 8.6/8.7, ATLAS mitigations/sub-techniques, "GAI-n" categories and
# CSA domain-only codes were not ported; retired AML.T0019 maps to AML.T0115.
CROSSWALK_CATALOGUE_VERSION: Final[str] = "2026.11.v2"

# Canonical framework IDs. Older call sites used variant spellings
# ("owasp_llm_top10" vs "owasp_llm_2025" vs "owasp_llm"); normalize everything
# through FW_ID_ALIASES so filtering never silently drops all controls.
CANONICAL_FRAMEWORK_IDS: Final[tuple[str, ...]] = (
    "nist_ai_rmf", "iso_42001", "owasp_llm", "owasp_agentic",
    "mitre_atlas", "nist_ai_600_1", "csa_aicm", "gdpr",
    "soc2", "iso_27002", "nist_sp_800_53", "cen_cenelec_jtc21",
)

FW_ID_ALIASES: Final[dict[str, str]] = {
    "owasp_llm_top10": "owasp_llm",
    "owasp_llm_2025": "owasp_llm",
    "owasp_agentic_top10": "owasp_agentic",
    "owasp_agentic": "owasp_agentic",
    "cen_cenelec": "cen_cenelec_jtc21",
    "jtc21": "cen_cenelec_jtc21",
}


def normalize_framework_id(fw_id: str) -> str:
    """Map a variant framework ID to its canonical form."""
    key = (fw_id or "").strip().lower()
    return FW_ID_ALIASES.get(key, key)


class FrameworkSubcategory(BaseModel):
    """A specific control, subcategory, or technique in a framework."""
    id: str
    name: str
    description: str
    level: int | None = None


class FrameworkFunction(BaseModel):
    """A top-level function, domain, or clause in a framework."""
    id: str
    name: str
    description: str
    subcategories: list[FrameworkSubcategory] = Field(default_factory=list)


class FrameworkDefinition(BaseModel):
    """Metadata and structure of a governance framework."""
    id: str
    name: str
    version: str
    description: str
    functions: list[FrameworkFunction] = Field(default_factory=list)


FRAMEWORK_LABELS: dict[str, str] = {
    "nist_ai_rmf": "NIST AI RMF 1.0",
    "iso_42001": "ISO/IEC 42001:2023",
    "owasp_llm": "OWASP LLM Top-10 (2025)",
    "owasp_agentic": "OWASP Agentic Top-10 (ASI)",
    "mitre_atlas": "MITRE ATLAS",
    "nist_ai_600_1": "NIST AI 600-1 GenAI Profile",
    "csa_aicm": "CSA AI Controls Matrix v1.0",
    "gdpr": "GDPR (EU 2016/679)",
    "soc2": "SOC 2 Type II",
    "iso_27002": "ISO/IEC 27002:2022",
    "nist_sp_800_53": "NIST SP 800-53 Rev. 5",
    "cen_cenelec_jtc21": "CEN-CENELEC JTC 21 Harmonised Standards",
}

# ─────────────────────────────────────────────────────────────────────────────
# Canonical Crosswalk: Dimension -> Framework Controls
# ─────────────────────────────────────────────────────────────────────────────

DIMENSION_CROSSWALK: dict[str, dict[str, list[str]]] = {
    "ai_literacy": {
        "nist_ai_rmf": ["GV-1.3", "GV-2.1"],
        "iso_42001": ["7.2", "7.3"],
        "owasp_llm": ["LLM09:2025"],
        "owasp_agentic": ["ASI09"],
        "iso_27002": ["5.2"],
        "soc2": ["CC1.1"],
        "gdpr": ["Art. 5(2)", "Art. 39(1)(b)"],
    },
    "risk_mgmt": {
        "nist_ai_rmf": ["GV-1.4", "GV-1.5", "MP-2.1", "MP-2.2", "MS-1.1", "MG-1.1", "MG-2.1"],
        "iso_42001": ["6.1", "8.2", "8.3", "A.5.2", "A.5.3"],
        "owasp_llm": ["LLM01:2025", "LLM05:2025"],
        "owasp_agentic": ["ASI01", "ASI02"],
        "mitre_atlas": ["AML.T0040", "AML.T0043"],
        "nist_ai_600_1": ["GV-1.4-001", "MP-2.1-001"],
        "csa_aicm": ["GRC-02", "GRC-10"],
        "soc2": ["CC3.1", "CC3.2"],
        "gdpr": ["Art. 35(1)", "Art. 35(7)"],
        "cen_cenelec_jtc21": ["prEN 18228 (draft)"],
    },
    "data_gov": {
        "nist_ai_rmf": ["MP-3.4", "MS-2.6", "MG-2.2"],
        "iso_42001": ["A.7.2", "A.7.3", "A.7.4", "A.7.5", "A.7.6"],
        "owasp_llm": ["LLM03:2025", "LLM04:2025", "LLM08:2025"],
        "owasp_agentic": ["ASI04", "ASI06"],
        "mitre_atlas": ["AML.T0018", "AML.T0115"],
        "csa_aicm": ["DSP-03", "DSP-20"],
        "iso_27002": ["8.10", "8.11"],
        "nist_sp_800_53": ["SI-10", "MP-2"],
        "soc2": ["PI1.1", "CC6.1"],
        "gdpr": ["Art. 5(1)(b)", "Art. 5(1)(c)", "Art. 5(1)(d)", "Art. 25(1)", "Art. 25(2)", "Art. 30(1)"],
        "cen_cenelec_jtc21": ["prEN 18283 (draft)", "prEN 18284 (draft)"],
    },
    "tech_docs": {
        "nist_ai_rmf": ["GV-4.1", "MP-1.1", "MP-4.1"],
        "iso_42001": ["7.5", "8.4", "A.7.2"],
        "owasp_llm": ["LLM09:2025"],
        "owasp_agentic": ["ASI09"],
        "csa_aicm": ["MDS-03"],
        "soc2": ["CC2.1"],
        "gdpr": ["Art. 30(1)", "Art. 24(1)"],
        # EN 18286:2026 (OJ L, 2026/2274, 14 Oct 2026) presumption covers
        # Art. 17(1) and the first sentence of Art. 11(1) only.
        "cen_cenelec_jtc21": ["EN 18286:2026"],
    },
    "logging": {
        "nist_ai_rmf": ["GV-1.5", "MS-3.1", "MS-3.2"],
        "iso_42001": ["9.1", "A.7.4"],
        "owasp_llm": ["LLM06:2025"],
        "owasp_agentic": ["ASI08"],
        "iso_27002": ["8.15", "8.16"],
        "nist_sp_800_53": ["AU-2", "AU-3", "AU-6"],
        "soc2": ["CC7.2", "CC7.3"],
        "gdpr": ["Art. 30(1)", "Art. 5(2)"],
        "cen_cenelec_jtc21": ["prEN 18229-1 (draft)"],
    },
    "transparency": {
        "nist_ai_rmf": ["GV-3.1", "GV-5.1", "MP-1.1", "MS-2.3"],
        "iso_42001": ["7.4", "A.8.2", "A.8.5"],
        "owasp_llm": ["LLM09:2025"],
        "owasp_agentic": ["ASI09"],
        "soc2": ["CC2.2", "CC2.3"],
        "gdpr": ["Art. 12(1)", "Art. 13(1)", "Art. 14(1)"],
        "cen_cenelec_jtc21": ["prEN 18229-1 (draft)"],
    },
    "content_transparency": {
        "nist_ai_rmf": ["MS-2.3", "GV-1.4"],
        "iso_42001": ["7.4", "7.5", "A.7.3"],
        "owasp_llm": ["LLM07:2025", "LLM09:2025"],
        "owasp_agentic": ["ASI09"],
        "nist_ai_600_1": ["MS-2.11-001"],
        "csa_aicm": ["DSP-20"],
        "soc2": ["CC2.2"],
        "gdpr": ["Art. 13(1)", "Art. 14(1)"],
    },
    "human_oversight": {
        "nist_ai_rmf": ["GV-2.1", "MS-2.1", "MG-2.1", "MG-3.1"],
        "iso_42001": ["5.3", "A.5.4"],
        "owasp_llm": ["LLM06:2025"],
        "owasp_agentic": ["ASI02", "ASI05"],
        "csa_aicm": ["GRC-15"],
        "soc2": ["CC5.2"],
        "gdpr": ["Art. 22(1)", "Art. 22(3)"],
        "cen_cenelec_jtc21": ["prEN 18229-1 (draft)"],
    },
    "security": {
        "nist_ai_rmf": ["MS-2.5", "MG-2.1", "MG-3.2"],
        "iso_42001": ["A.6.2.4", "A.6.2.6"],
        "owasp_llm": ["LLM01:2025", "LLM02:2025", "LLM05:2025", "LLM07:2025"],
        "owasp_agentic": ["ASI01", "ASI03", "ASI05", "ASI07"],
        "mitre_atlas": ["AML.T0015", "AML.T0040", "AML.T0051"],
        "nist_ai_600_1": ["MS-2.5-001", "MS-2.7-001"],
        "csa_aicm": ["AIS-02", "AIS-08", "AIS-09"],
        "iso_27002": ["8.1", "8.7", "8.8"],
        "nist_sp_800_53": ["SI-3", "SI-4", "SC-7"],
        "soc2": ["CC6.1", "CC6.6", "CC7.1"],
        "gdpr": ["Art. 32(1)"],
        "cen_cenelec_jtc21": ["prEN 18229-2 (draft)", "prEN 18282 (draft)"],
    },
    "quality_management": {
        "nist_ai_rmf": ["GV-1.1", "GV-1.2", "MS-4.1"],
        "iso_42001": ["4.4", "5.1", "9.2", "9.3", "10.1", "10.2"],
        "soc2": ["CC5.1", "CC5.3"],
        "gdpr": ["Art. 24(1)", "Art. 25(1)"],
        # First AI Act harmonised standard cited in the OJ (Commission
        # Implementing Decision (EU) 2026/2274, 14 Oct 2026) — Art. 17(1)
        # plus first sentence of Art. 11(1) only.
        "cen_cenelec_jtc21": ["EN 18286:2026"],
    },
    "conformity_assessment": {
        "nist_ai_rmf": ["GV-1.1", "MS-2.1"],
        "iso_42001": ["9.2", "9.3"],
        "soc2": ["CC2.1"],
    },
    "deployer_obligations": {
        "nist_ai_rmf": ["GV-1.1", "MP-4.1", "MS-3.1"],
        "iso_42001": ["A.9.2", "A.10.2"],
        "owasp_agentic": ["ASI02", "ASI05"],
        "csa_aicm": ["GRC-10"],
        "gdpr": ["Art. 24(1)", "Art. 28(1)", "Art. 35(1)"],
    },
    "gpai": {
        "nist_ai_rmf": ["GV-6.1", "MP-1.1", "MS-2.3"],
        "iso_42001": ["A.8.2", "A.8.5"],
        "owasp_llm": ["LLM02:2025", "LLM03:2025"],
        "csa_aicm": ["MDS-03"],
    },
    "gpai_systemic_risk": {
        "nist_ai_rmf": ["GV-1.4", "MS-1.1", "MS-2.5", "MG-1.1"],
        "iso_42001": ["6.1", "A.5.3"],
        "mitre_atlas": ["AML.T0000"],
        "nist_ai_600_1": ["GV-1.4-001", "MS-2.7-001"],
    },
    # ── Agent-era + platform dimensions (catalogue v2) ─────────────────
    # Every KB dimension maps somewhere: an unmapped scored dimension is
    # invisible to the projection, which read as false assurance (avg 100%
    # while headline dims scored 0). Control IDs validated against NIST AI
    # RMF 1.0 Core, OWASP LLM 2025 (LLM01-LLM10), OWASP Agentic (ASI01-ASI10),
    # MITRE ATLAS (AML.T####) and GDPR article numbers.
    "agent_inventory": {
        "nist_ai_rmf": ["MP-2.1", "MP-4.1", "GV-6.1"],
        "iso_42001": ["8.4", "A.7.2"],
        "owasp_agentic": ["ASI02"],
        "csa_aicm": ["IAM-03", "MDS-03"],
        "soc2": ["CC2.1"],
        "gdpr": ["Art. 30(1)"],
    },
    "tool_governance": {
        "nist_ai_rmf": ["MS-2.5", "MG-2.1"],
        "iso_42001": ["A.9.2", "A.9.4"],
        "owasp_llm": ["LLM01:2025", "LLM06:2025"],
        "owasp_agentic": ["ASI02", "ASI03", "ASI05"],
        "mitre_atlas": ["AML.T0051"],
        "soc2": ["CC6.1"],
        "gdpr": ["Art. 32(1)"],
    },
    "regulatory_perimeter": {
        "nist_ai_rmf": ["GV-1.1", "GV-6.1"],
        "iso_42001": ["4.1", "5.1"],
        "soc2": ["CC2.1"],
        "gdpr": ["Art. 24(1)"],
    },
    "access_control": {
        "nist_ai_rmf": ["MS-2.5", "MG-2.1"],
        "iso_42001": ["A.9.2"],
        "iso_27002": ["5.15", "5.17", "8.5"],
        "nist_sp_800_53": ["AC-2", "AC-3"],
        "owasp_agentic": ["ASI03"],
        "soc2": ["CC6.1", "CC6.6"],
        "gdpr": ["Art. 32(1)"],
    },
    "runtime_drift": {
        "nist_ai_rmf": ["MS-3.1", "MS-3.2", "MG-1.1"],
        "iso_42001": ["9.1", "A.7.4"],
        "soc2": ["CC7.2"],
        "gdpr": ["Art. 30(1)"],
    },
    "decision_governance": {
        "nist_ai_rmf": ["GV-2.1", "MS-2.1", "MG-2.1"],
        "iso_42001": ["5.3", "A.5.4"],
        "owasp_agentic": ["ASI02"],
        "soc2": ["CC5.2"],
        "gdpr": ["Art. 22(1)"],
    },
    "supply_chain": {
        "nist_ai_rmf": ["GV-6.1", "GV-6.2", "MG-3.1"],
        "iso_42001": ["A.10.3"],
        "iso_27002": ["5.19", "5.21"],
        "owasp_llm": ["LLM03:2025"],
        "owasp_agentic": ["ASI04"],
        "soc2": ["CC3.1"],
    },
    "infra_mlops": {
        "nist_ai_rmf": ["MS-2.5", "MG-3.2"],
        "iso_42001": ["A.4.4", "A.4.5"],
        "iso_27002": ["8.1", "8.9"],
        "nist_sp_800_53": ["SI-4", "AU-2"],
        "soc2": ["CC7.1", "CC7.2"],
    },
    "voluntary_codes": {
        "nist_ai_rmf": ["GV-5.1"],
        "iso_42001": ["7.4"],
        "owasp_llm": ["LLM09:2025"],
        "gdpr": ["Art. 40(1)"],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Article Crosswalk: EU AI Act Article -> Global Frameworks
# ─────────────────────────────────────────────────────────────────────────────

ARTICLE_FRAMEWORK_CROSSWALK: dict[str, dict[str, list[str]]] = {
    "Art. 5": {
        "nist_ai_rmf": ["GV-1.1", "MS-2.1"],
        "iso_42001": ["5.1", "A.5.2"],
        "owasp_llm": ["LLM01:2025"],
        "owasp_agentic": ["ASI01"],
        "gdpr": ["Art. 22"],
    },
    "Art. 6": {
        "nist_ai_rmf": ["MP-2.1", "MP-2.2", "MP-2.3"],
        "iso_42001": ["6.1", "8.2"],
        "gdpr": ["Art. 35"],
    },
    "Art. 4": {
        "nist_ai_rmf": ["GV-1.3", "GV-2.1", "GV-1.4"],
        "iso_42001": ["7.2", "7.3"],
        "owasp_llm": ["LLM09:2025"],
        "owasp_agentic": ["ASI09"],
        "gdpr": ["Art. 39(1)(b)"],
        "soc2": ["CC1.4", "CC1.5"],
        "nist_sp_800_53": ["AT-2", "AT-3"],
    },
    "Art. 9": {
        "nist_ai_rmf": ["GV-1.4", "MP-2.1", "MP-2.2", "MS-1.1", "MG-1.1", "MG-2.1", "GV-1.5", "MP-1.1", "MP-5.1", "MS-2.3", "MG-1.2", "MG-2.4"],
        "iso_42001": ["6.1", "8.2", "8.3", "A.5.2", "A.5.3", "6.1.2", "7.4", "8.4", "9.1"],
        "mitre_atlas": ["AML.T0040", "AML.T0043", "AML.T0048"],
        "csa_aicm": ["GRC-02", "GRC-10"],
        "gdpr": ["Art. 35", "Art. 25"],
        "cen_cenelec_jtc21": ["prEN 18228 (draft)"],
        "soc2": ["CC3.1", "CC3.2", "CC3.3", "CC3.4", "CC9.1"],
        "nist_sp_800_53": ["CM-3", "CM-4", "PM-30", "RA-3", "RA-5", "SA-8"],
        "nist_ai_600_1": ["GV-1.3-001", "GV-1.4-001"],
        "owasp_llm": ["LLM04:2025"],
        "owasp_agentic": ["ASI08", "ASI10"],
    },
    "Art. 10": {
        "nist_ai_rmf": ["MP-3.4", "MS-2.6", "MG-2.2", "GV-1.5", "MP-2.3", "MS-2.10", "MS-2.11", "MG-2.1", "MG-2.3"],
        "iso_42001": ["A.7.2", "A.7.3", "A.7.4", "A.7.5", "A.7.6", "7.5", "8.4"],
        "owasp_llm": ["LLM03:2025", "LLM08:2025", "LLM04:2025"],
        "mitre_atlas": ["AML.T0018", "AML.T0115", "AML.T0020", "AML.T0036", "AML.T0057", "AML.T0070"],
        "gdpr": ["Art. 5(1)(d)", "Art. 25", "Art. 5", "Art. 6", "Art. 9"],
        "cen_cenelec_jtc21": ["prEN 18283 (draft)", "prEN 18284 (draft)"],
        "iso_27002": ["5.12", "5.34"],
        "soc2": ["CC2.1", "CC6.1", "PI1.4"],
        "nist_sp_800_53": ["SI-10", "SI-18"],
        "owasp_agentic": ["ASI06"],
    },
    "Art. 11": {
        "nist_ai_rmf": ["GV-4.1", "MP-1.1", "MP-4.1", "GV-1.4", "MP-2.2", "MS-1.3", "MG-1.1", "MG-2.4"],
        "iso_42001": ["7.5", "8.4", "A.7.2", "9.1"],
        "csa_aicm": ["MDS-03"],
        "gdpr": ["Art. 30"],
        # EN 18286:2026 OJ citation (14 Oct 2026) covers first sentence of Art. 11(1) only.
        "cen_cenelec_jtc21": ["EN 18286:2026"],
        "iso_27002": ["5.33", "5.36"],
        "soc2": ["A1.1", "CC2.1", "CC2.2", "CC8.1"],
        "nist_sp_800_53": ["AU-2", "SA-5", "SA-11", "SA-15"],
        "nist_ai_600_1": ["MP-2.3-001"],
        "owasp_llm": ["LLM03:2025"],
        "owasp_agentic": ["ASI04"],
    },
    "Art. 12": {
        "nist_ai_rmf": ["GV-1.5", "MS-3.1", "MS-3.2", "MS-2.6", "MG-4.1"],
        "iso_42001": ["9.1", "A.7.4", "7.5"],
        "owasp_agentic": ["ASI08"],
        "gdpr": ["Art. 30", "Art. 5(2)"],
        "cen_cenelec_jtc21": ["prEN 18229-1 (draft)", "prEN ISO/IEC 24970 (draft)"],
        "iso_27002": ["5.33", "8.15", "8.16"],
        "soc2": ["CC7.2", "CC7.3"],
        "nist_sp_800_53": ["AU-2", "AU-6", "AU-12"],
    },
    "Art. 13": {
        "nist_ai_rmf": ["GV-3.1", "MP-1.1", "MS-2.3", "GV-1.4", "MS-2.9", "MG-1.1", "MG-1.2", "MG-2.4"],
        "iso_42001": ["7.4", "A.8.2", "A.8.5", "6.1.4", "7.5", "9.1"],
        "gdpr": ["Art. 13", "Art. 14", "Art. 22"],
        "cen_cenelec_jtc21": ["prEN 18229-1 (draft)"],
        "soc2": ["CC2.2", "CC2.3"],
        "nist_sp_800_53": ["SA-5"],
        "nist_ai_600_1": ["MP-2.3-001"],
        "owasp_llm": ["LLM09:2025"],
    },
    "Art. 14": {
        "nist_ai_rmf": ["GV-2.1", "MS-2.1", "MG-2.1", "GV-1.5", "MS-2.7", "MS-2.9", "MG-2.4"],
        "iso_42001": ["5.3", "A.5.4", "6.1.4", "7.4", "9.1"],
        "owasp_agentic": ["ASI02", "ASI05", "ASI01", "ASI03", "ASI09"],
        "gdpr": ["Art. 22"],
        "cen_cenelec_jtc21": ["prEN 18229-1 (draft)"],
        "soc2": ["CC1.4", "CC1.5", "CC5.1"],
        "nist_sp_800_53": ["AC-3", "AC-4", "AC-6"],
        "nist_ai_600_1": ["MG-2.4-001"],
        "owasp_llm": ["LLM06:2025", "LLM09:2025"],
    },
    "Art. 15": {
        "nist_ai_rmf": ["MS-2.5", "MG-2.1", "MG-3.2", "GV-1.5", "MS-2.3", "MS-2.9", "MS-2.11", "MG-2.3", "MG-2.4", "MG-3.1"],
        "iso_42001": ["A.6.2.4", "A.6.2.6", "7.5", "8.4", "9.1"],
        "owasp_llm": ["LLM01:2025", "LLM02:2025", "LLM05:2025", "LLM03:2025", "LLM04:2025", "LLM07:2025", "LLM08:2025", "LLM10:2025"],
        "owasp_agentic": ["ASI01", "ASI03", "ASI07", "ASI02", "ASI04", "ASI05", "ASI06"],
        "mitre_atlas": ["AML.T0015", "AML.T0051", "AML.T0010", "AML.T0029", "AML.T0031", "AML.T0043", "AML.T0053", "AML.T0054", "AML.T0055"],
        "nist_ai_600_1": ["MS-2.5-001", "MS-2.7-001", "MS-2.6-001"],
        "gdpr": ["Art. 32"],
        "cen_cenelec_jtc21": ["prEN 18229-2 (draft)", "prEN 18282 (draft)"],
        "iso_27002": ["5.7", "5.15", "5.30", "8.7", "8.8", "8.16"],
        "soc2": ["A1.2", "CC6.1", "CC6.6", "CC7.2"],
        "nist_sp_800_53": ["AC-3", "AC-6", "RA-5", "SC-7", "SI-4", "SI-7", "SI-10", "SI-15", "SI-16"],
    },
    "Art. 17": {
        "nist_ai_rmf": ["GV-1.1", "GV-1.2", "MS-4.1", "GV-1.4", "MG-1.2"],
        "iso_42001": ["4.4", "5.1", "9.2", "9.3", "10.1", "10.2"],
        "gdpr": ["Art. 24", "Art. 25"],
        # EN 18286:2026 OJ-cited 14 Oct 2026 (OJ L 2026/2274) for Art. 17(1).
        "cen_cenelec_jtc21": ["EN 18286:2026"],
        "iso_27002": ["5.1", "5.37", "8.25"],
        "soc2": ["CC1.1", "CC1.2", "CC2.2", "CC8.1"],
        "nist_sp_800_53": ["SA-11", "SA-15"],
    },
    "Art. 26": {
        "nist_ai_rmf": ["GV-1.1", "MP-4.1", "MS-3.1"],
        "iso_42001": ["A.9.2", "A.10.2"],
        "owasp_agentic": ["ASI02"],
        "gdpr": ["Art. 24", "Art. 28"],
    },
    "Art. 27": {
        "nist_ai_rmf": ["MP-5.1", "MS-1.1"],
        "iso_42001": ["8.3", "A.5.3"],
        "gdpr": ["Art. 35"],
    },
    "Art. 43": {
        "nist_ai_rmf": ["GV-1.1", "MS-4.1"],
        "iso_42001": ["9.2", "9.3"],
        "soc2": ["CC2.1"],
    },
    "Art. 49": {
        "nist_ai_rmf": ["GV-4.1", "MP-1.1"],
        "iso_42001": ["7.5", "A.7.2"],
        "gdpr": ["Art. 30"],
    },
    "Art. 53": {
        "nist_ai_rmf": ["GV-6.1", "MP-1.1"],
        "iso_42001": ["A.8.2", "A.8.5"],
        "csa_aicm": ["MDS-03"],
    },
    "Art. 55": {
        "nist_ai_rmf": ["MS-1.1", "MS-2.5", "MG-1.1"],
        "iso_42001": ["6.1", "A.5.3"],
        "nist_ai_600_1": ["GV-1.4-001", "MS-2.7-001"],
    },
    "Art. 72": {
        "nist_ai_rmf": ["MS-3.1", "MS-3.2", "MG-1.1", "MG-4.1", "MS-2.6", "MS-4.1", "MG-4.2"],
        "iso_42001": ["9.1", "10.2", "10.1"],
        "soc2": ["CC7.2", "CC7.3", "CC7.4"],
        "iso_27002": ["5.7", "8.16"],
        "mitre_atlas": ["AML.T0031"],
        "nist_sp_800_53": ["CA-7", "SI-4"],
    },
    "Art. 50": {
        "nist_ai_rmf": ["MS-2.3", "GV-1.4"],
        "iso_42001": ["7.4", "7.5", "A.7.3"],
        "owasp_llm": ["LLM09:2025"],
        "owasp_agentic": ["ASI09"],
        "nist_ai_600_1": ["MS-2.11-001", "MS-2.6-001"],
        "csa_aicm": ["DSP-20"],
        "gdpr": ["Art. 13", "Art. 14"],
        "soc2": ["CC2.2", "CC2.3"],
    },
    # Articles present in the KB that previously had no framework projection:
    # a gap there rendered an empty crosswalk ("no controls" read as "nothing
    # to do").
    "Art. 25": {
        "nist_ai_rmf": ["GV-6.1", "GV-6.2", "MP-1.1", "MG-3.1"],
        "iso_42001": ["A.10.2", "A.10.3", "7.4", "8.4"],
        "owasp_agentic": ["ASI03", "ASI04"],
        "csa_aicm": ["STA-12"],
        "soc2": ["CC3.1"],
        "gdpr": ["Art. 24", "Art. 28"],
        "iso_27002": ["5.19", "5.20", "5.21", "5.22", "5.23"],
        "mitre_atlas": ["AML.T0010", "AML.T0053"],
        "nist_sp_800_53": ["PM-30", "SR-3", "SR-5", "SR-6"],
        "nist_ai_600_1": ["MG-3.2-001"],
        "owasp_llm": ["LLM03:2025"],
    },
    "Art. 47": {
        "nist_ai_rmf": ["GV-4.1", "MP-4.1"],
        "iso_42001": ["7.5", "A.7.2"],
        "csa_aicm": ["MDS-03"],
        "soc2": ["CC2.1"],
        "gdpr": ["Art. 30"],
    },
    "Art. 48": {
        "nist_ai_rmf": ["GV-4.1", "MS-2.3"],
        "iso_42001": ["7.5"],
        "csa_aicm": ["MDS-03"],
        "soc2": ["CC2.1"],
    },
    "Art. 51": {
        "nist_ai_rmf": ["GV-1.4", "MS-1.1", "MS-2.5"],
        "iso_42001": ["6.1", "A.5.3"],
        "nist_ai_600_1": ["GV-1.4-001", "MS-2.7-001"],
    },
    "Art. 95": {
        "nist_ai_rmf": ["GV-5.1", "GV-5.2"],
        "iso_42001": ["7.4", "A.5.2"],
        "owasp_llm": ["LLM09:2025"],
        "gdpr": ["Art. 40"],
    },
}


def get_crosswalk_for_dimension(dimension_id: str) -> dict[str, list[str]]:
    """Return mapped framework controls for a KB dimension."""
    return DIMENSION_CROSSWALK.get(dimension_id, {})


def get_crosswalk_for_article(article_ref: str) -> dict[str, list[str]]:
    """Return mapped framework controls for an EU AI Act article.

    Accepts every article spelling in the codebase: KB keys (``"art15"``),
    internal refs (``"Art. 15"``, ``"Art. 15(4)"``) and user-facing refs
    (``"Article 15.4"``). Unparseable or unknown articles return ``{}``.
    """
    from scanner.refs import to_internal

    key = to_internal(article_ref) if article_ref else ""
    if not key:
        key = (article_ref or "").strip()
    # Article-level entry first, then the paragraph's parent article.
    direct = ARTICLE_FRAMEWORK_CROSSWALK.get(key)
    if direct:
        return direct
    article_only = key.split("(", 1)[0].strip()
    return ARTICLE_FRAMEWORK_CROSSWALK.get(article_only, {})
