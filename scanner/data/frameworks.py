"""Cross-framework catalog and canonical crosswalk for EU AI Act compliance.

Maps EU AI Act compliance dimensions and articles to global AI governance,
security, and risk standards:
- NIST AI Risk Management Framework (NIST AI RMF 1.0 / AI 100-1)
- ISO/IEC 42001:2023 (Artificial Intelligence Management System)
- OWASP Top 10 for LLM Applications (2025 edition)
- OWASP Top 10 for Agentic Applications (ASI01-ASI10)
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
- NIST AI 600-1 (Generative AI Profile)
- CSA AI Controls Matrix (AICM v1.0)
- GDPR (General Data Protection Regulation EU 2016/679)
- SOC 2 Trust Services Criteria
- ISO/IEC 27002:2022 (Information Security Controls)
- NIST SP 800-53 Rev. 5

Provides the "Satisfy Once, Comply Everywhere" foundation so teams can prove
compliance across multiple international regulatory frameworks from a single scan.
"""

from __future__ import annotations

from typing import Final

from pydantic import BaseModel, Field

CROSSWALK_CATALOGUE_VERSION: Final[str] = "2026.10.v1"


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
    "owasp_llm_top10": "OWASP LLM Top-10 (2025)",
    "owasp_agentic_top10": "OWASP Agentic Top-10 (ASI)",
    "mitre_atlas": "MITRE ATLAS",
    "nist_ai_600_1": "NIST AI 600-1 GenAI Profile",
    "csa_aicm": "CSA AI Controls Matrix v1.0",
    "gdpr": "GDPR (EU 2016/679)",
    "soc2": "SOC 2 Type II",
    "iso_27002": "ISO/IEC 27002:2022",
    "nist_sp_800_53": "NIST SP 800-53 Rev. 5",
}

# ─────────────────────────────────────────────────────────────────────────────
# Canonical Crosswalk: Dimension -> Framework Controls
# ─────────────────────────────────────────────────────────────────────────────

DIMENSION_CROSSWALK: dict[str, dict[str, list[str]]] = {
    "ai_literacy": {
        "nist_ai_rmf": ["GV-1.3", "GV-2.1"],
        "iso_42001": ["7.2", "7.3"],
        "owasp_llm_top10": ["LLM09:2025"],
        "owasp_agentic_top10": ["ASI09"],
        "iso_27002": ["5.2"],
        "soc2": ["CC1.1"],
        "gdpr": ["5.2", "39.1.b"],
    },
    "risk_mgmt": {
        "nist_ai_rmf": ["GV-1.4", "GV-1.5", "MP-2.1", "MP-2.2", "MS-1.1", "MG-1.1", "MG-2.1"],
        "iso_42001": ["6.1", "8.2", "8.3", "A.5.2", "A.5.3"],
        "owasp_llm_top10": ["LLM01:2025", "LLM05:2025"],
        "owasp_agentic_top10": ["ASI01", "ASI02"],
        "mitre_atlas": ["AML.T0040", "AML.T0043"],
        "nist_ai_600_1": ["GV-1.4-001", "MP-2.1-001"],
        "csa_aicm": ["AIM-01", "AIM-02"],
        "soc2": ["CC3.1", "CC3.2"],
        "gdpr": ["35.1", "35.7"],
    },
    "data_gov": {
        "nist_ai_rmf": ["MP-3.4", "MS-2.6", "MG-2.2"],
        "iso_42001": ["8.5", "A.6.1", "A.6.2", "A.6.3"],
        "owasp_llm_top10": ["LLM03:2025", "LLM04:2025", "LLM08:2025"],
        "owasp_agentic_top10": ["ASI04", "ASI06"],
        "mitre_atlas": ["AML.T0018", "AML.T0019"],
        "csa_aicm": ["AIM-05", "DGV-01"],
        "iso_27002": ["8.10", "8.11"],
        "nist_sp_800_53": ["SI-10", "MP-2"],
        "soc2": ["PI1.1", "CC6.1"],
        "gdpr": ["5.1.b", "5.1.c", "5.1.d", "25.1", "25.2", "30.1"],
    },
    "tech_docs": {
        "nist_ai_rmf": ["GV-4.1", "MP-1.1", "MP-4.1"],
        "iso_42001": ["7.5", "8.4", "A.7.2"],
        "owasp_llm_top10": ["LLM09:2025"],
        "owasp_agentic_top10": ["ASI09"],
        "csa_aicm": ["AIM-07"],
        "soc2": ["CC2.1"],
        "gdpr": ["30.1", "24.1"],
    },
    "logging": {
        "nist_ai_rmf": ["GV-1.5", "MS-3.1", "MS-3.2"],
        "iso_42001": ["9.1", "A.7.4"],
        "owasp_llm_top10": ["LLM06:2025"],
        "owasp_agentic_top10": ["ASI08"],
        "mitre_atlas": ["AML.M0006"],
        "iso_27002": ["8.15", "8.16"],
        "nist_sp_800_53": ["AU-2", "AU-3", "AU-6"],
        "soc2": ["CC7.2", "CC7.3"],
        "gdpr": ["30.1", "5.2"],
    },
    "transparency": {
        "nist_ai_rmf": ["GV-3.1", "GV-5.1", "MP-1.1", "MS-2.3"],
        "iso_42001": ["7.4", "8.4", "A.7.1", "A.7.3"],
        "owasp_llm_top10": ["LLM09:2025"],
        "owasp_agentic_top10": ["ASI09"],
        "soc2": ["CC2.2", "CC2.3"],
        "gdpr": ["12.1", "13.1", "14.1"],
    },
    "content_transparency": {
        "nist_ai_rmf": ["MEASURE-2.3", "GOVERN-1.4"],
        "iso_42001": ["7.4", "7.5", "A.7.3"],
        "owasp_llm_top10": ["LLM07:2025", "LLM09:2025"],
        "owasp_agentic_top10": ["ASI09"],
        "mitre_atlas": ["AML.M0020"],
        "nist_ai_600_1": ["MS-2.6-001", "GAI-8"],
        "csa_aicm": ["TAA-01"],
        "soc2": ["CC2.2"],
        "gdpr": ["13.1", "14.1"],
    },
    "human_oversight": {
        "nist_ai_rmf": ["GV-2.1", "MS-2.1", "MG-2.1", "MG-3.1"],
        "iso_42001": ["5.3", "A.5.4"],
        "owasp_llm_top10": ["LLM06:2025"],
        "owasp_agentic_top10": ["ASI02", "ASI05"],
        "mitre_atlas": ["AML.M0012"],
        "csa_aicm": ["AIM-03"],
        "soc2": ["CC5.2"],
        "gdpr": ["22.1", "22.3"],
    },
    "security": {
        "nist_ai_rmf": ["MS-2.5", "MG-2.1", "MG-3.2"],
        "iso_42001": ["A.9.1", "A.9.2"],
        "owasp_llm_top10": ["LLM01:2025", "LLM02:2025", "LLM05:2025", "LLM07:2025"],
        "owasp_agentic_top10": ["ASI01", "ASI03", "ASI05", "ASI07"],
        "mitre_atlas": ["AML.T0015", "AML.T0040", "AML.T0051"],
        "nist_ai_600_1": ["MS-2.5-001", "GAI-1", "GAI-2"],
        "csa_aicm": ["AIS-01", "AIS-02", "AIS-03"],
        "iso_27002": ["8.1", "8.7", "8.8"],
        "nist_sp_800_53": ["SI-3", "SI-4", "SC-7"],
        "soc2": ["CC6.1", "CC6.6", "CC7.1"],
        "gdpr": ["32.1"],
    },
    "quality_management": {
        "nist_ai_rmf": ["GV-1.1", "GV-1.2", "MS-4.1"],
        "iso_42001": ["4.4", "5.1", "9.2", "9.3", "10.1", "10.2"],
        "soc2": ["CC5.1", "CC5.3"],
        "gdpr": ["24.1", "25.1"],
    },
    "conformity_assessment": {
        "nist_ai_rmf": ["GV-1.1", "MS-2.1"],
        "iso_42001": ["9.2", "9.3"],
        "soc2": ["CC2.1"],
    },
    "deployer_obligations": {
        "nist_ai_rmf": ["GV-1.1", "MP-4.1", "MS-3.1"],
        "iso_42001": ["A.10.1", "A.10.2"],
        "owasp_agentic_top10": ["ASI02", "ASI05"],
        "csa_aicm": ["AIM-04"],
        "gdpr": ["24.1", "28.1", "35.1"],
    },
    "gpai": {
        "nist_ai_rmf": ["GV-6.1", "MP-1.1", "MS-2.3"],
        "iso_42001": ["A.8.1", "A.8.2"],
        "owasp_llm_top10": ["LLM02:2025", "LLM03:2025"],
        "csa_aicm": ["AIM-06"],
    },
    "gpai_systemic_risk": {
        "nist_ai_rmf": ["GV-1.4", "MS-1.1", "MS-2.5", "MG-1.1"],
        "iso_42001": ["6.1", "A.5.3"],
        "mitre_atlas": ["AML.T0000"],
        "nist_ai_600_1": ["GAI-10", "GAI-11"],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Article Crosswalk: EU AI Act Article -> Global Frameworks
# ─────────────────────────────────────────────────────────────────────────────

ARTICLE_FRAMEWORK_CROSSWALK: dict[str, dict[str, list[str]]] = {
    "Art. 4": {
        "nist_ai_rmf": ["GV-1.3", "GV-2.1"],
        "iso_42001": ["7.2", "7.3"],
        "owasp_llm_2025": ["LLM09:2025"],
        "owasp_agentic": ["ASI09"],
        "gdpr": ["Art. 39(1)(b)"],
    },
    "Art. 9": {
        "nist_ai_rmf": ["GV-1.4", "MP-2.1", "MP-2.2", "MS-1.1", "MG-1.1", "MG-2.1"],
        "iso_42001": ["6.1", "8.2", "8.3", "A.5.2", "A.5.3"],
        "mitre_atlas": ["AML.T0040", "AML.T0043"],
        "csa_aicm": ["AIM-01", "AIM-02"],
        "gdpr": ["Art. 35"],
    },
    "Art. 10": {
        "nist_ai_rmf": ["MP-3.4", "MS-2.6", "MG-2.2"],
        "iso_42001": ["8.5", "A.6.1", "A.6.2", "A.6.3"],
        "owasp_llm_2025": ["LLM03:2025", "LLM08:2025"],
        "mitre_atlas": ["AML.T0018", "AML.T0019"],
        "gdpr": ["Art. 5(1)(d)", "Art. 25"],
    },
    "Art. 11": {
        "nist_ai_rmf": ["GV-4.1", "MP-1.1", "MP-4.1"],
        "iso_42001": ["7.5", "8.4", "A.7.2"],
        "csa_aicm": ["AIM-07"],
        "gdpr": ["Art. 30"],
    },
    "Art. 12": {
        "nist_ai_rmf": ["GV-1.5", "MS-3.1", "MS-3.2"],
        "iso_42001": ["9.1", "A.7.4"],
        "owasp_agentic": ["ASI08"],
        "mitre_atlas": ["AML.M0006"],
        "gdpr": ["Art. 30", "Art. 5(2)"],
    },
    "Art. 13": {
        "nist_ai_rmf": ["GV-3.1", "MP-1.1", "MS-2.3"],
        "iso_42001": ["7.4", "8.4", "A.7.1", "A.7.3"],
        "gdpr": ["Art. 13", "Art. 14"],
    },
    "Art. 14": {
        "nist_ai_rmf": ["GV-2.1", "MS-2.1", "MG-2.1"],
        "iso_42001": ["5.3", "A.5.4"],
        "owasp_agentic": ["ASI02", "ASI05"],
        "mitre_atlas": ["AML.M0012"],
        "gdpr": ["Art. 22"],
    },
    "Art. 15": {
        "nist_ai_rmf": ["MS-2.5", "MG-2.1", "MG-3.2"],
        "iso_42001": ["A.9.1", "A.9.2"],
        "owasp_llm_2025": ["LLM01:2025", "LLM02:2025", "LLM05:2025"],
        "owasp_agentic": ["ASI01", "ASI03", "ASI07"],
        "mitre_atlas": ["AML.T0015", "AML.T0051"],
        "nist_ai_600_1": ["MS-2.5-001", "GAI-1"],
        "gdpr": ["Art. 32"],
    },
    "Art. 17": {
        "nist_ai_rmf": ["GV-1.1", "GV-1.2", "MS-4.1"],
        "iso_42001": ["4.4", "5.1", "9.2", "9.3", "10.1", "10.2"],
        "gdpr": ["Art. 24", "Art. 25"],
    },
    "Art. 26": {
        "nist_ai_rmf": ["GV-1.1", "MP-4.1", "MS-3.1"],
        "iso_42001": ["A.10.1", "A.10.2"],
        "owasp_agentic": ["ASI02"],
        "gdpr": ["Art. 24", "Art. 28"],
    },
    "Art. 27": {
        "nist_ai_rmf": ["MP-5.1", "MS-1.1"],
        "iso_42001": ["8.3", "A.5.3"],
        "gdpr": ["Art. 35"],
    },
    "Art. 50": {
        "nist_ai_rmf": ["MEASURE-2.3", "GOVERN-1.4"],
        "iso_42001": ["7.4", "7.5", "A.7.3"],
        "owasp_llm_2025": ["LLM09:2025"],
        "owasp_agentic": ["ASI09"],
        "mitre_atlas": ["AML.M0020"],
        "nist_ai_600_1": ["MS-2.6-001", "GAI-8"],
        "csa_aicm": ["TAA-01"],
        "gdpr": ["Art. 13", "Art. 14"],
    },
}


def get_crosswalk_for_dimension(dimension_id: str) -> dict[str, list[str]]:
    """Return mapped framework controls for a KB dimension."""
    return DIMENSION_CROSSWALK.get(dimension_id, {})


def get_crosswalk_for_article(article_ref: str) -> dict[str, list[str]]:
    """Return mapped framework controls for an EU AI Act article (e.g. 'Art. 15')."""
    return ARTICLE_FRAMEWORK_CROSSWALK.get(article_ref, {})
