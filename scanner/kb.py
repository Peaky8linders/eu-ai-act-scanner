"""EU AI Act compliance dimensions — static reference data.

Vendored subset derived from EU Regulation 2024/1689. Each dimension maps an
analyzer finding to the article(s) it supports. This file is intentionally
minimal — questions, risk-level routing, and full assessment logic belong in
downstream compliance engines (e.g. CodexAI), not in a static analysis tool.

If you believe a dimension is mis-described, please open an issue with a
reference to the specific article paragraph.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Dimension:
    id: str
    label: str
    article: str
    description: str


DIMENSIONS: dict[str, Dimension] = {
    "ai_literacy": Dimension(
        id="ai_literacy",
        label="AI Literacy",
        article="Art. 4",
        description="Staff and users have sufficient AI literacy. In force since Feb 2025.",
    ),
    "risk_mgmt": Dimension(
        id="risk_mgmt",
        label="Risk Management",
        article="Art. 9",
        description="Continuous risk management throughout AI lifecycle.",
    ),
    "data_gov": Dimension(
        id="data_gov",
        label="Data Governance",
        article="Art. 10",
        description="Data governance, bias assessment, quality controls.",
    ),
    "tech_docs": Dimension(
        id="tech_docs",
        label="Technical Documentation",
        article="Art. 11",
        description="Annex IV compliant documentation.",
    ),
    "logging": Dimension(
        id="logging",
        label="Record-Keeping",
        article="Art. 12",
        description="Automatic tamper-resistant event logging.",
    ),
    "transparency": Dimension(
        id="transparency",
        label="Transparency",
        article="Art. 13 & 50",
        description="AI interaction disclosure and content labeling.",
    ),
    "human_oversight": Dimension(
        id="human_oversight",
        label="Human Oversight",
        article="Art. 14",
        description="Human override, stop, and oversight mechanisms.",
    ),
    "security": Dimension(
        id="security",
        label="Accuracy & Security",
        article="Art. 15",
        description="Accuracy, robustness, cybersecurity.",
    ),
    "conformity_assessment": Dimension(
        id="conformity_assessment",
        label="Conformity Assessment",
        article="Art. 43, 47, 48",
        description="Conformity assessment procedures, EU declaration, CE marking.",
    ),
    "quality_management": Dimension(
        id="quality_management",
        label="Quality Management System",
        article="Art. 17",
        description="QMS covering compliance strategy, procedures, testing, and accountability.",
    ),
    "deployer_obligations": Dimension(
        id="deployer_obligations",
        label="Deployer Obligations",
        article="Art. 26 & 27",
        description="High-risk AI deployer responsibilities and FRIA.",
    ),
    "content_transparency": Dimension(
        id="content_transparency",
        label="Content Transparency",
        article="Art. 50(2-4)",
        description="AI-generated content marking, deep fake disclosure, machine-readable labeling.",
    ),
    "gpai": Dimension(
        id="gpai",
        label="GPAI Model Obligations",
        article="Art. 53",
        description="General-purpose AI model provider obligations. In force since Aug 2025.",
    ),
    "gpai_systemic_risk": Dimension(
        id="gpai_systemic_risk",
        label="GPAI Systemic Risk",
        article="Art. 51, 55",
        description="Additional obligations for GPAI models with systemic risk (>10^25 FLOP).",
    ),
    "decision_governance": Dimension(
        id="decision_governance",
        label="Decision Governance",
        article="Art. 9, 14, 15, 72",
        description="Runtime AI decision interception, behavioral rules, and audit trail.",
    ),
    "access_control": Dimension(
        id="access_control",
        label="Access Control & Identity",
        article="Art. 15 / ISO 27002",
        description="IAM, RBAC, service accounts, and MFA for AI systems.",
    ),
    "infra_mlops": Dimension(
        id="infra_mlops",
        label="Infrastructure & MLOps Security",
        article="Art. 15 / NIST SP 800-53",
        description="Network segmentation, config hardening, and CI/CD pipeline security.",
    ),
    "supply_chain": Dimension(
        id="supply_chain",
        label="Supply Chain & Third-Party Risk",
        article="Art. 15 / NIST SP 800-161",
        description="Third-party models, open-source security, and data provider risk.",
    ),
    "voluntary_codes": Dimension(
        id="voluntary_codes",
        label="Voluntary Codes of Conduct",
        article="Art. 95",
        description="Voluntary commitments for minimal-risk AI systems.",
    ),
}


# Fast lookup by EU AI Act article number → dimension IDs.
# Enables `/ai-act-article 15` to show which analyzers feed Art. 15 findings.
ARTICLE_TO_DIMENSIONS: dict[str, list[str]] = {
    "art4": ["ai_literacy"],
    "art9": ["risk_mgmt", "decision_governance"],
    "art10": ["data_gov"],
    "art11": ["tech_docs"],
    "art12": ["logging"],
    "art13": ["transparency"],
    "art14": ["human_oversight", "decision_governance"],
    "art15": ["security", "access_control", "infra_mlops", "supply_chain", "decision_governance"],
    "art17": ["quality_management"],
    "art26": ["deployer_obligations"],
    "art27": ["deployer_obligations"],
    "art43": ["conformity_assessment"],
    "art47": ["conformity_assessment"],
    "art48": ["conformity_assessment"],
    "art50": ["transparency", "content_transparency"],
    "art51": ["gpai_systemic_risk"],
    "art53": ["gpai"],
    "art55": ["gpai_systemic_risk"],
    "art72": ["decision_governance"],
    "art95": ["voluntary_codes"],
}


def get_dimension(dim_id: str) -> Dimension | None:
    """Return the Dimension for a given id, or None if unknown."""
    return DIMENSIONS.get(dim_id)


def dimensions_for_article(article: str) -> list[Dimension]:
    """Return all dimensions mapped to a given article (e.g. 'art15').

    Accepts canonical lowercase 'artNN' form. Unknown articles return [].
    """
    dim_ids = ARTICLE_TO_DIMENSIONS.get(article.lower(), [])
    return [DIMENSIONS[d] for d in dim_ids if d in DIMENSIONS]
