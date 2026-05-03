"""Operator-role obligation registry — EU AI Act + Art. 2(1)(c) extraterritorial.

This module is the canonical mapping from operator role to the EU AI Act
articles each role owes. It captures the 6-role NLF decision tree
(provider, deployer, importer, distributor, product_manufacturer,
authorized_representative) plus three additional roles surfaced by
*AI Agents Under EU Law* (Working Paper, 7 April 2026):

* ``gpai_provider`` — Chapter V Art. 53 obligations (line 437-438).
* ``gpai_systemic_provider`` — Art. 51(2) systemic-risk additional
  obligations (line 439-443; autonomy + tool-use decisive per AI Office).
* ``extraterritorial_non_eu`` — non-EU entity placing a product on the EU
  market triggering MSR Art. 4 / AI Act Art. 74 designated-responsible-person
  obligations (lines 1066-1075). Covers the US-based-entity case the paper
  flags as *most AI agent providers based in the United States have not yet
  addressed* (line 1071-1072), and any non-EU entity processing personal data
  of EU individuals in the offering of goods/services per GDPR Art. 3(2)
  (lines 1196-1200).

The module is data-only — no I/O, no mutable state, deterministic for the
same inputs. Engines reference these tables the same way they reference
:mod:`scanner.kb` (single source of truth).

Citation line numbers refer to *AI Agents Under EU Law* (Working Paper,
7 April 2026).
"""

from __future__ import annotations

from typing import TypedDict

ROLE_OBLIGATIONS_VERSION = "2026.04.27.v1"


# String IDs match the canonical EU AI Act NLF role names plus three
# extension values introduced by *AI Agents Under EU Law* (gpai_provider,
# gpai_systemic_provider, extraterritorial_non_eu).
ROLE_PROVIDER = "provider"
ROLE_DEPLOYER = "deployer"
ROLE_IMPORTER = "importer"
ROLE_DISTRIBUTOR = "distributor"
ROLE_PRODUCT_MANUFACTURER = "product_manufacturer"
ROLE_AUTHORIZED_REPRESENTATIVE = "authorized_representative"
ROLE_GPAI_PROVIDER = "gpai_provider"
ROLE_GPAI_SYSTEMIC_PROVIDER = "gpai_systemic_provider"
ROLE_EXTRATERRITORIAL_NON_EU = "extraterritorial_non_eu"


# Canonical role list — order matches the obligation hierarchy in §3 of the
# taxonomy extraction (provider > product_manufacturer > importer >
# distributor > deployer > authorized_rep > GPAI provider > systemic GPAI).
# The extraterritorial role is treated as *modifier* — a non-EU entity in
# any of the above roles inherits MSR Art. 4 obligations on top.
CANONICAL_ROLE_IDS = (
    ROLE_PROVIDER,
    ROLE_DEPLOYER,
    ROLE_IMPORTER,
    ROLE_DISTRIBUTOR,
    ROLE_PRODUCT_MANUFACTURER,
    ROLE_AUTHORIZED_REPRESENTATIVE,
    ROLE_GPAI_PROVIDER,
    ROLE_GPAI_SYSTEMIC_PROVIDER,
    ROLE_EXTRATERRITORIAL_NON_EU,
)


class RoleObligation(TypedDict, total=False):
    """One row in :data:`ROLE_OBLIGATIONS`."""

    id: str
    label: str
    art_3_definition: str
    summary: str
    source: str
    paper_lines: str
    primary_articles: list[str]
    secondary_articles: list[str]
    kb_dimensions: list[str]
    flips_provider_under: list[str]
    notes: list[str]


ROLE_OBLIGATIONS: list[RoleObligation] = [
    {
        "id": ROLE_PROVIDER,
        "label": "Provider",
        "art_3_definition": "Art. 3(3) — develops or commissions an AI system and places it on the market or puts it into service under its own name or trademark.",
        "summary": (
            "Bears the primary compliance obligations for high-risk AI systems: "
            "Art. 9-15 essential requirements, Art. 17 QMS, Art. 43 conformity "
            "assessment, Art. 47 EU declaration, Art. 49 EU database registration, "
            "Art. 50 transparency where applicable, Art. 72 post-market monitoring, "
            "Art. 73 serious incident reporting."
        ),
        "source": "Art. 3(3) + Chapter III Section 2 + Section 3",
        "paper_lines": "1010-1014, 1644-1765",
        "primary_articles": [
            "Art. 9",
            "Art. 10",
            "Art. 11",
            "Art. 12",
            "Art. 13",
            "Art. 14",
            "Art. 15",
            "Art. 17",
            "Art. 25(4)",
            "Art. 43",
            "Art. 47",
            "Art. 48",
            "Art. 49",
            "Art. 50",
            "Art. 72",
            "Art. 73",
        ],
        "secondary_articles": ["Art. 4", "Art. 5", "Art. 95"],
        "kb_dimensions": [
            "ai_literacy",
            "risk_mgmt",
            "data_gov",
            "tech_docs",
            "logging",
            "transparency",
            "human_oversight",
            "security",
            "conformity_assessment",
            "quality_management",
            "decision_governance",
            "access_control",
            "infra_mlops",
            "supply_chain",
        ],
        "flips_provider_under": [],
        "notes": [
            "Article 14 oversight must be effective during use, not merely designed-for at design time (footnote 20, lines 969-974).",
            "Article 25(4) requires written agreements with high-risk-AI suppliers (lines 1881-1883).",
        ],
    },
    {
        "id": ROLE_DEPLOYER,
        "label": "Deployer",
        "art_3_definition": "Art. 3(4) — uses an AI system under its authority (not for personal non-professional activity).",
        "summary": (
            "Operates an AI system without modifying it. Owes Art. 26 obligations "
            "of use in accordance with instructions, Art. 27 FRIA where high-risk "
            "public-sector + selected private-sector contexts apply, Art. 50 "
            "downstream transparency to affected persons, Art. 26(9) DPIA "
            "input/output coordination, Art. 26(11) human oversight, Art. 26(7) "
            "input data appropriateness, Art. 26(12) decision-record preservation."
        ),
        "source": "Art. 3(4) + Art. 26 + Art. 27",
        "paper_lines": "1010-1014, 1738-1744",
        "primary_articles": ["Art. 26", "Art. 27", "Art. 50", "Art. 72"],
        "secondary_articles": ["Art. 4", "Art. 14", "Art. 13"],
        "kb_dimensions": [
            "ai_literacy",
            "deployer_obligations",
            "transparency",
            "human_oversight",
            "decision_governance",
        ],
        "flips_provider_under": [
            "Art. 25(1) — putting own name/trademark on a high-risk system.",
            "Art. 25(1) — substantial modification (Art. 3(23)).",
            "Art. 25(1) — change of intended purpose so the system becomes high-risk.",
            ">1/3 original training compute fine-tuning of GPAI per Commission guidelines (lines 455-457, 1621-1624).",
        ],
        "notes": [
            "AEPD: 'technological autonomy does not displace legal responsibility… processing remains legally attributable to the controller that deploys the system' (lines 1160-1162).",
            "Configurable automation boundary at deployer level — granular per *decision type*, not system-wide (footnote 36, lines 1738-1744).",
        ],
    },
    {
        "id": ROLE_IMPORTER,
        "label": "Importer",
        "art_3_definition": "Art. 3(7) — places on the EU market an AI system bearing the name or trademark of a non-EU provider.",
        "summary": (
            "Verifies provider conformity-assessment carried out, technical "
            "documentation exists, CE marking affixed, EU declaration of "
            "conformity drawn up; cooperates with market surveillance authorities."
        ),
        "source": "Art. 3(7) + Art. 23",
        "paper_lines": "1010-1014",
        "primary_articles": ["Art. 23"],
        "secondary_articles": ["Art. 25", "Art. 47", "Art. 48"],
        "kb_dimensions": ["tech_docs", "supply_chain", "quality_management"],
        "flips_provider_under": [
            "Art. 25(1) — substantial modification, own-name application, or intended-purpose change.",
        ],
        "notes": [],
    },
    {
        "id": ROLE_DISTRIBUTOR,
        "label": "Distributor",
        "art_3_definition": "Art. 3(8) — makes an AI system available on the EU market without affecting its properties (and is neither importer nor provider).",
        "summary": (
            "Verifies CE marking + required documentation accompanies the system "
            "and storage/transport conditions don't compromise compliance."
        ),
        "source": "Art. 3(8) + Art. 24",
        "paper_lines": "1010-1014",
        "primary_articles": ["Art. 24"],
        "secondary_articles": ["Art. 25"],
        "kb_dimensions": ["tech_docs", "supply_chain"],
        "flips_provider_under": [
            "Art. 25(1) — substantial modification, own-name application, or intended-purpose change.",
        ],
        "notes": [],
    },
    {
        "id": ROLE_PRODUCT_MANUFACTURER,
        "label": "Product Manufacturer",
        "art_3_definition": "Art. 25(1) — integrates an AI system into a product placed on the market under the manufacturer's name or trademark; treated as provider.",
        "summary": (
            "Inherits the full provider obligation set when integrating a "
            "high-risk AI system into a product."
        ),
        "source": "Art. 25(1)",
        "paper_lines": "407-410, 1606-1611",
        "primary_articles": [
            "Art. 9",
            "Art. 10",
            "Art. 11",
            "Art. 12",
            "Art. 13",
            "Art. 14",
            "Art. 15",
            "Art. 17",
            "Art. 43",
            "Art. 47",
            "Art. 48",
            "Art. 49",
        ],
        "secondary_articles": ["Art. 25(4)"],
        "kb_dimensions": [
            "risk_mgmt",
            "data_gov",
            "tech_docs",
            "logging",
            "transparency",
            "human_oversight",
            "security",
            "conformity_assessment",
            "quality_management",
        ],
        "flips_provider_under": [],
        "notes": [
            "Multi-layer assembly chains may trigger Art. 25 status flips at multiple layers simultaneously (footnote 33, lines 1606-1611).",
        ],
    },
    {
        "id": ROLE_AUTHORIZED_REPRESENTATIVE,
        "label": "Authorized Representative",
        "art_3_definition": "Art. 22 — appointed by a non-EU provider as their authorized representative in the EU under written mandate.",
        "summary": (
            "Acts on behalf of the non-EU provider; verifies declaration of "
            "conformity + technical documentation; cooperates with MSAs; "
            "terminates mandate where the provider violates obligations."
        ),
        "source": "Art. 22",
        "paper_lines": "1011, 1082-1085",
        "primary_articles": ["Art. 22"],
        "secondary_articles": ["Art. 47", "Art. 48", "Art. 74"],
        "kb_dimensions": ["tech_docs", "quality_management", "supply_chain"],
        "flips_provider_under": [],
        "notes": [
            "Required when the provider is not established in the Union — operates under written mandate (footnote 23, lines 1082-1085).",
        ],
    },
    {
        "id": ROLE_GPAI_PROVIDER,
        "label": "GPAI Model Provider",
        "art_3_definition": "Art. 3(63) — provider of a general-purpose AI model placed on the market.",
        "summary": (
            "Owes Chapter V obligations: Art. 53 technical documentation per "
            "Annex XI, downstream transparency per Annex XII, Union copyright "
            "compliance, training-data summary. Art. 56 voluntary GPAI Code of "
            "Practice published 10 July 2025. Obligations are independent from "
            "system-level Chapter III obligations."
        ),
        "source": "Chapter V (Art. 51-56)",
        "paper_lines": "433-462, 2091-2094",
        "primary_articles": ["Art. 53", "Art. 56"],
        "secondary_articles": ["Art. 51", "Art. 52", "Art. 95"],
        "kb_dimensions": ["gpai", "tech_docs", "transparency"],
        "flips_provider_under": [
            ">1/3 original training compute fine-tuning crosses the threshold from deployer → provider (lines 455-457, 1621-1624).",
        ],
        "notes": [
            "Commission GPAI guidelines: >1/3 of original training compute is the indicative threshold for fine-tuning to flip a downstream entity into provider status.",
        ],
    },
    {
        "id": ROLE_GPAI_SYSTEMIC_PROVIDER,
        "label": "GPAI Provider with Systemic Risk",
        "art_3_definition": "Art. 51(2) — GPAI model meeting the quantitative criterion (or designated by the AI Office) carrying systemic risk.",
        "summary": (
            "Additional obligations on top of Art. 53: model evaluation, "
            "adversarial testing, incident reporting to the AI Office, adequate "
            "cybersecurity measures. Autonomy and tool use are decisive factors "
            "in this designation per AI Office (Art. 51(1)(b), Annex XIII)."
        ),
        "source": "Art. 51(2) + Art. 55 + Art. 56",
        "paper_lines": "439-443, 2091-2094",
        "primary_articles": ["Art. 51", "Art. 55", "Art. 56"],
        "secondary_articles": ["Art. 53"],
        "kb_dimensions": ["gpai", "gpai_systemic_risk", "security"],
        "flips_provider_under": [],
        "notes": [
            "GPAI Code of Practice already operationalises agentic considerations in its systemic risk measures (line 443).",
            "Art. 56 + Recital 116 establishes a 'risk taxonomy of the type and nature of the systemic risks at Union level, including their sources' (line 2203).",
        ],
    },
    {
        "id": ROLE_EXTRATERRITORIAL_NON_EU,
        "label": "Extraterritorial (Non-EU) Entity",
        "art_3_definition": "Art. 2(1)(c) — places on the EU market or puts into service AI in the Union, OR provides outputs used in the Union, regardless of establishment location.",
        "summary": (
            "Any non-EU entity (notably US-based) reached by Art. 2(1)(c) must "
            "additionally designate a 'responsible person' established in the EU "
            "per MSR Art. 4 / AI Act Art. 74 for: verifying conformity-assessment "
            "completed, ensuring technical documentation availability to MSAs, "
            "cooperating with authorities, reporting risks. MSAs may request and "
            "access documentation and source code (Art. 74(12)-(13)). GDPR Art. "
            "3(2) parallel also applies where personal data of EU individuals is "
            "processed."
        ),
        "source": "Art. 2(1)(c) + Art. 74 + MSR Reg. (EU) 2019/1020 Art. 4 + GDPR Art. 3(2)",
        "paper_lines": "1027-1075, 1196-1200, 2343-2389",
        "primary_articles": ["Art. 22", "Art. 74"],
        "secondary_articles": ["Art. 3", "Art. 47", "Art. 48"],
        "kb_dimensions": ["supply_chain", "quality_management", "tech_docs"],
        "flips_provider_under": [],
        "notes": [
            "Concrete operational obligation that 'most AI agent providers based in the United States have not yet addressed' (line 1071-1072).",
            "Treat as a *modifier* — applies in addition to whichever core role (provider / GPAI provider / etc.) the entity occupies.",
            "MSAs may request and access documentation and source code (Art. 74(12)-(13)); Art. 74(5) remote enforcement; Art. 74(11) joint cross-Member-State investigations (lines 1073-1075).",
        ],
    },
]


# ─── Fast lookups ────────────────────────────────────────────────────────


ROLE_OBLIGATION_BY_ID: dict[str, RoleObligation] = {
    entry["id"]: entry for entry in ROLE_OBLIGATIONS
}


def get_role_obligation(role_id: str) -> RoleObligation | None:
    """Return the obligation entry for ``role_id``, or ``None`` if unknown."""
    return ROLE_OBLIGATION_BY_ID.get(role_id)


def articles_for_role(role_id: str, *, include_secondary: bool = True) -> list[str]:
    """Return the article list owed by ``role_id``.

    When ``include_secondary`` is False, only the primary list is returned.
    """
    entry = ROLE_OBLIGATION_BY_ID.get(role_id)
    if not entry:
        return []
    primaries = list(entry.get("primary_articles", []))
    if not include_secondary:
        return primaries
    return primaries + list(entry.get("secondary_articles", []))


def applies_to_role(article_ref: str, role_id: str) -> bool:
    """Return True iff ``article_ref`` is owed by ``role_id``.

    Matches paragraph references such as ``Art. 9(2)(a)`` against article-level
    entries by checking prefix containment in either direction.
    """
    if not article_ref or not role_id:
        return False
    entry = ROLE_OBLIGATION_BY_ID.get(role_id)
    if not entry:
        return False
    candidates = list(entry.get("primary_articles", [])) + list(
        entry.get("secondary_articles", [])
    )
    for owned in candidates:
        if article_ref == owned:
            return True
        # Allow paragraph-level lookup against article-level entry.
        if article_ref.startswith(f"{owned}(") or article_ref.startswith(f"{owned} "):
            return True
        # Allow article-level lookup against paragraph-level entry.
        if owned.startswith(f"{article_ref}(") or owned.startswith(f"{article_ref} "):
            return True
    return False


def filter_articles_for_role(
    article_refs: list[str], role_id: str
) -> list[str]:
    """Return the subset of ``article_refs`` owed by ``role_id``.

    Order is preserved. Unknown roles return an empty list.
    """
    return [ref for ref in article_refs if applies_to_role(ref, role_id)]


def compute_applicable_roles(article_ref: str) -> list[str]:
    """Return every canonical role ID whose obligation set covers ``article_ref``.

    Used to back-fill the ``applicable_roles`` field on a ``ComplianceGap``
    or ``EvidenceCitation`` from the role-obligation registry. The
    extraterritorial-non-EU modifier is always returned when the article
    is one that an extraterritorial entity must verify (Art. 22, Art. 74).

    Order matches :data:`CANONICAL_ROLE_IDS` so the returned list is
    deterministic.
    """
    if not article_ref:
        return []
    return [
        role_id
        for role_id in CANONICAL_ROLE_IDS
        if applies_to_role(article_ref, role_id)
    ]


def is_extraterritorial_modifier(role_id: str) -> bool:
    """Return True iff ``role_id`` is the extraterritorial-non-EU modifier."""
    return role_id == ROLE_EXTRATERRITORIAL_NON_EU


def is_gpai_role(role_id: str) -> bool:
    """Return True iff ``role_id`` is a GPAI provider role."""
    return role_id in (ROLE_GPAI_PROVIDER, ROLE_GPAI_SYSTEMIC_PROVIDER)


__all__ = [
    "ROLE_OBLIGATIONS_VERSION",
    "ROLE_PROVIDER",
    "ROLE_DEPLOYER",
    "ROLE_IMPORTER",
    "ROLE_DISTRIBUTOR",
    "ROLE_PRODUCT_MANUFACTURER",
    "ROLE_AUTHORIZED_REPRESENTATIVE",
    "ROLE_GPAI_PROVIDER",
    "ROLE_GPAI_SYSTEMIC_PROVIDER",
    "ROLE_EXTRATERRITORIAL_NON_EU",
    "CANONICAL_ROLE_IDS",
    "RoleObligation",
    "ROLE_OBLIGATIONS",
    "ROLE_OBLIGATION_BY_ID",
    "get_role_obligation",
    "articles_for_role",
    "applies_to_role",
    "filter_articles_for_role",
    "compute_applicable_roles",
    "is_extraterritorial_modifier",
    "is_gpai_role",
]
