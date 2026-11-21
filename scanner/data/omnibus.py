"""Digital Omnibus on AI (Regulation (EU) 2026/1744) + as-of applicability resolver.

Pure-offline static amendment table and deterministic date-applicability engine:

1. **Amendment facts** — verified against the Official Journal text and EUR-Lex
   metadata for CELEX ``32026R1744`` (Regulation (EU) 2026/1744 of 8 July 2026,
   published 24 July 2026, in force 27 July 2026). Records both what the
   Omnibus amended (:data:`AMENDMENTS`) and the key provisions it deliberately
   left untouched (:data:`UNAMENDED`).
2. **As-of applicability resolver** — :func:`live_phase` and
   :func:`resolve_applicability` answer *"which EU AI Act duties apply to an
   operator of risk class R on date D?"* directly from :mod:`scanner.data.ontology`.

No I/O, no network, no system clock. Callers supply ``as_of: date``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Literal

from pydantic import BaseModel, Field

from scanner.data.ontology import (
    EVERY_RISK_CLASS_OBLIGATIONS,
    MODEL_RISK_CLASSES,
    OPERATOR_ROLES,
    PHASE_REGISTRY,
    PRACTICE_REGISTRY,
    RISK_CLASS_PHASE,
    ActorRole,
    Phase,
    Practice,
    RiskClass,
    obligations_for,
)

# ─── The amending instrument ─────────────────────────────────────────────────

OMNIBUS_ID: str = "legal_instrument_digital_omnibus_ai"
OMNIBUS_CELEX: str = "32026R1744"
OMNIBUS_ELI: str = "http://data.europa.eu/eli/reg/2026/1744/oj"
OMNIBUS_OJ_REF: str = "OJ L, 2026/1744, 24.7.2026"
OMNIBUS_LEGAL_LINK: str = (
    "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32026R1744"
)
OMNIBUS_SHORT_TITLE: str = "Digital Omnibus on AI"
OMNIBUS_TITLE: str = (
    "Regulation (EU) 2026/1744 of the European Parliament and of the Council "
    "of 8 July 2026 amending Regulations (EU) 2024/1689, (EU) 2018/1139 and "
    "(EU) 2023/1230 as regards the simplification of the implementation of "
    "harmonised rules on artificial intelligence (Digital Omnibus on AI)"
)
OMNIBUS_DATE_DOCUMENT: str = "2026-07-08"
OMNIBUS_DATE_PUBLISHED: str = "2026-07-24"
OMNIBUS_DATE_IN_FORCE: str = "2026-07-27"
OMNIBUS_PROCEDURE: str = "2025/0359(COD)"
OMNIBUS_PROPOSAL_CELEX: str = "52025PC0836"

#: The Omnibus amends three regulations, not just the AI Act.
OMNIBUS_AMENDED_REGULATIONS: tuple[str, ...] = (
    "2024/1689",  # AI Act
    "2018/1139",  # civil aviation / EASA
    "2023/1230",  # machinery
)

#: The separate non-AI "Digital Omnibus" (COM(2025) 837, procedure 2025/0360(COD))
#: amending GDPR / Data Act / ePrivacy / NIS2 / CER — distinct from 2026/1744.
NON_AI_OMNIBUS_PROCEDURE: str = "2025/0360(COD)"
NON_AI_OMNIBUS_PROPOSAL_CELEX: str = "52025PC0837"
NON_AI_OMNIBUS_ADOPTED: bool = False

#: Point-in-time consolidation of Regulation (EU) 2024/1689 as amended.
AI_ACT_CONSOLIDATED_CELEX: str = "02024R1689-20260727"
AI_ACT_CONSOLIDATED_ELI: str = (
    "https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng"
)
AI_ACT_CONSOLIDATION_DATE: str = "2026-07-27"


@dataclass(frozen=True)
class Amendment:
    """One numbered amendment Regulation (EU) 2026/1744 makes to the AI Act.

    ``provision`` is the amending instruction inside Regulation (EU) 2026/1744
    (e.g. ``"Art. 1(40)(b)"``); ``target`` is the AI Act provision it acts on.
    """

    target: str
    provision: str
    operation: str  # "replaced" | "inserted" | "deleted"
    summary: str
    applies_from: str = ""
    date_source: str = ""


AMENDMENTS: tuple[Amendment, ...] = (
    Amendment(
        target="Art. 113",
        provision="Art. 1(40)(b)",
        operation="replaced",
        summary=(
            "Chapter III Sections 1, 2 and 3 (except Art. 6(5)) apply from "
            "2 December 2027 for systems high-risk under Art. 6(2) and Annex III, "
            "and from 2 August 2028 for systems high-risk under Art. 6(1) and "
            "Annex I. The pre-amendment text applied Annex III via the general "
            "2 August 2026 date and set 2 August 2027 for Art. 6(1)."
        ),
        applies_from="2027-12-02",
    ),
    Amendment(
        target="Art. 113",
        provision="Art. 1(40)(a)",
        operation="replaced",
        summary=(
            "Carves the new Art. 5(1)(ba), (bb) and Art. 5(1a), (1b) out of the "
            "2 February 2025 date for Chapters I and II; they apply from "
            "2 December 2026 instead."
        ),
        applies_from="2026-12-02",
    ),
    Amendment(
        target="Art. 113",
        provision="Art. 1(40)(c)",
        operation="inserted",
        summary="New point (d): Articles 102 to 110 apply from 27 July 2026.",
        applies_from="2026-07-27",
    ),
    Amendment(
        target="Art. 5",
        provision="Art. 1(7)(a)",
        operation="inserted",
        summary=(
            "New prohibition Art. 5(1)(ba): AI systems generating or manipulating "
            "realistic intimate or sexually explicit material of an identifiable "
            "natural person without their freely given, specific, informed, "
            "unambiguous and explicit consent. New prohibition Art. 5(1)(bb): AI "
            "systems generating or manipulating child sexual abuse material within "
            "the meaning of Art. 2, points (c) and (e), of Directive 2011/93/EU."
        ),
        applies_from="2026-12-02",
        date_source="Art. 1(40)(a)",
    ),
    Amendment(
        target="Art. 5",
        provision="Art. 1(7)(b)",
        operation="inserted",
        summary=(
            "New Art. 5(1a) narrows both new prohibitions: the market/service limb "
            "bites only where the generation is the intended purpose, or is a "
            "reasonably foreseeable and reproducible outcome without significant "
            "technical modification AND the system lacks reasonable and adequate "
            "safeguards; the use limb bites only where the deployer uses the system "
            "for that purpose. New Art. 5(1b) excludes manipulation that neither "
            "increases exposure of depicted intimate parts nor alters the nature of "
            "depicted sexually explicit activity."
        ),
        applies_from="2026-12-02",
        date_source="Art. 1(40)(a)",
    ),
    Amendment(
        target="Art. 4",
        provision="Art. 1(5)",
        operation="replaced",
        summary=(
            "AI literacy softened from 'ensure' to 'take measures to support the "
            "development of', with an express disclaimer that providers and "
            "deployers need not guarantee any specific level of AI literacy of any "
            "individual. Date unchanged — Chapter I, applicable since "
            "2 February 2025."
        ),
        applies_from="2025-02-02",
        date_source="Art. 1(40)(a)",
    ),
    Amendment(
        target="Art. 4a",
        provision="Art. 1(6)",
        operation="inserted",
        summary=(
            "New Article 4a permits providers of high-risk AI systems to process "
            "Art. 9 GDPR special-category data for bias detection and correction "
            "under six cumulative conditions, extended by 4a(2) to other AI systems "
            "and models and to deployers. Expressly creates no obligation to perform "
            "bias detection."
        ),
    ),
    Amendment(
        target="Art. 10",
        provision="Art. 1(9)(b)",
        operation="deleted",
        summary=(
            "Art. 10(5) is deleted; its special-category-data content moves to the "
            "new Art. 4a with a wider personal scope. Art. 10(1) and 10(6) now "
            "cross-refer to Art. 4a(1). Any rule keyed to Art. 10(5) now points at a "
            "deleted provision."
        ),
    ),
    Amendment(
        target="Art. 6",
        provision="Art. 1(8)",
        operation="inserted",
        summary=(
            "New Art. 6(1a), (1b), (1c) redefine the safety-component gate. 6(1a) "
            "excludes systems used solely for non-safety aspects (user assistance, "
            "performance optimisation, service efficiency, automation, convenience, "
            "quality control); 6(1b) preserves high-risk status where failure "
            "endangers health and safety; 6(1c) excludes products needing "
            "third-party conformity assessment solely for non-health/safety risks. "
            "Art. 6(2), 6(3) and 6(5) are NOT amended and Annex III is NOT amended."
        ),
    ),
    Amendment(
        target="Art. 2",
        provision="Art. 1(2)(a)",
        operation="replaced",
        summary=(
            "Art. 2(2) narrowed: for Annex I Section B products (aviation, rail, "
            "marine equipment, motor vehicles and now machinery) only Art. 6(1), the "
            "new Art. 60a and Arts. 102-112 apply; Arts. 57-59 apply only in so far "
            "as AI Act requirements have been integrated into that sectoral "
            "legislation."
        ),
    ),
    Amendment(
        target="Art. 2",
        provision="Art. 1(3)",
        operation="inserted",
        summary=(
            "New Art. 2(13): a delegated-act power to LIMIT Arts. 9-15 and 17-25 for "
            "Art. 6(1) high-risk systems where Annex I Section A legislation provides "
            "equivalent or higher protection. The Commission must adopt the "
            "specifying delegated acts by 2 August 2027 — until they exist, nothing "
            "is actually limited."
        ),
    ),
    Amendment(
        target="Art. 3",
        provision="Art. 1(4)",
        operation="replaced",
        summary=(
            "Definition (14) 'safety component' rewritten around a safety FUNCTION "
            "rather than mere integration. New definitions (14a) 'SME' and (14b) "
            "'SMC' (small mid-cap enterprise, Recommendation (EU) 2025/1099) — a "
            "wholly new operator category threaded through Arts. 11, 17, 96 and 99."
        ),
    ),
    Amendment(
        target="Art. 27",
        provision="Art. 1(13)",
        operation="replaced",
        summary=(
            "FRIA: Art. 27(4) now lets the deployer satisfy the obligation by "
            "cross-referencing or importing parts of an Art. 35 GDPR / Art. 27 LED "
            "DPIA. Art. 27(5) moves the questionnaire template duty to the AI Office "
            "and requires an automated tool. The FRIA duty and its deployer scope "
            "are unchanged."
        ),
    ),
    Amendment(
        target="Art. 50",
        provision="Art. 1(20)",
        operation="replaced",
        summary=(
            "ONLY Art. 50(7) is amended — codes of practice for detection, marking "
            "and labelling, plus a new Commission power to adopt an implementing act "
            "specifying common rules if a code is inadequate. Art. 50(1)-(6) are NOT "
            "amended and no carve-out is introduced: the transparency duties remain "
            "on their 2 August 2026 date and are in force."
        ),
        applies_from="2026-08-02",
        date_source="Art. 113, second paragraph (unamended)",
    ),
    Amendment(
        target="Art. 72",
        provision="Art. 1(30)",
        operation="replaced",
        summary=(
            "Art. 72(3): the post-market monitoring plan is now expressly part of the "
            "technical documentation referred to in Annex IV, and the Commission must "
            "adopt guidance including a template by 2 September 2027 — guidance, not "
            "an implementing act."
        ),
    ),
    Amendment(
        target="Art. 99",
        provision="Art. 1(38)",
        operation="replaced",
        summary=(
            "Art. 99(1) replaced; new point (da) in Art. 99(4) covering Art. 25(2) "
            "and (4); new Art. 99(6a) caps fines for SMCs at the lower of the "
            "percentage or the absolute amount. The Art. 99(3) ceiling (EUR "
            "35 000 000 or 7% of worldwide turnover) attaches to Art. 5 generically, "
            "so it covers the new (ba)/(bb) prohibitions once they apply."
        ),
    ),
    Amendment(
        target="Art. 111",
        provision="Art. 1(39)(a)",
        operation="replaced",
        summary=(
            "Art. 111(2): the significant-design-change trigger is preserved, but "
            "providers and deployers of high-risk AI systems intended to be used by "
            "public authorities must comply by 2 August 2030 regardless."
        ),
        applies_from="2030-08-02",
    ),
    Amendment(
        target="Art. 111",
        provision="Art. 1(39)(b)",
        operation="inserted",
        summary=(
            "New Art. 111(4): providers of AI systems, including GPAI systems, "
            "generating synthetic audio, image, video or text placed on the market "
            "before 2 August 2026 must comply with Art. 50(2) by 2 December 2026. "
            "This is the only date relief on the Art. 50 side, and it is "
            "transitional — systems placed on the market on or after 2 August 2026 "
            "get no grace period."
        ),
        applies_from="2026-12-02",
    ),
    Amendment(
        target="Annex VIII",
        provision="Art. 1(42)",
        operation="deleted",
        summary=(
            "Annex VIII Section B points 7 and 9 are deleted — the narrative "
            "justification and the Member-State list for Art. 49(2) registrations by "
            "providers who conclude under Art. 6(3) that an Annex III system is not "
            "high-risk. Point 6 survives, so the tick-box stays and the free-text "
            "rationale goes. Art. 49 and Art. 71 themselves are NOT amended."
        ),
    ),
)

#: Provisions verified as untouched by Regulation (EU) 2026/1744.
UNAMENDED: tuple[tuple[str, str], ...] = (
    ("Annex III", "No Annex III category is added, removed or reworded."),
    ("Art. 6(2)", "The Annex III high-risk trigger is unchanged; only its date moved."),
    ("Art. 6(3)", "The profiling override and the derogation conditions are unchanged."),
    (
        "Art. 6(5)",
        "Expressly carved out of the deferral — still applies from 2 August 2026.",
    ),
    (
        "Art. 49",
        "The registration duty, including the Art. 49(3) deployer duty, survives intact.",
    ),
    ("Art. 71", "The EU database provisions are unchanged."),
    ("Art. 51", "The 10^25 FLOP systemic-risk presumption is unchanged."),
    (
        "Art. 53",
        "GPAI provider obligations are unchanged; Chapter V keeps its 2 August 2025 date.",
    ),
    ("Art. 55", "Systemic-risk obligations are unchanged."),
    ("Art. 50", "Paragraphs (1)-(6) are unchanged; only paragraph (7) was replaced."),
)


def amendments_for(article_ref: str) -> list[Amendment]:
    """Return every Omnibus amendment targeting ``article_ref`` (e.g. ``"Art. 113"``)."""
    needle = (article_ref or "").strip()
    return [a for a in AMENDMENTS if a.target == needle]


def is_unamended(article_ref: str) -> str:
    """Return the recorded reason ``article_ref`` is unchanged, else ``""``.

    ``""`` means "not on the checked list" (unchecked, not confirmed amended).
    """
    needle = (article_ref or "").strip()
    for ref, reason in UNAMENDED:
        if ref == needle:
            return reason
    return ""


def amended_article_numbers() -> list[str]:
    """Bare AI Act article numbers recorded in :data:`AMENDMENTS` (e.g. ``"113"``, ``"4a"``)."""
    out: list[str] = []
    for amendment in AMENDMENTS:
        if not amendment.target.startswith("Art. "):
            continue
        number = amendment.target[len("Art. ") :].strip()
        if number not in out:
            out.append(number)
    return out


# ─── As-of regulatory applicability resolver ─────────────────────────────────

BASIS = (
    "Regulation (EU) 2024/1689 as amended by Regulation (EU) 2026/1744 "
    f"(consolidated text CELEX {AI_ACT_CONSOLIDATED_CELEX}). The amendment entered "
    f"into force on {OMNIBUS_DATE_IN_FORCE}, before either date it replaced, so no "
    "superseded date ever applied."
)


class SupersededPhaseRef(BaseModel):
    """An applicability phase replaced by a later act. Never a live date."""

    id: str
    label: str
    original_date: str = Field(
        description="ISO date the phase carried before it was superseded"
    )
    superseded_by: str = Field(description="Id of the phase that replaced it")


class ApplicablePhase(BaseModel):
    """A live applicability phase that dates at least one returned duty."""

    id: str
    label: str
    effective_date: str = Field(description="ISO date the phase applies from")
    articles: list[str]
    replaces: list[SupersededPhaseRef] = Field(
        default_factory=list,
        description="Superseded phases whose date this phase replaced",
    )


class ApplicableDuty(BaseModel):
    """One duty an operator owes, dated by the live phase it applies from."""

    ref: str = Field(description="Article or point, e.g. 'Art. 26' or 'Art. 5(1)(ba)'")
    source: Literal["prohibition", "risk_class", "every_risk_class"] = Field(
        description=(
            "Why it is owed: an Art. 5 prohibition, the risk class's own regime, "
            "or a duty every AI system's provider or deployer owes"
        )
    )
    applies_from: str = Field(description="ISO date the duty applies from")
    phase_id: str
    replaces: list[SupersededPhaseRef] = Field(
        default_factory=list,
        description="Superseded phases whose date this duty's date replaced",
    )


class ApplicabilityResult(BaseModel):
    """What the EU AI Act requires of one operator, for one risk class, on one date."""

    as_of: str = Field(description="ISO date the answer is for")
    risk_class: str
    role: str
    basis: str = Field(description="The text of the Act the dates follow")
    phases_in_force: list[ApplicablePhase]
    phases_pending: list[ApplicablePhase]
    duties_in_force: list[ApplicableDuty]
    duties_pending: list[ApplicableDuty]


def live_phase(phase_id: str) -> Phase:
    """Follow ``superseded_by`` from ``phase_id`` to the phase that is live law."""
    seen: set[str] = set()
    phase = PHASE_REGISTRY[phase_id]
    while phase.superseded_by:
        if phase.id in seen:
            raise ValueError(f"superseded_by cycle through {phase.id}")
        seen.add(phase.id)
        phase = PHASE_REGISTRY[phase.superseded_by]
    return phase


def _replaced(live_id: str) -> list[SupersededPhaseRef]:
    """Superseded phases whose pointer chain ends at ``live_id`` (deduplicated)."""
    seen: set[str] = set()
    out: list[SupersededPhaseRef] = []
    for p in PHASE_REGISTRY.values():
        if p.id in seen:
            continue
        if p.superseded_by and live_phase(p.id).id == live_id:
            seen.add(p.id)
            out.append(
                SupersededPhaseRef(
                    id=p.id,
                    label=p.label,
                    original_date=p.effective_date.isoformat(),
                    superseded_by=p.superseded_by,
                )
            )
    return out


def _phase_listing(article: str) -> Phase:
    """The one live phase that lists ``article``. Two or none is a data error."""
    unique_matches = {
        p.id: p
        for p in PHASE_REGISTRY.values()
        if not p.superseded_by and article in p.articles
    }
    if len(unique_matches) != 1:
        raise ValueError(
            f"{article} is listed by {len(unique_matches)} live phases; "
            "exactly one must date it"
        )
    return next(iter(unique_matches.values()))


def _practice_ref(practice: Practice) -> str:
    """``"5.1.ba"`` -> ``"Art. 5(1)(ba)"``."""
    article, paragraph, point = practice.sub_paragraph.split(".")
    return f"Art. {article}({paragraph})({point})"


def _owed(risk_class: RiskClass, role: ActorRole) -> list[tuple[str, str, Phase]]:
    """Every duty ``role`` owes for ``risk_class`` as ``(ref, source, live_phase)``."""
    owed: list[tuple[str, str, Phase]] = []
    is_system = risk_class not in MODEL_RISK_CLASSES
    if is_system and "Art. 5" in obligations_for(role, RiskClass.PROHIBITED):
        seen_practice_ids: set[str] = set()
        for p in PRACTICE_REGISTRY.values():
            if p.id in seen_practice_ids:
                continue
            seen_practice_ids.add(p.id)
            owed.append((_practice_ref(p), "prohibition", live_phase(p.effective_phase)))
    if risk_class is not RiskClass.PROHIBITED:
        regime = live_phase(RISK_CLASS_PHASE[risk_class])
        owed.extend(
            (article, "risk_class", regime)
            for article in obligations_for(role, risk_class)
        )
    if is_system:
        owed.extend(
            (article, "every_risk_class", live_phase(_phase_listing(article).id))
            for article in EVERY_RISK_CLASS_OBLIGATIONS.get(role, ())
        )
    return owed


def resolve_applicability(
    as_of: date,
    risk_class: RiskClass,
    role: ActorRole,
) -> ApplicabilityResult:
    """Return the phases and duties in force for ``role`` on ``as_of``, and those pending.

    A duty is in force from its phase's date, the day itself included (Art. 113
    "shall apply from"). Raises ``ValueError`` for a role outside
    :data:`~scanner.data.ontology.OPERATOR_ROLES`.
    """
    if role not in OPERATOR_ROLES:
        raise ValueError(
            f"role {role.value!r} is not a value-chain operator; expected one of "
            f"{', '.join(r.value for r in OPERATOR_ROLES)}"
        )

    duties_in_force: list[ApplicableDuty] = []
    duties_pending: list[ApplicableDuty] = []
    phases: dict[str, Phase] = {}
    dated_by: dict[str, str] = {}
    for ref, source, phase in _owed(risk_class, role):
        if ref in dated_by:
            if dated_by[ref] != phase.id:
                raise ValueError(
                    f"{ref} is dated by both {dated_by[ref]} and {phase.id}"
                )
            continue
        dated_by[ref] = phase.id
        phases[phase.id] = phase
        duty = ApplicableDuty(
            ref=ref,
            source=source,  # type: ignore[arg-type]
            applies_from=phase.effective_date.isoformat(),
            phase_id=phase.id,
            replaces=_replaced(phase.id),
        )
        (duties_in_force if phase.effective_date <= as_of else duties_pending).append(
            duty
        )

    phases_in_force: list[ApplicablePhase] = []
    phases_pending: list[ApplicablePhase] = []
    for phase in sorted(phases.values(), key=lambda p: (p.effective_date, p.id)):
        entry = ApplicablePhase(
            id=phase.id,
            label=phase.label,
            effective_date=phase.effective_date.isoformat(),
            articles=list(phase.articles),
            replaces=_replaced(phase.id),
        )
        (phases_in_force if phase.effective_date <= as_of else phases_pending).append(
            entry
        )

    duties_in_force.sort(key=lambda d: d.applies_from)
    duties_pending.sort(key=lambda d: d.applies_from)
    return ApplicabilityResult(
        as_of=as_of.isoformat(),
        risk_class=risk_class.value,
        role=role.value,
        basis=BASIS,
        phases_in_force=phases_in_force,
        phases_pending=phases_pending,
        duties_in_force=duties_in_force,
        duties_pending=duties_pending,
    )


__all__ = [
    "OMNIBUS_ID",
    "OMNIBUS_CELEX",
    "OMNIBUS_ELI",
    "OMNIBUS_OJ_REF",
    "OMNIBUS_LEGAL_LINK",
    "OMNIBUS_SHORT_TITLE",
    "OMNIBUS_TITLE",
    "OMNIBUS_DATE_DOCUMENT",
    "OMNIBUS_DATE_PUBLISHED",
    "OMNIBUS_DATE_IN_FORCE",
    "OMNIBUS_PROCEDURE",
    "OMNIBUS_PROPOSAL_CELEX",
    "OMNIBUS_AMENDED_REGULATIONS",
    "NON_AI_OMNIBUS_PROCEDURE",
    "NON_AI_OMNIBUS_PROPOSAL_CELEX",
    "NON_AI_OMNIBUS_ADOPTED",
    "AI_ACT_CONSOLIDATED_CELEX",
    "AI_ACT_CONSOLIDATED_ELI",
    "AI_ACT_CONSOLIDATION_DATE",
    "Amendment",
    "AMENDMENTS",
    "UNAMENDED",
    "amendments_for",
    "is_unamended",
    "amended_article_numbers",
    "BASIS",
    "SupersededPhaseRef",
    "ApplicablePhase",
    "ApplicableDuty",
    "ApplicabilityResult",
    "live_phase",
    "resolve_applicability",
]
