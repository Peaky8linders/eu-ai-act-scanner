"""Typed ontology for the EU AI Act knowledge base.

Promotes the previously-implicit entity model (scattered across
``EC_CHECKER_OBLIGATION_MAP`` in :mod:`app.data.kb`,
``_KEYWORD_ENTITY_MAP`` / ``_CLASSIFICATION_TOPICS`` in
:mod:`app.engines.graph_rag`, and ``KEYWORD_TO_ARTICLE`` /
``_AI_ACT_ANCHORS`` in :mod:`app.integrations.regenold.scope`) into a
single typed source of truth.

## Entity types

* :class:`ActorRole` — provider / deployer / importer / distributor /
  authorised representative / downstream provider / notified body /
  affected person. The "role" the user takes in the value chain.
* :class:`RiskClass` — prohibited / high_risk_annex_i / high_risk_annex_iii /
  limited_risk / minimal_risk / gpai / gpai_systemic. The taxonomy
  the regulation uses to gate obligations.
* :class:`Practice` — each Art. 5(1)(a)..(h) prohibited practice + the
  Digital Omnibus 9th prohibition (CSAM/NCII) as a first-class entity.
* :class:`AnnexIIICategory` — each of the 8 high-risk use-case
  categories from Annex III.
* :class:`Phase` — applicability timeline phases (2 Feb 2025, 2 Aug
  2025, 2 Aug 2026, 2 Aug 2027, Digital Omnibus deferrals).

## Relationship types

Relationships are typed pointers between entities, modelled as tuple
fields on the dataclasses (each side knows its peers). The route's
retrieval engine can traverse these without a graph DB.

* ``Practice → Article`` (primary anchor — typically Art. 5 + sub-paragraph)
* ``Practice → ExemptionContext`` (workplace-only, medical-safety, narrow
  judicial authorisation, etc.)
* ``AnnexIIICategory → Article`` (Art. 6.2 + Annex III + Chapter III Section 2)
* ``RiskClass → Article`` (which articles enumerate the class)
* ``ActorRole → Article`` (which obligations apply to the role)
* ``Phase → Article`` (which obligations come into force at the phase)

## Why this exists

Three reasons (from the May 2026 audit triple):

1. **Eliminates duplication** between the four lookup maps. Each
   entry now exists in one place; the legacy maps become derived
   views in a later refactor pass.
2. **Enables role × system_type → obligations matrix queries** without
   adding more regex topics. Today's `_CLASSIFICATION_TOPICS` has 18
   hand-curated entries; a typed query against this ontology can
   answer arbitrarily many compositional questions.
3. **Surfaces the schema** so an outside reviewer (regulator, partner,
   future engineer) can audit "what does the system believe about the
   EU AI Act?" by reading one file. See ``docs/ontology/ONTOLOGY.md``
   for the human-readable schema.

The ontology is intentionally additive — existing
``EC_CHECKER_OBLIGATION_MAP`` rows and ``_CLASSIFICATION_TOPICS`` entries
stay live and the engine prefers them when they fire. The ontology
is the new source-of-truth for everything we add from here on, and
the legacy maps will be migrated into derived views in a follow-up.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import StrEnum

# ── Actor roles (Art. 3 definitions, AI Act value chain) ─────────────────


class ActorRole(StrEnum):
    """The eight operator roles defined by the AI Act value chain.

    Each role carries a discrete obligation profile. ``user`` is the
    natural person being affected by an AI output — useful for remedies
    (Arts. 85-86) even though they're not an obligation-bearer.
    """

    PROVIDER = "provider"  # Art. 3(3), primary obligation-bearer
    DEPLOYER = "deployer"  # Art. 3(4), end-user organisation
    IMPORTER = "importer"  # Art. 3(6)
    DISTRIBUTOR = "distributor"  # Art. 3(7)
    AUTHORISED_REPRESENTATIVE = "authorised_representative"  # Art. 3(5)
    DOWNSTREAM_PROVIDER = "downstream_provider"  # Recital 85 + Art. 89
    NOTIFIED_BODY = "notified_body"  # Art. 29 + Annex VII
    AFFECTED_PERSON = "affected_person"  # Arts. 85-86 — not an obligation-bearer


# ── Risk classes (Arts. 5/6 + GPAI dichotomy) ────────────────────────────


class RiskClass(StrEnum):
    """The seven mutually-exclusive risk classes the AI Act enumerates.

    The two high-risk subclasses are kept separate because they trigger
    different conformity-assessment routes (third-party for Annex I
    safety components vs. internal control + optional notified-body
    for Annex III). GPAI is orthogonal to the AI-system risk class —
    a model can be GPAI AND, when integrated into a system, be
    high-risk-by-use-case.
    """

    PROHIBITED = "prohibited"  # Art. 5 — unacceptable risk
    HIGH_RISK_ANNEX_I = "high_risk_annex_i"  # Art. 6.1 — safety component
    HIGH_RISK_ANNEX_III = "high_risk_annex_iii"  # Art. 6.2 — listed use case
    LIMITED_RISK = "limited_risk"  # Art. 50 transparency-only
    MINIMAL_RISK = "minimal_risk"  # No specific obligations (Art. 4 literacy only)
    GPAI = "gpai"  # Art. 51-55 — general-purpose AI model
    GPAI_SYSTEMIC = "gpai_systemic"  # Art. 55 — GPAI with systemic risk


# ── Applicability phases (Art. 113 + Digital Omnibus) ────────────────────


@dataclass(frozen=True)
class Phase:
    """One applicability date in the AI Act rollout.

    The Digital Omnibus political agreement (7 May 2026) defers several
    obligations; we encode the original date plus a ``superseded_by``
    pointer to the deferred phase so date-shaped queries can resolve
    "what applies on date X?" deterministically.
    """

    id: str
    label: str
    effective_date: date
    articles: tuple[str, ...]
    description: str
    superseded_by: str | None = None  # id of a later Phase (Digital Omnibus)


PHASE_REGISTRY: dict[str, Phase] = {
    "phase_2025_02_02": Phase(
        id="phase_2025_02_02",
        label="Article 5 prohibitions + Article 4 AI literacy",
        effective_date=date(2025, 2, 2),
        articles=("Art. 5", "Art. 4"),
        description=(
            "Prohibitions on the eight unacceptable practices (subliminal "
            "manipulation, vulnerability exploitation, social scoring, "
            "profiling-based criminal-risk prediction, untargeted facial-image "
            "scraping, workplace/education emotion recognition, biometric "
            "categorisation by sensitive attributes, real-time RBI in public "
            "spaces). AI literacy obligation also takes effect."
        ),
    ),
    "phase_2025_08_02": Phase(
        id="phase_2025_08_02",
        label="GPAI provider obligations + governance + penalties",
        effective_date=date(2025, 8, 2),
        articles=("Art. 53", "Art. 55", "Art. 99", "Art. 64", "Art. 65"),
        description=(
            "GPAI provider obligations (technical documentation per Annex XI, "
            "downstream-provider information per Annex XII, copyright policy, "
            "training-data summary). Systemic-risk obligations for designated "
            "GPAIs. AI Office and Board operational. Penalty regime for the "
            "prohibitions takes effect."
        ),
    ),
    "phase_2026_08_02": Phase(
        id="phase_2026_08_02",
        label="High-risk AI obligations (Annex III + most other obligations)",
        effective_date=date(2026, 8, 2),
        articles=("Art. 6", "Art. 8", "Art. 9", "Art. 10", "Art. 11", "Art. 13",
                  "Art. 14", "Art. 15", "Art. 16", "Art. 17", "Art. 26", "Art. 27",
                  "Annex III"),
        description=(
            "Full Chapter III Section 2 obligations for Annex III high-risk AI "
            "systems take effect. Deployer obligations under Art. 26, FRIA "
            "under Art. 27, transparency under Arts. 13/50."
        ),
    ),
    "phase_2027_08_02": Phase(
        id="phase_2027_08_02",
        label="High-risk AI obligations (Annex I safety-component path)",
        effective_date=date(2027, 8, 2),
        articles=("Art. 6", "Annex I"),
        description=(
            "Full high-risk obligations for AI as a safety component of a "
            "product regulated by Annex I harmonisation legislation (MDR, "
            "IVDR, machinery, toys, etc.). The longer runway lets sectoral "
            "conformity-assessment bodies update procedures."
        ),
        # Digital Omnibus defers this to 2 Aug 2028 in some sectors —
        # see PHASE_REGISTRY["phase_omnibus_2028_08_02"].
        superseded_by="phase_omnibus_2028_08_02",
    ),
    "phase_omnibus_2026_12_02": Phase(
        id="phase_omnibus_2026_12_02",
        label="Digital Omnibus 9th prohibition (CSAM / NCII)",
        effective_date=date(2026, 12, 2),
        articles=("Art. 5",),
        description=(
            "Pending the Digital Omnibus political agreement of 7 May 2026 "
            "and formal adoption: adds a 9th prohibition under Article 5 for "
            "AI systems that generate child sexual abuse material (CSAM) or "
            "non-consensual intimate imagery. Currently in draft."
        ),
    ),
    "phase_omnibus_2028_08_02": Phase(
        id="phase_omnibus_2028_08_02",
        label="Digital Omnibus deferred Annex I high-risk obligations",
        effective_date=date(2028, 8, 2),
        articles=("Art. 6", "Annex I"),
        description=(
            "Digital Omnibus defers Annex I safety-component high-risk "
            "obligations by 12 months in selected sectors to align with "
            "sectoral conformity-assessment infrastructure readiness."
        ),
    ),
}


# ── Practices (Art. 5 prohibited practices + Omnibus additions) ──────────


@dataclass(frozen=True)
class Practice:
    """One prohibited practice under Art. 5 (or Omnibus extension).

    Each instance is addressable as a sub-paragraph node (Art. 5(1)(a)
    through (h), plus the proposed 9th paragraph for CSAM/NCII). Carries
    the practice description, the exact citation chain, exception
    contexts (workplace-only narrowing, medical-safety carve-out, etc.),
    and the verdict-template prose used by the classification path.
    """

    id: str
    sub_paragraph: str  # e.g. "5.1.a"
    short_name: str
    description: str
    citation: tuple[str, ...]  # e.g. ("Art. 5", "Art. 5.1.a") — internal form
    exceptions: tuple[str, ...] = ()
    related_high_risk_anchor: str | None = None  # e.g. "Annex III" if the
    # exempted variant falls into high-risk
    effective_phase: str = "phase_2025_02_02"
    keywords: tuple[str, ...] = ()  # phrases that anchor a question to this Practice


PRACTICE_REGISTRY: dict[str, Practice] = {
    "subliminal_manipulation": Practice(
        id="subliminal_manipulation",
        sub_paragraph="5.1.a",
        short_name="Subliminal / manipulative / deceptive techniques",
        description=(
            "AI systems that deploy subliminal techniques beyond a person's "
            "consciousness, or purposefully manipulative or deceptive "
            "techniques, with the objective or effect of materially distorting "
            "a person's behaviour in a manner that causes or is reasonably "
            "likely to cause significant harm."
        ),
        citation=("Art. 5", "Art. 5.1.a"),
        exceptions=(
            "Lawful and persuasive advertising or commercial practice that the "
            "individual is aware of and can freely consent to (Recital 29).",
            "Lawful medical treatment for an established mental condition, "
            "with the patient's consent.",
        ),
        keywords=("subliminal", "manipulative technique", "deceptive technique",
                  "subliminal manipulation", "neural data"),
    ),
    "vulnerability_exploitation": Practice(
        id="vulnerability_exploitation",
        sub_paragraph="5.1.b",
        short_name="Exploitation of vulnerabilities",
        description=(
            "AI systems that exploit any of the vulnerabilities of a natural "
            "person or specific group of persons due to age, disability, or a "
            "specific social or economic situation, with the objective or effect "
            "of materially distorting their behaviour in a manner that causes or "
            "is reasonably likely to cause significant harm."
        ),
        citation=("Art. 5", "Art. 5.1.b"),
        exceptions=(
            "Incidental impact on disadvantaged groups via biased training data "
            "is regulated under Art. 10 data governance, not under this "
            "prohibition (Commission Guidelines on Prohibited Practices, "
            "Feb 2025).",
        ),
        keywords=("exploit vulnerabilities", "exploit the vulnerabilities",
                  "exploiting vulnerabilities", "vulnerable groups",
                  "elderly", "exploits the vulnerabilities"),
    ),
    "social_scoring": Practice(
        id="social_scoring",
        sub_paragraph="5.1.c",
        short_name="Social scoring",
        description=(
            "AI systems that evaluate or classify natural persons or groups "
            "based on social behaviour or known/inferred/predicted personal "
            "characteristics, with the social score leading to detrimental or "
            "unfavourable treatment in unrelated social contexts, or to "
            "treatment that is unjustified or disproportionate to their social "
            "behaviour or its gravity."
        ),
        citation=("Art. 5", "Art. 5.1.c"),
        # Art. 5(1)(c) prohibits scoring that LEADS TO detrimental treatment
        # in UNRELATED contexts. Lawful credit/risk scoring in financial
        # services isn't an "exception" to the prohibition — it's a
        # separate use case that's high-risk under Annex III(5)(b), not
        # prohibited under Art. 5(1)(c). Reworded from "exception" to
        # "boundary clarification" per the May 2026 ontology audit.
        exceptions=(
            "Credit-scoring and creditworthiness assessment of natural persons "
            "is NOT an Art. 5(1)(c) prohibition (the data is used in its "
            "original context) but instead falls into the high-risk regime "
            "under Annex III(5)(b) with Chapter III Section 2 obligations.",
        ),
        related_high_risk_anchor="Annex III",
        keywords=("social scoring", "social score"),
    ),
    "profiling_for_criminal_risk": Practice(
        id="profiling_for_criminal_risk",
        sub_paragraph="5.1.d",
        short_name="Predictive policing by personality profiling",
        description=(
            "AI systems that make risk assessments of natural persons in order "
            "to assess or predict the risk of committing a criminal offence, "
            "based solely on profiling of the person or on assessing personality "
            "traits and characteristics."
        ),
        citation=("Art. 5", "Art. 5.1.d"),
        exceptions=(
            "AI systems that support the human assessment of a person's "
            "involvement in a criminal activity based on objective and "
            "verifiable facts directly linked to the activity. These remain "
            "permitted but qualify as high-risk under Annex III(6)(d).",
        ),
        related_high_risk_anchor="Annex III",
        keywords=("predictive policing", "predicting criminality",
                  "criminal-risk profiling", "criminal risk", "criminal-risk"),
    ),
    "facial_recognition_database": Practice(
        id="facial_recognition_database",
        sub_paragraph="5.1.e",
        short_name="Untargeted facial-image scraping",
        description=(
            "AI systems that create or expand facial-recognition databases "
            "through the untargeted scraping of facial images from the "
            "internet or CCTV footage. Applies regardless of whether the "
            "database is temporary, centralised, or decentralised."
        ),
        citation=("Art. 5", "Art. 5.1.e"),
        exceptions=(
            "Targeted scraping for a specific individual (e.g. reverse image "
            "search for a missing person) remains permitted.",
            "Untargeted scraping of non-facial biometric data (voice samples) "
            "or scraping for purposes other than facial-recognition database "
            "building falls outside this prohibition.",
        ),
        keywords=("facial recognition database", "scraping facial",
                  "scraping of facial", "scraping facial images",
                  "untargeted scraping"),
    ),
    "emotion_recognition_workplace": Practice(
        id="emotion_recognition_workplace",
        sub_paragraph="5.1.f",
        short_name="Emotion recognition in workplace or education",
        description=(
            "AI systems that infer emotions of a natural person in the areas of "
            "workplace and education institutions. The Commission's guidelines "
            "interpret both contexts broadly — workplace includes selection and "
            "hiring phases; education includes vocational training."
        ),
        citation=("Art. 5", "Art. 5.1.f"),
        exceptions=(
            "Narrow medical or safety purposes (e.g. detecting pilot or driver "
            "fatigue to prevent accidents) — interpreted narrowly per "
            "Commission Guidelines.",
            "Outside workplace/education contexts the system is high-risk "
            "under Annex III(1)(c), not prohibited.",
        ),
        related_high_risk_anchor="Annex III",
        keywords=("emotion recognition", "emotion inference", "emotion detection",
                  "infer emotions"),
    ),
    "biometric_categorisation_sensitive": Practice(
        id="biometric_categorisation_sensitive",
        sub_paragraph="5.1.g",
        short_name="Biometric categorisation by sensitive attributes",
        description=(
            "Biometric categorisation systems that categorise natural persons "
            "based on their biometric data to deduce or infer race, political "
            "opinion, trade-union membership, religious or philosophical "
            "beliefs, sex life, or sexual orientation."
        ),
        citation=("Art. 5", "Art. 5.1.g"),
        exceptions=(
            "Labelling or filtering of lawfully acquired biometric datasets is "
            "permitted.",
            "Inferences of ethnic origin, health, or genetic data fall outside "
            "this prohibition but are high-risk under Annex III(1)(b).",
        ),
        related_high_risk_anchor="Annex III",
        keywords=("biometric categorisation", "biometric categorization"),
    ),
    "real_time_rbi": Practice(
        id="real_time_rbi",
        sub_paragraph="5.1.h",
        short_name="Real-time remote biometric ID in public spaces",
        description=(
            "Real-time remote biometric identification of natural persons in "
            "publicly accessible spaces by law enforcement, where the "
            "identification is made without the individual's involvement and "
            "the biometric capture-and-match has minimal delay."
        ),
        citation=("Art. 5", "Art. 5.1.h"),
        exceptions=(
            "Narrow law-enforcement exceptions with prior judicial or "
            "administrative authorisation: search for missing persons or "
            "victims of trafficking; prevention of a specific, substantial, "
            "imminent threat to life or terrorist attack; localisation of "
            "suspects in serious crimes listed in Annex II.",
            "Biometric verification (e.g. unlocking your phone) is "
            "distinguished from identification and not prohibited.",
        ),
        keywords=("real-time biometric", "real time biometric",
                  "real-time remote biometric", "biometric identification",
                  "rbi in public", "remote biometric identification"),
    ),
    "omnibus_csam_ncii": Practice(
        id="omnibus_csam_ncii",
        sub_paragraph="5.1.i",  # proposed 9th paragraph
        short_name="AI-generated CSAM / non-consensual intimate imagery (Omnibus)",
        description=(
            "Pending Digital Omnibus adoption (political agreement 7 May 2026): "
            "AI systems specifically intended to generate or modify content "
            "constituting child sexual abuse material (CSAM) or non-consensual "
            "intimate imagery of natural persons. Captured by Member State "
            "criminal law and the AI Act's Art. 50 transparency duty for "
            "synthetic content until the Omnibus takes effect."
        ),
        citation=("Art. 5",),
        exceptions=(),
        effective_phase="phase_omnibus_2026_12_02",
        keywords=("csam", "ai-generated csam", "ai csam", "nudification",
                  "non-consensual intimate", "non consensual intimate",
                  "intimate imagery"),
    ),
}


# ── Annex III categories (the 8 high-risk use cases) ─────────────────────


@dataclass(frozen=True)
class AnnexIIICategory:
    """One of the eight high-risk use-case categories enumerated in Annex III.

    Each category triggers the full Chapter III Section 2 obligations
    on providers (Arts. 8-15), the deployer duties of Art. 26, and —
    for public-sector deployers and selected private deployers — the
    Fundamental Rights Impact Assessment of Art. 27. Some categories
    also relate to specific Art. 5 prohibitions (e.g. category (1)
    biometrics borders on Art. 5(1)(g)/(h), category (6) law
    enforcement borders on Art. 5(1)(d)/(h)).
    """

    id: str
    number: int  # 1-8
    short_name: str
    description: str
    sub_points: tuple[str, ...] = ()  # sub-categories within the high-risk row
    related_prohibitions: tuple[str, ...] = ()  # Practice ids that border this category
    keywords: tuple[str, ...] = ()


ANNEX_III_REGISTRY: dict[str, AnnexIIICategory] = {
    "biometrics": AnnexIIICategory(
        id="biometrics",
        number=1,
        short_name="Biometric systems (non-prohibited variants)",
        description=(
            "AI systems intended to be used for remote biometric identification "
            "of natural persons (post-incident or not in public spaces — "
            "real-time RBI in public spaces is PROHIBITED under Art. 5(1)(h)), "
            "biometric categorisation by non-sensitive attributes, or emotion "
            "recognition outside workplaces and educational institutions."
        ),
        sub_points=("(1)(a) Remote biometric ID (non-real-time / not public-space)",
                    "(1)(b) Biometric categorisation by non-sensitive attributes",
                    "(1)(c) Emotion recognition outside workplace/education"),
        related_prohibitions=("real_time_rbi", "biometric_categorisation_sensitive",
                              "emotion_recognition_workplace"),
        keywords=("biometric identification", "post-remote biometric",
                  "emotion recognition"),
    ),
    "critical_infrastructure": AnnexIIICategory(
        id="critical_infrastructure",
        number=2,
        short_name="Critical infrastructure",
        description=(
            "AI systems intended to be used as safety components in the "
            "management and operation of critical digital infrastructure, road "
            "traffic, or the supply of water, gas, heating, or electricity."
        ),
        keywords=("critical infrastructure", "critical digital infrastructure",
                  "road traffic", "water supply", "electricity grid",
                  "energy grid", "gas supply"),
    ),
    "education_grading": AnnexIIICategory(
        id="education_grading",
        number=3,
        short_name="Education and vocational training",
        description=(
            "AI systems intended to be used for determining access or admission, "
            "evaluating learning outcomes, assessing the appropriate level of "
            "education, or monitoring prohibited behaviour during tests."
        ),
        sub_points=("(3)(a) Access / admission decisions",
                    "(3)(b) Evaluation of learning outcomes",
                    "(3)(c) Level-of-education assessment",
                    "(3)(d) Test-behaviour monitoring"),
        keywords=("education grading", "student grading", "essay grading",
                  "student assessment", "exam monitoring", "admission decisions"),
    ),
    "employment": AnnexIIICategory(
        id="employment",
        number=4,
        short_name="Employment and worker management",
        description=(
            "AI systems intended to be used for recruitment or selection of "
            "candidates (including targeted job advertisements, screening, "
            "filtering, and evaluation), or for taking employment-related "
            "decisions affecting terms, promotion, termination, task "
            "allocation, or monitoring."
        ),
        sub_points=("(4)(a) Recruitment / selection",
                    "(4)(b) Decisions affecting work relationships"),
        keywords=("cv screening", "resume screening", "hr screening",
                  "hiring decision", "candidate screening", "applicant screening",
                  "worker monitoring", "employment ai"),
    ),
    "essential_services": AnnexIIICategory(
        id="essential_services",
        number=5,
        short_name="Essential private and public services",
        description=(
            "AI systems intended to be used for: (a) eligibility for essential "
            "public assistance benefits and services (welfare, healthcare, "
            "education); (b) evaluating creditworthiness of natural persons or "
            "establishing credit scores (except detection of financial fraud); "
            "(c) risk assessment and pricing in life and health insurance for "
            "natural persons; (d) emergency-response dispatch and triage."
        ),
        sub_points=("(5)(a) Public benefit eligibility",
                    "(5)(b) Creditworthiness / credit score",
                    "(5)(c) Life/health insurance pricing",
                    "(5)(d) Emergency-response triage"),
        keywords=("credit scoring", "creditworthiness", "credit score",
                  "welfare eligibility", "insurance pricing",
                  "emergency dispatch"),
    ),
    "law_enforcement": AnnexIIICategory(
        id="law_enforcement",
        number=6,
        short_name="Law enforcement (non-prohibited variants)",
        description=(
            "AI systems intended for use by or on behalf of law-enforcement "
            "authorities for: (a) individual risk assessment as victim of "
            "criminal offence; (b) polygraph-like tools; (c) reliability of "
            "evidence; (d) profiling of natural persons in the context of "
            "detection, investigation or prosecution; (e) crime analytics. "
            "Profiling-based criminal-risk prediction of a person is "
            "PROHIBITED under Art. 5(1)(d); real-time RBI is PROHIBITED under "
            "Art. 5(1)(h)."
        ),
        related_prohibitions=("profiling_for_criminal_risk", "real_time_rbi"),
        keywords=("law enforcement", "police risk assessment", "crime analytics",
                  "evidence reliability", "criminal investigation"),
    ),
    "migration_asylum": AnnexIIICategory(
        id="migration_asylum",
        number=7,
        short_name="Migration, asylum, and border control",
        description=(
            "AI systems intended for use by or on behalf of competent public "
            "authorities for: (a) polygraph-like tools at border crossings; "
            "(b) risk assessment of irregular migrants; (c) examination of "
            "asylum, visa, or residence-permit applications; (d) detection, "
            "recognition, or identification of natural persons in migration / "
            "asylum / border-control contexts (excluding travel-document "
            "authenticity checks)."
        ),
        keywords=("asylum application", "asylum applications", "migration risk",
                  "visa application", "border control", "migrant"),
    ),
    "justice_democracy": AnnexIIICategory(
        id="justice_democracy",
        number=8,
        short_name="Administration of justice and democratic processes",
        description=(
            "AI systems intended for use by judicial authorities (or alternative "
            "dispute resolution bodies) to assist in researching and "
            "interpreting facts and law and applying the law to a specific set "
            "of facts; or AI systems intended to influence the outcome of an "
            "election or referendum, or the voting behaviour of natural persons "
            "(excluding outputs not directed at people, like administrative or "
            "logistical tools)."
        ),
        keywords=("judicial authority", "assist judges", "legal interpretation",
                  "election outcome", "voting behaviour", "voting behavior",
                  "judiciary ai"),
    ),
}


# ── Cross-entity helpers ─────────────────────────────────────────────────


def practice_for_keyword(keyword: str) -> Practice | None:
    """Return the :class:`Practice` whose ``keywords`` contains ``keyword``.

    Substring-aware case-insensitive match (mirrors the scope filter's
    keyword convention). Returns ``None`` if no Practice matches.
    """
    needle = keyword.lower().strip()
    if not needle:
        return None
    for practice in PRACTICE_REGISTRY.values():
        if any(kw in needle or needle in kw for kw in practice.keywords):
            return practice
    return None


def category_for_keyword(keyword: str) -> AnnexIIICategory | None:
    """Return the :class:`AnnexIIICategory` whose ``keywords`` contains ``keyword``."""
    needle = keyword.lower().strip()
    if not needle:
        return None
    for category in ANNEX_III_REGISTRY.values():
        if any(kw in needle or needle in kw for kw in category.keywords):
            return category
    return None


def all_articles_referenced() -> frozenset[str]:
    """Every Art./Annex referenced anywhere in the ontology.

    Used by :mod:`tests.test_kb_consistency` to verify every reference
    in the typed ontology resolves to a real entry in
    :data:`app.data.article_existence.ARTICLE_EXISTENCE`.
    """
    refs: set[str] = set()
    for practice in PRACTICE_REGISTRY.values():
        refs.update(practice.citation)
        if practice.related_high_risk_anchor:
            refs.add(practice.related_high_risk_anchor)
    for _category in ANNEX_III_REGISTRY.values():
        # The Annex III registry doesn't carry citations on the dataclass
        # because every category is implicitly Annex III + Art. 6.2 +
        # Chapter III Section 2 — but we treat "Annex III" + "Art. 6" as
        # the canonical anchor set.
        refs.update({"Annex III", "Art. 6"})
    for phase in PHASE_REGISTRY.values():
        refs.update(phase.articles)
    return frozenset(refs)


# ── Role → obligation matrix ─────────────────────────────────────────────


# Static role-obligation matrix: which articles bind each operator role
# regardless of system risk class. This is the "you don't need to ask
# what risk class — you're a deployer so Art. 26 always applies to your
# high-risk system uses" lookup. The matrix is intentionally static —
# every entry is grounded in a specific article in the Regulation, so
# the system can answer "I'm an X, what do I owe?" without LLM cost.
ROLE_OBLIGATIONS: dict[ActorRole, dict[RiskClass, tuple[str, ...]]] = {
    ActorRole.PROVIDER: {
        RiskClass.PROHIBITED: (
            "Art. 5",  # Cannot place on market — no obligations, just a ban.
        ),
        # Chapter III Section 2 = Arts. 8–15 (Section-2 requirements:
        # risk management, data governance, technical documentation,
        # record-keeping/logging, transparency, human oversight,
        # accuracy/robustness/cybersecurity). Art. 12 (record-keeping)
        # was previously missing from this list — fixed in the May 2026
        # ontology review per the senior-engineer audit.
        RiskClass.HIGH_RISK_ANNEX_I: (
            "Art. 6", "Art. 8", "Art. 9", "Art. 10", "Art. 11", "Art. 12",
            "Art. 13", "Art. 14", "Art. 15", "Art. 16", "Art. 17",
            "Art. 43", "Art. 47", "Art. 48", "Art. 49", "Art. 72",
            "Annex I", "Annex IV",
        ),
        RiskClass.HIGH_RISK_ANNEX_III: (
            "Art. 6", "Art. 8", "Art. 9", "Art. 10", "Art. 11", "Art. 12",
            "Art. 13", "Art. 14", "Art. 15", "Art. 16", "Art. 17",
            "Art. 43", "Art. 47", "Art. 48", "Art. 49", "Art. 72",
            "Annex III", "Annex IV",
        ),
        RiskClass.LIMITED_RISK: (
            "Art. 50",  # Transparency obligations only
        ),
        RiskClass.MINIMAL_RISK: (
            "Art. 4",  # AI literacy
        ),
        # GPAI provider obligations are Art. 53 (technical documentation
        # + downstream-provider info + copyright policy + training-data
        # summary) plus Annex XI / XII content schemas. Art. 54 is the
        # AUTHORISED-REPRESENTATIVE article for GPAI providers in third
        # countries — it does NOT bind GPAI providers in general. The
        # May 2026 audit caught Art. 54 incorrectly listed here; moved
        # to AUTHORISED_REPRESENTATIVE × GPAI where it correctly sits.
        RiskClass.GPAI: (
            "Art. 53",
            "Annex XI", "Annex XII",  # Technical doc + downstream-provider info
        ),
        RiskClass.GPAI_SYSTEMIC: (
            "Art. 53", "Art. 55", "Art. 56",
            "Annex XI", "Annex XII", "Annex XIII",
        ),
    },
    ActorRole.DEPLOYER: {
        RiskClass.PROHIBITED: ("Art. 5",),
        # Annex I (safety-component) deployers DON'T owe Art. 27 FRIA —
        # Art. 27(1) limits the FRIA obligation to deployers of certain
        # Annex III high-risk systems (public-sector + Annex III(5)(a)/(b)
        # selected categories). Annex I medical-device deployers operate
        # under MDR/IVDR oversight, not the FRIA regime. Fixed in the
        # May 2026 ontology audit.
        RiskClass.HIGH_RISK_ANNEX_I: (
            "Art. 26",  # General deployer obligations
            "Art. 13",  # Read & follow instructions
        ),
        RiskClass.HIGH_RISK_ANNEX_III: (
            "Art. 26", "Art. 27", "Art. 13", "Art. 86",  # right to explanation
        ),
        RiskClass.LIMITED_RISK: ("Art. 50",),
        RiskClass.MINIMAL_RISK: ("Art. 4",),
        RiskClass.GPAI: (),  # Deployer obligations attach to the AI SYSTEM, not the model
        RiskClass.GPAI_SYSTEMIC: (),
    },
    ActorRole.IMPORTER: {
        RiskClass.PROHIBITED: ("Art. 5",),
        RiskClass.HIGH_RISK_ANNEX_I: ("Art. 23",),
        RiskClass.HIGH_RISK_ANNEX_III: ("Art. 23",),
        RiskClass.LIMITED_RISK: ("Art. 23",),  # Importer still verifies marking
        RiskClass.MINIMAL_RISK: (),
        RiskClass.GPAI: (),
        RiskClass.GPAI_SYSTEMIC: (),
    },
    ActorRole.DISTRIBUTOR: {
        RiskClass.PROHIBITED: ("Art. 5",),
        RiskClass.HIGH_RISK_ANNEX_I: ("Art. 24",),
        RiskClass.HIGH_RISK_ANNEX_III: ("Art. 24",),
        RiskClass.LIMITED_RISK: ("Art. 24",),
        RiskClass.MINIMAL_RISK: (),
        RiskClass.GPAI: (),
        RiskClass.GPAI_SYSTEMIC: (),
    },
    ActorRole.AUTHORISED_REPRESENTATIVE: {
        RiskClass.HIGH_RISK_ANNEX_I: ("Art. 22",),
        RiskClass.HIGH_RISK_ANNEX_III: ("Art. 22",),
        RiskClass.GPAI: ("Art. 54",),
        RiskClass.GPAI_SYSTEMIC: ("Art. 54",),
    },
    ActorRole.DOWNSTREAM_PROVIDER: {
        RiskClass.GPAI: ("Art. 53", "Art. 89", "Annex XII"),
        RiskClass.GPAI_SYSTEMIC: ("Art. 53", "Art. 55", "Art. 89", "Annex XII"),
    },
    # Notified-body obligations live across Arts. 31 (notification),
    # 33 (requirements relating to notified bodies), and 34 (operational
    # obligations of notified bodies), with conformity-assessment
    # procedures referenced through Annex VII. The May 2026 audit
    # caught the earlier "Art. 29" entry — that's actually a deployer
    # article in the AI Act, not notified-body.
    ActorRole.NOTIFIED_BODY: {
        RiskClass.HIGH_RISK_ANNEX_I: ("Art. 31", "Art. 33", "Art. 34", "Annex VII"),
        RiskClass.HIGH_RISK_ANNEX_III: ("Art. 31", "Art. 33", "Art. 34", "Annex VII"),
    },
    ActorRole.AFFECTED_PERSON: {
        RiskClass.HIGH_RISK_ANNEX_III: ("Art. 85", "Art. 86"),
        RiskClass.HIGH_RISK_ANNEX_I: ("Art. 85", "Art. 86"),
    },
}


def obligations_for(role: ActorRole, risk_class: RiskClass) -> tuple[str, ...]:
    """Return the article/annex references that bind ``role`` when handling
    a system of ``risk_class``.

    Returns an empty tuple when the combination is structurally empty
    (e.g. deployer of GPAI — deployer obligations attach to the AI
    *system* built on top, not the underlying model).
    """
    return ROLE_OBLIGATIONS.get(role, {}).get(risk_class, ())


# ── Public API ───────────────────────────────────────────────────────────


__all__ = [
    # Enums
    "ActorRole",
    "RiskClass",
    # Dataclasses
    "Practice",
    "AnnexIIICategory",
    "Phase",
    # Registries
    "PRACTICE_REGISTRY",
    "ANNEX_III_REGISTRY",
    "PHASE_REGISTRY",
    "ROLE_OBLIGATIONS",
    # Helpers
    "practice_for_keyword",
    "category_for_keyword",
    "all_articles_referenced",
    "obligations_for",
]
