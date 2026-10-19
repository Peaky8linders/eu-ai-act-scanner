"""Catalogue-integrity tests for the cross-framework crosswalk.

The projection is only as trustworthy as its identifiers: a fabricated or
non-canonical control ID (``MEASURE-2.3``, ``AIM-07``, ``GAI-8``) reads as a
real mapping to anyone who does not have the standard open next to it, and a
retired ID silently rots. These tests pin the ID grammar of every framework so
a wrong ID fails CI instead of shipping.
"""

from __future__ import annotations

import re

import pytest

from scanner.data.frameworks import (
    ARTICLE_FRAMEWORK_CROSSWALK,
    CANONICAL_FRAMEWORK_IDS,
    DIMENSION_CROSSWALK,
    FRAMEWORK_LABELS,
    get_crosswalk_for_article,
    normalize_framework_id,
)
from scanner.data.frameworks import CANONICAL_FRAMEWORK_IDS as _CANON

# Canonical ID grammar per framework, verified against the published catalogues:
#   NIST AI RMF 1.0      -> GV/MP/MS/MG-<category>.<subcategory>
#   ISO/IEC 42001:2023   -> clause numbers / Annex A control numbers
#   OWASP LLM 2025       -> LLM01:2025 .. LLM10:2025
#   OWASP Agentic 2025   -> ASI01 .. ASI10
#   MITRE ATLAS          -> AML.T#### techniques (threats mitigated, not controls)
#   NIST AI 600-1        -> <function>-<cat>.<subcat>-<action#>
#   CSA AICM v1.0        -> <domain>-<NN> over its 18 published domains
#   GDPR                 -> Art. <n>[(p)][(x)]
#   SOC 2                -> CC<n>.<n> / PI1.<n> / A1.<n> / C1.<n>
#   ISO/IEC 27002:2022   -> <theme>.<control>
#   NIST SP 800-53 r5    -> <FAMILY>-<n>
ID_PATTERNS: dict[str, re.Pattern[str]] = {
    "nist_ai_rmf": re.compile(r"^(GV|MP|MS|MG)-\d+\.\d+$"),
    "iso_42001": re.compile(r"^(\d+\.\d+|A\.\d+\.\d+)$"),
    "owasp_llm": re.compile(r"^LLM(0[1-9]|10):2025$"),
    "owasp_agentic": re.compile(r"^ASI(0[1-9]|10)$"),
    "mitre_atlas": re.compile(r"^AML\.T\d{4}$"),
    "nist_ai_600_1": re.compile(r"^(GV|MP|MS|MG)-\d+\.\d+-\d{3}$"),
    "csa_aicm": re.compile(
        r"^(A&A|AIS|BCR|CCC|CEK|DCS|DSP|GRC|HRS|IAM|IPY|I&S|LOG|MDS|SEF|STA|TVM|UEM)-\d{2}$"
    ),
    "gdpr": re.compile(r"^Art\. \d+(\(\d+\))?(\([a-z]\))?$"),
    "soc2": re.compile(r"^(CC\d\.\d|PI1\.\d|A1\.\d|C1\.\d)$"),
    "iso_27002": re.compile(r"^\d{1,2}\.\d{1,2}$"),
    "nist_sp_800_53": re.compile(r"^[A-Z]{2}-\d+$"),
}

# IDs that were removed/renamed upstream and must not come back.
RETIRED_IDS = {
    "AML.T0019",  # Publish Poisoned Datasets -> folded into AML.T0115
    "MEASURE-2.3",  # long form; canonical is MS-2.3
    "GOVERN-1.4",  # long form; canonical is GV-1.4
}


def _all_mappings() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for dim, mapping in DIMENSION_CROSSWALK.items():
        for fw, ids in mapping.items():
            rows.extend((f"dimension:{dim}", fw, cid) for cid in ids)
    for art, mapping in ARTICLE_FRAMEWORK_CROSSWALK.items():
        for fw, ids in mapping.items():
            rows.extend((f"article:{art}", fw, cid) for cid in ids)
    return rows


def test_id_grammar_has_a_pattern_for_every_canonical_framework() -> None:
    assert set(ID_PATTERNS) == set(_CANON)


def test_every_referenced_framework_is_canonical() -> None:
    for owner, fw, _ in _all_mappings():
        assert fw in CANONICAL_FRAMEWORK_IDS, f"{owner} uses non-canonical framework {fw!r}"
        assert fw in FRAMEWORK_LABELS, f"{owner} framework {fw!r} has no label"


def test_control_ids_match_published_grammar() -> None:
    bad = [
        (owner, fw, cid)
        for owner, fw, cid in _all_mappings()
        if not ID_PATTERNS[fw].match(cid)
    ]
    assert bad == [], f"non-canonical control IDs: {bad}"


def test_no_retired_identifiers() -> None:
    offenders = [
        (owner, fw, cid)
        for owner, fw, cid in _all_mappings()
        if cid in RETIRED_IDS or cid.startswith("GAI-")
    ]
    assert offenders == [], f"retired IDs reintroduced: {offenders}"


def test_no_duplicate_controls_within_a_framework_and_dimension() -> None:
    for dim, mapping in DIMENSION_CROSSWALK.items():
        for fw, ids in mapping.items():
            assert len(ids) == len(set(ids)), f"{dim}/{fw} has duplicates: {ids}"


def test_gdpr_uses_one_vocabulary() -> None:
    """Dimension and article tables used two spellings ('30.1' vs 'Art. 30')."""
    for owner, fw, cid in _all_mappings():
        if fw != "gdpr":
            continue
        assert cid.startswith("Art. "), f"{owner} has bare GDPR ref {cid!r}"


def test_atlas_entries_are_techniques_not_mitigations() -> None:
    """Documented contract: ATLAS maps threats the control mitigates (AML.T)."""
    for owner, fw, cid in _all_mappings():
        if fw == "mitre_atlas":
            assert cid.startswith("AML.T"), f"{owner} maps an ATLAS mitigation {cid!r}"


def test_taxonomy_display_labels_match_published_titles() -> None:
    """Labels are shown to auditors next to code findings, so a drifted or
    invented title reads as a citation. Pinned against the published lists
    (OWASP LLM Top 10 2025; MITRE ATLAS technique index)."""
    from scanner.data.incident_crosswalk import MITRE_ATLAS_LABELS, OWASP_LLM_LABELS

    assert OWASP_LLM_LABELS == {
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
    assert MITRE_ATLAS_LABELS["AML.T0010"] == "AI Supply Chain Compromise"
    assert MITRE_ATLAS_LABELS["AML.T0020"] == "Poison Training Data"
    assert MITRE_ATLAS_LABELS["AML.T0049"] == "Exploit Public-Facing Application"


def test_article_25_4_guidance_separates_legal_duty_from_paper_recommendation() -> None:
    """Art. 25(4) binds the provider of a high-risk system toward the suppliers of
    AI systems/models/tools/services/components it integrates, with a FOSS carve-out
    (GPAI models excluded). The taxonomy used to require agreements with "every
    static tool supplier" — broader than the Act — while calling tool-supplier
    cooperation merely encouraged. Wrong in opposite directions; pin the split."""
    from scanner.data.agentic_taxonomy import AGENT_ARCHETYPES, COMPOUND_RISK_TYPES

    attribution = next(r for r in COMPOUND_RISK_TYPES if r["id"] == "attribution")
    text = " ".join(
        attribution["failure_modes"]
        + attribution["mitigation_pattern"]
        + attribution["evidence_required"]
    )
    assert "every static tool supplier" not in text
    assert "carved out" in text, "FOSS carve-out must be stated with the duty"
    assert "paper recommends" in text, "paper-only guidance must be attributed"
    assert "integrated" in text, "duty is limited to integrated components"

    discovery = next(a for a in AGENT_ARCHETYPES if a["id"] == "dynamic_tool_discovery")
    assert "Falls outside Art. 25(4)" not in discovery["description"]
    assert "presupposes an identified supplier" in discovery["description"]


def test_every_taxonomy_recommendation_is_provenance_tagged() -> None:
    """Every mitigation/evidence item must be machine-classifiable.

    Prose can drift; the tag cannot. ``act_required`` must cite an Act article,
    ``paper_suggested`` must cite the paper, and the legacy string lists must
    be exactly the tagged structure flattened — never maintained separately.
    """
    from scanner.data.agentic_taxonomy import (
        COMPOUND_RISK_TYPES,
        SOURCE_LABELS,
        RecommendationKind,
        RecommendationSource,
        all_recommendations,
        recommendation_provenance_summary,
    )

    sources = {s.value for s in RecommendationSource}
    kinds = {k.value for k in RecommendationKind}
    for entry in COMPOUND_RISK_TYPES:
        recs = entry["recommendations"]
        assert recs, f"{entry['id']} carries no tagged recommendations"
        for rec in recs:
            assert rec["text"].strip(), rec
            assert rec["source"] in sources, rec
            assert rec["kind"] in kinds, rec
            assert rec["ref"].strip(), rec
            if rec["source"] == RecommendationSource.act_required.value:
                assert rec["ref"].startswith("Art. "), rec
            else:
                assert rec["ref"].startswith("paper"), rec
        assert entry["mitigation_pattern"] == [
            r["text"] for r in recs if r["kind"] == RecommendationKind.mitigation.value
        ]
        assert entry["evidence_required"] == [
            r["text"] for r in recs if r["kind"] == RecommendationKind.evidence.value
        ]

    flat = all_recommendations()
    assert len(flat) == sum(len(e["recommendations"]) for e in COMPOUND_RISK_TYPES)
    counts = recommendation_provenance_summary()
    assert set(counts) == set(SOURCE_LABELS)
    for source in RecommendationSource:
        assert counts[source.value] == sum(1 for r in flat if r["source"] == source.value)
    assert counts[RecommendationSource.act_required.value] > 0
    assert counts[RecommendationSource.paper_suggested.value] > 0


def test_attribution_duty_and_paper_extension_carry_opposite_tags() -> None:
    """The Art. 25(4) duty and the catalogue-wide extension must not share a tag."""
    from scanner.data.agentic_taxonomy import RecommendationSource, recommendations_for_risk

    recs = recommendations_for_risk("attribution")
    duty = next(r for r in recs if r["ref"] == "Art. 25(4)" and r["kind"] == "mitigation")
    extension = next(r for r in recs if "extending that written record" in r["text"])
    assert duty["source"] == RecommendationSource.act_required.value
    assert extension["source"] == RecommendationSource.paper_suggested.value
    assert extension["ref"].startswith("paper")


def test_every_kb_dimension_has_a_crosswalk() -> None:
    from scanner.kb import DIMENSIONS

    assert sorted(set(DIMENSIONS) - set(DIMENSION_CROSSWALK)) == []


def test_every_kb_article_has_a_crosswalk() -> None:
    from scanner.kb import ARTICLE_TO_DIMENSIONS

    missing = [a for a in ARTICLE_TO_DIMENSIONS if not get_crosswalk_for_article(a)]
    assert missing == [], f"KB articles with no framework projection: {missing}"


def test_crosswalk_articles_exist_in_the_kb_or_are_known_additions() -> None:
    from scanner.kb import ARTICLE_TO_DIMENSIONS

    allowed_extra = {"Art. 5", "Art. 6", "Art. 49"}
    kb_keys = set(ARTICLE_TO_DIMENSIONS)
    unknown = [
        art
        for art in ARTICLE_FRAMEWORK_CROSSWALK
        if art not in allowed_extra
        and "art" + art.split(" ", 1)[1] not in kb_keys
    ]
    assert unknown == [], f"crosswalk references articles outside the KB: {unknown}"


@pytest.mark.parametrize("spelling", ["art15", "Art. 15", "Article 15", "15", "Art. 15(4)"])
def test_article_lookup_accepts_every_spelling(spelling: str) -> None:
    cw = get_crosswalk_for_article(spelling)
    assert "nist_ai_rmf" in cw and "owasp_llm" in cw


def test_unknown_article_returns_empty_mapping() -> None:
    assert get_crosswalk_for_article("Art. 999") == {}
    assert get_crosswalk_for_article("") == {}


def test_variant_framework_ids_are_aliased() -> None:
    for variant, canonical in (
        ("owasp_llm_top10", "owasp_llm"),
        ("owasp_llm_2025", "owasp_llm"),
        ("owasp_agentic_top10", "owasp_agentic"),
    ):
        assert normalize_framework_id(variant) == canonical
