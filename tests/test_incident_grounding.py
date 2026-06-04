"""Tests for the incident-grounding feature (v0.4).

Covers corpus integrity, crosswalk correctness, grounding API behaviour,
coverage guarantees, and end-to-end integration with the analyzer + orchestrator
pipeline.

Conventions match ``test_scanners.py`` and ``test_agent_aware_scanners.py``:
classes group related assertions; helpers are module-level functions.
"""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from scanner.analyzers import AnalyzerContext, run_all_analyzers
from scanner.data.agentic_taxonomy import ThreatCategory
from scanner.data.incident_corpus import (
    ALL_INCIDENTS,
    CORPUS_META,
    INCIDENT_BY_ID,
    Incident,
    get_incident,
)
from scanner.data.incident_crosswalk import (
    DIMENSION_TO_SPEC,
    THREAT_TO_SPEC,
    IncidentTags,
    MatchSpec,
    match_score,
)
from scanner.incident_grounding import (
    incident_corpus_stats,
    incidents_for_article,
    incidents_for_dimension,
    incidents_for_finding,
    incidents_for_threat,
)
from scanner.kb import DIMENSIONS

FIXTURE = Path(__file__).parent / "fixtures" / "sample_project"


# ── helpers ──────────────────────────────────────────────────────────────────


def _build_ctx(files: dict[str, str]) -> AnalyzerContext:
    """Build an AnalyzerContext from a dict of {path: content} — same
    pattern used in test_agent_aware_scanners.py."""
    return AnalyzerContext(
        files=files,
        file_list=list(files.keys()),
        languages={"python": len(files)},
    )


def _load_fixture_ctx() -> AnalyzerContext:
    """Load the sample_project fixture the same way test_scanners.py does."""
    files: dict[str, str] = {}
    for p in FIXTURE.rglob("*"):
        if p.is_file():
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                files[str(p.relative_to(FIXTURE))] = content
            except OSError:
                pass
    return AnalyzerContext(
        files=files,
        file_list=list(files.keys()),
        languages={"python": len(files)},
    )


# ── TestIncidentCorpus ────────────────────────────────────────────────────────


class TestIncidentCorpus:
    def test_all_incidents_non_empty(self):
        assert len(ALL_INCIDENTS) > 0

    def test_incident_ids_unique(self):
        ids = [inc.id for inc in ALL_INCIDENTS]
        assert len(ids) == len(set(ids)), "duplicate incident ids found"

    def test_every_incident_id_non_empty(self):
        for inc in ALL_INCIDENTS:
            assert inc.id, f"incident with empty id: {inc!r}"

    def test_corpus_meta_license(self):
        assert CORPUS_META.license == "CC-BY-4.0"

    def test_corpus_meta_dataset_id_non_empty(self):
        assert CORPUS_META.dataset_id, "dataset_id is empty"

    def test_every_incident_has_taxonomy_signal(self):
        """Each incident must carry at least one classifiable taxonomy signal."""
        for inc in ALL_INCIDENTS:
            has_signal = (
                bool(inc.owasp_llm)
                or bool(inc.owasp_asi)
                or bool(inc.mitre_atlas)
                or bool(inc.attack_vector)
            )
            assert has_signal, f"{inc.id} has no taxonomy signal"

    def test_get_incident_round_trips(self):
        first_id = ALL_INCIDENTS[0].id
        result = get_incident(first_id)
        assert isinstance(result, Incident)
        assert result.id == first_id

    def test_get_incident_unknown_returns_none(self):
        assert get_incident("nope") is None

    def test_incident_by_id_lookup(self):
        first_id = ALL_INCIDENTS[0].id
        assert INCIDENT_BY_ID[first_id].id == first_id

    def test_to_dict_is_json_serializable(self):
        for inc in ALL_INCIDENTS[:10]:
            d = inc.to_dict()
            # Should not raise
            json.dumps(d)

    def test_to_dict_contains_required_keys(self):
        d = ALL_INCIDENTS[0].to_dict()
        for key in ("id", "title", "owasp_llm", "attack_vector", "mitre_atlas"):
            assert key in d, f"to_dict() missing key {key!r}"

    def test_corpus_count_is_at_least_ten(self):
        """Corpus floor guard — not exact so re-syncs don't break the suite."""
        assert len(ALL_INCIDENTS) >= 10


# ── TestIncidentCrosswalk ─────────────────────────────────────────────────────


class TestIncidentCrosswalk:
    def test_empty_spec_scores_zero(self):
        assert match_score(IncidentTags(), MatchSpec()) == 0

    def test_owasp_llm_overlap_scores_positive(self):
        tags = IncidentTags(owasp_llm=frozenset({"LLM01"}))
        spec = MatchSpec(owasp_llm=frozenset({"LLM01", "LLM07"}))
        assert match_score(tags, spec) > 0

    def test_attack_vector_match_scores_positive(self):
        tags = IncidentTags(attack_vector="prompt-injection")
        spec = MatchSpec(attack_vectors=frozenset({"prompt-injection", "jailbreak"}))
        assert match_score(tags, spec) > 0

    def test_owasp_asi_booster_scores_positive(self):
        tags = IncidentTags(owasp_asi=frozenset({"ASI05"}))
        spec = MatchSpec(owasp_asi_any=True)
        assert match_score(tags, spec) > 0

    def test_mitre_atlas_overlap_scores_positive(self):
        tags = IncidentTags(mitre_atlas=frozenset({"AML.T0051"}))
        spec = MatchSpec(mitre_atlas=frozenset({"AML.T0051"}))
        assert match_score(tags, spec) > 0

    def test_combined_signal_scores_higher_than_single(self):
        """Attack-vector + OWASP LLM should outscore OWASP LLM alone."""
        tags_single = IncidentTags(owasp_llm=frozenset({"LLM01"}))
        tags_both = IncidentTags(
            owasp_llm=frozenset({"LLM01"}),
            attack_vector="prompt-injection",
        )
        spec = MatchSpec(
            owasp_llm=frozenset({"LLM01"}),
            attack_vectors=frozenset({"prompt-injection"}),
        )
        assert match_score(tags_both, spec) > match_score(tags_single, spec)

    def test_constructed_prompt_injection_tags_score_against_spec(self):
        tags = IncidentTags(
            owasp_llm=frozenset({"LLM01"}),
            attack_vector="prompt-injection",
        )
        spec = THREAT_TO_SPEC["prompt_injection"]
        assert match_score(tags, spec) > 0

    def test_no_overlap_scores_zero(self):
        tags = IncidentTags(owasp_llm=frozenset({"LLM03"}))
        spec = MatchSpec(owasp_llm=frozenset({"LLM01"}))
        assert match_score(tags, spec) == 0

    def test_threat_to_spec_keys_are_valid_threat_categories(self):
        valid_values = {tc.value for tc in ThreatCategory}
        for key in THREAT_TO_SPEC:
            assert key in valid_values, f"THREAT_TO_SPEC key {key!r} not a ThreatCategory value"

    def test_dimension_to_spec_keys_are_valid_kb_dimensions(self):
        for key in DIMENSION_TO_SPEC:
            assert key in DIMENSIONS, f"DIMENSION_TO_SPEC key {key!r} not in DIMENSIONS"


# ── TestIncidentGrounding ─────────────────────────────────────────────────────


class TestIncidentGrounding:
    # ── incidents_for_dimension ──────────────────────────────────────────

    def test_incidents_for_security_dimension_non_empty(self):
        results = incidents_for_dimension("security")
        assert len(results) > 0

    def test_incidents_for_dimension_respects_limit(self):
        results = incidents_for_dimension("security", 2)
        assert len(results) <= 2

    def test_incidents_for_dimension_default_limit_at_most_five(self):
        results = incidents_for_dimension("security")
        assert len(results) <= 5

    def test_incidents_for_dimension_returns_incident_objects(self):
        results = incidents_for_dimension("security", 3)
        for inc in results:
            assert isinstance(inc, Incident)

    def test_incidents_for_dimension_deterministic(self):
        a = [inc.id for inc in incidents_for_dimension("security", 5)]
        b = [inc.id for inc in incidents_for_dimension("security", 5)]
        assert a == b, "incidents_for_dimension is not deterministic"

    def test_incidents_for_dimension_unknown_returns_empty(self):
        assert incidents_for_dimension("nope") == []

    # ── incidents_for_threat ─────────────────────────────────────────────

    def test_incidents_for_prompt_injection_non_empty(self):
        results = incidents_for_threat("prompt_injection")
        assert len(results) > 0

    def test_incidents_for_threat_returns_incident_objects(self):
        results = incidents_for_threat("prompt_injection", 2)
        for inc in results:
            assert isinstance(inc, Incident)

    def test_incidents_for_threat_unknown_returns_empty(self):
        assert incidents_for_threat("nope") == []

    def test_incidents_for_threat_respects_limit(self):
        results = incidents_for_threat("prompt_injection", 2)
        assert len(results) <= 2

    # ── incidents_for_article ────────────────────────────────────────────

    def test_incidents_for_art15_non_empty(self):
        results = incidents_for_article("art15")
        assert len(results) > 0

    def test_incidents_for_article_returns_incident_objects(self):
        for inc in incidents_for_article("art15"):
            assert isinstance(inc, Incident)

    def test_incidents_for_article_unknown_returns_empty(self):
        assert incidents_for_article("art999") == []

    def test_incidents_for_article_case_insensitive(self):
        lower = incidents_for_article("art15")
        upper = incidents_for_article("Art15")
        assert [i.id for i in lower] == [i.id for i in upper]

    # ── incidents_for_finding ────────────────────────────────────────────

    def test_incidents_for_finding_with_threat_signal(self):
        finding = types.SimpleNamespace(
            threat_categories=["prompt_injection"],
            compliance_dimensions=["security"],
        )
        results = incidents_for_finding(finding)
        assert len(results) > 0

    def test_incidents_for_finding_with_no_signal_returns_empty(self):
        finding = types.SimpleNamespace(
            threat_categories=[],
            compliance_dimensions=[],
        )
        assert incidents_for_finding(finding) == []

    def test_incidents_for_finding_with_only_dimension_signal(self):
        finding = types.SimpleNamespace(
            threat_categories=[],
            compliance_dimensions=["data_gov"],
        )
        results = incidents_for_finding(finding)
        assert len(results) > 0

    def test_incidents_for_finding_returns_incident_objects(self):
        finding = types.SimpleNamespace(
            threat_categories=["prompt_injection"],
            compliance_dimensions=[],
        )
        for inc in incidents_for_finding(finding):
            assert isinstance(inc, Incident)

    def test_incidents_for_finding_limit_respected(self):
        finding = types.SimpleNamespace(
            threat_categories=["prompt_injection"],
            compliance_dimensions=["security"],
        )
        results = incidents_for_finding(finding, limit=1)
        assert len(results) <= 1

    def test_incidents_for_finding_missing_attrs_tolerated(self):
        """incidents_for_finding must handle objects with missing attributes."""
        bare = types.SimpleNamespace()
        # Should not raise; gracefully returns empty
        results = incidents_for_finding(bare)
        assert isinstance(results, list)

    # ── incident_corpus_stats ────────────────────────────────────────────

    def test_stats_count_positive(self):
        stats = incident_corpus_stats()
        assert stats["count"] > 0

    def test_stats_license(self):
        assert incident_corpus_stats()["license"] == "CC-BY-4.0"

    def test_stats_taxonomy_coverage_keys(self):
        tc = incident_corpus_stats()["taxonomy_coverage"]
        for key in ("owasp_llm", "owasp_asi", "attack_vectors", "mitre_atlas_techniques"):
            assert key in tc, f"taxonomy_coverage missing key {key!r}"

    def test_stats_taxonomy_owasp_llm_non_empty(self):
        tc = incident_corpus_stats()["taxonomy_coverage"]
        assert len(tc["owasp_llm"]) > 0

    def test_stats_taxonomy_attack_vectors_non_empty(self):
        tc = incident_corpus_stats()["taxonomy_coverage"]
        assert len(tc["attack_vectors"]) > 0

    def test_stats_mitre_atlas_techniques_count_positive(self):
        tc = incident_corpus_stats()["taxonomy_coverage"]
        assert tc["mitre_atlas_techniques"] > 0


# ── TestIncidentGroundingCoverageGuarantee ────────────────────────────────────


class TestIncidentGroundingCoverageGuarantee:
    """Regression guards: every crosswalk key must resolve to ≥1 incident.

    The bundled corpus is curated to ensure this — these tests catch a
    corpus re-sync or crosswalk edit that drops coverage.
    """

    @pytest.mark.parametrize("threat_id", sorted(THREAT_TO_SPEC.keys()))
    def test_every_threat_has_at_least_one_incident(self, threat_id: str):
        results = incidents_for_threat(threat_id)
        assert len(results) >= 1, (
            f"incidents_for_threat({threat_id!r}) returned no incidents — "
            "corpus or crosswalk may have lost coverage for this threat bucket"
        )

    @pytest.mark.parametrize("dim_id", sorted(DIMENSION_TO_SPEC.keys()))
    def test_every_dimension_has_at_least_one_incident(self, dim_id: str):
        results = incidents_for_dimension(dim_id)
        assert len(results) >= 1, (
            f"incidents_for_dimension({dim_id!r}) returned no incidents — "
            "corpus or crosswalk may have lost coverage for this dimension"
        )


# ── TestIncidentGroundingIntegration ─────────────────────────────────────────


class TestIncidentGroundingIntegration:
    """End-to-end: analyzer pipeline + orchestrator wiring."""

    @pytest.fixture(scope="class")
    def all_findings(self):
        ctx = _load_fixture_ctx()
        results = run_all_analyzers(ctx)
        return [f for r in results for f in r.findings]

    def test_at_least_one_gap_finding_has_incidents(self, all_findings):
        gap_findings = [f for f in all_findings if f.compliance_impact == "gap"]
        assert len(gap_findings) > 0, "no gap findings in fixture project"
        grounded = [f for f in gap_findings if f.related_incidents]
        assert len(grounded) >= 1, "no gap finding has related_incidents"

    def test_positive_findings_have_empty_related_incidents(self, all_findings):
        positive = [f for f in all_findings if f.compliance_impact == "positive"]
        for f in positive:
            assert f.related_incidents == [], (
                f"positive finding {f.id!r} unexpectedly carries related_incidents"
            )

    def test_incident_ids_in_findings_resolve_to_incidents(self, all_findings):
        """Every id stored in related_incidents must be a valid corpus id."""
        for f in all_findings:
            for inc_id in f.related_incidents:
                resolved = get_incident(inc_id)
                assert resolved is not None, (
                    f"finding {f.id!r} references unknown incident id {inc_id!r}"
                )
                assert isinstance(resolved, Incident)

    def test_scan_project_incident_grounding_is_dict(self):
        from scanner import scan_project

        result = scan_project(FIXTURE)
        assert isinstance(result.incident_grounding, dict)

    def test_scan_project_incident_grounding_ids_resolve(self):
        from scanner import scan_project

        result = scan_project(FIXTURE)
        for dim_id, inc_ids in result.incident_grounding.items():
            assert isinstance(inc_ids, list), f"{dim_id!r} value is not a list"
            for inc_id in inc_ids:
                resolved = get_incident(inc_id)
                assert resolved is not None, (
                    f"scan_project incident_grounding[{dim_id!r}] contains "
                    f"unknown id {inc_id!r}"
                )
