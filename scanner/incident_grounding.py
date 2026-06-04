"""Incident grounding — map scanner findings to real-world incidents.

This is the evidence layer that turns a normative gap ("you have no
prompt-injection defence — Art. 15(4)") into an evidence-based one ("...and
here are the documented incidents where exactly that gap was exploited, mapped
to OWASP LLM01 + MITRE ATLAS AML.T0051, with the published mitigations").

It crosswalks the scanner's own vocabulary — KB dimensions
(:mod:`scanner.kb`), agentic threat categories
(:mod:`scanner.data.agentic_taxonomy`), and EU AI Act article references — to
the taxonomy carried by every incident in the vendored corpus
(:mod:`scanner.data.incident_corpus`), using the match rules in
:mod:`scanner.data.incident_crosswalk`.

Pure, deterministic, offline. Same inputs always return the same ranked list.

Public API:
    incidents_for_dimension(dim_id, limit=5)
    incidents_for_threat(threat_id, limit=5)
    incidents_for_article(article, limit=5)
    incidents_for_finding(finding, limit=3)
    incident_corpus_stats()
"""

from __future__ import annotations

from typing import Any

from scanner.data.incident_corpus import ALL_INCIDENTS, CORPUS_META, Incident
from scanner.data.incident_crosswalk import (
    IncidentTags,
    MatchSpec,
    match_score,
    spec_for_dimension,
    spec_for_threat,
)
from scanner.kb import ARTICLE_TO_DIMENSIONS

_QUALITY_RANK = {"curated": 3, "reviewed": 2, "auto": 1}
_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def _tags(inc: Incident) -> IncidentTags:
    return IncidentTags(
        owasp_llm=frozenset(inc.owasp_llm),
        owasp_asi=frozenset(inc.owasp_asi),
        attack_vector=inc.attack_vector,
        mitre_atlas=frozenset(inc.mitre_atlas),
    )


# Precompute tags once — the corpus is small and immutable.
_TAGS_BY_ID: dict[str, IncidentTags] = {inc.id: _tags(inc) for inc in ALL_INCIDENTS}


def _rank_key(score: int, inc: Incident) -> tuple:
    """Deterministic ordering: relevance > vetting > severity > recency > id."""
    return (
        score,
        _QUALITY_RANK.get(inc.quality_tier, 0),
        _SEVERITY_RANK.get(inc.severity, 0),
        inc.year,
        # id descending-as-tiebreak handled by the final sort on a stable list
    )


def _match(spec: MatchSpec, limit: int) -> list[Incident]:
    scored: list[tuple[int, Incident]] = []
    for inc in ALL_INCIDENTS:
        s = match_score(_TAGS_BY_ID[inc.id], spec)
        if s > 0:
            scored.append((s, inc))
    # Sort by rank key desc, then id asc for a fully deterministic order.
    scored.sort(key=lambda t: (_rank_key(t[0], t[1]), _neg_id(t[1].id)), reverse=True)
    return [inc for _s, inc in scored[: max(0, limit)]]


def _neg_id(incident_id: str) -> tuple:
    """Tiebreak helper: makes lexically-smaller ids sort first under reverse=True."""
    # Under reverse=True the largest key wins; invert the codepoints so a
    # smaller id ("INC-00113") beats a larger one ("INC-09999") on ties.
    return tuple(-ord(c) for c in incident_id)


def incidents_for_threat(threat_id: str, limit: int = 5) -> list[Incident]:
    """Incidents that exploited a given agentic threat category.

    ``threat_id`` is a :class:`scanner.data.agentic_taxonomy.ThreatCategory`
    value, e.g. ``"prompt_injection"`` or ``"tool_misuse_privilege_escalation"``.
    Unknown ids return ``[]``.
    """
    spec = spec_for_threat(threat_id)
    return _match(spec, limit) if spec else []


def incidents_for_dimension(dim_id: str, limit: int = 5) -> list[Incident]:
    """Incidents relevant to a KB compliance dimension (e.g. ``"security"``).

    Unknown dimension ids return ``[]``.
    """
    spec = spec_for_dimension(dim_id)
    return _match(spec, limit) if spec else []


def incidents_for_article(article: str, limit: int = 5) -> list[Incident]:
    """Incidents relevant to an EU AI Act article (canonical ``artNN`` form).

    Unions the article's KB dimensions, ranks the matched incidents across all
    of them, and returns the top ``limit`` (deduplicated). Unknown articles
    return ``[]``.
    """
    dim_ids = ARTICLE_TO_DIMENSIONS.get(article.lower(), [])
    if not dim_ids:
        return []
    best: dict[str, tuple[int, Incident]] = {}
    for dim_id in dim_ids:
        spec = spec_for_dimension(dim_id)
        if not spec:
            continue
        for inc in ALL_INCIDENTS:
            s = match_score(_TAGS_BY_ID[inc.id], spec)
            if s > 0 and (inc.id not in best or s > best[inc.id][0]):
                best[inc.id] = (s, inc)
    ranked = sorted(
        best.values(),
        key=lambda t: (_rank_key(t[0], t[1]), _neg_id(t[1].id)),
        reverse=True,
    )
    return [inc for _s, inc in ranked[: max(0, limit)]]


def incidents_for_finding(finding: Any, limit: int = 3) -> list[Incident]:
    """Incidents grounding a scanner Finding.

    Prefers the finding's agentic ``threat_categories``; falls back to its
    ``compliance_dimensions``. Accepts any object exposing those attributes
    (a :class:`scanner.analyzers._base.Finding` or a duck-typed stand-in), so
    this module never imports the analyzer layer. Returns ``[]`` for findings
    with no crosswalkable signal.
    """
    threats = list(getattr(finding, "threat_categories", []) or [])
    dims = list(getattr(finding, "compliance_dimensions", []) or [])

    best: dict[str, tuple[int, Incident]] = {}
    specs = [spec_for_threat(t) for t in threats]
    specs += [spec_for_dimension(d) for d in dims]
    for spec in specs:
        if not spec:
            continue
        for inc in ALL_INCIDENTS:
            s = match_score(_TAGS_BY_ID[inc.id], spec)
            if s > 0 and (inc.id not in best or s > best[inc.id][0]):
                best[inc.id] = (s, inc)
    ranked = sorted(
        best.values(),
        key=lambda t: (_rank_key(t[0], t[1]), _neg_id(t[1].id)),
        reverse=True,
    )
    return [inc for _s, inc in ranked[: max(0, limit)]]


def incident_corpus_stats() -> dict:
    """Summary of the bundled corpus: counts, provenance, taxonomy coverage."""
    owasp_llm: set[str] = set()
    owasp_asi: set[str] = set()
    attack_vectors: set[str] = set()
    mitre: set[str] = set()
    real_world = 0
    with_mitigations = 0
    for inc in ALL_INCIDENTS:
        owasp_llm.update(inc.owasp_llm)
        owasp_asi.update(inc.owasp_asi)
        if inc.attack_vector:
            attack_vectors.add(inc.attack_vector)
        mitre.update(inc.mitre_atlas)
        if inc.category == "real-world":
            real_world += 1
        if inc.mitigations:
            with_mitigations += 1
    return {
        "count": len(ALL_INCIDENTS),
        "real_world": real_world,
        "research": len(ALL_INCIDENTS) - real_world,
        "with_mitigations": with_mitigations,
        "source": CORPUS_META.dataset_id,
        "source_url": CORPUS_META.dataset_url,
        "license": CORPUS_META.license,
        "doi": CORPUS_META.doi,
        "pip": CORPUS_META.pip,
        "last_synced": CORPUS_META.last_synced,
        "total_source_rows": CORPUS_META.total_source_rows,
        "attribution": CORPUS_META.attribution,
        "taxonomy_coverage": {
            "owasp_llm": sorted(owasp_llm),
            "owasp_asi": sorted(owasp_asi),
            "attack_vectors": sorted(attack_vectors),
            "mitre_atlas_techniques": len(mitre),
        },
    }


__all__ = [
    "incidents_for_threat",
    "incidents_for_dimension",
    "incidents_for_article",
    "incidents_for_finding",
    "incident_corpus_stats",
]
