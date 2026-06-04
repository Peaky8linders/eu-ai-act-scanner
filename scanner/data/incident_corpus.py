"""Vendored GenAI & agentic-AI security incident corpus.

Loads the curated, reviewed-tier subset of the open
``emmanuelgjr/genai-incidents`` dataset (CC-BY-4.0) bundled at
``scanner/data/incidents.json``. The corpus is the evidence base for
:mod:`scanner.incident_grounding`, which crosswalks scanner findings to the
real-world incidents that exploited each gap class.

Loaded once at import via :mod:`importlib.resources` — no network calls, no
telemetry, deterministic. Regenerate the JSON with
``python scripts/sync_incident_corpus.py``.

Attribution: GenAI & Agentic AI Security Incidents dataset by Emmanuel G.
(``emmanuelgjr`` on HuggingFace), licensed CC-BY-4.0. The full dataset
(7,725+ incidents) is available via ``pip install genai-incidents`` or
``load_dataset("emmanuelgjr/genai-incidents")``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources


@dataclass(frozen=True)
class IncidentReference:
    """A source citation for an incident."""

    title: str = ""
    url: str = ""


@dataclass(frozen=True)
class Incident:
    """A single GenAI / agentic-AI security incident.

    Taxonomy facets carry the dataset's native codes verbatim:
    ``owasp_llm`` (OWASP Top 10 for LLM Applications 2025, e.g. ``LLM01``),
    ``owasp_asi`` (OWASP Agentic AI / ASI Top 10, e.g. ``ASI05``),
    ``nist_ai_rmf`` (e.g. ``MEASURE-2.7``), and ``mitre_atlas`` /
    ``mitre_atlas_tactics`` (e.g. ``AML.T0051`` / ``AML.TA0005``).
    """

    id: str
    title: str
    year: int = 0
    severity: str = ""
    category: str = ""        # real-world | vulnerability-disclosure | research | ...
    corpus: str = ""          # security | ai-harm
    attack_vector: str = ""
    description: str = ""
    owasp_llm: tuple[str, ...] = ()
    owasp_asi: tuple[str, ...] = ()
    nist_ai_rmf: tuple[str, ...] = ()
    mitre_atlas: tuple[str, ...] = ()
    mitre_atlas_tactics: tuple[str, ...] = ()
    mitigations: tuple[str, ...] = ()
    cve_ids: tuple[str, ...] = ()
    cvss_score: float | None = None
    references: tuple[IncidentReference, ...] = ()
    quality_tier: str = ""

    def to_dict(self) -> dict:
        """JSON-friendly representation (for CLI / MCP output)."""
        return {
            "id": self.id,
            "title": self.title,
            "year": self.year,
            "severity": self.severity,
            "category": self.category,
            "corpus": self.corpus,
            "attack_vector": self.attack_vector,
            "description": self.description,
            "owasp_llm": list(self.owasp_llm),
            "owasp_asi": list(self.owasp_asi),
            "nist_ai_rmf": list(self.nist_ai_rmf),
            "mitre_atlas": list(self.mitre_atlas),
            "mitre_atlas_tactics": list(self.mitre_atlas_tactics),
            "mitigations": list(self.mitigations),
            "cve_ids": list(self.cve_ids),
            "cvss_score": self.cvss_score,
            "references": [{"title": r.title, "url": r.url} for r in self.references],
            "quality_tier": self.quality_tier,
        }


@dataclass(frozen=True)
class CorpusMeta:
    """Provenance + attribution for the bundled corpus."""

    dataset_id: str = ""
    dataset_url: str = ""
    license: str = ""
    doi: str = ""
    pip: str = ""
    source_aggregation: tuple[str, ...] = ()
    crosswalk_version: str = ""
    total_source_rows: int = 0
    vetted_rows: int = 0
    selected: int = 0
    last_synced: str = ""
    attribution: str = ""

    def to_dict(self) -> dict:
        return {
            "dataset_id": self.dataset_id,
            "dataset_url": self.dataset_url,
            "license": self.license,
            "doi": self.doi,
            "pip": self.pip,
            "source_aggregation": list(self.source_aggregation),
            "crosswalk_version": self.crosswalk_version,
            "total_source_rows": self.total_source_rows,
            "vetted_rows": self.vetted_rows,
            "selected": self.selected,
            "last_synced": self.last_synced,
            "attribution": self.attribution,
        }


def _load_raw() -> dict:
    """Read the bundled incidents.json as a package resource."""
    data_pkg = resources.files("scanner.data")
    with (data_pkg / "incidents.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _build_incident(row: dict) -> Incident:
    return Incident(
        id=row["id"],
        title=row.get("title", ""),
        year=int(row.get("year") or 0),
        severity=row.get("severity", ""),
        category=row.get("category", ""),
        corpus=row.get("corpus", ""),
        attack_vector=row.get("attack_vector", ""),
        description=row.get("description", ""),
        owasp_llm=tuple(row.get("owasp_llm") or ()),
        owasp_asi=tuple(row.get("owasp_asi") or ()),
        nist_ai_rmf=tuple(row.get("nist_ai_rmf") or ()),
        mitre_atlas=tuple(row.get("mitre_atlas") or ()),
        mitre_atlas_tactics=tuple(row.get("mitre_atlas_tactics") or ()),
        mitigations=tuple(row.get("mitigations") or ()),
        cve_ids=tuple(row.get("cve_ids") or ()),
        cvss_score=row.get("cvss_score"),
        references=tuple(
            IncidentReference(title=r.get("title", ""), url=r.get("url", ""))
            for r in (row.get("references") or [])
            if isinstance(r, dict)
        ),
        quality_tier=row.get("quality_tier", ""),
    )


@lru_cache(maxsize=1)
def _corpus() -> tuple[tuple[Incident, ...], CorpusMeta]:
    raw = _load_raw()
    incidents = tuple(_build_incident(r) for r in raw.get("incidents", []))
    m = raw.get("_meta", {})
    meta = CorpusMeta(
        dataset_id=m.get("dataset_id", ""),
        dataset_url=m.get("dataset_url", ""),
        license=m.get("license", ""),
        doi=m.get("doi", ""),
        pip=m.get("pip", ""),
        source_aggregation=tuple(m.get("source_aggregation") or ()),
        crosswalk_version=m.get("crosswalk_version", ""),
        total_source_rows=int(m.get("total_source_rows") or 0),
        vetted_rows=int(m.get("vetted_rows") or 0),
        selected=int(m.get("selected") or len(incidents)),
        last_synced=m.get("last_synced", ""),
        attribution=m.get("attribution", ""),
    )
    return incidents, meta


# Eager module-level handles (cheap; ~88 records). Computed once.
ALL_INCIDENTS: tuple[Incident, ...] = _corpus()[0]
CORPUS_META: CorpusMeta = _corpus()[1]
INCIDENT_BY_ID: dict[str, Incident] = {inc.id: inc for inc in ALL_INCIDENTS}


def get_incident(incident_id: str) -> Incident | None:
    """Return one incident by id (e.g. ``INC-00671``), or None."""
    return INCIDENT_BY_ID.get(incident_id)


__all__ = [
    "Incident",
    "IncidentReference",
    "CorpusMeta",
    "ALL_INCIDENTS",
    "CORPUS_META",
    "INCIDENT_BY_ID",
    "get_incident",
]
