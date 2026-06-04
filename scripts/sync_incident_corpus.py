"""Regenerate the vendored incident corpus from the open dataset.

Source: ``emmanuelgjr/genai-incidents`` on HuggingFace (CC-BY-4.0), an
aggregated, de-duplicated corpus of 7,725+ real-world and research GenAI &
agentic-AI security incidents mapped to OWASP LLM Top 10 (2025), OWASP Agentic
AI (ASI) Top 10, NIST AI RMF, and MITRE ATLAS.

This script downloads the published parquet, keeps only the maintainer-vetted
tiers (``reviewed`` + ``curated``), and selects a *coverage-complete* subset:
for every crosswalk target in :mod:`scanner.data.incident_crosswalk` it keeps
the top-ranked incidents, so the bundled snapshot can ground a finding for
every KB dimension and threat category the scanner emits. The output is a
deterministic JSON file (sorted, truncated, ASCII-normalised) committed at
``scanner/data/incidents.json``.

Why vendored: the scanner is local-only by design (no network calls, no
telemetry). The full dataset stays one ``pip install genai-incidents`` away;
the bundled subset gives offline grounding out of the box.

Usage:
    python -m pip install pyarrow requests
    python scripts/sync_incident_corpus.py            # regenerate in place
    python scripts/sync_incident_corpus.py --max 160  # tune the cap

Re-run when the upstream dataset publishes a new revision. Review the diff:
incidents are real, named, and citable — the change set should make sense.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import unicodedata
import urllib.request
from pathlib import Path

# Make the sibling ``scanner`` package importable when run as a script.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scanner.data.incident_crosswalk import (  # noqa: E402
    ALL_SPEC_KEYS,
    CROSSWALK_VERSION,
    IncidentTags,
    match_score,
)

PARQUET_URL = (
    "https://huggingface.co/datasets/emmanuelgjr/genai-incidents/"
    "resolve/refs%2Fconvert%2Fparquet/default/train/0000.parquet"
)
DATASET_ID = "emmanuelgjr/genai-incidents"
DATASET_URL = "https://huggingface.co/datasets/emmanuelgjr/genai-incidents"
DATASET_LICENSE = "CC-BY-4.0"
DATASET_DOI = "10.57967/hf/genai-incidents"  # placeholder until the minted DOI is confirmed
DATASET_PIP = "genai-incidents"
SOURCE_AGGREGATION = [
    "AIID", "OECD AIM", "AIAAIC", "MITRE ATLAS", "AVID",
    "MIT AI Risk Repository", "NVD", "GHSA", "OSV", "garak", "promptfoo",
]

OUT_PATH = _REPO_ROOT / "scanner" / "data" / "incidents.json"

_QUALITY_RANK = {"curated": 3, "reviewed": 2, "auto": 1}
_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
_VETTED_TIERS = {"reviewed", "curated"}

_ASCII_FIXUPS = {
    "—": "-", "–": "-", "→": "->", "←": "<-",
    "‘": "'", "’": "'", "“": '"', "”": '"',
    "…": "...", "•": "-", " ": " ", "▸": ">",
}


def _ascii(text: str) -> str:
    """Normalise text to clean ASCII for a vendored, diff-friendly data file."""
    if not text:
        return ""
    for bad, good in _ASCII_FIXUPS.items():
        text = text.replace(bad, good)
    text = unicodedata.normalize("NFKD", text)
    return text.encode("ascii", "ignore").decode("ascii").strip()


def _truncate(text: str, limit: int) -> str:
    text = _ascii(text)
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _str_list(values, limit: int, item_cap: int = 200) -> list[str]:
    out: list[str] = []
    for v in values or []:
        s = _truncate(str(v), item_cap)
        if s:
            out.append(s)
        if len(out) >= limit:
            break
    return out


def _refs(values, limit: int = 2) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for r in values or []:
        if not isinstance(r, dict):
            continue
        url = _ascii(str(r.get("url", "")))
        if not url:
            continue
        out.append({"title": _truncate(str(r.get("title", "")), 140), "url": url})
        if len(out) >= limit:
            break
    return out


def _download_parquet(dst: Path) -> None:
    if dst.exists() and dst.stat().st_size > 1_000_000:
        print(f"  using cached parquet: {dst} ({dst.stat().st_size:,} bytes)")
        return
    print(f"  downloading {PARQUET_URL}")
    urllib.request.urlretrieve(PARQUET_URL, dst)  # noqa: S310 - pinned HTTPS HF URL
    print(f"  saved {dst} ({dst.stat().st_size:,} bytes)")


def _tags(row: dict) -> IncidentTags:
    return IncidentTags(
        owasp_llm=frozenset(row.get("owasp_llm") or []),
        owasp_asi=frozenset(row.get("owasp_asi") or []),
        attack_vector=str(row.get("attack_vector") or ""),
        mitre_atlas=frozenset(row.get("mitre_atlas") or []),
    )


def _quality_key(row: dict) -> tuple:
    """Deterministic ranking key: vetting > severity > evidence > recency."""
    return (
        _QUALITY_RANK.get(row.get("quality_tier", ""), 0),
        _SEVERITY_RANK.get(row.get("severity", ""), 0),
        1 if (row.get("mitigations") or []) else 0,
        1 if (row.get("references") or []) else 0,
        int(row.get("year") or 0),
        str(row.get("id") or ""),
    )


def _project(row: dict) -> dict:
    """Shrink a raw row to the vendored record shape (ASCII, truncated)."""
    return {
        "id": _ascii(str(row.get("id", ""))),
        "title": _truncate(str(row.get("title", "")), 180),
        "year": int(row.get("year") or 0),
        "severity": _ascii(str(row.get("severity", ""))),
        "category": _ascii(str(row.get("category", ""))),
        "corpus": _ascii(str(row.get("corpus", ""))),
        "attack_vector": _ascii(str(row.get("attack_vector", ""))),
        "description": _truncate(str(row.get("description", "")), 360),
        "owasp_llm": sorted(row.get("owasp_llm") or []),
        "owasp_asi": sorted(row.get("owasp_asi") or []),
        "nist_ai_rmf": sorted(row.get("nist_ai_rmf") or []),
        "mitre_atlas": sorted(row.get("mitre_atlas") or []),
        "mitre_atlas_tactics": sorted(row.get("mitre_atlas_tactics") or []),
        "mitigations": _str_list(row.get("mitigations"), limit=4),
        "cve_ids": _str_list(row.get("cve_ids"), limit=6, item_cap=24),
        "cvss_score": (
            round(float(row["cvss_score"]), 1)
            if row.get("cvss_score") not in (None, "")
            else None
        ),
        "references": _refs(row.get("references")),
        "quality_tier": _ascii(str(row.get("quality_tier", ""))),
    }


def build(max_total: int, per_bucket: int) -> dict:
    import pyarrow.parquet as pq

    cache = Path(__file__).resolve().parent / ".genai-incidents.parquet"
    _download_parquet(cache)
    rows = pq.read_table(cache).to_pylist()
    total_source = len(rows)
    vetted = [r for r in rows if r.get("quality_tier") in _VETTED_TIERS]
    print(f"  source rows: {total_source:,} | vetted (reviewed+curated): {len(vetted):,}")

    # Coverage-complete selection: for every crosswalk target, keep the
    # top-`per_bucket` vetted incidents by (match_score, quality). Union the
    # picks so every KB dimension + threat category is groundable.
    selected: dict[str, dict] = {}
    coverage: dict[str, int] = {}
    for key, spec in ALL_SPEC_KEYS:
        scored = []
        for r in vetted:
            s = match_score(_tags(r), spec)
            if s > 0:
                scored.append((s, _quality_key(r), r))
        scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
        picked = scored[:per_bucket]
        coverage[key] = len(picked)
        for _s, _q, r in picked:
            rid = str(r.get("id", ""))
            if rid and rid not in selected:
                selected[rid] = r

    # Respect a soft cap: if over, drop the lowest-quality records that are not
    # the *sole* representative of any bucket (preserve coverage first).
    if len(selected) > max_total:
        sole = _sole_representatives(selected, vetted, per_bucket)
        droppable = [r for rid, r in selected.items() if rid not in sole]
        droppable.sort(key=_quality_key)  # worst first
        for r in droppable:
            if len(selected) <= max_total:
                break
            selected.pop(str(r.get("id", "")), None)

    records = sorted((_project(r) for r in selected.values()), key=lambda x: x["id"])
    print(f"  selected: {len(records)} incidents covering {sum(1 for v in coverage.values() if v)} / {len(coverage)} buckets")

    meta = {
        "dataset_id": DATASET_ID,
        "dataset_url": DATASET_URL,
        "license": DATASET_LICENSE,
        "doi": DATASET_DOI,
        "pip": DATASET_PIP,
        "source_aggregation": SOURCE_AGGREGATION,
        "crosswalk_version": CROSSWALK_VERSION,
        "total_source_rows": total_source,
        "vetted_rows": len(vetted),
        "selected": len(records),
        "quality_tiers_included": sorted(_VETTED_TIERS),
        "last_synced": _dt.date.today().isoformat(),
        "attribution": (
            "GenAI & Agentic AI Security Incidents dataset by Emmanuel G. "
            "(emmanuelgjr), HuggingFace, licensed CC-BY-4.0. Bundled subset is "
            "a curated, reviewed-tier derivative used for offline incident "
            "grounding; the full dataset is available via "
            "`pip install genai-incidents`."
        ),
    }
    return {"_meta": meta, "incidents": records}


def _sole_representatives(selected: dict, vetted: list, per_bucket: int) -> set[str]:
    """IDs that are the only selected match for at least one crosswalk bucket."""
    sole: set[str] = set()
    for _key, spec in ALL_SPEC_KEYS:
        matched = [rid for rid, r in selected.items() if match_score(_tags(r), spec) > 0]
        if len(matched) == 1:
            sole.add(matched[0])
    return sole


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Regenerate scanner/data/incidents.json")
    ap.add_argument("--max", type=int, default=160, help="soft cap on bundled incidents")
    ap.add_argument("--per-bucket", type=int, default=6, help="top-N per crosswalk target")
    args = ap.parse_args(argv)

    print("Regenerating vendored incident corpus ...")
    payload = build(args.max, args.per_bucket)
    OUT_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"  wrote {OUT_PATH} ({OUT_PATH.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
