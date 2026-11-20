"""Per-repo opt-in local baseline tracking and diffing for EU AI Act Scanner.

Allows teams to snapshot a local scan baseline (e.g. `.ai-act-baseline.json`)
and compare subsequent scans to track progress, detect regressions, and prove
remediation deltas in PR reviews — purely locally and deterministically.

Contract:
- Never mutates scanner confidence scores or any field on ``ScanResult``.
- Atomic writes via ``tempfile.NamedTemporaryFile`` + ``os.replace``.
- Pure stdlib + Pydantic, 100% offline, zero remote URLs.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from scanner.models import DiscoveredComponent, ScanResult

_BASELINE_SCHEMA_VERSION = "1.0"
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _gap_id(comp: DiscoveredComponent) -> str:
    """Derive a stable, deterministic identifier for a gap component."""
    if isinstance(comp.details, dict):
        explicit = comp.details.get("id") or comp.details.get("rule_id")
        if isinstance(explicit, str) and explicit.strip():
            return explicit.strip()
    comp_type = _SLUG_RE.sub("-", comp.component_type.lower()).strip("-") or "gap"
    title_slug = _SLUG_RE.sub("-", comp.name.lower()).strip("-")[:48].rstrip("-") or "finding"
    file_slug = _SLUG_RE.sub("-", comp.file_path.replace("\\", "/").lower()).strip("-")[:40].rstrip("-")
    if file_slug:
        return f"{comp_type}:{title_slug}:{file_slug}"
    return f"{comp_type}:{title_slug}"


def _extract_gaps(result: ScanResult) -> list[dict[str, Any]]:
    """Extract sorted, deduplicated gap records from a ``ScanResult``."""
    by_id: dict[str, dict[str, Any]] = {}
    for comp in result.components:
        if comp.compliance_impact != "gap":
            continue
        gid = _gap_id(comp)
        if gid not in by_id:
            by_id[gid] = {
                "id": gid,
                "title": comp.name,
                "component_type": comp.component_type,
                "file_path": comp.file_path.replace("\\", "/"),
                "dimensions": sorted(comp.compliance_dimensions),
            }
    return [by_id[k] for k in sorted(by_id)]


def save_baseline(result: ScanResult, path: Path | str) -> Path:
    """Atomically save a local baseline snapshot from ``result`` to ``path``.

    Uses ``tempfile.NamedTemporaryFile`` in the destination directory followed
    by ``os.replace`` so interrupted writes can never corrupt an existing
    baseline file.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    payload: dict[str, Any] = {
        "schema_version": _BASELINE_SCHEMA_VERSION,
        "project_name": result.project_name,
        "scan_id": result.scan_id,
        "scanner_version": result.scanner_version,
        "is_ai_system": bool(result.is_ai_system),
        "overall_score": round(float(result.overall_compliance_pct), 1),
        "dimension_scores": {
            dim_id: round(float(score), 1)
            for dim_id, score in sorted(result.compliance_scores.items())
        },
        "gaps": _extract_gaps(result),
    }

    serialized = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_path = Path(handle.name)
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise

    return target


def _load_baseline(baseline_path: Path) -> dict[str, Any]:
    if not baseline_path.is_file():
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")
    try:
        raw = baseline_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid baseline JSON in {baseline_path}: {exc}") from exc

    if not isinstance(data, dict) or "overall_score" not in data or "dimension_scores" not in data:
        raise ValueError(
            f"Malformed baseline file {baseline_path}: missing 'overall_score' or 'dimension_scores'"
        )
    return data


def diff_baseline(result: ScanResult, baseline_path: Path | str) -> dict[str, Any]:
    """Compare ``result`` against a saved local baseline without mutating ``result``."""
    baseline = _load_baseline(Path(baseline_path))

    baseline_overall = round(float(baseline.get("overall_score", 0.0)), 1)
    current_overall = round(float(result.overall_compliance_pct), 1)
    score_delta = round(current_overall - baseline_overall, 1)

    baseline_dims_raw = baseline.get("dimension_scores") or {}
    baseline_dims: dict[str, float] = {
        str(k): round(float(v), 1) for k, v in baseline_dims_raw.items()
    }
    current_dims: dict[str, float] = {
        str(k): round(float(v), 1) for k, v in result.compliance_scores.items()
    }

    all_dims = sorted(set(baseline_dims) | set(current_dims))
    dimension_deltas: dict[str, float] = {
        dim_id: round(current_dims.get(dim_id, 0.0) - baseline_dims.get(dim_id, 0.0), 1)
        for dim_id in all_dims
    }

    baseline_gaps_list = [
        g for g in (baseline.get("gaps") or []) if isinstance(g, dict) and isinstance(g.get("id"), str)
    ]
    baseline_by_id: dict[str, dict[str, Any]] = {g["id"]: g for g in baseline_gaps_list}

    current_gaps_list = _extract_gaps(result)
    current_by_id: dict[str, dict[str, Any]] = {g["id"]: g for g in current_gaps_list}

    baseline_ids = set(baseline_by_id)
    current_ids = set(current_by_id)

    fixed_gaps = [baseline_by_id[gid] for gid in sorted(baseline_ids - current_ids)]
    new_gaps = [current_by_id[gid] for gid in sorted(current_ids - baseline_ids)]
    unchanged_gap_count = len(baseline_ids & current_ids)

    return {
        "project_name": result.project_name,
        "baseline_is_ai_system": bool(baseline.get("is_ai_system", True)),
        "current_is_ai_system": bool(result.is_ai_system),
        "baseline_overall_score": baseline_overall,
        "current_overall_score": current_overall,
        "score_delta": score_delta,
        "fixed_gaps": fixed_gaps,
        "new_gaps": new_gaps,
        "unchanged_gap_count": unchanged_gap_count,
        "dimension_deltas": dimension_deltas,
    }


def _signed(value: float) -> str:
    if value > 0:
        return f"+{value:.1f}"
    if value < 0:
        return f"{value:.1f}"
    return "0.0"


def format_baseline_diff(diff: dict[str, Any]) -> str:
    """Format a baseline diff dictionary as crisp, offline-safe Markdown."""
    baseline_score = float(diff.get("baseline_overall_score", 0.0))
    current_score = float(diff.get("current_overall_score", 0.0))
    delta = float(diff.get("score_delta", 0.0))
    fixed_gaps = diff.get("fixed_gaps") or []
    new_gaps = diff.get("new_gaps") or []
    unchanged = int(diff.get("unchanged_gap_count", 0))
    dim_deltas: dict[str, float] = diff.get("dimension_deltas") or {}

    lines = [
        f"# Baseline Diff — {diff.get('project_name', 'Project')}",
        "",
        f"- **Overall score**: {baseline_score:.1f}% -> **{current_score:.1f}%** (`{_signed(delta)} pts`)",
        f"- **Fixed gaps**: {len(fixed_gaps)} | **New gaps**: {len(new_gaps)} | **Unchanged gaps**: {unchanged}",
    ]

    if fixed_gaps:
        lines.append("")
        lines.append("## Fixed Gaps")
        for gap in fixed_gaps:
            loc = f" (`{gap['file_path']}`)" if gap.get("file_path") else ""
            lines.append(f"- [FIXED] {gap.get('title', gap.get('id', 'gap'))}{loc}")

    if new_gaps:
        lines.append("")
        lines.append("## New Gaps (Regressions)")
        for gap in new_gaps:
            loc = f" (`{gap['file_path']}`)" if gap.get("file_path") else ""
            lines.append(f"- [NEW] {gap.get('title', gap.get('id', 'gap'))}{loc}")

    changed_dims = [(dim_id, val) for dim_id, val in sorted(dim_deltas.items()) if val != 0.0]
    if changed_dims:
        lines.append("")
        lines.append("## Dimension Deltas")
        for dim_id, val in changed_dims:
            lines.append(f"- `{dim_id}`: `{_signed(val)} pts`")

    return "\n".join(lines)


__all__ = [
    "save_baseline",
    "diff_baseline",
    "format_baseline_diff",
]
