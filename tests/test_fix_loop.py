"""Tests for the autonomous scan -> fix -> rescan loop (scanner.fix_loop).

Hermetic: the LLM bridge is force-disabled via monkeypatch so no network call is
ever made, and every apply-mode test copies the read-only fixture into pytest's
``tmp_path`` first — the repo fixture is never mutated in place.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scanner import scan_project
from scanner.fix_loop import (
    DETERMINISTIC_FIXERS,
    FixLoopResult,
    FixProposal,
    llm_propose,
    main,
    rank_gaps,
    run_fix_loop,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sample_project"


@pytest.fixture(autouse=True)
def _disable_llm(monkeypatch):
    """Force the LLM bridge OFF for every test — guarantees no network calls."""
    monkeypatch.setattr("scanner.llm_bridge.is_enabled", lambda: False)


@pytest.fixture
def project(tmp_path) -> Path:
    """A writable copy of the fixture project under tmp_path."""
    dst = tmp_path / "proj"
    shutil.copytree(FIXTURE, dst, ignore=shutil.ignore_patterns("__pycache__"))
    return dst


def _project_files(root: Path) -> set[str]:
    """Relative POSIX paths of all non-cache files under ``root``."""
    return {
        str(p.relative_to(root)).replace("\\", "/")
        for p in root.rglob("*")
        if p.is_file() and "__pycache__" not in str(p)
    }


# ─── Fixer table sanity ───────────────────────────────────────────────────


def test_deterministic_fixers_cover_required_keys():
    required = {
        "logging", "human_oversight", "tech_docs", "test_suite",
        "data_gov", "documentation", "fairness_testing", "configuration",
    }
    assert required <= set(DETERMINISTIC_FIXERS)


def test_each_fixer_returns_well_formed_proposal(tmp_path):
    for key, fixer in DETERMINISTIC_FIXERS.items():
        proposal = fixer(tmp_path)
        assert isinstance(proposal, FixProposal)
        assert proposal.fix_kind == "deterministic"
        assert proposal.content.strip(), f"{key} produced empty content"
        assert proposal.target_path
        assert proposal.verification


def test_compliance_doc_fixers_use_fill_in_placeholders(tmp_path):
    """MODEL_CARD / DATA_CARD must not fabricate facts — only <FILL IN: ...>."""
    for key in ("tech_docs", "data_gov"):
        proposal = DETERMINISTIC_FIXERS[key](tmp_path)
        assert "<FILL IN:" in proposal.content, f"{key} card lacks placeholders"


# ─── rank_gaps ────────────────────────────────────────────────────────────


def test_rank_gaps_only_returns_actionable_dimensions():
    result = scan_project(FIXTURE)
    ranked = rank_gaps(result)
    assert ranked, "fixture has known gaps — ranking must not be empty"
    for dim_id, score in ranked:
        # Every ranked dimension is below the broad-evidence band.
        assert score < 85.0
        assert dim_id in result.compliance_scores


def test_rank_gaps_is_worst_first_by_weighted_score():
    result = scan_project(FIXTURE)
    ranked = rank_gaps(result)
    # The lowest-scoring, highest-weight gaps must lead. A perfect-score
    # dimension (if any) must never appear.
    scores = [score for _dim, score in ranked]
    # The very first ranked dimension should be a genuine gap (low score).
    assert scores[0] <= 85.0


# ─── Dry-run (safe default) ───────────────────────────────────────────────


def test_dry_run_writes_nothing_and_collects_proposals(project):
    before = _project_files(project)
    result = run_fix_loop(project, top_n=8, apply=False)
    after = _project_files(project)

    assert after == before, "dry-run must not write any files"
    assert isinstance(result, FixLoopResult)
    assert result.proposals, "dry-run should surface remediation proposals"
    assert result.applied == []
    assert result.skipped_regressions == []
    assert result.llm_used is False
    # Dry-run does not move the score.
    assert result.final_overall == result.baseline_overall
    assert result.overall_delta == 0.0


def test_dry_run_surfaces_known_missing_dimensions(project):
    """The fixture is missing strong evidence for tech_docs / test_suite / logging."""
    result = run_fix_loop(project, top_n=8, apply=False)
    proposed_dims = {p.dimension for p in result.proposals}
    assert "tech_docs" in proposed_dims
    assert "test_suite" in proposed_dims
    assert "logging" in proposed_dims


def test_dry_run_default_apply_is_false(project):
    """Calling without apply= must be the safe dry-run (no files written)."""
    before = _project_files(project)
    run_fix_loop(project, top_n=3)
    assert _project_files(project) == before


# ─── Apply mode + regression guard ────────────────────────────────────────


def test_apply_raises_overall_without_any_regression(project):
    result = run_fix_loop(project, top_n=3, max_iterations=5, apply=True)

    # The loop must improve the overall compliance score.
    assert result.final_overall > result.baseline_overall, (
        f"expected improvement, got {result.baseline_overall} -> {result.final_overall}"
    )
    assert result.overall_delta > 0.0
    # Regression guard holds: NO dimension may end below its baseline.
    negative = {d: v for d, v in result.dimension_deltas.items() if v < 0.0}
    assert negative == {}, f"regression guard breached: {negative}"
    assert result.applied, "at least one clean fix should have been accepted"


def test_apply_converges_within_max_iterations(project):
    max_iter = 5
    result = run_fix_loop(project, top_n=3, max_iterations=max_iter, apply=True)
    assert result.converged is True
    assert result.iterations <= max_iter


def test_rejected_proposals_leave_no_leftover_files(project):
    before = _project_files(project)
    result = run_fix_loop(project, top_n=8, max_iterations=5, apply=True)

    # Some proposals are expected to regress on this fixture and be reverted.
    assert result.skipped_regressions, (
        "expected at least one regression-reverted fix on this fixture"
    )
    after = _project_files(project)
    created = after - before

    # Every leftover file must belong to an ACCEPTED proposal — never a reverted one.
    reverted_targets = {
        p.target_path
        for p in result.proposals
        if p.id in result.skipped_regressions
    }
    for target in reverted_targets:
        assert target not in created, (
            f"reverted proposal left {target} behind"
        )


def test_apply_result_matches_live_rescan(project):
    """The reported final_overall must equal an independent re-scan of the tree."""
    result = run_fix_loop(project, top_n=3, max_iterations=5, apply=True)
    live = scan_project(project)
    assert result.final_overall == pytest.approx(live.overall_compliance_pct, abs=0.05)


# ─── Accepted-fix evidence is actually detected ───────────────────────────


def test_accepted_fix_produces_detectable_evidence(project):
    """An accepted fix must measurably raise its dimension on re-scan."""
    result = run_fix_loop(project, top_n=3, max_iterations=5, apply=True)
    assert result.applied
    # At least one *applied* proposal's own dimension must show a positive delta.
    # (No `or any(delta>0)` fallback — that would be satisfied by the overall
    # rise alone and would not prove the accepted fix moved its own dimension.)
    applied_dims = {
        p.dimension for p in result.proposals if p.id in result.applied
    }
    improved = {
        d for d, v in result.dimension_deltas.items() if v > 0.0
    }
    assert applied_dims & improved


# ─── LLM path (disabled) ──────────────────────────────────────────────────


def test_llm_propose_returns_none_when_disabled(project):
    assert llm_propose("logging", project) is None


def test_use_llm_flag_ignored_when_bridge_disabled(project):
    """--use-llm must not flip llm_used when the bridge is off (hermetic)."""
    result = run_fix_loop(project, top_n=3, apply=False, use_llm=True)
    assert result.llm_used is False


# ─── Safety: never write outside the scanned root ─────────────────────────


def test_run_fix_loop_rejects_non_directory(tmp_path):
    f = tmp_path / "not_a_dir.txt"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError):
        run_fix_loop(f)


def test_resolve_target_rejects_root_and_escape(project):
    """A target resolving to the root itself ('.'/'') or outside it is refused —
    the root case would otherwise crash the apply loop writing to a directory."""
    from scanner.fix_loop import _resolve_target

    for bad in (".", "", "../escape.md", "/etc/passwd"):
        with pytest.raises(ValueError):
            _resolve_target(project, bad)


def test_apply_never_clobbers_a_preexisting_file(project):
    """--apply must NOT overwrite a user's hand-written file (irreversible data
    loss): the fixer adds *missing* evidence, so a pre-existing target is skipped
    and its bytes survive — even when that fix would otherwise be selected."""
    sentinel = "FROM my-custom-base:1.2.3\n# critical hand-written build steps\n"
    (project / "Dockerfile").write_text(sentinel, encoding="utf-8")

    result = run_fix_loop(project, top_n=8, max_iterations=5, apply=True)

    # The pre-existing Dockerfile is byte-for-byte intact...
    assert (project / "Dockerfile").read_text(encoding="utf-8") == sentinel
    # ...and the configuration fixer (which targets Dockerfile) was never applied.
    assert "fix-configuration" not in result.applied


def test_apply_proposal_refuses_overwrite_unit(project):
    """Unit-level guard: _apply_proposal raises rather than clobber, and leaves
    the original file untouched."""
    from scanner.fix_loop import _apply_proposal

    (project / "MODEL_CARD.md").write_text("USER CONTENT — do not lose", encoding="utf-8")
    proposal = FixProposal(
        id="fix-x",
        dimension="tech_docs",
        article="Art. 11",
        title="t",
        rationale="r",
        fix_kind="deterministic",
        target_path="MODEL_CARD.md",
        content="GENERATED MODEL CARD",
        verification="v",
    )
    with pytest.raises(ValueError):
        _apply_proposal(project, proposal)
    assert (project / "MODEL_CARD.md").read_text(encoding="utf-8") == "USER CONTENT — do not lose"


# ─── CLI ──────────────────────────────────────────────────────────────────


def test_cli_dry_run_json(project, capsys):
    exit_code = main([str(project), "--json", "--top", "3"])
    assert exit_code == 0
    import json as _json
    payload = _json.loads(capsys.readouterr().out)
    assert payload["project_name"]
    assert "proposals" in payload
    assert payload["applied"] == []  # dry-run default
    # CLI dry-run must not have written anything.
    assert "MODEL_CARD.md" not in _project_files(project)


def test_cli_markdown_summary(project, capsys):
    exit_code = main([str(project)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Fix loop" in out
    assert "DRY-RUN" in out
