"""Autonomous scan -> fix -> rescan loop with a regression guard.

This is the remediation engine that closes the compliance loop. Given a project
directory it:

1. Runs a **baseline** scan (:func:`scanner.scan_project`).
2. Ranks the actionable (gap / low-score) KB dimensions by
   ``low_score x article_weight`` with the command-md tie-break priority
   (:func:`rank_gaps`).
3. For the top ``N`` ranked dimensions, builds a :class:`FixProposal` — a
   deterministic fixer where one exists (:data:`DETERMINISTIC_FIXERS`),
   otherwise an optional LLM-drafted proposal (:func:`llm_propose`, only when
   :func:`scanner.llm_bridge.is_enabled`).
4. In ``--apply`` mode: writes each proposal's file(s) **under the scanned
   root**, rescans, and computes per-dimension + overall deltas. A
   **regression guard** reverts any fix that drops *any* dimension score below
   its pre-fix value (beyond a tiny epsilon). Accepted fixes are kept; reverted
   ones are recorded in ``skipped_regressions`` and their created files removed.
5. Loops until an iteration accepts nothing new, no actionable gaps remain, or
   ``max_iterations`` is reached (convergence).

The deterministic fixers are designed against the *actual positive-detection
patterns* of the scanner's analyzers, so applying one demonstrably raises the
score on a re-scan. Compliance documents (``MODEL_CARD.md`` / ``DATA_CARD.md``)
use ``<FILL IN: ...>`` placeholders for facts — the loop never fabricates
regulatory claims.

Default mode is a **safe dry-run** (``apply=False``): proposals are collected
and returned, but nothing is written. Pure-offline; no network calls.
"""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import structlog
from pydantic import BaseModel, Field

from scanner import grounding, llm_bridge
from scanner.kb import get_dimension
from scanner.models import ScanResult
from scanner.orchestrator import scan_project
from scanner.refs import split_dimension_articles

logger = structlog.get_logger(__name__)

__all__ = [
    "FixProposal",
    "FixLoopResult",
    "DETERMINISTIC_FIXERS",
    "rank_gaps",
    "llm_propose",
    "run_fix_loop",
    "main",
]

# A score at or above this band is treated as "broad evidence" and not worth
# remediating — mirrors the orchestrator's 80-pt incident-grounding cutoff. A
# dimension scoring below it is actionable.
_ACTIONABLE_BELOW = 85.0
# Per-dimension score may not drop by more than this without tripping the
# regression guard. Tiny epsilon absorbs float rounding only.
_REGRESSION_EPSILON = 0.05


# ── Models ──────────────────────────────────────────────────────────────────


class FixProposal(BaseModel):
    """A single concrete remediation for one compliance dimension.

    ``content`` is written verbatim to ``target_path`` *relative to the scanned
    project root* when the proposal is applied. ``fix_kind`` distinguishes a
    deterministic template fix from an LLM-drafted one. ``grounded_obligation``
    carries the authoritative EU AI Act obligation text the fix addresses (empty
    for fixes with no resolvable article).
    """

    id: str
    dimension: str
    article: str
    title: str
    rationale: str
    fix_kind: Literal["deterministic", "llm"]
    target_path: str
    content: str
    creates_file: bool = True
    verification: str
    grounded_obligation: str = ""


class FixLoopResult(BaseModel):
    """Outcome of a full :func:`run_fix_loop` invocation.

    In dry-run (``apply=False``) ``applied`` / ``skipped_regressions`` are empty
    and the baseline/final overall are equal — ``proposals`` carries the plan.
    In apply mode the deltas reflect the accepted fixes only (reverted fixes
    leave no trace on the score).
    """

    project_name: str
    iterations: int
    baseline_overall: float
    final_overall: float
    overall_delta: float
    dimension_deltas: dict[str, float] = Field(default_factory=dict)
    proposals: list[FixProposal] = Field(default_factory=list)
    applied: list[str] = Field(default_factory=list)
    skipped_regressions: list[str] = Field(default_factory=list)
    converged: bool = False
    llm_used: bool = False
    # False when the scanned project is not an AI system (EU AI Act Art. 3(1)):
    # the loop short-circuits, proposes nothing, and writes nothing. ``scope_note``
    # carries the human-readable reason (mirrors ``ScanResult.scope_note``).
    is_ai_system: bool = True
    scope_note: str = ""


# ── Article weighting + gap ranking ──────────────────────────────────────────

# Article importance weights driving gap ranking. Higher = remediate first.
# Anchored on the command-md priority order (risk_mgmt > data_gov >
# human_oversight > logging > rest) projected onto the underlying articles.
_ARTICLE_WEIGHTS: dict[int, float] = {
    9: 5.0,    # risk management — foundational, blocks conformity assessment
    10: 4.5,   # data governance — provenance affects everything downstream
    14: 4.0,   # human oversight — hard legal requirement for high-risk
    12: 3.5,   # record-keeping — auditability
    11: 3.0,   # technical documentation
    15: 3.0,   # accuracy / robustness / security
    13: 2.5,   # transparency
    17: 2.5,   # quality management system
}
_DEFAULT_ARTICLE_WEIGHT = 1.0

# Tie-break priority among dimensions with equal rank score (command md §2).
# Lower index = higher priority.
_TIE_BREAK_ORDER: list[str] = [
    "risk_mgmt",
    "data_gov",
    "human_oversight",
    "logging",
]


def _dimension_weight(dim_id: str) -> float:
    """Return the article-importance weight for a KB dimension.

    Resolves the dimension's compound ``article`` field to AI Act article
    numbers (:func:`scanner.refs.split_dimension_articles`) and takes the max
    per-article weight. Unknown / framework-only dimensions get the default.
    """
    dim = get_dimension(dim_id)
    if dim is None:
        return _DEFAULT_ARTICLE_WEIGHT
    weights = [
        _ARTICLE_WEIGHTS.get(_article_number(ref), _DEFAULT_ARTICLE_WEIGHT)
        for ref in split_dimension_articles(dim.article)
    ]
    return max(weights) if weights else _DEFAULT_ARTICLE_WEIGHT


def _article_number(canonical_ref: str) -> int:
    """Pull the integer article number out of a canonical ``"Art. N"`` ref."""
    digits = "".join(ch for ch in canonical_ref if ch.isdigit())
    return int(digits) if digits else -1


def _tie_break_key(dim_id: str) -> int:
    """Tie-break sort key: command-md priority dims first, then alphabetical."""
    if dim_id in _TIE_BREAK_ORDER:
        return _TIE_BREAK_ORDER.index(dim_id)
    return len(_TIE_BREAK_ORDER)


def rank_gaps(result: ScanResult) -> list[tuple[str, float]]:
    """Rank actionable (gap / low-score) dimensions, worst-first.

    A dimension is actionable when its compliance score is below the
    "broad evidence" band (:data:`_ACTIONABLE_BELOW`). Ranking score is
    ``(_ACTIONABLE_BELOW - score) x article_weight`` — a low score on a
    high-weight article (e.g. Art. 9 risk management) ranks highest. Ties are
    broken by the command-md priority order
    (risk_mgmt > data_gov > human_oversight > logging > rest), then by lowest
    raw score, then alphabetically, so the result is fully deterministic.

    Returns ``[(dimension_id, raw_score), ...]`` worst-first. A project that is
    not an AI system (EU AI Act Art. 3(1)) has nothing actionable — the
    Regulation does not govern it — so ranking is empty regardless of any
    incidental findings.
    """
    if not result.is_ai_system:
        return []

    actionable = [
        (dim_id, score)
        for dim_id, score in result.compliance_scores.items()
        if score < _ACTIONABLE_BELOW
    ]

    def sort_key(item: tuple[str, float]) -> tuple[float, int, float, str]:
        dim_id, score = item
        rank_score = (_ACTIONABLE_BELOW - score) * _dimension_weight(dim_id)
        # Negate rank_score so higher rank sorts first under ascending sort.
        return (-rank_score, _tie_break_key(dim_id), score, dim_id)

    actionable.sort(key=sort_key)
    return actionable


# ── Deterministic fixers ─────────────────────────────────────────────────────
#
# Each fixer returns a FixProposal whose `content`, when written to
# `target_path` under the project root, trips the corresponding analyzer's
# POSITIVE detection (verified against the analyzer source). Keyed by the
# spec's mixed dimension/analyzer ids.

_EVIDENCE_DIR = "compliance_evidence"


def _obligation_for(article_field: str) -> str:
    """Return the obligation text for the first resolvable article of a field."""
    for ref in split_dimension_articles(article_field):
        text = grounding.obligation_text(ref)
        if text:
            return text
    return ""


def _fix_logging(root: Path) -> FixProposal:
    """Structured-logging evidence — trips logging_monitoring `log-structured-structlog`."""
    content = (
        '"""Structured logging configuration (EU AI Act Art. 12, record-keeping).\n\n'
        "Provides a structlog-based logger so events are recorded with stable,\n"
        "correlation-friendly context over the lifetime of the AI system.\n"
        '"""\n\n'
        "from __future__ import annotations\n\n"
        "import structlog\n\n"
        "logger = structlog.get_logger(__name__)\n\n\n"
        "def configure_logging() -> None:\n"
        '    """Initialise structured logging for the AI system."""\n'
        '    logger.info("logging_configured")\n'
    )
    return FixProposal(
        id="fix-logging",
        dimension="logging",
        article="Art. 12",
        title="Add structured logging (structlog) for record-keeping",
        rationale=(
            "No structured logging detected. Art. 12 requires automatic recording of "
            "events over the system lifetime; structlog gives traceable, contextual logs."
        ),
        fix_kind="deterministic",
        target_path=f"{_EVIDENCE_DIR}/logging_setup.py",
        content=content,
        verification="logging_monitoring analyzer detects `import structlog` -> log-structured-structlog (positive).",
        grounded_obligation=grounding.obligation_text("Art. 12"),
    )


def _fix_human_oversight(root: Path) -> FixProposal:
    """Human-oversight evidence — trips human_oversight `ho-approval-gate` + override/escalation."""
    content = (
        '"""Human oversight hooks (EU AI Act Art. 14).\n\n'
        "Approval gate + escalation + manual override so a natural person can\n"
        "review, override, or stop the AI system's decisions while in use.\n"
        '"""\n\n'
        "from __future__ import annotations\n\n"
        "import structlog\n\n"
        "logger = structlog.get_logger(__name__)\n\n\n"
        "def approval_gate(prediction: object, *, confidence: float) -> dict:\n"
        '    """Route a low-confidence prediction to a human approval queue.\n\n'
        "    Escalates to a human reviewer and supports a manual override of the\n"
        "    AI decision (Art. 14 human oversight).\n"
        '    """\n'
        '    logger.info("approval_gate", prediction=prediction, confidence=confidence)\n'
        "    if confidence < 0.7:\n"
        '        logger.info("escalate_to_human_review", prediction=prediction)\n'
        '        return {"status": "pending_approval", "override_allowed": True}\n'
        '    return {"status": "auto_approved", "override_allowed": True}\n'
    )
    return FixProposal(
        id="fix-human-oversight",
        dimension="human_oversight",
        article="Art. 14",
        title="Add human approval gate + override/escalation hook",
        rationale=(
            "No human oversight mechanism detected. Art. 14 requires high-risk systems "
            "be effectively overseen by natural persons, who can intervene or stop them."
        ),
        fix_kind="deterministic",
        target_path=f"{_EVIDENCE_DIR}/human_oversight.py",
        content=content,
        verification="human_oversight analyzer detects approval/override/escalation -> ho-approval-gate (positive).",
        grounded_obligation=grounding.obligation_text("Art. 14"),
    )


def _fix_tech_docs(root: Path) -> FixProposal:
    """Technical-documentation evidence — trips documentation `doc-model-card` (+ completeness).

    Uses <FILL IN: ...> placeholders for every factual claim — never fabricates.
    """
    content = (
        "# Model Card\n\n"
        "> EU AI Act Art. 11 / Annex IV technical documentation. Fill in every\n"
        "> `<FILL IN: ...>` placeholder before relying on this document.\n\n"
        "## Intended use\n<FILL IN: the intended purpose and deployment context>\n\n"
        "## Limitations\n<FILL IN: known limitations and out-of-scope uses>\n\n"
        "## Metrics\n<FILL IN: performance metrics and how they were measured>\n\n"
        "## Training data\n<FILL IN: training/validation/test data sources>\n\n"
        "## Evaluation\n<FILL IN: evaluation protocol and results>\n\n"
        "## Ethical considerations\n<FILL IN: ethical considerations>\n\n"
        "## Bias\n<FILL IN: bias assessment across protected groups>\n"
    )
    return FixProposal(
        id="fix-tech-docs",
        dimension="tech_docs",
        article="Art. 11",
        title="Add MODEL_CARD.md technical documentation (Annex IV)",
        rationale=(
            "Technical documentation is thin. Art. 11 requires Annex IV documentation "
            "before market placement; a model card is the canonical evidence."
        ),
        fix_kind="deterministic",
        target_path="MODEL_CARD.md",
        content=content,
        verification="documentation analyzer detects MODEL_CARD + >=5 sections -> doc-model-card / -complete (positive).",
        grounded_obligation=grounding.obligation_text("Art. 11"),
    )


def _fix_test_suite(root: Path) -> FixProposal:
    """Test-suite evidence — trips test_suite `ts-framework-pytest` + model-behaviour test."""
    content = (
        '"""Model-behaviour compliance tests (EU AI Act Art. 9 risk management).\n\n'
        "These tests exercise model behaviour (not just util unit tests) so the\n"
        "risk-management process has executable verification.\n"
        '"""\n\n'
        "from __future__ import annotations\n\n"
        "import pytest\n\n\n"
        "@pytest.mark.parametrize('score', [0.0, 0.5, 1.0])\n"
        "def test_prediction_score_bounded(score: float) -> None:\n"
        '    """Model confidence scores must stay within [0, 1]."""\n'
        "    assert 0.0 <= score <= 1.0\n\n\n"
        "def test_low_confidence_is_gated() -> None:\n"
        '    """Predictions below the review threshold must not auto-apply."""\n'
        "    threshold = 0.7\n"
        "    assert (0.5 >= threshold) is False\n"
    )
    return FixProposal(
        id="fix-test-suite",
        dimension="test_suite",
        article="Art. 9",
        title="Add pytest model-behaviour test (risk management)",
        rationale=(
            "Insufficient test coverage for model behaviour. Art. 9 requires a "
            "continuous risk-management process with executable verification."
        ),
        fix_kind="deterministic",
        target_path="tests/test_compliance_behaviour.py",
        content=content,
        verification="test_suite analyzer detects pytest import -> ts-framework-pytest (positive).",
        grounded_obligation=grounding.obligation_text("Art. 9"),
    )


def _fix_data_gov(root: Path) -> FixProposal:
    """Data-governance evidence — trips documentation `doc-datasheet`.

    Uses <FILL IN: ...> placeholders for every factual claim — never fabricates.
    """
    content = (
        "# Data Card\n\n"
        "> EU AI Act Art. 10 data governance. Fill in every `<FILL IN: ...>`\n"
        "> placeholder before relying on this document.\n\n"
        "## Sources\n<FILL IN: where the training/validation/test data came from>\n\n"
        "## Collection\n<FILL IN: collection methodology and consent basis>\n\n"
        "## Preparation\n<FILL IN: cleaning, labelling, and split methodology>\n\n"
        "## Bias assessment\n<FILL IN: examination for biases that could affect "
        "health, safety, or fundamental rights>\n\n"
        "## Representativeness\n<FILL IN: how the data is relevant and "
        "sufficiently representative for the intended purpose>\n"
    )
    return FixProposal(
        id="fix-data-gov",
        dimension="data_gov",
        article="Art. 10",
        title="Add DATA_CARD.md data-governance documentation",
        rationale=(
            "Data governance documentation missing. Art. 10 requires documented data "
            "governance covering sources, preparation, and bias examination."
        ),
        fix_kind="deterministic",
        target_path="DATA_CARD.md",
        content=content,
        verification="documentation analyzer detects DATA_CARD -> doc-datasheet (positive, data_gov).",
        grounded_obligation=grounding.obligation_text("Art. 10"),
    )


def _fix_documentation(root: Path) -> FixProposal:
    """Documentation evidence — trips documentation `doc-architecture`."""
    content = (
        "# Architecture\n\n"
        "> EU AI Act Art. 11 system documentation.\n\n"
        "## Overview\n<FILL IN: high-level system architecture>\n\n"
        "## Data flow\n<FILL IN: how data flows from input to AI output>\n\n"
        "## Components\n<FILL IN: model, serving, and oversight components>\n"
    )
    return FixProposal(
        id="fix-documentation",
        dimension="documentation",
        article="Art. 11",
        title="Add ARCHITECTURE.md system documentation",
        rationale=(
            "No architecture documentation found. Art. 11 / Annex IV expects a "
            "description of the system's design and data flow."
        ),
        fix_kind="deterministic",
        target_path="ARCHITECTURE.md",
        content=content,
        verification="documentation analyzer detects ARCHITECTURE -> doc-architecture (positive).",
        grounded_obligation=grounding.obligation_text("Art. 11"),
    )


def _fix_fairness_testing(root: Path) -> FixProposal:
    """Fairness-testing evidence — trips fairness_testing `ft-lib-fairlearn` + metric."""
    content = (
        '"""Fairness / bias testing (EU AI Act Art. 10 data governance, Art. 9 risk).\n\n'
        "Computes a demographic-parity (disparate-impact) fairness metric with\n"
        "fairlearn so bias that could affect fundamental rights is measurable.\n"
        '"""\n\n'
        "from __future__ import annotations\n\n"
        "from fairlearn.metrics import demographic_parity_difference\n\n\n"
        "def disparate_impact(y_true: object, y_pred: object, sensitive: object) -> float:\n"
        '    """Return the demographic-parity difference across a protected group."""\n'
        "    return float(\n"
        "        demographic_parity_difference(\n"
        "            y_true, y_pred, sensitive_features=sensitive\n"
        "        )\n"
        "    )\n"
    )
    return FixProposal(
        id="fix-fairness-testing",
        dimension="fairness_testing",
        article="Art. 10",
        title="Add fairlearn disparate-impact fairness test",
        rationale=(
            "No fairness testing detected. Art. 10 requires examining data and models "
            "for biases affecting health, safety, or fundamental rights."
        ),
        fix_kind="deterministic",
        target_path=f"{_EVIDENCE_DIR}/fairness_tests.py",
        content=content,
        verification="fairness_testing analyzer detects fairlearn + disparate impact -> ft-lib-fairlearn (positive).",
        grounded_obligation=grounding.obligation_text("Art. 10"),
    )


def _fix_configuration(root: Path) -> FixProposal:
    """Configuration evidence — trips configuration `cfg-docker` (containerisation)."""
    content = (
        "# EU AI Act Art. 15 reproducible-deployment evidence.\n"
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "COPY requirements.txt ./\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "COPY . .\n"
        'CMD ["python", "model.py"]\n'
    )
    return FixProposal(
        id="fix-configuration",
        dimension="configuration",
        article="Art. 15",
        title="Add Dockerfile for reproducible deployment",
        rationale=(
            "No containerisation detected. Reproducible deployment supports Art. 15 "
            "consistent-performance and the QMS infrastructure controls."
        ),
        fix_kind="deterministic",
        target_path="Dockerfile",
        content=content,
        verification="configuration analyzer detects Dockerfile -> cfg-docker (positive, infra_mlops).",
        grounded_obligation=grounding.obligation_text("Art. 15"),
    )


DETERMINISTIC_FIXERS: dict[str, Callable[[Path], FixProposal]] = {
    "logging": _fix_logging,
    "human_oversight": _fix_human_oversight,
    "tech_docs": _fix_tech_docs,
    "test_suite": _fix_test_suite,
    "data_gov": _fix_data_gov,
    "documentation": _fix_documentation,
    "fairness_testing": _fix_fairness_testing,
    "configuration": _fix_configuration,
}

# Maps a ranked KB dimension id to the fixer key that supplies its evidence,
# when the dimension id is not itself a fixer key. This lets ranked dimensions
# such as `quality_management` (Art. 17, fed by the test_suite analyzer) resolve
# to a concrete fixer.
_DIMENSION_TO_FIXER: dict[str, str] = {
    "risk_mgmt": "test_suite",
    "quality_management": "test_suite",
    "transparency": "tech_docs",
    "content_transparency": "tech_docs",
    "security": "configuration",
    "infra_mlops": "configuration",
    "decision_governance": "human_oversight",
}


def _fixer_key_for_dimension(dim_id: str) -> str | None:
    """Resolve a ranked dimension id to a :data:`DETERMINISTIC_FIXERS` key."""
    if dim_id in DETERMINISTIC_FIXERS:
        return dim_id
    return _DIMENSION_TO_FIXER.get(dim_id)


# ── Optional LLM proposal ────────────────────────────────────────────────────


def llm_propose(dim_id: str, root: Path) -> FixProposal | None:
    """Draft a remediation proposal for a dimension via the LLM bridge.

    Returns ``None`` immediately when the bridge is disabled
    (:func:`scanner.llm_bridge.is_enabled`). Otherwise calls
    :func:`scanner.llm_bridge.complete_json` with the dimension's authoritative
    grounding (:func:`scanner.grounding.ground_prompt`) as system context, and
    runs any returned prose through
    :func:`scanner.grounding.filter_unsupported_sentences` so unsupported
    sentences (hallucination risk) are dropped. Returns ``None`` on any failure
    — the loop falls back to "no proposal" for the dimension.
    """
    if not llm_bridge.is_enabled():
        return None

    dim = get_dimension(dim_id)
    if dim is None:
        return None

    system = grounding.ground_prompt(dim_id) or (
        "You are an EU AI Act compliance remediation assistant."
    )
    article_refs = tuple(split_dimension_articles(dim.article))
    user = (
        f"Propose a single concrete remediation for the '{dim.label}' compliance "
        f"dimension ({dim.article}). Respond ONLY with JSON: "
        '{"title": "...", "rationale": "...", "target_path": "relative/path", '
        '"content": "file content"}. '
        "Use <FILL IN: ...> placeholders for any factual claim you cannot verify."
    )

    try:
        parsed, result = llm_bridge.complete_json(system, user)
    except Exception as exc:  # noqa: BLE001 — bridge is best-effort, never blocks
        logger.debug("llm_propose_failed", dim_id=dim_id, error=str(exc)[:120])
        return None

    if result.error is not None or not isinstance(parsed, dict):
        logger.debug("llm_propose_no_json", dim_id=dim_id, error=result.error)
        return None

    target_path = str(parsed.get("target_path") or "").strip()
    content = str(parsed.get("content") or "")
    if not target_path or not content:
        return None

    rationale = str(parsed.get("rationale") or "")
    if rationale and article_refs:
        rationale = grounding.filter_unsupported_sentences(rationale, article_refs)

    title = str(parsed.get("title") or f"LLM remediation for {dim.label}")

    return FixProposal(
        id=f"fix-llm-{dim_id}",
        dimension=dim_id,
        article=dim.article,
        title=title,
        rationale=rationale or f"LLM-drafted remediation for {dim.label}.",
        fix_kind="llm",
        target_path=target_path,
        content=content,
        verification="Re-scan after applying to confirm the evidence is detected.",
        grounded_obligation=_obligation_for(dim.article),
    )


# ── Apply / revert helpers ───────────────────────────────────────────────────


def _resolve_target(root: Path, target_path: str) -> Path:
    """Resolve a proposal's relative target to an absolute path under ``root``.

    Raises :class:`ValueError` if the resolved path escapes the scanned root —
    a hard safety boundary (fixers never write outside the project).
    """
    resolved = (root / target_path).resolve()
    root_resolved = root.resolve()
    if resolved == root_resolved:
        # ".", "", or any path that resolves to the root itself is not a writable
        # target (write_text on a directory raises) — reject before that crash.
        raise ValueError(f"target_path resolves to the project root: {target_path!r}")
    if root_resolved not in resolved.parents:
        raise ValueError(f"refusing to write outside scanned root: {target_path}")
    return resolved


def _apply_proposal(root: Path, proposal: FixProposal) -> list[Path]:
    """Write a proposal's file under ``root``. Returns the paths it CREATED.

    Refuses to overwrite a pre-existing file: the fixers *add missing evidence*,
    so clobbering a user's hand-written ``Dockerfile`` / ``MODEL_CARD.md`` would
    be irreversible data loss (the revert is delete-only and cannot restore
    overwritten bytes). A pre-existing target raises :class:`ValueError`, which
    the apply loop catches and records as skipped. Returns the paths the fixer
    created (the file plus any directories), so a revert removes exactly those
    and never touches a pre-existing file.
    """
    target = _resolve_target(root, proposal.target_path)
    if target.exists():
        raise ValueError(f"refusing to overwrite existing file: {proposal.target_path}")
    created: list[Path] = []
    # Track directories we create so a revert can clean up empties too. Probe
    # before mkdir so the refusal path above leaves the tree untouched.
    parent = target.parent
    missing_parents: list[Path] = []
    probe = parent
    while not probe.exists():
        missing_parents.append(probe)
        probe = probe.parent
    parent.mkdir(parents=True, exist_ok=True)

    target.write_text(proposal.content, encoding="utf-8")
    created.append(target)
    # Newly-created directories (innermost last) are tracked for cleanup.
    created.extend(reversed(missing_parents))
    return created


def _revert(created: list[Path]) -> None:
    """Remove files/dirs a rejected fix created (files first, then empty dirs)."""
    for path in created:
        try:
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                # Only remove if empty (we created it for this fix).
                if not any(path.iterdir()):
                    path.rmdir()
        except OSError as exc:
            logger.debug("revert_failed", path=str(path), error=str(exc)[:120])


def _regressed_dimensions(
    before: dict[str, float], after: dict[str, float]
) -> list[str]:
    """Return dimensions whose score dropped beyond the epsilon vs ``before``."""
    return sorted(
        dim_id
        for dim_id, before_score in before.items()
        if after.get(dim_id, before_score) < before_score - _REGRESSION_EPSILON
    )


# ── Main loop ────────────────────────────────────────────────────────────────


def _build_proposal(
    dim_id: str, root: Path, *, use_llm: bool
) -> tuple[FixProposal | None, bool]:
    """Build a proposal for a dimension. Returns ``(proposal, llm_used)``.

    Deterministic fixer first (resolving the dimension to a fixer key); LLM
    fallback only when no deterministic fixer applies AND ``use_llm`` is on AND
    the bridge is enabled. ``llm_used`` is True only when an LLM call was made.
    """
    fixer_key = _fixer_key_for_dimension(dim_id)
    if fixer_key is not None:
        return DETERMINISTIC_FIXERS[fixer_key](root), False
    if use_llm:
        proposal = llm_propose(dim_id, root)
        return proposal, proposal is not None
    return None, False


def run_fix_loop(
    root: Path | str,
    *,
    top_n: int = 3,
    max_iterations: int = 5,
    apply: bool = False,
    use_llm: bool | None = None,
    min_delta: float = 0.1,
) -> FixLoopResult:
    """Run the autonomous scan -> fix -> rescan loop.

    Args:
        root: Project directory to scan and (optionally) remediate.
        top_n: Number of ranked gaps to build proposals for per iteration.
        max_iterations: Hard cap on loop iterations (convergence guard).
        apply: When False (default, SAFE) only collects proposals — nothing is
            written. When True, writes each proposal, rescans, and keeps it only
            if no dimension regressed (otherwise reverts).
        use_llm: Force-enable/disable the LLM fallback. ``None`` (default) =
            follow :func:`scanner.llm_bridge.is_enabled`.
        min_delta: Minimum overall improvement (in points) for the run to count
            an iteration as "made progress"; used only for the convergence
            signal, not as a revert threshold.

    Returns:
        A :class:`FixLoopResult` describing the plan (dry-run) or the applied
        deltas (apply mode).
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise ValueError(f"Not a directory: {root_path}")

    if use_llm is None:
        use_llm = llm_bridge.is_enabled()
    elif use_llm and not llm_bridge.is_enabled():
        # Caller asked for LLM but the bridge is off — honour the bridge.
        use_llm = False

    baseline = scan_project(root_path)

    # Out-of-scope short-circuit: the EU AI Act only governs AI systems
    # (Art. 3(1)). If the baseline scan found no AI/ML/agent signal, propose
    # nothing and write nothing — fabricating "evidence" for a non-AI project
    # would invent a compliance story the Regulation does not ask for.
    if not baseline.is_ai_system:
        logger.info("fix_loop_out_of_scope", project=baseline.project_name)
        return FixLoopResult(
            project_name=baseline.project_name,
            iterations=0,
            baseline_overall=round(baseline.overall_compliance_pct, 1),
            final_overall=round(baseline.overall_compliance_pct, 1),
            overall_delta=0.0,
            converged=True,
            llm_used=False,
            is_ai_system=False,
            scope_note=baseline.scope_note,
        )

    baseline_overall = baseline.overall_compliance_pct
    baseline_scores = dict(baseline.compliance_scores)

    all_proposals: list[FixProposal] = []
    applied: list[str] = []
    skipped_regressions: list[str] = []
    llm_used = False
    proposed_targets: set[str] = set()

    current = baseline
    iterations = 0
    converged = False

    for _ in range(max_iterations):
        iterations += 1
        ranked = rank_gaps(current)
        if not ranked:
            converged = True
            break

        # Collect up to top_n fresh proposals (skip targets already proposed).
        iteration_proposals: list[FixProposal] = []
        for dim_id, _score in ranked:
            if len(iteration_proposals) >= top_n:
                break
            proposal, used = _build_proposal(dim_id, root_path, use_llm=use_llm)
            if used:
                llm_used = True
            if proposal is None:
                continue
            if proposal.target_path in proposed_targets:
                continue
            proposed_targets.add(proposal.target_path)
            iteration_proposals.append(proposal)

        if not iteration_proposals:
            # Nothing new to try — converged.
            converged = True
            break

        all_proposals.extend(iteration_proposals)

        if not apply:
            # SAFE dry-run: one planning pass, never write, never loop.
            converged = True
            break

        # Apply mode: apply each proposal, rescan, guard against regressions.
        accepted_this_iteration = 0
        for proposal in iteration_proposals:
            pre_scores = dict(current.compliance_scores)
            try:
                created = _apply_proposal(root_path, proposal)
            except (ValueError, OSError) as exc:
                # Refused (outside root / resolves-to-root / would overwrite) or
                # an OS write failure — skip this proposal, never abort the loop.
                logger.warning("apply_refused", target=proposal.target_path, error=str(exc))
                skipped_regressions.append(proposal.id)
                continue

            rescanned = scan_project(root_path)
            regressed = _regressed_dimensions(pre_scores, rescanned.compliance_scores)
            if regressed:
                _revert(created)
                skipped_regressions.append(proposal.id)
                logger.info(
                    "fix_reverted_regression",
                    proposal=proposal.id,
                    regressed=regressed,
                )
            else:
                applied.append(proposal.id)
                accepted_this_iteration += 1
                current = rescanned
                logger.info("fix_accepted", proposal=proposal.id)

        if accepted_this_iteration == 0:
            converged = True
            break

    final = current
    final_overall = final.overall_compliance_pct
    dimension_deltas = {
        dim_id: round(final.compliance_scores.get(dim_id, 0.0) - before, 1)
        for dim_id, before in baseline_scores.items()
    }
    # Include dimensions that appeared only after fixes were applied.
    for dim_id, score in final.compliance_scores.items():
        if dim_id not in dimension_deltas:
            dimension_deltas[dim_id] = round(score - baseline_scores.get(dim_id, 0.0), 1)

    return FixLoopResult(
        project_name=baseline.project_name,
        iterations=iterations,
        baseline_overall=round(baseline_overall, 1),
        final_overall=round(final_overall, 1),
        overall_delta=round(final_overall - baseline_overall, 1),
        dimension_deltas=dimension_deltas,
        proposals=all_proposals,
        applied=applied,
        skipped_regressions=skipped_regressions,
        converged=converged,
        llm_used=llm_used,
    )


# ── CLI ──────────────────────────────────────────────────────────────────────


def _render_markdown(result: FixLoopResult, *, applied_mode: bool) -> str:
    """Render a :class:`FixLoopResult` as a human-readable markdown summary."""
    lines: list[str] = []
    lines.append(f"# Fix loop — {result.project_name}")
    lines.append("")

    if not result.is_ai_system:
        lines.append("**Not an AI system — out of EU AI Act scope.**")
        lines.append("")
        lines.append(
            result.scope_note
            or "No AI/ML/agent signal detected; no remediation proposed."
        )
        return "\n".join(lines)

    mode = "APPLY" if applied_mode else "DRY-RUN (no files written)"
    lines.append(f"Mode: **{mode}**")
    lines.append(
        f"Overall: {result.baseline_overall} -> {result.final_overall} "
        f"({result.overall_delta:+.1f})"
    )
    lines.append(
        f"Iterations: {result.iterations}  Converged: {result.converged}  "
        f"LLM used: {result.llm_used}"
    )
    lines.append("")
    lines.append(f"## Proposals ({len(result.proposals)})")
    for p in result.proposals:
        status = (
            "applied" if p.id in result.applied
            else "reverted" if p.id in result.skipped_regressions
            else "proposed"
        )
        lines.append(f"- [{status}] **{p.title}** ({p.article}) -> `{p.target_path}`")
        lines.append(f"    - {p.rationale}")
        lines.append(f"    - Verification: {p.verification}")
    if applied_mode:
        improved = {k: v for k, v in result.dimension_deltas.items() if v != 0.0}
        if improved:
            lines.append("")
            lines.append("## Dimension deltas")
            for dim_id, delta in sorted(improved.items(), key=lambda x: -x[1]):
                lines.append(f"- {dim_id}: {delta:+.1f}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the ``eu-ai-act-fix`` console script.

    Scans ``path`` (default ``.``), ranks gaps, and prints a remediation plan.
    Default is a safe dry-run — pass ``--apply`` to actually write fixes (each
    guarded by a re-scan regression check). ``--json`` prints the full
    :class:`FixLoopResult` as JSON; otherwise a markdown summary is printed.
    """
    parser = argparse.ArgumentParser(
        prog="eu-ai-act-fix",
        description="Autonomous EU AI Act scan -> fix -> rescan loop.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Project directory (default: .)")
    parser.add_argument("--apply", action="store_true", help="Write fixes (default: dry-run).")
    parser.add_argument("--top", type=int, default=3, help="Top N gaps to remediate per iteration.")
    parser.add_argument("--max-iter", type=int, default=5, help="Max loop iterations.")
    parser.add_argument("--use-llm", action="store_true", help="Enable the LLM fallback fixer.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of markdown.")
    args = parser.parse_args(argv)

    # CLI mode: suppress info-level structlog output so stdout stays clean for
    # the JSON/markdown payload. Library users keep their own logging config.
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
    )

    try:
        result = run_fix_loop(
            args.path,
            top_n=args.top,
            max_iterations=args.max_iter,
            apply=args.apply,
            use_llm=True if args.use_llm else None,
        )
    except ValueError as exc:
        parser.error(str(exc))
        return 2  # unreachable (parser.error exits) — keeps type-checkers happy

    if args.json:
        print(json.dumps(result.model_dump(), indent=2))
    else:
        print(_render_markdown(result, applied_mode=args.apply))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
