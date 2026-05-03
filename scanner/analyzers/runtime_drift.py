"""Runtime Drift Analyzer — Art. 3(23) substantial modification scaffolding.

Implements the runtime-state-as-versioned-architecture posture from
Nannini et al. (2026) §6.4 (paper lines 901-991), Conclusion 4 (line
2459), and Conclusion 8 (line 2470: *"high-risk agentic systems with
untraceable behavioral drift cannot currently be placed on the EU
market"*).

The paper's three-mechanism taxonomy (lines 909-943):

- **(a)** Anticipated adaptive behavior (within conformity envelope) —
  ok if documented.
- **(b)** Continuous learning post-deployment — candidate for Art.
  3(23) substantial modification.
- **(c)** Emergent behavioral drift (novel tool composition,
  cross-session memory, oversight evasion) — hardest case.

What this analyzer flags as **gaps** (line 945: "runtime state must be
treated as versioned architecture"):

1. **Model snapshot pinning** — `model="gpt-4o"` or `model="claude-3"`
   without a date suffix means a silent third-party version flip
   leaves the conformity envelope without an evidence stamp.
2. **System-prompt versioning** — system prompts as bare string
   literals rather than templated/versioned files.
3. **Tool catalogue versioning** — tools registered inline in code
   rather than declared in a versioned manifest.
4. **Behavioral monitoring presence** — the operator must monitor
   trajectory metrics, not just per-prediction accuracy.
5. **Substantial-modification procedure documentation** — Art. 3(23)
   threshold-determination procedure is mandatory per the paper.

Maps to KB dimensions: runtime_drift, logging, conformity_assessment.

References:
- Paper §6.4 (lines 901-991)
- Paper Step 11 of compliance sequence (line 1758) — post-market
  monitoring + drift detection feedback loop
"""

from __future__ import annotations

import re

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    has_file,
    search_files,
)

# ─── Model snapshot pinning ──────────────────────────────────────────────

# Floating model name (no date suffix) — the silent-flip vector.
# Pinned: gpt-4o-2024-08-06, claude-3-5-sonnet-20241022, mistral-small-latest is fine
# because the SDK records the actual served version in response, but our
# heuristic is: if the configured string ends in a date or "latest", treat as pinned.

_FLOATING_MODEL_PATTERNS = [
    # gpt-4o, gpt-4o-mini, gpt-4-turbo (no date)
    r"model\s*=\s*[\"']gpt-(?:4o(?:-mini)?|4-turbo|3\.5-turbo)[\"']",
    # claude-3-5-sonnet, claude-3-opus (no date)
    r"model\s*=\s*[\"']claude-(?:3(?:-5)?-(?:opus|sonnet|haiku))[\"']",
    # gemini-1.5-pro / gemini-pro
    r"model\s*=\s*[\"']gemini-(?:1\.5-)?(?:pro|flash)[\"']",
]

_PINNED_MODEL_PATTERNS = [
    # ISO-style date suffix: gpt-4o-2024-08-06, mistral-large-2407
    r"model\s*=\s*[\"'][^\"']*\d{4}[-_]\d{2}[-_]\d{2}[\"']",
    # Compact 8-digit date: claude-3-5-sonnet-20241022
    r"model\s*=\s*[\"'][^\"']*\d{8}[\"']",
    # Provider-served `latest` alias (SDK records resolved snapshot in evidence)
    r"model\s*=\s*[\"'][^\"']*-latest[\"']",
    r"snapshot\s*=\s*[\"'][^\"']+[\"']",
]

# ─── System-prompt versioning ────────────────────────────────────────────

_INLINE_SYSTEM_PROMPT = [
    # role=system inline literal
    r'role\s*[:=]\s*[\"\'](system|developer)[\"\'].*[\"\'].{40,}',
    # SystemMessage("...") inline
    r'SystemMessage\s*\(\s*content\s*=?\s*[\"\']',
]

_VERSIONED_PROMPT_HINTS = [
    # `prompts/system_v3.md`, `prompts/v3.md`, `system_v3.md`, `system-prompt-v2.txt`
    r"prompts?[/_-][\w-]*v\d+\.(md|txt|json|ya?ml)",
    r"system[_-]prompts?[_-]?v\d+\.(md|txt|json|ya?ml)",
    r"system[_-]prompt\.(md|txt|json|ya?ml)",
    r"prompts?/templates?",
    r"\bversion\s*=\s*[\"']\d+\.\d+",
]

# ─── Tool catalogue versioning ───────────────────────────────────────────

_TOOL_DEFINITION_INLINE = [
    # OpenAI/Anthropic tools=[{"name": ...}] inline
    r"tools\s*=\s*\[\s*\{",
    # @tool decorator on a Python function
    r"^\s*@(tool|register_tool|mcp\.tool)",
]

_TOOL_MANIFEST_HINTS = [
    r"tools?[-_]?(catalog|manifest|registry)\.(json|ya?ml)",
    r"agent[-_]?tools\.(json|ya?ml)",
    r"\.mcp\.json",
]

# ─── Behavioral monitoring presence ──────────────────────────────────────

_BEHAVIOR_MONITORING_HINTS = [
    r"\btrajectory\b|\btrajectories\b",
    r"behavior(al)?[-_ ]baseline",
    r"agent[-_]session[-_]metrics",
    r"per[_-]session[_-]tool[_-]count",
    r"langsmith|langfuse|arize|phoenix",  # already detected in agent_cascade but useful here too
]

_BASELINE_VS_LIVE_HINTS = [
    r"baseline.*compare|compare.*baseline",
    r"deviation_from_baseline",
    r"behavior(al)?[-_]drift",
]

# ─── Art. 3(23) procedure documentation ──────────────────────────────────

_SUBSTANTIAL_MODIFICATION_HINTS = [
    r"substantial.modification",
    r"art\.?\s*3\s*\(?\s*23\s*\)?",
    r"re-?conformity|re[-_]assessment",
    r"\bconformity envelope\b",
]


def analyze_runtime_drift(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()

    # ── 1. Model snapshot pinning ───────────────────────────────────────
    floating_hits: list[tuple[str, str]] = []
    for pattern in _FLOATING_MODEL_PATTERNS:
        floating_hits.extend(search_files(ctx, pattern))
    pinned_hits: list[tuple[str, str]] = []
    for pattern in _PINNED_MODEL_PATTERNS:
        pinned_hits.extend(search_files(ctx, pattern))

    if floating_hits and not pinned_hits:
        first = floating_hits[0]
        evidence_files.add(first[0])
        findings.append(Finding(
            id="rd-model-floating", category="runtime_drift",
            title="Model name uses floating alias (no date snapshot)",
            description=(
                "Model is configured with a floating alias (e.g. `gpt-4o`, `claude-3-5-sonnet`) "
                "rather than a dated snapshot. When the upstream provider rolls the snapshot, "
                "the conformity envelope shifts silently. Per Nannini et al. §6.4 Conclusion 8, "
                "untraceable drift = non-compliance with Art. 12 / 14 / 15 / 43 / 72. "
                "Pin to a dated snapshot (e.g. `gpt-4o-2024-08-06`) or stamp the resolved "
                "snapshot ID in the evidence chain on every call."
            ),
            file_path=first[0], confidence=0.8,
            compliance_impact="gap",
            compliance_dimensions=["runtime_drift", "logging"],
            evidence_snippet=first[1],
            kb_question_ids=["rd-1"], suggested_answer="no",
        ))
    elif pinned_hits:
        first = pinned_hits[0]
        evidence_files.add(first[0])
        findings.append(Finding(
            id="rd-model-pinned", category="runtime_drift",
            title="Model snapshot pinning detected",
            description="Model is pinned to a dated snapshot or `latest` alias, the latter being acceptable when the SDK records the resolved snapshot in evidence.",
            file_path=first[0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["runtime_drift", "logging"],
            evidence_snippet=first[1],
            kb_question_ids=["rd-1"], suggested_answer="yes",
        ))

    # ── 2. System-prompt versioning ─────────────────────────────────────
    inline_prompt_hits: list[tuple[str, str]] = []
    for pattern in _INLINE_SYSTEM_PROMPT:
        inline_prompt_hits.extend(search_files(ctx, pattern))
    versioned_prompt_files = []
    for hint in _VERSIONED_PROMPT_HINTS:
        versioned_prompt_files.extend(has_file(ctx, hint))

    if inline_prompt_hits and not versioned_prompt_files:
        first = inline_prompt_hits[0]
        evidence_files.add(first[0])
        findings.append(Finding(
            id="rd-prompt-inline", category="runtime_drift",
            title="System prompt is an inline string literal (not versioned)",
            description=(
                "System prompts appear as inline string literals. Without a versioned prompt "
                "template (e.g. `prompts/system_v3.md`), an edit to the prompt is invisible to "
                "the conformity baseline. Per Art. 3(23), a non-trivial system-prompt change "
                "may constitute substantial modification — but only if you can detect the change."
            ),
            file_path=first[0], confidence=0.65,
            compliance_impact="gap",
            compliance_dimensions=["runtime_drift", "tech_docs"],
            evidence_snippet=first[1],
            kb_question_ids=["rd-2"], suggested_answer="no",
        ))
    elif versioned_prompt_files:
        evidence_files.add(versioned_prompt_files[0])
        findings.append(Finding(
            id="rd-prompt-versioned", category="runtime_drift",
            title="Versioned prompt templates detected",
            description="Prompt template files exist with versioned naming.",
            file_path=versioned_prompt_files[0], confidence=0.75,
            compliance_impact="positive",
            compliance_dimensions=["runtime_drift", "tech_docs"],
            evidence_snippet="",
            kb_question_ids=["rd-2"], suggested_answer="yes",
        ))

    # ── 3. Tool catalogue versioning ────────────────────────────────────
    inline_tool_defs: list[tuple[str, str]] = []
    for pattern in _TOOL_DEFINITION_INLINE:
        inline_tool_defs.extend(search_files(ctx, pattern))
    tool_manifests = []
    for hint in _TOOL_MANIFEST_HINTS:
        tool_manifests.extend(has_file(ctx, hint))

    if inline_tool_defs and not tool_manifests:
        first = inline_tool_defs[0]
        evidence_files.add(first[0])
        findings.append(Finding(
            id="rd-tools-inline", category="runtime_drift",
            title="Tools defined inline in code (no versioned manifest)",
            description=(
                "Tools are registered inline (`tools=[{...}]` or `@tool` decorators) rather than "
                "declared in a versioned `tools-catalog.json`/`.mcp.json`/etc. A new tool added "
                "to the agent's catalogue silently expands the action surface — the paper §6.4 "
                "calls out 'novel tool composition' as a substantial-modification candidate."
            ),
            file_path=first[0], confidence=0.6,
            compliance_impact="gap",
            compliance_dimensions=["runtime_drift", "tool_governance"],
            evidence_snippet=first[1],
            kb_question_ids=["rd-3"], suggested_answer="no",
        ))
    elif tool_manifests:
        evidence_files.add(tool_manifests[0])
        findings.append(Finding(
            id="rd-tools-manifest", category="runtime_drift",
            title="Versioned tool manifest detected",
            description="Tool catalogue is declared in a versioned manifest file.",
            file_path=tool_manifests[0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["runtime_drift", "tool_governance"],
            evidence_snippet="",
            kb_question_ids=["rd-3"], suggested_answer="yes",
        ))

    # ── 4. Behavioral monitoring presence ───────────────────────────────
    behavior_hits: list[tuple[str, str]] = []
    for pattern in _BEHAVIOR_MONITORING_HINTS:
        behavior_hits.extend(search_files(ctx, pattern))
    baseline_hits: list[tuple[str, str]] = []
    for pattern in _BASELINE_VS_LIVE_HINTS:
        baseline_hits.extend(search_files(ctx, pattern))

    if behavior_hits and baseline_hits:
        first = baseline_hits[0]
        evidence_files.add(first[0])
        findings.append(Finding(
            id="rd-behavior-monitor", category="runtime_drift",
            title="Behavioral monitoring vs baseline detected",
            description="Trajectory/behavioral metrics are tracked against a baseline.",
            file_path=first[0], confidence=0.8,
            compliance_impact="positive",
            compliance_dimensions=["runtime_drift", "logging"],
            evidence_snippet=first[1],
            kb_question_ids=["rd-4"], suggested_answer="yes",
        ))
    elif behavior_hits and not baseline_hits:
        first = behavior_hits[0]
        evidence_files.add(first[0])
        findings.append(Finding(
            id="rd-behavior-no-baseline", category="runtime_drift",
            title="Trajectory monitoring without baseline comparison",
            description=(
                "Trajectory or behavioral monitoring infrastructure exists, but no baseline-vs-live "
                "comparison is detected. Per Art. 72 + paper Step 11 (line 1758), the conformity "
                "baseline must be the reference point — not just live observation."
            ),
            file_path=first[0], confidence=0.55,
            compliance_impact="gap",
            compliance_dimensions=["runtime_drift", "logging"],
            evidence_snippet=first[1],
            kb_question_ids=["rd-4"], suggested_answer="partial",
        ))

    # ── 5. Substantial-modification procedure documentation ─────────────
    sm_doc_hits: list[tuple[str, str]] = []
    for pattern in _SUBSTANTIAL_MODIFICATION_HINTS:
        sm_doc_hits.extend(search_files(ctx, pattern, flags=re.IGNORECASE))
    if sm_doc_hits:
        first = sm_doc_hits[0]
        evidence_files.add(first[0])
        findings.append(Finding(
            id="rd-sm-procedure", category="runtime_drift",
            title="Art. 3(23) substantial-modification procedure referenced",
            description="The codebase or docs reference Art. 3(23) substantial modification or a re-conformity procedure.",
            file_path=first[0], confidence=0.7,
            compliance_impact="positive",
            compliance_dimensions=["runtime_drift", "conformity_assessment"],
            evidence_snippet=first[1],
            kb_question_ids=["rd-5"], suggested_answer="yes",
        ))
    else:
        findings.append(Finding(
            id="rd-no-sm-procedure", category="runtime_drift",
            title="No documented substantial-modification procedure",
            description=(
                "No file references Art. 3(23) substantial modification or a re-conformity "
                "procedure. Per Conclusion 8, untraceable drift = non-compliance. Add a written "
                "procedure: how is a change classified? Who decides re-conformity? Where is the "
                "decision recorded?"
            ),
            file_path="(no file)",
            confidence=0.55,
            compliance_impact="gap",
            compliance_dimensions=["runtime_drift", "conformity_assessment"],
            evidence_snippet="",
            kb_question_ids=["rd-5"], suggested_answer="no",
        ))

    # ── Score ───────────────────────────────────────────────────────────
    positives = sum(1 for f in findings if f.compliance_impact == "positive")
    gaps = sum(1 for f in findings if f.compliance_impact == "gap")
    if not gaps and positives:
        score = 85.0 + min(positives * 3, 12.0)
    elif gaps and positives:
        score = max(35.0, 65.0 - gaps * 9 + positives * 5)
    elif gaps:
        score = max(20.0, 55.0 - gaps * 9)
    else:
        score = 70.0

    return AnalyzerResult(
        analyzer_id="runtime_drift",
        label="Runtime Drift / Art. 3(23)",
        findings=findings,
        score=round(score, 1),
        file_count=len(evidence_files),
        graph_node_type="monitoring",
        graph_icon="⟲",
        connected_categories=["agent_inventory", "agent_cascade", "logging_monitoring"],
        metadata={
            "model_pinned": bool(pinned_hits),
            "model_floating": bool(floating_hits) and not bool(pinned_hits),
            "tool_manifest_present": bool(tool_manifests),
            "prompt_versioning_present": bool(versioned_prompt_files),
        },
    )
