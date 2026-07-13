# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-07-13

### Added — Article 50 transparency analyzer, grounded Q&A, and assisted mode

- **Real Article 50 detection.** New `article_50_transparency` analyzer (the 22nd
  analyzer) deterministically detects all four Art. 50 transparency obligations:
  AI-interaction disclosure (50(1)), machine-readable synthetic-content marking
  (50(2)), emotion-recognition / biometric-categorisation exposure notice (50(3)),
  and deep-fake / AI-generated-public-interest-text labelling (50(4)) — with
  positive-evidence detection and a no-false-gaps guard for backend-only repos.
  Ported from the CodexAI product scanner. Enforceable 2 Aug 2026 (the Digital
  Omnibus, adopted 29 Jun 2026, deferred high-risk to Dec 2027 but left Art. 50
  untouched).
- Removed the blanket `mt-llm-transparency-gap` from `model_typology` — it fired
  for every detected LLM regardless of whether disclosure existed, double-
  penalising the `transparency` dimension. The dedicated analyzer now owns the
  `transparency` / `content_transparency` dimensions precisely.
- **Grounded offline Q&A** — new `/ai-act-ask` command + `scanner.cli --ask` +
  `scanner.qa.answer_question`. Retrieves over a bundled knowledge base — verbatim
  EU AI Act statute text (`scanner/data/official_eu_ai_act.py`, EUR-Lex CELEX
  32024R1689) + obligation paraphrases + the compound-risk taxonomy — and returns a
  cited answer. Runs 100% locally with no LLM/network by default (mirrors the
  CodexAI "Lexy" deterministic fallback path); the optional LLM path runs through
  the citation guard so no uncited sentence survives.
- **Bundled knowledge graph / ontology** — vendored the full Regulation (EU)
  2024/1689 verbatim text and the typed offline ontology
  (`scanner/data/ontology.py`) for grounding and host-Claude traversal.
- **Assisted mode + settings** — new `scanner.settings` layer (project
  `.eu-ai-act-scanner.toml` + env overrides) surfaced via `/ai-act-settings` and
  `scanner.cli --settings` / `--set` / `--mode`. `mode: assisted` opts into using
  your **own Claude Code** (the host session — no API key, no wrapper) for a
  semantic pass over the deterministic findings, grounded Q&A, and — with
  `auto_apply: true` — applying fixes agentically. `deterministic` (default) keeps
  the historical 100%-local behaviour.

### Changed
- Reconciled the four skewed versions (`plugin.json` 0.5.0, `scanner/__init__.py`
  0.7.0, `pyproject.toml` 0.7.1) to a single **0.8.0**.
- CLI now forces UTF-8 stdout/stderr so `--ask` answers render on Windows
  cp1252/cp437 consoles.

## [0.7.1] - 2026-07-01

### Fixed — lethal_trifecta score could exceed the 0-100 bound

Found while dogfooding the scanner against a large real-world repo: the
`gaps and positives` scoring branch in `analyze_lethal_trifecta`
(`65.0 - len(gaps) * 15 + len(positives) * 5`) had no upper clamp, so a
project with many gated trifecta files and at least one ungated file could
push the score above 100 and crash `scan_project()` on `AnalyzerResult`'s
`score: float = Field(ge=0.0, le=100.0)` validation. Every other branch in
the same function already clamps its bound (`min(95.0, ...)`,
`max(15.0, ...)`); this branch now does too:
`min(100.0, max(35.0, ...))`. Added a regression test
(`test_lethal_trifecta_score_stays_within_bounds_with_many_gated_files`)
that reproduces the overflow with 14 gated files + 1 ungated file.

## [0.7.0] - 2026-06-28

### Fixed — AI-system scope gate (don't score / "fix" non-AI projects)

The compliance model previously rewarded the *presence* of evidence artifacts
regardless of whether the scanned project was an AI system at all. Running
`eu-ai-act-fix <dir> --apply` on a directory with **zero** AI source code still
raised "overall compliance" from 0 → ~60 by writing boilerplate evidence files
(`MODEL_CARD.md`, tests, `Dockerfile`, ...). The EU AI Act only governs *AI
systems* (Art. 3(1)), so a percentage for a non-AI project is meaningless and
the fix loop was effectively gaming its own score.

- **`scanner.analyzers.detect_ai_system`** — new gate keying on the three
  purpose-built AI detectors (`ai_frameworks` detected list, `model_typology`
  typology ≠ `none`, `agent_inventory` runtime signals). `ai_frameworks` is
  AST-import precise; `model_typology` / `agent_inventory` are heuristic and may
  occasionally match non-AI code — the gate intentionally errs toward in-scope
  (a false negative would wrongly drop a real AI system). The generic
  action-verb / deployment-category heuristics are deliberately excluded — they
  match ordinary non-AI code far too aggressively.
- **`ScanResult`** gains `is_ai_system`, `ai_system_signals`, and `scope_note`.
  When no AI signal is found, `scan_project` skips scoring entirely:
  `compliance_scores` is empty, `overall_compliance_pct` is `0.0` (not a
  compliance measure — check `is_ai_system` first), and compliance-framed
  `risk_indicators` / `recommendations` / `incident_grounding` are suppressed.
- **`scanner.fix_loop`** — `rank_gaps` returns `[]` for an out-of-scope result,
  and `run_fix_loop` short-circuits after the baseline scan: it proposes
  nothing and writes nothing. `FixLoopResult` gains `is_ai_system` / `scope_note`.
- **CLI / fix-loop markdown** render a "Not an AI system — out of EU AI Act
  scope" banner instead of a percentage; the `/ai-act-scan` and
  `/ai-act-scan-fix` commands check `is_ai_system` before reporting.
- Tradeoff: an AI system built only on a framework the scanner doesn't yet
  recognise is treated as out of scope (a false negative) rather than scored
  on boilerplate. The gate reuses the scanner's existing AI detectors, so its
  coverage tracks theirs — add an analyzer/framework signal to widen scope.

## [0.6.0] - 2026-06-28

### Added — deterministic obligations, an autonomous fix loop, and a Claude Max bridge

Five new modules port the production-hardened optimizations from the
`regenold-eu-ai-act-rag` system into the scanner and close the scan→fix loop.

- **`scanner/obligations.py` — deterministic operator-role + obligation inference.**
  A closed-vocabulary code-signal scan (ported in spirit from regenold's
  `entity_extractor.py`) infers which EU AI Act role(s) the scanned codebase occupies
  (provider / deployer / GPAI provider) and back-fills `applicable_roles` on every
  **gap** finding from the roles that actually owe its articles
  (`scanner.data.role_obligations`). `ScanResult` now carries `inferred_roles`. Runs
  automatically inside `run_all_analyzers` (gap findings only, idempotent, never
  overwrites analyzer-level tags).
- **`scanner/grounding.py` — authoritative article text + a citation guard.**
  `OBLIGATION_TEXT` covers every article in `kb.ARTICLE_TO_DIMENSIONS` with a faithful
  paraphrase grounded in the verbatim EUR-Lex prose; `filter_unsupported_sentences`
  (ported from regenold's `citation_guard.py`) drops any LLM sentence not supported by
  its cited articles. Anti-hallucination layer for the optional LLM paths.
- **`scanner/refs.py` — single-source EU AI Act citation converter.** Bridges the
  three citation vocabularies in the codebase (bare `14(4)`, display `Art. 13 & 50`,
  canonical `Art. 25(4)`) and the user-facing `Article 14.4` form.
- **`scanner/llm_bridge.py` — Claude Max bridge.** Routes the scanner's optional LLM
  calls through a local Claude-Code subscription wrapper
  (`EU_AI_ACT_SCANNER_LLM_BASE_URL`, default `http://127.0.0.1:8000`, also reachable
  over a Cloudflare tunnel) instead of a metered API key — so the LLM-assisted paths
  run on a Claude Max subscription. Includes the ported multi-strategy JSON extractor
  and structural-truncation heuristic from regenold's `graph_rag.py`. Fully graceful;
  never blocks a scan. `eu-ai-act-scan --llm-status` reports config + live health.
- **`scanner/fix_loop.py` — autonomous scan→fix→rescan loop.** New `eu-ai-act-fix`
  command. Ranks gaps, generates deterministic remediations validated against the
  analyzers' own positive-detection patterns (LLM-drafted fallback when the bridge is
  enabled), and in `--apply` mode writes each fix, re-scans, and **reverts any fix that
  regresses another dimension** (the antifragile property) before converging. Defaults
  to a safe dry-run; compliance docs use `<FILL IN: …>` placeholders — never fabricated.

### Changed

- `scanner/analyzers/_base.py`: the optional `llm_assess` helper now delegates to the
  Claude Max bridge; fixed the `ast.Str` Python 3.14 deprecation.
- `eu-ai-act-scan --markdown` now reports the inferred operator role(s).

## [0.5.0] - 2026-06-13

### Added — Art. 50 limited-risk transparency skill

New `eu-ai-act-article-50-transparency` skill, closing the Art. 50 coverage gap
flagged in the authoring meta-skill's own coverage audit (Art. 50 was listed as a
required topic with no dedicated decision-tree skill). It encodes the per-paragraph
**provider vs deployer** split — Art. 50(1) provider interaction-disclosure,
Art. 50(2) provider synthetic-content marking, Art. 50(3) deployer emotion/biometric
notice, Art. 50(4) deployer deep-fake disclosure — with a decision tree, a Common
Rationalizations table, and two cross-cutting guards: the **GPAI + Art. 50 dual
trigger** (a GPAI generating content is covered by Art. 50(2) by its own terms, and
by Art. 50(1) when it interacts with natural persons, on top of the Art. 53 GPAI
duties), and the **classify-first rule** (a general-purpose chatbot is limited-risk
and owes Art. 50(1) alone — do not stack high-risk Art. 13 transparency unless the
system is independently high-risk). Application date 2 August 2026; penalty tier
Art. 99(4). This is the scanner-side counterpart of the same legal-accuracy guards
added to the CodexAI Lexy RAG engine.

### Changed

- `plugin.json`: registered the new skill, bumped to 0.5.0, and added Art. 50
  limited-risk transparency to the description (14 article-grounded skills).
- `eu-ai-act-reference` and `eu-ai-act-gpai-classification` now cross-reference the
  new skill (the Art. 50 routing pointer and the GPAI dual-trigger).

## [0.4.0] - 2026-06-05

### Added — real-world incident grounding + MCP server

Turns every finding from a normative gap into an evidence-based one: each gap is
crosswalked to the documented incidents that exploited its class, mapped to the
frameworks security teams already report against.

**Incident corpus** (`scanner/data/incidents.json` + `scanner/data/incident_corpus.py`):

- A curated, reviewed-tier subset of the open **GenAI & Agentic AI Security
  Incidents** dataset (`emmanuelgjr/genai-incidents`, **CC-BY-4.0**) — real-world
  and research incidents aggregated from AIID, OECD AIM, AIAAIC, MITRE ATLAS,
  AVID, the MIT AI Risk Repository, NVD, GHSA, OSV, garak, promptfoo, and others.
- Each incident carries its native taxonomy verbatim: OWASP Top 10 for LLM
  Applications (2025), OWASP Agentic (ASI) Top 10, NIST AI RMF, MITRE ATLAS
  techniques + tactics, plus documented mitigations and CVE IDs.
- Bundled offline (ships in the wheel via `package-data`); no network at scan
  time. Regenerated deterministically by `scripts/sync_incident_corpus.py`
  (`pip install eu-ai-act-scanner[sync]`), which selects a coverage-complete
  subset so every KB dimension and threat category is groundable.

**Crosswalk + grounding** (`scanner/data/incident_crosswalk.py`,
`scanner/incident_grounding.py`):

- Maps the scanner's vocabulary (KB dimensions, agentic threat categories,
  EU AI Act article refs) to the incident taxonomy. Pure, deterministic, offline.
- New public API on `scanner`: `incidents_for_dimension`, `incidents_for_article`,
  `incidents_for_threat`, `incidents_for_finding`, `incident_corpus_stats`.
- `Finding` gains `related_incidents: list[str]`; gap findings are auto-grounded
  in `run_all_analyzers` (`_attach_incident_grounding`).
- `ScanResult` gains `incident_grounding: dict[str, list[str]]` — worst-scoring
  dimensions paired with the incidents that exploited them.

**MCP server** (`scanner/mcp_server.py` + `.mcp.json`):

- Roadmap v0.4 item delivered: `eu-ai-act-scan-mcp` exposes seven tools over the
  Model Context Protocol (`scan_project`, `list_dimensions`, `get_article`,
  `incidents_for_dimension`, `incidents_for_threat`, `incidents_for_article`,
  `incident_corpus_stats`) so non-Claude-Code agents can call the same engine.
  Tool logic is plain importable functions; the `mcp` SDK is an optional extra
  (`pip install eu-ai-act-scanner[mcp]`).

**Plugin surface**:

- New command `/ai-act-incidents <dimension|article|threat>` and CLI flag
  `eu-ai-act-scan --incidents KEY [--limit N]`; `--markdown` output now includes
  a "Real-world incident grounding" section.
- New skill `eu-ai-act-incident-grounding` (authored to the plugin standard:
  article-cited, audience-tiered, Common Rationalizations table, Official-Journal
  + dataset source footer).
- Plugin: 3 → 4 commands, 12 → 13 skills.

### Changed

- `pyproject.toml`: `[mcp]` and `[sync]` optional-dependency extras; package-data
  ships `scanner/data/*.json`; second console script `eu-ai-act-scan-mcp`.
- README + plugin description rewritten around the three-deliverable framing
  (plugin + library + MCP server) and the incident-grounding feature; corrected
  a stale "19 dimensions" reference to 23.

## [0.3.0] - 2026-05-03

### Added — agent-aware analyzers and four-axis compound-risk taxonomy

Backports the agentic-AI scanner work from CodexAI (the proprietary upstream
compliance platform), grounded in Nannini et al. (2026), *AI Agents under EU
Law: A Compliance Architecture for AI Providers*.

**Seven new analyzers** (registry now totals 21):

- `agent_inventory` — detects MCP clients, OpenAI Assistants v2, browser-use /
  Playwright agents, code-interpreter sandboxes (e2b, Daytona). Categorises
  deployments (healthcare → MDR / Annex I(A), finance, employment, etc.) and
  derives an action-verb taxonomy (`send_email`, `execute_code`,
  `authorize_payment`, ...). Flags missing inventory artefacts.
- `privilege_minimization` — flags the prompt-as-control antipattern
  ("don't delete files" in a system prompt), open exec on model output,
  long-lived hard-coded credentials, OAuth scope over-grant (e.g. requesting
  `gmail.send` while only reading), and recognises a `tools-permissions.yaml`
  permission registry.
- `runtime_drift` — flags floating model IDs (`gpt-4o`) over pinned ones
  (`gpt-4o-2024-08-06`), inline prompts vs. versioned prompt files, missing
  tool-catalogue manifests, and absence of an Art. 3(23) substantial-modification
  procedure.
- `regulatory_perimeter` — emits triggered-instrument signals for adjacent EU
  legislation: GDPR (CRM signals), Data Act (IoT / MQTT), CRA (CLI
  entry-points in `pyproject.toml`), MDR (FHIR / DICOM), NIS2 (OPC-UA /
  Modbus). Flags missing Step-9 adjacent-legislation documentation.
- `lethal_trifecta` — AEPD rule-of-2 detector: untrusted input + sensitive
  data + autonomous state-change without a human-oversight gate (Spanish DPA
  18 Feb 2026 guidance, aligned with Simon Willison's framing and Meta's 31
  Oct 2025 framework).
- `model_typology` — foundation / generative / decision-support / perception
  classification with Annex grounding.
- `cloud_deployment` — cloud-provider-specific control patterns and shared-
  responsibility flags.

**Four new compliance dimensions** (KB now totals 23):

- `agent_inventory` (Art. 11 / Annex IV) — documented external-action surface.
- `tool_governance` (Art. 14 / Art. 15(4)) — per-tool least-privilege scopes.
- `regulatory_perimeter` (Art. 25 / Art. 25(4) / Art. 3(23)) — perimeter
  classification with Art. 25(4) agreements.
- `runtime_drift` (Art. 3(23) / Art. 12 / Art. 72) — drift detection against
  the conformity-assessment baseline.

**New data modules** under `scanner.data`:

- `agentic_taxonomy` — four compound-risk axes (cascading, emergent,
  attribution, temporal), threat-category cross-walks (Kim et al., Hammond
  et al., OWASP Top-10 Agentic, AEPD), and seven agent archetypes.
- `role_obligations` — operator-role obligation registry covering the six NLF
  roles plus `gpai_provider`, `gpai_systemic_provider`, and the
  `extraterritorial_non_eu` modifier (MSR Art. 4 / AI Act Art. 74).

### Changed

- `Finding` model now carries `compound_risk_type`, `applicable_roles`, and
  `threat_categories` fields. Findings emitted by the four agent-aware
  analyzers are auto-tagged with their compound-risk axis via
  `_apply_default_taxonomy_tags`. Per-analyzer overrides win over defaults.
- `ARTICLE_TO_DIMENSIONS` map extended for Art. 11, 12, 14, 15, 25, 72.
- README rewritten with a separate "Agent-aware analyzers" table and a
  reference to the [arXiv preprint](https://arxiv.org/abs/2504.06255).
## [0.2.0] - 2026-04-19

### Added — full EU AI Act skill harness for law practitioners

Expanded from 3 to 12 skills with a consistent authoring standard. Every skill now
cites articles + paragraphs, states its audience (engineer / compliance officer /
legal counsel / deployer), includes a Common Rationalizations table, and ends with
a "Source of truth" reference to the Official Journal.

- `authoring-eu-ai-act-skills` — meta-skill enforcing the authoring standard for
  every skill in the plugin. Use it to add new skills or audit existing ones.
- `eu-ai-act-article-5-prohibited` — decision tree for the eight Art. 5(1)
  prohibited-practice categories, including the profiling exception-to-derogation.
- `eu-ai-act-article-6-classification` — high-risk classification via Art. 6 +
  Annex III, including the Art. 6(3) derogation applied strictly.
- `eu-ai-act-fria-guide` — Fundamental Rights Impact Assessment requirements under
  Art. 27, including trigger conditions (deployer + domain), the seven required
  contents, and the DPIA interaction.
- `eu-ai-act-operator-roles` — six operator roles with Art. 25 role-flip rules.
- `eu-ai-act-gpai-classification` — GPAI definition, systemic-risk threshold
  (Art. 51(2) 10^25 FLOPs), Art. 53 vs. Art. 55 obligation split, open-source
  exemption.
- `eu-ai-act-annex-iv-guide` — nine Annex IV sections required for Art. 11
  technical documentation, with concrete evidence guidance per section.
- `eu-ai-act-timeline` — Art. 113 staggered application dates and Art. 111
  transitional provisions.
- `eu-ai-act-penalties` — three-tier Art. 99 fine structure, Art. 101 GPAI fines,
  Art. 99(6) SME cap, and Art. 99(7) factors considered.

### Changed

- `using-eu-ai-act-scanner`, `interpreting-findings`, `eu-ai-act-reference` —
  rewritten against the new authoring standard. Added audience tiering, article
  citations, stronger cross-references, and Common Rationalizations tables.

## [0.1.0] - 2026-04-19

Initial public release. Extracted from [CodexAI](https://antifragile-ai.net) with
compliance-platform-specific logic (risk classifier, maturity assessor, roadmap
engine, documentation generators) removed.

### Added
- 14 EU AI Act analyzers covering AI frameworks, data pipelines, human oversight,
  security controls, fairness testing, test suites, logging/monitoring,
  documentation, configuration, agent cascades, adversarial robustness,
  Terraform, CloudFormation + Kubernetes, and CI/CD + Dockerfile.
- Knowledge base with 19 compliance dimensions and article → dimension map.
- Claude Code plugin with three commands (`/ai-act-scan`, `/ai-act-scan-fix`,
  `/ai-act-article`) and three skills (`using-eu-ai-act-scanner`,
  `interpreting-findings`, `eu-ai-act-reference`).
- CLI entry point `eu-ai-act-scan` with JSON / Markdown / article-filtered output.
- Python library API (`from scanner import scan_project`).
- Optional LLM-assisted analysis behind `EU_AI_ACT_SCANNER_LLM=true` env var.
- Test fixture AI project for deterministic end-to-end tests.

### Not yet included (roadmap)
- FastAPI router (Phase 2).
- MCP server wrapper (Phase 3).
- Baseline / diff mode (Phase 4).
