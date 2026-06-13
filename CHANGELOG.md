# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
