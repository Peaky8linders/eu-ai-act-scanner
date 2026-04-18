# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
