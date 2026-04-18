# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
