---
name: ai-act-scan
description: "Full EU AI Act scan of a codebase with scores per area, the top gaps, and recommended next steps."
argument-hint: "[path] [--article art50] [--role deployer|provider]"
---

# /ai-act-scan

Scan a codebase and explain the result in plain language.

1. Scan `$1` (default: the current folder). If the scanner MCP server is connected, call `scan_project(path="$1")`; its default concise response is enough. Otherwise run `eu-ai-act-scan "$1" --markdown`, adding any option the user asked for: `--article art50`, `--role provider`, `--cross-framework`, `--sarif`, `--save-baseline` / `--diff-baseline`, or `--ingest-claude-security FILE` / `--ingest-sarif FILE` / `--ingest-compliance-api FILE` (`eu-ai-act-scan --help` lists all).
2. If the result says the project is not an AI system, say that the EU AI Act does not appear to apply, quote the reason, and stop. Never show a compliance percentage for it.
3. Otherwise summarise in this order:
   - the overall score, explained as the share of expected evidence found (not a legal verdict);
   - the three lowest-scoring areas with their article;
   - the top three gaps, each with file:line when given and one sentence on why it matters;
   - one recommended next step.
4. Offer follow-ups: `/ai-act-quickstart` (founder priorities), `/ai-act-scan-fix` (fix plan), `/ai-act-cross-framework` (SOC 2 / ISO / NIST mapping), `/ai-act-graph` (visual map).

Report only what the scanner found. If the user doubts a finding, open the cited file and check it before agreeing; label anything you add as your own review. The scan runs locally and never uploads code.
