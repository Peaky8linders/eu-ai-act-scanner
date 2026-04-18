---
name: ai-act-scan
description: Scan a codebase for EU AI Act compliance evidence and gaps. Produces a dimension-scored report with per-file findings, architecture graph, and prioritized recommendations.
---

# /ai-act-scan

Run the EU AI Act compliance scanner on a local codebase and summarise the findings.

## Arguments

- `$1` (optional) — path to scan. Defaults to the current working directory.
- `--article ARTN` — filter results to a single article (e.g. `art9`, `art15`, `art50`).

## Behaviour

1. Run the scanner CLI in JSON mode:
   ```bash
   python -m scanner.cli "$1" --json
   ```
   If `$1` is empty, scan the current directory.
2. Parse the JSON output. Key fields:
   - `overall_compliance_pct` — 0–100
   - `compliance_scores` — map of dimension id → 0–100
   - `components` — list of discovered components with `component_type`, `compliance_impact`, `compliance_dimensions`
   - `risk_indicators` — top 10 gap-severity findings
   - `recommendations` — prioritised remediation suggestions
   - `file_findings` — per-file roll-up of findings/gaps/status
3. Present a summary in this order:
   1. **Headline**: overall compliance % and file count
   2. **Lowest-scoring dimensions** (bottom 3) with article references — use the `eu-ai-act-reference` skill if the user wants deeper article context
   3. **Top 3 risk indicators** verbatim from the result
   4. **Top 3 recommendations** verbatim
   5. Offer to drill into a specific dimension, article, or file
4. Never invent findings. If the scanner reports zero components, say so and suggest the project may not be an AI system or may use patterns the scanner does not yet recognise (and link to `CONTRIBUTING.md` for adding an analyzer).

## Example

User: `/ai-act-scan ./my-rag-app`

Response:
```
Scanned 412 files in my-rag-app. Overall compliance: 58.3%.

Lowest-scoring dimensions:
- logging (Art. 12) — 22%: no structured logging or MLflow integration detected
- human_oversight (Art. 14) — 28%: no human-in-the-loop patterns found
- risk_mgmt (Art. 9) — 31%: no risk register or threat-model artefacts

Top risk indicators:
1. AI system detected but no human oversight found
2. No adversarial robustness testing found
3. Logging present but no correlation/trace IDs

Want me to dive into any of these, or jump to a specific article (/ai-act-article art12)?
```

## Notes

- The scanner is **local-only** — never sends code off-machine.
- Scans respect standard exclusions (`.git`, `node_modules`, `__pycache__`, `.venv`, `dist`, `build`).
- Files over 2 MB are treated as binary (skipped for text analysis).
