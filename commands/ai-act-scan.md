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
   - `is_ai_system` — bool. **Check this first.** When `false` the codebase is
     out of EU AI Act scope (no AI/ML/agent signal): `compliance_scores` is empty
     and `overall_compliance_pct` is `0.0` but **not** a compliance measure.
   - `ai_system_signals` — the AI evidence that put the project in scope (e.g.
     `ai_framework:pytorch`, `model_typology:llm`); empty when out of scope.
   - `scope_note` — populated only when `is_ai_system` is `false`; explains why
     scoring was skipped.
   - `overall_compliance_pct` — 0–100 (only meaningful when `is_ai_system` is `true`)
   - `compliance_scores` — map of dimension id → 0–100
   - `components` — list of discovered components with `component_type`, `compliance_impact`, `compliance_dimensions`
   - `risk_indicators` — top 10 gap-severity findings
   - `recommendations` — prioritised remediation suggestions
   - `file_findings` — per-file roll-up of findings/gaps/status
3. **If `is_ai_system` is `false`**: do not present a compliance percentage.
   State that the project is not an AI system and is out of EU AI Act scope,
   show `scope_note` verbatim, and stop (optionally point to `CONTRIBUTING.md`
   if the user believes an AI pattern was missed). Otherwise present a summary in this order:
   1. **Headline**: overall compliance % and file count
   2. **Lowest-scoring dimensions** (bottom 3) with article references — use the `eu-ai-act-reference` skill if the user wants deeper article context
   3. **Top 3 risk indicators** verbatim from the result
   4. **Top 3 recommendations** verbatim
   5. Offer to drill into a specific dimension, article, or file
4. Never invent findings. If the scanner reports zero components, say so and suggest the project may not be an AI system or may use patterns the scanner does not yet recognise (and link to `CONTRIBUTING.md` for adding an analyzer).

Note: the dedicated **`article_50_transparency`** analyzer now reports real
findings for chatbot disclosure (Art. 50(1)), synthetic-content marking
(50(2)), emotion/biometric exposure notices (50(3)) and deep-fake / AI-generated
public-interest-text labelling (50(4)), under the `transparency` /
`content_transparency` dimensions.

## Mode: deterministic vs assisted (use your own Claude Code)

Read the active mode first: `python -m scanner.cli --settings`.

- **deterministic** (default) — present the scanner's findings as-is. The scan is
  100% local static analysis; do not add findings the scanner did not report.
- **assisted** — after presenting the deterministic report, use YOUR OWN
  reasoning (you are the user's Claude Code — no API key or wrapper needed) to add
  what the static pass cannot: read the flagged files, confirm or down-rank likely
  false positives, spot obligations the regex missed, and ground any regulatory
  claim with `/ai-act-ask`. Keep the deterministic scores as the objective
  baseline and label your additions clearly as an AI semantic review — never
  overwrite the scanner's numbers.

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
