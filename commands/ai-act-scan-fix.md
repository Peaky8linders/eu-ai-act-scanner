---
name: ai-act-scan-fix
description: Scan a codebase, then propose concrete remediation (code edits, new files, tests) for the top compliance gaps. Does NOT auto-apply — always shows the plan first.
---

# /ai-act-scan-fix

Run `/ai-act-scan`, then build a remediation plan for the top compliance gaps.

## Arguments

- `$1` (optional) — path to scan. Defaults to the current directory.
- `--top N` (default 3) — number of gaps to remediate.

## Behaviour

1. Invoke the scanner as in `/ai-act-scan`.
2. Select the top `N` gap findings by (low score × article weight). Prioritisation order when scores are tied:
   1. `risk_mgmt` (Art. 9) — foundational, blocks conformity assessment
   2. `data_gov` (Art. 10) — training-data provenance affects all downstream
   3. `human_oversight` (Art. 14) — hard legal requirement for high-risk
   4. `logging` (Art. 12) — auditability
   5. Everything else
3. For each selected gap, produce a **remediation proposal**:
   - **What**: one-sentence description of the missing control
   - **Article**: the obligation driving the fix (e.g. `Art. 14(1)`)
   - **Where**: specific file path(s) to create or edit
   - **What to add**: concrete code / YAML / markdown snippet
   - **Verification**: how the scanner would recognise the fix on a re-scan
4. **Show the plan. Do NOT apply edits yet.** Ask the user which proposals to apply. Then:
   - Apply approved proposals one at a time
   - Re-run the scanner after each fix
   - Report the delta in compliance score per dimension
5. If the user says "apply all", still apply serially and re-scan between fixes so regressions are caught early.

## Remediation pattern library

When proposing fixes, lean on these canonical patterns — they are what the scanner's analyzers are looking for:

| Gap dimension | Minimal evidence the scanner will accept |
|---|---|
| `logging` | `structlog` or `logging.getLogger()` with correlation IDs, OR MLflow run tracking |
| `human_oversight` | A function/decorator named `human_review`, `approval_gate`, `confidence_threshold`, or `human_in_the_loop` |
| `tech_docs` | A `README.md` with ≥5 sections covering purpose, data, risks, monitoring, and contacts; or a `MODEL_CARD.md` |
| `test_suite` | A `tests/` directory with pytest files covering model behaviour (not just unit tests on utils) |
| `data_gov` | A `DATA_CARD.md` or `docs/data/` describing sources, collection, bias assessment |
| `security_controls` | Auth middleware, rate limiting, input validation on any AI-serving endpoint |
| `fairness_testing` | Tests that import `aif360`, `fairlearn`, or compute disparate-impact metrics |

## Safety notes

- Never fabricate claims. If proposing a `MODEL_CARD.md`, leave content the user must fill in as `<FILL IN: …>` placeholders. Compliance documents with invented facts are worse than none.
- Never commit without explicit user approval. Compliance code changes can touch regulatory obligations — the human stays in the loop.
