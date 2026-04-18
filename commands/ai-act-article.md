---
name: ai-act-article
description: Show which analyzers, compliance dimensions, and current findings in this codebase map to a specific EU AI Act article.
---

# /ai-act-article

Trace a single EU AI Act article from regulation → compliance dimensions → scanner analyzers → findings in the current codebase.

## Arguments

- `$1` (required) — article identifier. Accepts `art9`, `Art. 9`, `9`, `ART9`, or `article 9`. Also accepts special identifiers: `annex-iii`, `gpai`, `fria`.

## Behaviour

1. Normalise `$1` to the canonical lowercase form (e.g. `art9`).
2. Run:
   ```bash
   python -m scanner.cli . --article art9
   ```
3. Parse the filtered JSON. Present the result in this structure:
   ```
   # Art. 9 — Risk Management
   
   **Regulation**: Continuous risk management throughout AI lifecycle (Art. 9(1-9)).
   
   **Compliance dimensions**: risk_mgmt, decision_governance
   
   **Current compliance in this repo**:
   - risk_mgmt: 34%
   - decision_governance: 28%
   
   **Evidence found**:
   - risk_mgmt → tests/test_risks.py
   - decision_governance → app/decision_hooks.py
   
   **Gaps**:
   - No post-market monitoring plan detected
   - No residual-risk communication artefact (`RISKS.md`, data card)
   ```
4. If the article has no mapped dimensions in the scanner (e.g. governance articles like Art. 65 on the AI Office), say so explicitly and note that the scanner targets obligations expressible in code/config, not governance/procedural articles.

## Article coverage

The scanner currently maps evidence to these articles:

| Article | Dimensions | Focus |
|---|---|---|
| Art. 4 | ai_literacy | Training programmes (usually not code-observable) |
| Art. 9 | risk_mgmt, decision_governance | Risk management process |
| Art. 10 | data_gov | Training data governance |
| Art. 11 | tech_docs | Annex IV technical documentation |
| Art. 12 | logging | Automatic event logging |
| Art. 13 | transparency | User-facing disclosures |
| Art. 14 | human_oversight, decision_governance | Human-in-the-loop controls |
| Art. 15 | security, access_control, infra_mlops, supply_chain | Accuracy, robustness, cybersecurity |
| Art. 17 | quality_management | QMS procedures |
| Art. 26, 27 | deployer_obligations | Deployer/operator duties (often doc-only) |
| Art. 43, 47, 48 | conformity_assessment | CE marking / declarations |
| Art. 50 | transparency, content_transparency | Limited-risk transparency |
| Art. 51, 55 | gpai_systemic_risk | GPAI systemic risk obligations |
| Art. 53 | gpai | GPAI provider obligations |
| Art. 72 | decision_governance | Post-market monitoring |
| Art. 95 | voluntary_codes | Voluntary codes of conduct |

Articles not in this table are out of scope for static code analysis — they target governance, market surveillance, or procedural obligations rather than code-level controls.
