---
name: interpreting-findings
description: Use after a scanner run when the user asks "what does this mean", "which finding should I fix first", "why did I get this score", or needs help understanding the dimension scores and their regulatory impact. Explains the scoring model, severity tiers, and priority rules.
user_invocable: true
---

# Interpreting EU AI Act Scanner Findings

Help the user understand what the scanner output *means*, not just what it says.

## The scoring model

Each **dimension score** is `avg(confidence of positive evidence) × 100 − gap_penalty`, clamped to [0, 100].

- **Positive finding** (`compliance_impact: "positive"`): evidence of a control that supports the obligation.
- **Gap finding** (`compliance_impact: "gap"`): evidence the control is missing or broken.
- **Neutral finding** (`compliance_impact: "neutral"`): the analyzer observed a pattern but it could be either supporting or concerning depending on context.

The score is **not a pass/fail grade**. Interpret it as: "how much evidence did the scanner find that the control is in place, discounted by how many gaps it found in the same area".

## Score bands

| Band | Range | Means |
|---|---|---|
| Gap | 0–29% | Almost no evidence; likely a real gap |
| Partial | 30–59% | Some evidence, material gaps remain |
| Present | 60–79% | Evidence found, may need documentation |
| Strong | 80–100% | Broad evidence; still requires human verification |

**Never equate any score with legal compliance.** Compliance is determined by conformity assessment (Art. 43), not by a static analysis percentage.

## Prioritising gaps

When the user asks "what should I fix first", follow this order:

1. **Legal blockers on high-risk systems**: `risk_mgmt` (Art. 9), `data_gov` (Art. 10), `human_oversight` (Art. 14). Without these, a high-risk system cannot clear conformity assessment.
2. **Auditability**: `logging` (Art. 12), `tech_docs` (Art. 11). Regulators will ask for records and documentation first.
3. **Runtime safety**: `security`, `access_control`, `infra_mlops`, `supply_chain` (all tied to Art. 15).
4. **Transparency**: `transparency` (Art. 13, 50), `content_transparency` (Art. 50(2-4)) — especially for user-facing systems.
5. **Operational maturity**: `quality_management` (Art. 17), `deployer_obligations` (Art. 26/27).
6. **GPAI**: `gpai` (Art. 53), `gpai_systemic_risk` (Art. 51, 55) — only if the system is a GPAI model above the systemic-risk threshold.

## Answering "why is this a gap"

For each gap the user asks about, explain:

1. **What the analyzer looked for** — the concrete evidence pattern it expects.
2. **What it found (or didn't)** — the absence or counter-evidence.
3. **What the obligation says** — cite the article number, not invented paragraph text.
4. **What a good fix looks like** — reference `ai-act-scan-fix` remediation patterns.

Example response when the user asks about a low `logging` score:

> The scanner looked for structured logging (`structlog`, `logging.getLogger()`), MLflow run tracking, or Prometheus metrics hooked into inference code. It found none of those. Art. 12 requires high-risk AI systems to keep automatic event logs that are tamper-resistant. The minimal fix is to wrap inference entrypoints with `structlog.get_logger().info("inference", input_hash=…, output=…, user_id=…)` and persist logs somewhere append-only (e.g. object storage with object lock). I can propose a concrete diff if you want.

## Common misinterpretations to correct

| User says | Say back |
|---|---|
| "The scanner says we're compliant" | The scanner surfaces evidence. Compliance is a legal determination. |
| "We got 80% — we're good" | 80% means broad evidence. Verify each dimension with a human reviewer. |
| "This analyzer is wrong — we have logging" | Ask which logging pattern. The scanner looks for specific signatures. If your pattern is new and legitimate, that's an analyzer gap — file an issue. |
| "GPAI doesn't apply to us" | Confirm: is your model a foundation/general-purpose model? If no, you can skip `gpai`/`gpai_systemic_risk`. If yes, the threshold for systemic risk is ≥10^25 FLOPs of training compute. |

## When the scanner is wrong

The scanner is deliberately conservative — it reports evidence patterns, not semantic understanding. False negatives (missed controls) are more common than false positives. If the user has a legitimate control the scanner missed:

1. Ask what pattern they use.
2. Confirm the control exists by reading the referenced file.
3. Suggest opening an issue at `github.com/Peaky8linders/eu-ai-act-scanner/issues` with the pattern so the analyzer can be extended.

Contributions improve everyone's scans. That is the point of making this public.
