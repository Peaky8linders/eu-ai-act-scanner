---
name: interpreting-findings
description: Use after a scanner run when the user asks "what does this mean", "which finding should I fix first", "why did I get this score", "are we compliant now", or needs help understanding how scanner output relates to EU AI Act obligations. Serves compliance officers (who translate scores to action), engineers (who fix the underlying code), and legal counsel (who assess whether the evidence supports a conformity claim). Explains the scoring model, severity tiers, priority rules, and the limits of static analysis.
user_invocable: true
---

# Interpreting EU AI Act Scanner Findings

Translate scanner output into decisions. Serves compliance officers deciding what to act on, engineers prioritising fixes, and legal counsel assessing whether the evidence will hold up in a conformity assessment (Art. 43).

## When to invoke

- After a `/ai-act-scan` run
- "what does this mean", "which should I fix first", "why did I get this score"
- "are we compliant now" — redirect to the non-verdict explanation below
- User looks at a dimension score and asks for context
- User wants to understand why the scanner flagged something as a gap

## Applies to

- Any output produced by `/ai-act-scan` or the `eu-ai-act-scan` CLI.
- **In scope**: dimension score meaning, gap prioritisation, false-positive diagnosis, remediation sequencing.
- **Out of scope**: drafting the actual fix (route to `/ai-act-scan-fix`), legal verdicts on compliance (requires human counsel + conformity procedure under Art. 43).

## Regulation scope

The scanner output is *evidence*, not a verdict. Under Art. 43, high-risk AI systems undergo a conformity assessment — either internal (Annex VI) or by a notified body (Annex VII), depending on the system type. Scanner evidence can be *cited* in that assessment but cannot *replace* it. This distinction matters enough to be the opening theme of any finding interpretation.

## The scoring model

Each dimension score is computed as `avg(confidence of positive evidence) × 100 − gap_penalty`, clamped to [0, 100]. The penalty is proportional to the gap-to-evidence ratio in that dimension.

| Finding impact | Meaning |
|---|---|
| `positive` | Evidence of a control that supports the obligation |
| `gap` | Evidence the control is missing or broken |
| `neutral` | Pattern detected; can be either supporting or concerning depending on context |

The score measures evidence weight, not legal adequacy.

## Score bands

| Band | Range | What it indicates |
|---|---|---|
| Gap | 0–29% | Almost no evidence; likely a real gap |
| Partial | 30–59% | Some evidence, material gaps remain |
| Present | 60–79% | Evidence found; documentation may still be needed |
| Strong | 80–100% | Broad evidence; still requires human verification before audit |

A score of 100% is not "compliant". A score of 0% is not "non-compliant". Both are inputs to the human assessment required by Art. 43.

## Prioritising gaps

When the user asks "what should I fix first", follow this order. The ordering reflects the EU AI Act's own hierarchy — without foundational obligations (Art. 9, 10, 14), a high-risk system cannot clear conformity assessment regardless of how strong its other evidence looks.

1. **Legal blockers on high-risk systems** — `risk_mgmt` (Art. 9), `data_gov` (Art. 10), `human_oversight` (Art. 14). Missing any one of these invalidates the conformity path.
2. **Auditability** — `logging` (Art. 12), `tech_docs` (Art. 11 + Annex IV). Regulators request records and documentation first; absence here means the rest cannot be evaluated.
3. **Runtime safety** — `security`, `access_control`, `infra_mlops`, `supply_chain` (all under Art. 15).
4. **Transparency** — `transparency` (Art. 13 to deployers, Art. 50 to users), `content_transparency` (Art. 50(2-4) for GenAI content).
5. **Operational maturity** — `quality_management` (Art. 17), `deployer_obligations` (Art. 26, 27).
6. **GPAI** — `gpai` (Art. 53), `gpai_systemic_risk` (Art. 51, 55). Only applies if the system is a general-purpose AI model.

## Answering "why is this a gap"

For each gap the user asks about, answer in four parts:

1. **What the analyzer looked for** — the concrete evidence pattern
2. **What it found (or didn't)** — the absence or counter-evidence
3. **What the obligation says** — cite the article + paragraph
4. **What a minimal fix looks like** — reference a concrete pattern

Example answer for a low `logging` score:

> The `logging_monitoring` analyzer looked for structured logging (`structlog`, `logging.getLogger`), MLflow run tracking, Prometheus metrics, or W&B hooks wrapped around inference code. It found stdlib `logging` but no correlation IDs and no append-only sink. Art. 12(1) requires high-risk AI systems to have **automatic recording of events (logs)** over their lifetime to an extent "appropriate to the intended purpose". The minimal fix is to emit structured events at inference entry and exit (input hash, output, user/session id, timestamp) to a sink that is append-only (object-locked bucket, immutable log index, or equivalent). The analyzer will recognise the fix once it sees `structlog.get_logger().info(...)` in inference code paths and either MLflow tracking or a Prometheus-wired metrics endpoint.

## Common misinterpretations to correct

| User says | Say back |
|---|---|
| "The scanner says we're compliant." | The scanner surfaces evidence. Compliance is determined by conformity assessment (Art. 43), not by static analysis percentages. |
| "We got 80% — we're good." | 80% means broad evidence for *that dimension*. Governance articles (Art. 4, 17, 26, 27) are not fully code-observable; a high score there can still reflect partial evidence. |
| "This analyzer is wrong — we *have* logging." | Ask which logging pattern. The scanner looks for specific signatures. If your pattern is legitimate and not recognised, that is an analyzer gap, not a compliance gap — file an issue at the repo. |
| "GPAI doesn't apply to us." | Confirm: is your model a foundation/general-purpose model, or are you using someone else's? Provider duties (Art. 53) apply to the model's creator. Deployer duties (Art. 26) and Art. 50 transparency still apply to downstream users. Route to [eu-ai-act-operator-roles](eu-ai-act-operator-roles.md). |
| "Art. 6(3) exception applies — we can skip high-risk obligations." | Art. 6(3) is narrow and has strict conditions: the system must perform a preparatory task, a narrow procedural task, detect decision-making patterns without replacing the decision, or perform human-oversight-assistive tasks. Even then, profiling of natural persons is always high-risk regardless of Art. 6(3). Route to [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md). |

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "The scanner didn't find a gap here, so we're fine on Art. X." | The scanner can only report on code-observable evidence. Many Art. X obligations (governance, training, documentation signoff) are not in code. Absence of a scanner gap ≠ presence of compliance. |
| "Let's chase the biggest-percentage improvements first." | Chase *article-weight* first. A 10-point improvement on `risk_mgmt` (Art. 9) matters more than a 30-point improvement on `voluntary_codes` (Art. 95) for a high-risk system. |
| "We'll accept the gap as risk-managed." | Accepting a gap is a valid decision. The Art. 9 risk management system requires that decision to be documented with justification, signed by a responsible role, and reviewed periodically. Don't treat "accepted" as synonymous with "resolved". |
| "The scanner's analyzer for X is too strict, we'll just ignore it." | Tightening rather than ignoring is the right move. Either the pattern the scanner expects is legitimate (and you need the fix), or the pattern is ambiguous (and you should file an issue so the analyzer improves). Ignoring erodes the harness. |

## When the scanner is wrong

The scanner is deliberately conservative. False negatives (missed controls) are more common than false positives. If the user has a legitimate control that was missed:

1. Ask what pattern they use.
2. Verify the control exists by reading the referenced file.
3. Suggest opening an issue at [github.com/Peaky8linders/eu-ai-act-scanner/issues](https://github.com/Peaky8linders/eu-ai-act-scanner/issues) with the pattern so the analyzer can be extended.

Contributions improve every future scan. That is the point of making this public.

## Cross-references

- [using-eu-ai-act-scanner](using-eu-ai-act-scanner.md) — orchestration, when to scan
- [eu-ai-act-reference](eu-ai-act-reference.md) — article → dimension map
- [eu-ai-act-fria-guide](eu-ai-act-fria-guide.md) — for deployer-side obligations the scanner cannot evaluate

## Source of truth

EU Regulation 2024/1689, published in the Official Journal of the European Union, 12 July 2024.
