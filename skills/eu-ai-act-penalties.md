---
name: eu-ai-act-penalties
description: Use when the user asks about fines, penalties, Art. 99, Art. 101, how much non-compliance costs, or wants to size exposure for risk registers / board reporting. Serves legal counsel (who need exact fine tiers), CFOs / risk owners (who size liabilities), compliance officers, and product leaders weighing go/no-go decisions. Explains the three-tier fine structure, the SME/start-up cap, and how turnover is calculated.
user_invocable: true
---

# Art. 99 — Penalties

Determine fine exposure for non-compliance with the EU AI Act. Fines are high by design — the worst tier (Art. 5 prohibitions) sits at 7% of worldwide annual turnover, higher than GDPR's 4% ceiling. Exposure calculations feed board reporting, risk registers, and deployment go/no-go decisions.

## When to invoke

- "What are the fines", "how much could this cost us"
- User mentions Art. 99, Art. 100, or Art. 101
- User is sizing compliance budget or risk exposure
- User is considering whether to continue with a project in regulatory grey area

## Applies to

- Fine structure for AI Act violations by providers, deployers, importers, distributors, authorised representatives.
- Separate rule for Union institutions (Art. 100).
- **In scope**: Art. 99 fine tiers and Art. 101 GPAI-specific fines.
- **Out of scope**: specific article obligations (route to per-article skills). Civil liability is not addressed in the AI Act — see the proposed AI Liability Directive separately.

## Regulation scope

Art. 99 defines administrative fines imposed by **Member States**. Each Member State may lay down rules, including the actual administrative fines applicable. The regulation caps the maximum at the amounts below. Fines are imposed per infringement, not per incident — a single systemic failure can trigger multiple simultaneous fines.

## Fine tiers

Three tiers of infringements under Art. 99:

### Tier 1 — Art. 99(3): Prohibited practices

- Infringement of Art. 5 (prohibited AI practices)
- Maximum fine: **€35 million** OR **7% of total worldwide annual turnover** for the preceding financial year (whichever is higher)

### Tier 2 — Art. 99(4): Most other high-risk obligations

Infringements of:
- Provider obligations (Art. 16)
- Authorised representative obligations (Art. 22)
- Importer obligations (Art. 23)
- Distributor obligations (Art. 24)
- Deployer obligations (Art. 26) — except Art. 27 which has its own tier below but same level
- Notified bodies' obligations (Art. 31, 33, 34)
- Transparency obligations for providers and deployers (Art. 50)

Maximum fine: **€15 million** OR **3% of total worldwide annual turnover** (whichever is higher)

### Tier 3 — Art. 99(5): Supply of incorrect information

- Supply of incorrect, incomplete, or misleading information to notified bodies or national competent authorities

Maximum fine: **€7.5 million** OR **1% of total worldwide annual turnover** (whichever is higher)

## GPAI-specific — Art. 101

Art. 101 covers administrative fines imposed directly by the **Commission** (not Member States) on GPAI model providers. Different structure from Art. 99:

- Maximum fine: **€15 million** OR **3% of total worldwide annual turnover** for the preceding financial year (whichever is higher)

Triggered by:
- Infringement of Art. 53 or Art. 55 obligations
- Failure to comply with a Commission request for information under Art. 91
- Failure to cooperate with the Commission under Art. 93

## SME and start-up cap

Art. 99(6): for SMEs, including start-ups, each of the fines in Art. 99(3), (4), and (5) is **capped at the percentage** (7%, 3%, 1%) OR **the euro amount, whichever is lower**. This reverses the default — for SMEs the absolute euro ceiling dominates when it's less than the percentage.

The Commission definition of SME applies (Recommendation 2003/361/EC): fewer than 250 employees AND annual turnover ≤ €50 million OR annual balance sheet total ≤ €43 million.

## Factors considered when imposing fines — Art. 99(7)

Member State authorities and the Commission consider all relevant circumstances, including:

- Nature, gravity, duration of infringement
- Whether multiple authorities have already applied fines
- Size, annual turnover, market share of the operator
- Any other aggravating or mitigating factor (financial benefit, losses avoided, damages caused, intent / negligence, remedial action, level of cooperation with authorities)
- Whether the operator had been previously sanctioned for same or other infringements
- Degree of responsibility (provider vs. distributor vs. deployer)
- How the infringement became known (self-notification weighs favourably)

## Union institutions — Art. 100

The European Data Protection Supervisor may impose fines on Union institutions, bodies, offices, and agencies:

- Art. 5 infringement: up to **€1.5 million**
- Other infringements: up to **€750,000**

## Fine calculation — "worldwide annual turnover"

Whichever is higher between euro amount and percentage. "Worldwide annual turnover" is the total turnover of the entire undertaking (group, parent, subsidiaries), not just the EU operation. This follows the established competition-law practice.

Example: A company with €5 billion worldwide turnover in breach of Art. 5 faces up to **€350 million** (7% of €5 billion), far above the €35 million nominal ceiling.

## What to do

1. Identify the infringement tier (1, 2, or 3, or Art. 101 for GPAI).
2. Pull the worldwide turnover figure (annual report).
3. Compute: `max(euro_ceiling, turnover_percentage × worldwide_turnover)` unless SME rule applies, in which case: `min(euro_ceiling, turnover_percentage × worldwide_turnover)`.
4. Apply Art. 99(7) factors to estimate likely fine — the maxima are ceilings, not expected values. First-infringement, cooperative operator, with remediation in motion typically faces a fraction of the maximum.
5. State the result as a range: lower bound (realistic first-infringement outcome after mitigation), upper bound (Art. 99 ceiling).

## Example sizing

- SaaS company, €80M turnover, minor high-risk obligation failure (late Annex IV update), first infringement, cooperative with authorities.
  - Tier 2 ceiling: max(€15M, 3% × €80M = €2.4M) = **€15M** theoretical ceiling
  - Realistic outcome under Art. 99(7): likely in low-hundreds-of-thousands to low-millions range given mitigating factors
- Large platform, €10B turnover, deploying a prohibited system under Art. 5(1)(c).
  - Tier 1 ceiling: max(€35M, 7% × €10B = €700M) = **€700M** theoretical ceiling
  - Realistic outcome: still tens to hundreds of millions, depending on duration and harm caused

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "€35M / €15M ceilings are our worst case." | For any undertaking with worldwide turnover above €500M / €500M / €750M respectively, the percentage exceeds the euro ceiling. Large groups face exposure in the hundreds of millions to billions. |
| "We're an SME, so fines are minimal." | Art. 99(6) SME cap makes fines the *lower* of percentage and euro amount. For a €20M-turnover SME, a Tier 1 fine is max 7% × €20M = €1.4M, capped at €1.4M (below the €35M ceiling). Still material and potentially business-ending. |
| "We'll use Chapter 11 / insolvency to escape fines." | Fines are imposed on the undertaking. Group liability rules may extend to parent companies depending on structural control. This is a legal question, not a compliance shortcut. |
| "We're non-Union; EU can't collect." | Art. 99 applies to operators placing AI on the Union market. Authorities can block market access (withdrawing CE marking via Art. 83, requiring withdrawal / recall). Unpaid fines can result in asset freezes in Union territory and enforcement through bilateral mechanisms. |
| "We'll self-report after launch if something goes wrong." | Self-reporting weighs favourably under Art. 99(7) but does not eliminate fines. The strongest mitigation is doing the work correctly before launch, supported by documented good-faith efforts. |
| "Penalties don't start until 2 Aug 2026 so we have time." | Most of Chapter XII (penalties) applies from 2 Aug 2025 per Art. 113(b) — covering GPAI and governance infringements. Art. 5 prohibitions carry enforcement exposure from 2 Feb 2025. The full provider/deployer penalty regime activates with the main obligations on 2 Aug 2026. |

## Cross-references

- [eu-ai-act-article-5-prohibited](eu-ai-act-article-5-prohibited.md) — highest-tier penalty exposure
- [eu-ai-act-gpai-classification](eu-ai-act-gpai-classification.md) — Art. 101 GPAI-specific fines
- [eu-ai-act-operator-roles](eu-ai-act-operator-roles.md) — role determines which Art. 99 subsection applies
- [eu-ai-act-timeline](eu-ai-act-timeline.md) — when penalty regimes activate

## Source of truth

EU Regulation 2024/1689, Art. 99, Art. 100, Art. 101, Art. 113, published in the Official Journal of the European Union, 12 July 2024. Commission Recommendation 2003/361/EC for the SME definition.
