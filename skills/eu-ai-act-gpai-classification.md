---
name: eu-ai-act-gpai-classification
description: Use when the user asks "is my model a GPAI", mentions general-purpose AI, foundation models, Art. 51, Art. 53, Art. 55, systemic risk, or the 10^25 FLOP threshold. Serves foundation-model providers (who bear Art. 53/55 obligations), downstream integrators (who need to know what the model provider owes them under Art. 53(1)(b)), legal counsel, and compliance officers. Separates GPAI provider duties from downstream-deployer duties, and clarifies what triggers the systemic-risk tier.
user_invocable: true
---

# GPAI Classification and Obligations

Determine whether an AI model is a General-Purpose AI model under Art. 3(63), whether it carries systemic risk under Art. 51, and which obligations under Art. 53-55 apply to which party. GPAI is where the most recent regulatory movement has happened — the Code of Practice under Art. 56 is still being finalised; treat any GPAI analysis as potentially affected by ongoing Commission guidance.

## When to invoke

- "Is my model GPAI", "what's a general-purpose AI"
- "Is our model systemic risk"
- "Do Art. 53 / 55 obligations apply"
- User mentions foundation models, base models, or pre-trained models intended for multiple tasks
- User mentions the 10^25 FLOP threshold

## Applies to

- Classification of whether an AI model is GPAI, and whether it is systemic-risk GPAI.
- Mapping of Art. 53 and Art. 55 obligations to the GPAI provider role.
- **In scope**: Art. 3(63), Art. 3(64) generality, Art. 51-55.
- **Out of scope**: Art. 6-15 high-risk *AI system* obligations (separate track — route to [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md)). Note that an AI system built on a GPAI model can simultaneously be high-risk under Art. 6 AND downstream-use a GPAI.

## Regulation scope

**GPAI model** (Art. 3(63)): an AI model, including where trained with a large amount of data using self-supervision at scale, that displays significant generality and is capable of competently performing a wide range of distinct tasks regardless of the way the model is placed on the market and that can be integrated into a variety of downstream systems or applications. This does not cover AI models used for research, development, or prototyping before being placed on the market.

**Generality** (Art. 3(64)): the ability of an AI system to perform in a distinct way that is relevant to its capability to perform diverse tasks. Indicative (not required): at least 10^22 FLOPs of training compute is a threshold the regulation references for identifying GPAI (see Recital 98).

**Systemic-risk GPAI** (Art. 51): A GPAI model has systemic risk if it has high-impact capabilities. Presumed when cumulative compute used for training exceeds **10^25 FLOPs** (Art. 51(2)). The Commission can adjust the threshold or designate specific models via delegated act under Art. 51(3).

## Decision tree

```
Step 1 — Is the model placed on the Union market or put into service
in the Union?
  └─ no  → Not in scope for Art. 53/55 obligations. Act may still
            apply extraterritorially if outputs used in Union (Art. 2).
  └─ yes → Step 2

Step 2 — Is the model research-only, development-only, or prototype
pre-market?
  └─ yes → NOT GPAI under Art. 3(63) scope exclusion.
  └─ no  → Step 3

Step 3 — Does the model display significant generality AND is capable
of competently performing a wide range of distinct tasks AND can be
integrated into a variety of downstream systems?
  └─ no  → Not GPAI. It may still be an AI system under Art. 3(1).
            Classify via Art. 6.
  └─ yes → GPAI. Step 4.

Step 4 — Is cumulative training compute >= 10^25 FLOPs,
OR has the Commission designated this model as systemic-risk under
Art. 51(1)(b)?
  └─ yes → SYSTEMIC-RISK GPAI. Art. 53 AND Art. 55 obligations apply.
  └─ no  → GPAI without systemic risk. Art. 53 obligations apply.
```

### Thresholds — use precisely

- **10^22 FLOPs** (Recital 98) — indicative floor for "generality" in large language models. Recital, not article. Not binding, but a useful reference.
- **10^25 FLOPs** (Art. 51(2)) — binding threshold for systemic-risk presumption. Note this is **cumulative training compute**, not inference compute, not fine-tuning compute alone.
- **Designation by the Commission** (Art. 51(1)(b)) — a model below the FLOP threshold can still be designated as systemic-risk based on the criteria in Annex XIII.

## Obligations — Art. 53 (all GPAI providers)

Every GPAI provider (systemic-risk or not) must:

- **Art. 53(1)(a)**: Draw up and keep up to date technical documentation of the model (see Annex XI contents). Provide to the AI Office and national authorities upon request.
- **Art. 53(1)(b)**: Draw up information and documentation for downstream providers that integrate the model into their AI systems, enabling them to understand capabilities, limitations, and comply with their own obligations. See Annex XII.
- **Art. 53(1)(c)**: Put in place a policy to comply with Union law on copyright and related rights, particularly for opt-outs under Art. 4(3) of Directive (EU) 2019/790.
- **Art. 53(1)(d)**: Publish a sufficiently detailed summary of the content used to train the GPAI model, using a template provided by the AI Office.

**Exemption for open-source GPAI** (Art. 53(2)): If the model is released under a free and open-source licence that allows access, use, modification, and distribution, AND the parameters (weights), architecture, usage info are made publicly available, then 53(1)(a) and 53(1)(b) do NOT apply — UNLESS the model is systemic-risk (Art. 51), in which case the exemption is lifted.

## Obligations — Art. 55 (systemic-risk GPAI)

In addition to Art. 53, systemic-risk GPAI providers must:

- **Art. 55(1)(a)**: Perform model evaluation per state-of-the-art protocols, including adversarial testing, to identify and mitigate systemic risks.
- **Art. 55(1)(b)**: Assess and mitigate possible systemic risks at Union level, including their sources, arising from development, placement, or use.
- **Art. 55(1)(c)**: Track, document, and report — without undue delay — serious incidents and possible corrective measures to the AI Office and relevant national authorities.
- **Art. 55(1)(d)**: Ensure an adequate level of cybersecurity protection for the model and its physical infrastructure.

**Art. 55(2)**: Providers may rely on codes of practice under Art. 56 to demonstrate compliance until harmonised standards are published.

**Art. 55(3)**: Notification duty (Art. 52) — a provider that knows or ought to know its model meets the systemic-risk criteria must notify the Commission within two weeks.

## GPAI vs. downstream — who owes what

A company that builds a product on top of a third-party GPAI model is:

- A **downstream provider** of its own product. Its product obligations depend on the product's risk tier (Art. 5 / Art. 6).
- NOT a provider of the underlying GPAI model. Art. 53 obligations remain with the GPAI creator.
- Entitled under Art. 53(1)(b) to receive the documentation needed to comply with its own obligations.

A company that fine-tunes a GPAI model may cross a threshold. Under Art. 25(1)(b), substantially modifying a high-risk AI system makes the modifier a provider. For GPAI: the Commission has signalled that significant fine-tuning that changes model behaviour materially could make the fine-tuner a GPAI provider for the modified variant. Treat as open — legal judgement required.

## What to do

1. Ask the user: what model, what training compute (rough order of magnitude), what release model (open weights vs. API-only vs. hosted).
2. Walk the decision tree. State the conclusion: "GPAI" / "Systemic-risk GPAI" / "Not GPAI".
3. If the user is the provider, list the applicable Art. 53 items (and Art. 55 if systemic-risk).
4. If the user is a downstream integrator, state what they are entitled to receive under Art. 53(1)(b), and what their *own* product obligations are under Art. 6.
5. Flag any threshold near-misses (just below 10^25 FLOPs, just outside "sufficient generality"). The regulation's text is clear but the application at the margin is not.

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "We use GPT-4 via API — we're a GPAI provider." | No. Using a third-party model via API makes you a downstream *AI system* provider or deployer. GPAI provider duties (Art. 53) stay with the model's creator. You are entitled to documentation under Art. 53(1)(b) to comply with your own product obligations. |
| "Our training compute was 5 x 10^24 FLOPs, so we're below the threshold." | The Art. 51(2) threshold is a *presumption* of systemic risk at ≥10^25 FLOPs. Art. 51(1)(b) allows Commission designation below the threshold based on criteria in Annex XIII (parameters, dataset size/quality, reasoning capabilities, autonomy, reach). Verify you are also not in scope via designation. |
| "We open-sourced our model, so Art. 53 doesn't apply." | Art. 53(2) exempts open-source GPAI from 53(1)(a) and 53(1)(b) ONLY. The copyright policy (53(1)(c)) and training-data summary (53(1)(d)) still apply. And if the model is systemic-risk, the open-source exemption does not apply at all. |
| "Fine-tuning with LoRA is minor — we're not a new GPAI provider." | The answer depends on whether the modification is *substantial* and whether the modified model meets the generality test independently. Low-rank adapters that preserve base behaviour are typically not substantial. Large-scale fine-tuning that changes capability profile may be. Route to counsel. |
| "Research-prototype exclusion covers our entire pre-production pipeline." | Art. 3(63) excludes AI models used for research, development, or prototyping before being placed on the market. Once placed on the market, the exclusion ends. "Placed on the market" is the making available on the Union market for distribution or use in the course of commercial activity. |
| "We don't know our training FLOPs exactly — we can round down." | Art. 51(2) presumption is triggered at ≥10^25 FLOPs. Rounding down to avoid classification is a compliance-fraud risk. Document the calculation methodology, be transparent, and apply counsel judgement at the margin. |
| "The AI Office hasn't published the training-data-summary template, so we can skip Art. 53(1)(d)." | The substantive obligation to publish a sufficiently detailed summary applies. Use a reasonable interim format until the template is published. Document your assumptions. |

## Cross-references

- [eu-ai-act-operator-roles](eu-ai-act-operator-roles.md) — GPAI provider vs. downstream AI system provider
- [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md) — a downstream product can still be high-risk
- [eu-ai-act-article-50-transparency](eu-ai-act-article-50-transparency.md) — a GPAI that generates synthetic content (Art. 50(2)) or interacts with natural persons (Art. 50(1)) owes Art. 50 in addition to Art. 53
- [eu-ai-act-annex-iv-guide](eu-ai-act-annex-iv-guide.md) — for downstream high-risk AI systems using GPAI
- [eu-ai-act-timeline](eu-ai-act-timeline.md) — GPAI obligations applied from 2 August 2025

## Source of truth

EU Regulation 2024/1689, Art. 3(63)-(64), Art. 51-56, Annex XI, Annex XII, Annex XIII, Recital 98, published in the Official Journal of the European Union, 12 July 2024.
