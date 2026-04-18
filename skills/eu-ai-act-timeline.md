---
name: eu-ai-act-timeline
description: Use when the user asks about EU AI Act deadlines, when obligations kick in, Art. 113, "when do we need to comply", the application timeline for prohibitions or high-risk obligations or GPAI. Serves legal counsel, compliance officers, product leads, and board-level stakeholders planning compliance budgets and roadmaps. Names each of the staggered application dates under Art. 113 and which obligations attach at each.
user_invocable: true
---

# EU AI Act — Application Timeline (Art. 113)

Map each category of obligation to its application date under Art. 113. Compliance planning requires knowing which obligations are already live, which are imminent, and which are further out — the answer differs by article, not by system.

## When to invoke

- "When does the AI Act apply to us"
- "When do we need to be compliant"
- "What's the timeline", "what are the deadlines"
- User mentions Art. 113
- User is planning budgets, roadmaps, or board reporting
- User asks about a specific obligation with "when does this start"

## Applies to

- All obligations under EU Regulation 2024/1689.
- **In scope**: application dates set by Art. 113 and carve-outs under Art. 111.
- **Out of scope**: specific obligations themselves (route to the relevant per-article skill).

## Regulation scope

Art. 113 sets entry into force and staggered application of the regulation's provisions. The regulation was published in the Official Journal on **12 July 2024**, so entry into force was **1 August 2024** (twentieth day following publication). Application then proceeds on a staggered schedule.

## Key dates

| Date | What applies | Article |
|---|---|---|
| **1 Aug 2024** | Entry into force | Art. 113 |
| **2 Feb 2025** | Chapters I (general provisions) and II (Art. 5 prohibited practices) | Art. 113(a) |
| **2 Aug 2025** | Chapters III Sec 4 (notifying authorities, notified bodies), V (GPAI obligations — Art. 53-55), VII (governance), Chapter XII (penalties except Art. 101), Art. 78 (confidentiality) | Art. 113(b) |
| **2 Aug 2026** | **Most of the regulation, including** Art. 6 high-risk classification, Art. 9-15 high-risk obligations, Art. 17 QMS, Art. 26-27 deployer obligations and FRIA, Art. 43 conformity assessment, Art. 50 transparency, Annex III | Art. 113 (default) |
| **2 Aug 2027** | Art. 6(1) for AI systems that are safety components of products covered by Annex I Section A (product legislation with third-party conformity — machinery, toys, lifts, medical devices, etc.) | Art. 113(c) |
| **End 2030** | Art. 111(1) large-scale EU IT system AI systems placed on market before 2 Aug 2027 must achieve compliance by **31 Dec 2030** | Art. 111(1) |

### Quick summary by role

**Providers of prohibited-category AI**: immediate stop since 2 Feb 2025.

**Providers of GPAI models**: Art. 53 and Art. 55 obligations applied from **2 Aug 2025**. However, GPAI models placed on the market before 2 Aug 2025 have until **2 Aug 2027** to achieve compliance per Art. 111(3).

**Providers of high-risk AI under Annex III**: full stack of obligations from **2 Aug 2026**.

**Providers of high-risk AI embedded in Annex I Section A products (Art. 6(1))**: from **2 Aug 2027** for new systems. Pre-existing systems: transitional regime per Art. 111(2).

**Deployers**: Art. 26 and Art. 27 (FRIA) from **2 Aug 2026**.

**National authorities**: notification and governance bodies must be in place from **2 Aug 2025**.

## Art. 111 — transitional provisions

Art. 111 addresses systems already on the market. Read precisely — the transitions are narrow.

- **Art. 111(1)**: AI systems that are components of large-scale EU IT systems listed in Annex X, placed on market or put into service before 2 Aug 2027, must achieve compliance **by 31 December 2030**.
- **Art. 111(2)**: Operators of high-risk AI systems placed on the market or put into service before 2 Aug 2026 are subject to the regulation **only if those systems are subject to significant changes in design** after that date. Public authority deployers must achieve compliance by **2 Aug 2030** regardless.
- **Art. 111(3)**: GPAI providers that placed models on market before 2 Aug 2025 must take necessary steps to comply with Art. 53-55 by **2 Aug 2027**.

**"Significant changes in design"** is not defined precisely — Commission guidance expected. Substantial modification under Art. 3(23) is a useful proxy but not identical.

## What to do

1. Ask the user what **role** they are (provider / deployer / distributor) and what **category** of AI system / GPAI model.
2. Match to the date table above.
3. State the applicable date clearly. If the system is subject to a transitional regime (Art. 111), state the specific cut-off.
4. If the user asks for a compliance plan timeline, work backwards from the applicable date — typical governance setup, technical remediation, documentation assembly, and third-party conformity assessment (if required) can take 6-12 months combined.
5. Flag obligations already in effect that the user may have missed — Art. 5 prohibitions since 2 Feb 2025, GPAI obligations since 2 Aug 2025.

## Dependency graph — what must be ready before what

Working backwards from a high-risk AI system going live after 2 Aug 2026:

```
Risk classification (Art. 6)                        ← before scope/budget decisions
     ↓
Risk Management System (Art. 9)                     ← ongoing from design phase
     ↓
Data governance (Art. 10)                           ← before training
     ↓
Technical documentation (Art. 11 + Annex IV)        ← complete before placing on market
     ↓
Record-keeping architecture (Art. 12)               ← before first production inference
     ↓
Human oversight design (Art. 14)                    ← before first deployment
     ↓
Quality Management System (Art. 17)                 ← organisational process
     ↓
Conformity assessment (Art. 43)                     ← before placing on market
     ↓
CE marking + EU declaration (Art. 47, 48)           ← at point of placing on market
     ↓
EU database registration (Art. 49)                  ← before placing on market
     ↓
Post-market monitoring (Art. 72)                    ← from first use onwards
     ↓
Deployer FRIA (Art. 27, if in scope)                ← before first use by deployer
```

Every step upstream blocks every step downstream. Starting at the conformity-assessment stage in Q2 2026 for an Aug 2026 deadline is almost certainly too late.

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "The Act doesn't apply until 2026, so we have time." | Prohibitions (Art. 5) apply since 2 Feb 2025. GPAI obligations (Art. 53-55) since 2 Aug 2025. High-risk is 2 Aug 2026, but the preparation time dwarfs the runway. |
| "We placed our system on the market before 2 Aug 2026, so we're grandfathered." | Art. 111(2) is narrow. You are out of scope only until you make significant changes in design. For most products in active development, significant changes occur within 12-24 months. Also, public-authority deployers must comply by 2 Aug 2030 regardless. |
| "We'll wait for harmonised standards before we start." | Harmonised standards provide presumption of conformity. Their absence does not suspend obligations. Art. 9-15 apply by 2 Aug 2026 with or without harmonised standards — state-of-the-art engineering practice is the baseline. |
| "The AI Office hasn't published guidance on X, so we can't plan." | True of some areas (Art. 6(3) derogation, simplified SME form). Not a reason to delay the bulk of compliance work (RMS, data governance, documentation, logging, QMS) which has clear requirements in the text. |
| "Our GPAI model is from before August 2025, so Art. 53 doesn't apply." | Art. 111(3) gives pre-existing GPAI providers until **2 Aug 2027** to achieve compliance. Not an exemption — a deferred deadline. |
| "We're a deployer — providers carry the weight." | Deployers have their own obligations under Art. 26 (applicable 2 Aug 2026) and, in Annex III.5 domains, FRIA under Art. 27. Free-riding on provider compliance is not a legal position. |

## Cross-references

- [eu-ai-act-article-5-prohibited](eu-ai-act-article-5-prohibited.md) — live since 2 Feb 2025
- [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md) — determines which 2026/2027 track applies
- [eu-ai-act-gpai-classification](eu-ai-act-gpai-classification.md) — GPAI timeline
- [eu-ai-act-fria-guide](eu-ai-act-fria-guide.md) — FRIA deadlines for deployers
- [eu-ai-act-penalties](eu-ai-act-penalties.md) — penalty dates (Art. 101 applies from 2 Aug 2026 except as noted)

## Source of truth

EU Regulation 2024/1689, Art. 113, Art. 111, published in the Official Journal of the European Union, 12 July 2024.
