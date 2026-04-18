---
name: eu-ai-act-operator-roles
description: Use when the user asks "am I a provider or deployer", mentions distinguishing roles (importer, distributor, authorised representative, product manufacturer), asks which obligations apply to their organisation, or is unsure which duties flow from their position in the AI supply chain. Serves legal counsel, product leads, and compliance officers. Determining the role is the gateway decision — every downstream obligation (Art. 9-15 vs. Art. 26-27 vs. Art. 23 importer duties) depends on it.
user_invocable: true
---

# EU AI Act Operator Roles

Determine which role(s) an organisation plays under the AI Act. Obligations flow from role — provider duties (Art. 9-15, 17) are fundamentally different from deployer duties (Art. 26, 27) or importer duties (Art. 23). Organisations often play multiple roles simultaneously, and the role can change (e.g., a deployer who substantially modifies a system becomes a provider under Art. 25).

## When to invoke

- "Am I a provider or a deployer"
- "What obligations apply to us"
- User describes their position in the AI supply chain
- User mentions importer, distributor, authorised representative
- User is writing a RACI / responsibility matrix for compliance

## Applies to

- Role classification for an organisation or natural person in the Union or placing AI systems on the Union market.
- **In scope**: the six operator roles defined in Art. 3(3)-(8) and the role-flip provisions in Art. 25.
- **Out of scope**: whether a given obligation is satisfied — that's handled by per-article skills.

## Regulation scope

Art. 2 sets territorial scope. Art. 3 defines the roles. Each role has its own obligation bundle:

- **Provider** (Art. 3(3)) — develops or has developed an AI system/GPAI model and places it on the market or puts it into service under its own name or trademark, whether for payment or free of charge. Obligations: Art. 9-17 (for high-risk), Art. 53-55 (for GPAI), conformity assessment (Art. 43), CE marking (Art. 48), EU database registration (Art. 49).
- **Deployer** (Art. 3(4)) — natural or legal person, public authority, agency, or other body using an AI system under its authority, except where use is in the course of a personal non-professional activity. Obligations: Art. 26 deployer duties, Art. 27 FRIA (for specific Annex III domains + deployer types).
- **Authorised representative** (Art. 3(5)) — natural or legal person in the Union mandated in writing by a non-Union provider to perform/carry out its obligations. Required for non-Union providers of high-risk AI under Art. 22.
- **Importer** (Art. 3(6)) — natural or legal person in the Union placing on the market an AI system bearing the name/trademark of a natural or legal person established outside the Union. Obligations: Art. 23 (verification duties).
- **Distributor** (Art. 3(7)) — natural or legal person in the supply chain, other than provider or importer, making an AI system available on the Union market. Obligations: Art. 24 (verification + cooperation).
- **Product manufacturer** (Art. 3(8)) — manufacturer who places on the market or puts into service an AI system together with its product and under its name/trademark. Treated as a provider for the purposes of obligations, per Art. 25(3).

## Decision tree

```
Step 1 — Do you develop, train, or fine-tune an AI system/GPAI model
and make it available in the Union under your name?
  └─ yes → PROVIDER (Art. 3(3))
         Provider obligations apply. If outside the Union, appoint
         an authorised representative (Art. 22).
  └─ no  → Step 2

Step 2 — Do you use an AI system under your authority in a professional
context (internal use, customer-facing, decision-making)?
  └─ yes → DEPLOYER (Art. 3(4)).
         Deployer obligations (Art. 26) apply. Check Art. 27 for FRIA
         trigger.
  └─ no  → Step 3 (you may still be in another role)

Step 3 — Do you place on the Union market an AI system bearing the
name/trademark of a non-Union entity?
  └─ yes → IMPORTER (Art. 3(6)).
         Art. 23 verification duties apply.
  └─ no  → Step 4

Step 4 — Do you distribute AI systems placed on the Union market by
someone else, without bearing your own name?
  └─ yes → DISTRIBUTOR (Art. 3(7)).
         Art. 24 verification and cooperation duties apply.
  └─ no  → Step 5

Step 5 — Were you mandated in writing by a non-Union provider to
perform its obligations?
  └─ yes → AUTHORISED REPRESENTATIVE (Art. 3(5)).
         Art. 22 duties apply.
```

An organisation can occupy multiple roles simultaneously (e.g., a provider can also be a deployer of its own system for internal use). Each role carries its own obligations — roles do not substitute.

## Role flips — Art. 25

Art. 25 redefines roles in cases that frequently trip up organisations:

- **Art. 25(1)(a)**: A distributor, importer, or deployer (or any other third party) is considered a **provider** of a high-risk AI system IF it puts its name or trademark on the system (without relabelling-arrangement flags from the original provider).
- **Art. 25(1)(b)**: A distributor/importer/deployer is considered a provider IF it **substantially modifies** a high-risk AI system such that it remains high-risk after modification.
- **Art. 25(1)(c)**: The deployer (or other actor) is considered a provider IF it modifies the intended purpose of an AI system in a way that causes the system to become high-risk when it was not before.

"Substantial modification" (Art. 3(23)): change not foreseen by the original provider that affects compliance with the regulation or modifies the intended purpose.

Practical consequences:

- A bank deploying a vendor's credit-scoring AI under its own label → likely provider under Art. 25(1)(a).
- A company fine-tuning a foundation model on proprietary data and productising it → likely provider under Art. 25(1)(b) if the modification is substantial.
- Using a general-purpose chatbot as a medical-diagnosis assistant → provider under Art. 25(1)(c) since intended purpose changed, potentially making it high-risk.

Art. 25(2) — the *original* provider is released from the role of provider for *that* modified instance, and must cooperate with the new provider per Art. 25(5).

## GPAI-specific role notes

- GPAI **provider** obligations (Art. 53-55) apply to whoever develops the GPAI model and places it on the Union market. Using a GPAI model via an API generally does not make the API caller a GPAI provider.
- GPAI **downstream providers** — if you build a product on top of a GPAI model and distribute it, you are a *provider* (in the general sense) of the downstream product, but the GPAI-specific obligations (Art. 53 model card, Art. 55 systemic-risk testing) remain with the GPAI creator. You still inherit Art. 6-15 obligations if the downstream product is high-risk.

Route GPAI-specific questions to [eu-ai-act-gpai-classification](eu-ai-act-gpai-classification.md).

## Role-to-obligation quick map

| Role | Primary obligations | Key articles |
|---|---|---|
| Provider of high-risk AI | RMS, data governance, technical docs, logging, transparency, human oversight, accuracy/robustness, QMS, conformity assessment, CE marking, EU database | Art. 9-17, 43, 47-49 |
| Provider of GPAI | Model documentation, training data summary, policy on copyright, cooperation with AI Office | Art. 53, 55 |
| Deployer | Use per instructions, monitor, log, inform workers, cooperate with authorities | Art. 26 |
| Deployer (Annex III.5 domains) | FRIA, notification | Art. 27 |
| Authorised representative | Keep declaration + tech docs available, cooperate with authorities, terminate mandate if provider non-compliant | Art. 22 |
| Importer | Verify conformity assessment done, CE marking affixed, declaration available, instructions provided; refuse to place if doubts | Art. 23 |
| Distributor | Verify CE + instructions; cooperate with authorities; suspend if non-compliance suspected | Art. 24 |
| Product manufacturer (AI-integrated products) | Treated as provider | Art. 25(3) |

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "We just use OpenAI's API, so we're a user, not a deployer." | Art. 3(4) definition of deployer includes any natural/legal person using an AI system under its authority in a professional context. Using the OpenAI API in your product makes you a deployer of that model. |
| "We rebrand an off-the-shelf model but don't change its code, so we're not a provider." | Art. 25(1)(a) explicitly makes a rebrand a provider role for high-risk AI. Putting your name or trademark on the system = you are the provider. |
| "Our fine-tuning is minor — it's not substantial modification." | "Substantial" (Art. 3(23)) turns on whether the modification affects compliance or intended purpose, not on how many parameters changed. Fine-tuning that changes output distribution for a new use case is typically substantial. Document the analysis with counsel. |
| "We're a non-Union company with no Union presence, so the Act doesn't apply." | Art. 2(1) extraterritorial: the Act applies to providers placing AI systems on the Union market **regardless of where established**, to deployers in the Union, and to providers/deployers outside the Union when the output is used in the Union. Non-Union providers of high-risk systems must appoint an authorised representative under Art. 22. |
| "We're a reseller, so only Art. 24 distributor duties apply." | If you add your own name/trademark, you become a provider under Art. 25(1)(a) — not a distributor. The key test is branding/attribution, not commercial role. |
| "The provider told us they did the conformity assessment, so we can just deploy." | As a deployer, Art. 26(1) requires you to use the system **according to the provider's instructions**, ensure human oversight is actually exercised (Art. 26(2)), monitor operation (Art. 26(5)), and keep logs (Art. 26(6)). Trust in the provider's conformity is necessary but not sufficient. |
| "We're an employer deploying a hiring AI, but we have no Annex III.4(a) obligations because the vendor is the provider." | Annex III.4(a) high-risk classification triggers both provider duties AND deployer duties. As deployer-employer, you must also inform workers/reps per Art. 26(7), perform a FRIA if you qualify (Art. 27), and retain logs (Art. 26(6)). |

## Cross-references

- [eu-ai-act-article-5-prohibited](eu-ai-act-article-5-prohibited.md) — prohibition applies to all roles
- [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md) — role determines which article bundle applies
- [eu-ai-act-fria-guide](eu-ai-act-fria-guide.md) — FRIA is deployer-only, specific domains
- [eu-ai-act-gpai-classification](eu-ai-act-gpai-classification.md) — GPAI provider vs. downstream provider
- [eu-ai-act-reference](eu-ai-act-reference.md) — article-to-obligation map

## Source of truth

EU Regulation 2024/1689, Art. 2, Art. 3(3)-(8), Art. 22-27, published in the Official Journal of the European Union, 12 July 2024.
