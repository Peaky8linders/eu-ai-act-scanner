---
name: eu-ai-act-fria-guide
description: Use when the user asks about Fundamental Rights Impact Assessment, FRIA, Art. 27, whether they need to perform one, or what it must contain. Serves deployers of high-risk AI (primary audience — FRIA is a deployer obligation, not a provider one), compliance officers, and legal counsel. Clarifies the narrow triggering scope (specific Annex III domains, specific deployer types), the required elements of the assessment, and the interaction with DPIA under GDPR.
user_invocable: true
---

# Art. 27 — Fundamental Rights Impact Assessment (FRIA)

Determine whether a FRIA is required, and if so, structure one that meets Art. 27. FRIA is frequently misunderstood — it is not required for every high-risk system, and it is performed by the **deployer**, not the provider. Wrong assumptions here either over-burden providers (who have no such obligation) or leave deployers exposed to enforcement.

## When to invoke

- "Do we need a FRIA", "what is a FRIA"
- User mentions Art. 27 or "fundamental rights impact assessment"
- User is a deployer (public authority, public-service private entity) in Annex III domains and needs to plan compliance
- User is writing a deployer runbook / compliance playbook

## Applies to

- Classification of whether Art. 27 applies to a specific deployer + system combination.
- Structuring the FRIA document against Art. 27(1) contents.
- **In scope**: the Art. 27 obligation and its interaction with GDPR Art. 35 DPIA.
- **Out of scope**: provider-side obligations (Art. 9, 11, 13 etc.), risk-tier classification (route to [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md)).

## Regulation scope

Art. 27(1) requires certain **deployers** of **high-risk AI systems** in specific Annex III domains to perform a FRIA **before the first use** of the system.

Trigger conditions — ALL must be true:

1. The AI system is high-risk under Art. 6(2) (Annex III), AND
2. The Annex III point is one of:
   - Annex III.5(a) — public authorities' eligibility assessments for benefits/services, OR
   - Annex III.5(b) — creditworthiness/credit scoring (but NOT fraud detection), OR
   - Annex III.5(c) — life and health insurance risk/pricing, OR
3. The deployer is one of:
   - A body governed by public law, OR
   - A private entity providing public services (health, transport, energy, social services, housing, electronic communications, etc.), OR
   - An operator in Annex III.5(b) (creditworthiness) or Annex III.5(c) (life/health insurance) regardless of public/private

For AI systems listed in Annex III.1 (biometrics) and Annex III.2 (critical infrastructure), Art. 27 does **not** apply.

## Required contents — Art. 27(1)(a) to (g)

A FRIA must contain:

- **(a)** A description of the processes in which the high-risk AI system will be used, in line with its intended purpose.
- **(b)** The period of time within which, and frequency with which, the high-risk AI system is intended to be used.
- **(c)** Categories of natural persons and groups likely to be affected by its use in the specific context.
- **(d)** Specific risks of harm likely to have an impact on the categories of natural persons or groups identified under (c), taking into account the provider's information per Art. 13.
- **(e)** A description of the implementation of human oversight measures, according to the instructions for use.
- **(f)** Measures to be taken in case those risks materialise, including arrangements for internal governance and complaint mechanisms.
- **(g)** Assessment of the risks of harm to fundamental rights that may result from the use of the AI system.

## What to do

### Determining whether a FRIA is required

Walk the trigger conditions above with the user. Ask:

1. Is this AI system high-risk under Art. 6(2)? If unsure, route to [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md).
2. Which Annex III point? If not 5(a), 5(b), or 5(c) — Art. 27 does not apply (but other deployer obligations under Art. 26 still do).
3. Who is the deployer? Public body, private public-service provider, or insurance/credit operator? If none of these — Art. 27 does not apply.

If the trigger fires, state clearly: "A FRIA is required before you first use this system (Art. 27(1))." Do not soften that.

### Structuring the FRIA

Produce a template with the seven required sections (a)-(g) above. Leave concrete content as `<FILL IN:>` placeholders — do not fabricate. A FRIA with invented facts is worse than none.

For each section, the template should cue the deployer with:

- **(a)** Process description: who uses the system, on whom, in what decision context.
- **(b)** Usage period: pilot dates, production rollout, review cadence.
- **(c)** Affected persons: demographics, vulnerable groups (Art. 5(1)(b) categories especially), intersectional analysis.
- **(d)** Specific harms: material harms (denial of benefit, incorrect pricing, delayed service), dignitary harms (profiling, stigma), procedural harms (inability to contest).
- **(e)** Human oversight: who reviews outputs, on what trigger, with what authority to override. Reference the provider's Art. 14 instructions.
- **(f)** If-risks-materialise: incident procedures, complaint channels, escalation, notification to market surveillance authorities per Art. 73.
- **(g)** Fundamental-rights assessment: reference the EU Charter of Fundamental Rights. Map each risk to the rights potentially engaged — non-discrimination (Art. 21), data protection (Art. 8), human dignity (Art. 1), effective remedy (Art. 47).

### Interaction with GDPR Art. 35 DPIA

If the deployer is already conducting a Data Protection Impact Assessment under GDPR Art. 35, Art. 27(4) allows the FRIA to complement the DPIA — they can be combined in a single document. This does not reduce the scope: the FRIA-specific elements under Art. 27(1)(a)-(g) must still appear. A DPIA focused on data protection risks alone does not satisfy Art. 27.

### Notification to market surveillance authority

Per Art. 27(3), once the FRIA has been performed, the deployer must **notify the market surveillance authority of the results** by submitting a summary using the template the AI Office will publish. Until that template is available, the notification obligation remains; use the national authority's interim process.

### Updates

Art. 27(2): if any of the elements listed in (a)-(g) change during use, the deployer must update the FRIA.

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "We're a provider, so the FRIA is our problem." | FRIA under Art. 27 is a **deployer** obligation. Providers have Art. 9 risk management and Art. 11 technical documentation. Confusing the two creates gaps on both sides. |
| "We're private, so Art. 27 doesn't apply to us." | Art. 27(1) applies to bodies governed by public law AND to private entities providing public services AND to operators in Annex III.5(b)/(c) regardless of public/private status. Check the domain, not just public/private. |
| "Our DPIA covers this — we don't need a separate FRIA." | Art. 27(4) allows FRIA to complement DPIA in a single document, but the Art. 27(1)(a)-(g) elements must still be present. A DPIA's privacy focus does not substitute for the fundamental-rights scope of a FRIA. |
| "We're only piloting — no need for a FRIA yet." | Art. 27(1) requires FRIA **before the first use**. A pilot is first use. If the pilot involves natural persons subject to the Annex III decision, FRIA applies. |
| "The provider told us the system is safe, so we don't need to assess risks." | Art. 27 places the assessment obligation on the *deployer* because the risk profile depends on the deployment context (who uses it, on whom, in what decision). Provider assurances are input to the FRIA, not a substitute for it. |
| "We'll do the FRIA after deployment if issues arise." | Art. 27(1) is explicit: "before first use". Post-hoc FRIAs are non-compliant and expose the deployer to penalties under Art. 99(4). |
| "The AI Office hasn't published the notification template, so Art. 27(3) can't apply yet." | The substantive FRIA obligation is not suspended pending the template. The notification mechanics may rely on national authority interim processes. Document your FRIA now; file per whatever process applies. |

## Cross-references

- [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md) — is the system high-risk?
- [eu-ai-act-operator-roles](eu-ai-act-operator-roles.md) — am I a deployer?
- [eu-ai-act-reference](eu-ai-act-reference.md) — Art. 27 context in the broader map
- [eu-ai-act-penalties](eu-ai-act-penalties.md) — deployer-side penalty exposure

## Source of truth

EU Regulation 2024/1689, Art. 27, Art. 26, Annex III points 5(a)-(c), published in the Official Journal of the European Union, 12 July 2024. Charter of Fundamental Rights of the European Union (2000/C 364/01).
