---
name: eu-ai-act-article-6-classification
description: Use when the user asks "is my system high-risk", "does Annex III apply to us", mentions Art. 6, or describes a use case that could fall under the eight Annex III domains (biometrics, critical infrastructure, education, employment, essential services, law enforcement, migration/asylum, justice/democracy). Serves legal counsel, product leads, compliance officers, and deployers who need to determine risk tier before investing in Art. 9-15 obligations. Walks Art. 6 + Annex III with the Art. 6(3) derogation applied strictly.
user_invocable: true
---

# Art. 6 + Annex III — High-Risk Classification

Determine whether an AI system is classified as high-risk under Art. 6. High-risk triggers the full weight of the regulation — Art. 9 (RMS), Art. 10 (data governance), Art. 11 (technical docs), Art. 12 (logging), Art. 13 (transparency), Art. 14 (human oversight), Art. 15 (accuracy/robustness), Art. 17 (QMS), and conformity assessment under Art. 43. Getting the classification wrong is expensive either direction.

## When to invoke

- "Is my system high-risk"
- "Does Annex III apply"
- "Do we need a conformity assessment"
- User mentions Art. 6 or Annex III
- User describes a use case in biometrics, critical infrastructure, education, employment, essential services, law enforcement, migration, or justice

## Applies to

- A single AI system whose purpose and use context are known.
- **In scope**: classification under Art. 6(1), Art. 6(2) + Annex III, and the Art. 6(3) derogation.
- **Out of scope**: prohibited-practice analysis (route to [eu-ai-act-article-5-prohibited](eu-ai-act-article-5-prohibited.md)), GPAI-specific obligations (route to [eu-ai-act-gpai-classification](eu-ai-act-gpai-classification.md)).

## Regulation scope

Two independent paths to high-risk classification:

- **Art. 6(1)** — AI system is a safety component of, or is itself, a product covered by Union harmonisation legislation listed in Annex I, AND that product must undergo a third-party conformity assessment under that legislation. (Think: medical devices, machinery, toys, radio equipment.)
- **Art. 6(2)** — AI system is listed in Annex III (the eight domains below).

Either path triggers high-risk status. Art. 6(3) provides a narrow derogation: a system that otherwise falls under Annex III may be deemed *not* high-risk if it meets specific conditions — but profiling of natural persons always remains high-risk.

## Annex III — the eight high-risk domains

1. **Biometrics** (where permitted under applicable law):
   - (a) Remote biometric identification (excluding verification of a specific individual's claimed identity)
   - (b) Biometric categorisation based on sensitive or protected attributes
   - (c) Emotion recognition

2. **Critical infrastructure** — safety components in the management and operation of critical digital infrastructure, road traffic, or supply of water, gas, heating, or electricity.

3. **Education and vocational training**:
   - (a) Admissions or assignment
   - (b) Evaluation of learning outcomes / steering of learning processes
   - (c) Assessment of appropriate level of education an individual will receive
   - (d) Monitoring and detecting prohibited behaviour during tests

4. **Employment, worker management, access to self-employment**:
   - (a) Recruitment or selection (including advertising, filtering applications, evaluating candidates)
   - (b) Decisions affecting work-related relationships (promotion, termination, task allocation, performance monitoring, behaviour evaluation)

5. **Access to and enjoyment of essential private and public services**:
   - (a) Public authorities' eligibility assessments for benefits and services
   - (b) Creditworthiness / credit scoring (excluding fraud detection)
   - (c) Risk assessment and pricing for life and health insurance
   - (d) Emergency services dispatch / triage / classification

6. **Law enforcement** (where permitted under applicable law):
   - (a) Assessment of individual's risk of victimisation of criminal offences
   - (b) Polygraph and similar tools
   - (c) Reliability assessment of evidence
   - (d) Individual risk assessment for offending or re-offending (excluding profiling prohibited under Art. 5(1)(d))
   - (e) Profiling of natural persons in the course of detection, investigation, or prosecution
   - (f) Crime analytics for individuals

7. **Migration, asylum, border control**:
   - (a) Polygraph and similar tools
   - (b) Risk assessment of individuals entering the Union
   - (c) Examination of applications for asylum, visas, residence permits / associated complaints
   - (d) Detecting/recognising/identifying persons in migration context (excluding travel doc verification)

8. **Administration of justice and democratic processes**:
   - (a) AI assisting judicial authorities in researching/interpreting facts and law and applying law to concrete facts (also applies to alternative dispute resolution)
   - (b) AI intended to influence election or referendum outcomes or voting behaviour (excluding outputs that do not interact directly with natural persons, e.g. organisational logistics tools)

## Decision tree

```
Step 1 — Annex I (product-embedded AI):
Is the AI system a safety component of, or itself, a product covered
by Annex I AND does that product undergo third-party conformity
assessment under that legislation?
  └─ yes → HIGH-RISK (Art. 6(1)). Do NOT proceed to Art. 6(3) derogation.
  └─ no  → Step 2

Step 2 — Annex III (stand-alone AI):
Does the system's intended purpose fall under any of the eight
Annex III domains (1–8 above)?
  └─ no  → NOT high-risk under Art. 6(2). Check transparency obligations
            under Art. 50 (chatbots, GenAI content), and GPAI obligations
            if applicable.
  └─ yes → Step 3

Step 3 — Art. 6(3) derogation:
Per Art. 6(3), a system listed in Annex III is NOT considered high-risk
if it does NOT pose a significant risk of harm to health, safety, or
fundamental rights, INCLUDING by not materially influencing the outcome
of decision-making, AND it falls into one of:
  (a) narrow procedural task
  (b) improves the result of a previously completed human activity
  (c) detects decision-making patterns or deviations without replacing or
      influencing the previously completed human assessment (without proper
      human review)
  (d) preparatory task to an assessment relevant for the purposes in Annex III

EXCEPTION-TO-THE-DEROGATION: profiling of natural persons is ALWAYS high-risk
under Art. 6(3) final subparagraph, regardless of whether (a)-(d) apply.

Does the system satisfy at least one of (a)–(d) AND not profile natural persons?
  └─ yes → NOT high-risk (Art. 6(3) derogation applies). Document justification
            under Art. 6(4).
  └─ no  → HIGH-RISK (Art. 6(2)).
```

## Art. 6(3) derogation — apply strictly

The derogation is narrow. Abuse is expected and the Commission will issue guidelines. Until then, apply these tests:

- **(a) Narrow procedural task** — not a decision; data validation, format conversion, document classification for triage. If the AI output materially influences an outcome, this is not narrow.
- **(b) Improves prior human activity** — the human has already acted and the AI polishes/refines. Suggestion engines for code-completion may qualify; hiring-filter AI does not.
- **(c) Pattern detection without replacing assessment** — the AI flags anomalies, a human reviews each flag. If the human rubber-stamps the flag without re-assessing, this is not (c).
- **(d) Preparatory task** — data gathering, enrichment, summarisation where a human performs the downstream assessment. If the "assessment" is just accepting the AI's pre-sorted output, this is not (d).

**Profiling exception**: Art. 3(52) defines profiling by reference to GDPR Art. 4(4) — any automated processing of personal data to evaluate personal aspects, analyse or predict performance, economic situation, health, preferences, interests, reliability, behaviour, location, or movements. If the system profiles natural persons, Art. 6(3) derogation cannot apply.

## Art. 6(4) — documentation requirement

If the provider relies on Art. 6(3), it must document its assessment **before placing the system on the market or putting it into service**. The documentation must be provided to national competent authorities on request. The provider must also register the system in the EU database under Art. 49(2).

In practice: Art. 6(3) is not a free pass. It is a documented legal judgement with a registration obligation and inspection exposure.

## What to do

1. Collect: **intended purpose** (Art. 3(12)), **domain of use**, **whether it profiles natural persons**, **whether a human makes the final decision** and on what basis.
2. Walk the three steps above.
3. If the answer is high-risk, state the triggering path (Art. 6(1) vs. Annex III point N) and route to the relevant obligation skills.
4. If the answer is "not high-risk via Art. 6(3)", flag that the provider must document the assessment and register under Art. 49(2). Recommend counsel sign-off.
5. If the answer is "not high-risk via Art. 6(2) (not in Annex III)", still check Art. 50 transparency duties and GPAI obligations.

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "The AI is just decision-support; a human makes the final call, so it's not high-risk." | Annex III does not require the AI to be the decision-maker. It covers AI *used for* employment decisions, creditworthiness, etc. Route to Art. 6(3) derogation analysis — the derogation requires NO material influence on the outcome, which is a higher bar than "human in the loop". |
| "We're in critical infrastructure, but we do demand-forecasting, not safety control." | Annex III.2 covers AI as a *safety component* of critical infrastructure. Pure analytics that do not affect the physical safety of the system are outside scope. Check whether the forecasts feed control systems that could cause safety failure if mis-predicted. |
| "Our resume-screener is just keyword filtering, not real AI." | Art. 3(1) definition of AI system is broad. If the system generates outputs (recommendations, rankings, decisions) that influence employment selection, Annex III.4(a) applies regardless of how simple the underlying technique is. |
| "Art. 6(3) derogation applies because our AI is a preparatory task." | (d) preparatory task requires that a human then performs the assessment, and that the AI's output does not materially influence the assessment. If the downstream human just accepts the AI-enriched data as the basis for decision, (d) does not apply. |
| "Credit-scoring AI is fine because it's for fraud detection." | Annex III.5(b) excludes fraud detection from its scope. But if the system is used for fraud detection AND for creditworthiness in the same product, the creditworthiness use makes the whole system high-risk. Partition use cases or accept the high-risk classification. |
| "We're processing data about companies, not natural persons, so the profiling exception doesn't apply." | Correct that GDPR-style profiling targets natural persons. But Art. 6(3) derogation has separate conditions (a)-(d). The profiling exception-to-derogation applies where profiling occurs; absence of profiling does not by itself qualify for the derogation — you still need to satisfy (a), (b), (c), or (d). |
| "We operate in Annex III.3 education, but our users are consenting adults, not students." | Annex III.3(a)-(d) covers education and vocational training *for natural persons*. Adult learners are included. Consent does not remove the high-risk classification — it may affect the lawfulness of processing under GDPR, but not the AI Act risk tier. |

## Cross-references

- [eu-ai-act-article-5-prohibited](eu-ai-act-article-5-prohibited.md) — is it prohibited rather than merely high-risk?
- [eu-ai-act-operator-roles](eu-ai-act-operator-roles.md) — once high-risk, which role is the user
- [eu-ai-act-fria-guide](eu-ai-act-fria-guide.md) — deployer-specific FRIA obligation for Annex III.5/.7/.8
- [eu-ai-act-annex-iv-guide](eu-ai-act-annex-iv-guide.md) — Art. 11 technical documentation
- [eu-ai-act-timeline](eu-ai-act-timeline.md) — high-risk obligations apply 24 months after entry into force, with some product-embedded cases at 36 months

## Source of truth

EU Regulation 2024/1689, Art. 6, Art. 3(12), Art. 3(52), Annex I, Annex III, published in the Official Journal of the European Union, 12 July 2024.
