---
name: eu-ai-act-article-5-prohibited
description: Use when the user asks whether a use case is prohibited under the EU AI Act, mentions Art. 5, describes a system involving biometric identification/categorisation/emotion recognition, social scoring, manipulation, exploitation of vulnerabilities, or predictive policing for individuals. Serves legal counsel (primary), product leads (who must not ship a prohibited system), and deployers. Provides a decision tree mapping the eight prohibited categories in Art. 5(1) to the user's use case, with named open questions where the regulation is ambiguous.
user_invocable: true
---

# Art. 5 — Prohibited AI Practices

Determine whether a use case falls under Art. 5(1) prohibitions. Getting this wrong in either direction is costly: a false positive kills a product that could have shipped; a false negative exposes the organisation to fines up to 7% of global turnover (Art. 99(3)) and bans on placing the system on the market.

## When to invoke

- User asks "is this prohibited", "can we ship this", "is this allowed under the AI Act"
- User describes biometric identification, emotion recognition, social scoring, predictive policing, scraping for facial databases, or manipulation of users
- User mentions Art. 5 by name
- User describes a system targeted at vulnerable groups (children, disabled persons, economically distressed populations)

## Applies to

- Classification of a single use case against the eight prohibitions in Art. 5(1).
- **In scope**: Art. 5(1)(a) through (h) — the prohibited categories listed in the regulation.
- **Out of scope**: risk-tier classification for non-prohibited systems (route to [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md)). Provider/deployer role determination (route to [eu-ai-act-operator-roles](eu-ai-act-operator-roles.md)).

## Regulation scope

Art. 5(1) lists eight categories of AI practices that **cannot be placed on the market, put into service, or used** in the Union. The prohibitions apply from **2 February 2025** per Art. 113(a). Each category has specific scope, and several have named exceptions — read them precisely; the exceptions are narrower than often described.

The eight categories:

1. **Art. 5(1)(a)**: subliminal / purposefully manipulative / deceptive techniques that materially distort behaviour and cause or are reasonably likely to cause significant harm.
2. **Art. 5(1)(b)**: exploitation of vulnerabilities due to age, disability, or social/economic situation to materially distort behaviour and cause or are reasonably likely to cause significant harm.
3. **Art. 5(1)(c)**: social scoring — evaluation or classification of natural persons over time based on social behaviour or personality traits, leading to detrimental or unfavourable treatment in unrelated contexts or that is unjustified/disproportionate.
4. **Art. 5(1)(d)**: individual risk assessment for committing criminal offences based solely on profiling or personality traits. Exception: AI used to support human assessment of involvement already established on objective and verifiable facts directly linked to a criminal activity.
5. **Art. 5(1)(e)**: creation or expansion of facial recognition databases through untargeted scraping of facial images from the internet or CCTV.
6. **Art. 5(1)(f)**: inference of emotions in workplaces and educational institutions. Exception: medical or safety reasons.
7. **Art. 5(1)(g)**: biometric categorisation systems that classify natural persons based on biometric data to infer race, political opinions, trade union membership, religious/philosophical beliefs, sex life, or sexual orientation. Narrow exception for lawful labelling/filtering of biometric datasets in law enforcement.
8. **Art. 5(1)(h)**: real-time remote biometric identification in publicly accessible spaces for law enforcement. Narrow exceptions under Art. 5(2-7) with authorisation, specific objectives, and safeguards.

## Decision tree

Ask in this order. Stop at the first `yes` with citation.

```
1. Is the system designed to manipulate behaviour using subliminal
   or deceptive techniques to cause significant harm?               → Art. 5(1)(a) PROHIBITED
2. Does it exploit age/disability/socio-economic vulnerabilities
   to distort behaviour and cause harm?                             → Art. 5(1)(b) PROHIBITED
3. Does it score/classify natural persons based on social behaviour
   or personality, leading to detrimental treatment?                → Art. 5(1)(c) PROHIBITED
4. Does it assess individual risk of committing a crime based on
   profiling or personality traits alone?                           → Art. 5(1)(d) PROHIBITED
     Exception: purely supports human assessment of involvement
     already grounded in objective verifiable facts. Apply strictly.
5. Does it scrape facial images from the internet or CCTV to build
   a facial-recognition database?                                   → Art. 5(1)(e) PROHIBITED
6. Does it infer emotions of natural persons in workplace or
   educational settings?                                            → Art. 5(1)(f) PROHIBITED
     Exception: medical or safety use. Apply narrowly.
7. Does it categorise persons biometrically to infer protected
   characteristics (race, politics, religion, sex life, etc.)?      → Art. 5(1)(g) PROHIBITED
     Exception: lawful dataset labelling in law enforcement.
8. Does it perform real-time remote biometric identification in
   publicly accessible spaces for law enforcement?                  → Art. 5(1)(h) PROHIBITED
     Exceptions under Art. 5(2-7) apply ONLY with prior judicial
     or independent administrative authorisation, named serious
     objective, and documented safeguards.
```

If every step is `no`, the system is not prohibited under Art. 5. Route to [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md) to determine if it is high-risk.

## What to do

1. Ask the user for the **system's purpose** (what it is built to do) and **intended users** (who will use it, on whom). Prohibitions turn on purpose + affected persons.
2. Walk the decision tree above, explicitly asking yes/no at each step.
3. On a `yes`, cite the paragraph and stop. Do not attempt to "engineer around" a prohibition — the regulation targets outcomes, not phrasing.
4. On a `no` throughout, state: "Not prohibited under Art. 5 based on the information given. This does not determine risk tier." Route to Art. 6.
5. If the user claims an exception (Art. 5(1)(d), (f), (g) second clause, or Art. 5(2-7) for (h)), do not validate the exception yourself. State the exception's conditions and flag the analysis for legal counsel.

## Ambiguity — name the open questions

The regulation has contested edges. Do not pretend they are settled:

- **"Materially distort behaviour"** (Art. 5(1)(a)/(b)) has no quantitative threshold. Commission guidance is expected but not yet published.
- **"Significant harm"** under (a)/(b) includes financial, psychological, and physical harm — but the line between marketing persuasion and manipulation is not definitively drawn.
- **"Detrimental or unfavourable treatment"** in social-scoring (c) is evaluated against (i) context unrelated to the data collection, or (ii) disproportionality. Both are facts-and-circumstances tests.
- **"Publicly accessible spaces"** (h) is broader than "public spaces" — includes shops, transport hubs, hospitals.

When any of these apply, say "This is a legal judgement call; recommend counsel review before proceeding."

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "We're just using emotion detection for UX research, so (f) doesn't apply." | Art. 5(1)(f) prohibits emotion inference **in workplaces and education**. If the UX research involves employees or students, it is prohibited. The purpose of the system, not the branding of the study, determines applicability. |
| "It's not really social scoring — we're scoring engagement." | Art. 5(1)(c) targets evaluation of natural persons based on social behaviour or personality traits leading to detrimental treatment in unrelated contexts. If an engagement score fed into an unrelated service (loan approval, hiring) it can trigger (c). The output pathway matters more than the feature name. |
| "We're scraping only celebrity faces from news sites." | Art. 5(1)(e) prohibits *untargeted* scraping from the internet or CCTV for face-database creation or expansion. "Untargeted" does not mean "random" — it means not tied to specific named subjects in a targeted investigation. Celebrity scraping is untargeted. |
| "Our predictive-policing tool is just decision support — a human makes the final call." | Art. 5(1)(d) excepts AI *supporting* human assessment where involvement is already established on objective verifiable facts directly linked to criminal activity. If the tool is generating the suspicion rather than corroborating an already-established involvement, (d) applies. Decision-support framing does not cure the prohibition. |
| "Real-time biometric ID in a shopping mall is fine because it's private property." | Art. 3(44) defines publicly accessible spaces broadly — includes privately-owned spaces that are open to the public such as shops and transport. (h) applies. |
| "Art. 5(1)(b) needs intent to exploit; we just happen to serve elderly users." | (b) requires that the AI system exploits vulnerabilities "in a way that materially distorts behaviour and causes or is reasonably likely to cause significant harm". Intent is not required — foreseeable exploitation is enough. If the system design foreseeably distorts behaviour of a vulnerable group, (b) is in scope. |

## Penalty exposure

Infringement of Art. 5 prohibitions carries the highest fine tier under Art. 99(3): up to **€35 million or 7% of worldwide annual turnover** (whichever is higher). This is the heaviest penalty bracket in the regulation. Do not frame Art. 5 compliance as discretionary.

## Cross-references

- [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md) — if not prohibited, is it high-risk?
- [eu-ai-act-operator-roles](eu-ai-act-operator-roles.md) — who bears the obligation
- [eu-ai-act-penalties](eu-ai-act-penalties.md) — full Art. 99 fine structure
- [eu-ai-act-timeline](eu-ai-act-timeline.md) — Art. 5 applies from 2 February 2025

## Source of truth

EU Regulation 2024/1689, Art. 5 and Art. 113, published in the Official Journal of the European Union, 12 July 2024.
