---
name: eu-ai-act-article-50-transparency
description: Use when the user asks about transparency to end users, AI-interaction disclosure, chatbot disclaimers, labelling of AI-generated or synthetic content, deep-fake disclosure, emotion-recognition or biometric-categorisation notices, or names Art. 50. Distinguishes the four Art. 50 duties by actor (which are the provider's, which are the deployer's) and separates limited-risk Art. 50 transparency from high-risk Art. 13 transparency. Serves legal counsel (primary), product leads, and deployers.
user_invocable: true
---

# Art. 50 — Transparency Obligations for Certain AI Systems

Determine which Art. 50 transparency duty applies, and to whom. Art. 50 is the limited-risk transparency regime: it attaches to a system because of *how it interacts or what it outputs*, not because the system is high-risk. The four paragraphs split cleanly between the provider and the deployer; the most common error is attributing a deployer paragraph to the provider, or asserting high-risk Art. 13 transparency when only limited-risk Art. 50 applies. Covers Art. 50(1)–(4).

## When to invoke

- User asks "do we need a chatbot disclaimer", "must we label AI-generated content", "deep-fake disclosure", "do users have to be told they're talking to an AI"
- User describes a generative system that produces audio, image, video, or text
- User describes an emotion-recognition or biometric-categorisation system being deployed on people
- User mentions Art. 50, "transparency to users", "synthetic media labelling", or "AI watermarking"
- User conflates Art. 50 (transparency to natural persons) with Art. 13 (transparency to deployers of high-risk systems)

## Applies to

- **In scope**: the four limited-risk transparency duties in Art. 50(1)–(4), and the actor (provider vs deployer) that bears each.
- **Out of scope**: high-risk transparency *to deployers* under Art. 13 (a high-risk obligation, different actor and trigger). GPAI provider documentation duties under Art. 53 (route to [eu-ai-act-gpai-classification](eu-ai-act-gpai-classification.md)). Whether a system is high-risk at all (route to [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md)). Prohibited emotion recognition in workplaces/education (route to [eu-ai-act-article-5-prohibited](eu-ai-act-article-5-prohibited.md) — Art. 5(1)(f) bans it outright; Art. 50(3) only governs disclosure where the practice is otherwise lawful).

## Regulation scope — the four duties by actor

Art. 50 splits by paragraph **and** by operator. Attribute each duty to the correct actor; never assign a deployer paragraph to the provider or vice versa.

| Para | Actor | Duty |
|---|---|---|
| **Art. 50(1)** | **Provider** | Design AI systems *intended to interact directly with natural persons* so those persons are informed they are interacting with an AI system, unless it is obvious to a reasonably well-informed person. |
| **Art. 50(2)** | **Provider** | Mark outputs of systems generating synthetic audio, image, video, or text in a machine-readable format detectable as artificially generated or manipulated. Solutions must be effective, interoperable, robust, and reliable as far as technically feasible. **Applies to GPAI systems generating synthetic content by its own terms.** |
| **Art. 50(3)** | **Deployer** | Inform natural persons exposed to an emotion-recognition system or a biometric-categorisation system of its operation. |
| **Art. 50(4)** | **Deployer** | Disclose that image, audio, or video content constituting a **deep fake** has been artificially generated or manipulated. For AI-generated/manipulated **text published to inform the public on matters of public interest**, disclose AI generation unless the content underwent human review with editorial responsibility. |

Disclosure must be clear and distinguishable, provided at the latest at the first interaction or exposure (Art. 50(5)). Narrow law-enforcement carve-outs exist in several paragraphs; do not validate them yourself — name the condition and flag for counsel.

**Application date**: Art. 50 applies from **2 August 2026** (general application under Art. 113), not 2 February 2025.

## What to do

1. **Classify the system first.** Establish risk tier before asserting any duty. A general-purpose chatbot answering general queries is **limited-risk**: its only transparency duty is Art. 50(1). Do not stack Art. 13 high-risk transparency on top unless the system is *independently* high-risk (an Annex III use case or a safety component — confirm via [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md)).
2. **Identify the operator role.** Art. 50(1)/(2) are provider duties; Art. 50(3)/(4) are deployer duties. The same organisation can be both — split the analysis. Confirm via [eu-ai-act-operator-roles](eu-ai-act-operator-roles.md).
3. **Map the system's behaviour to the paragraphs.** Direct interaction → 50(1). Generates synthetic content → 50(2). Emotion recognition / biometric categorisation → 50(3). Deep fakes or public-interest text → 50(4). A single system can trigger several (e.g. a generative chatbot triggers 50(1) and 50(2)).
4. **For a GPAI system, check the dual trigger.** A GPAI model that generates synthetic content is covered by Art. 50(2) directly; if it also interacts with natural persons, Art. 50(1) also applies; and the GPAI provider separately carries the Art. 53 documentation duties. Cite all that apply.
5. **State evidence, not verdicts.** "Art. 50(1) requires interaction disclosure; the chat UI shows no AI-interaction notice — evidence of the disclosure is absent." Let a human decide.

## Decision tree

Ask in this order; a system can match more than one.

```
Is the system intended to interact directly with natural persons?
    → Art. 50(1)  PROVIDER must ensure users are informed it is an AI
      (unless obvious). Exempt only where law authorises it for
      criminal-offence detection, with safeguards.

Does the system generate synthetic audio / image / video / text?
    → Art. 50(2)  PROVIDER must mark outputs machine-readable as
      artificially generated. Applies to GPAI too. Exempt for assistive
      / standard-editing functions that do not substantially alter the
      input, or where authorised by law for criminal-offence detection.

Is an emotion-recognition or biometric-categorisation system deployed
on people?
    → Art. 50(3)  DEPLOYER must inform the exposed natural persons.
      (If the practice is emotion recognition in a workplace or school,
       check Art. 5(1)(f) FIRST — it may be prohibited outright.)

Does the deployer publish a deep fake, or AI-generated text on a matter
of public interest?
    → Art. 50(4)  DEPLOYER must disclose the artificial generation /
      manipulation. Text is exempt where a human held editorial
      responsibility; art/satire disclosed in an appropriate manner.
```

## Cross-references

- [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md) — classify risk tier before asserting any transparency duty
- [eu-ai-act-operator-roles](eu-ai-act-operator-roles.md) — provider vs deployer, which paragraph is whose
- [eu-ai-act-gpai-classification](eu-ai-act-gpai-classification.md) — GPAI + Art. 50 dual trigger and Art. 53 duties
- [eu-ai-act-article-5-prohibited](eu-ai-act-article-5-prohibited.md) — emotion recognition in work/education is prohibited (Art. 5(1)(f)), not merely disclosed
- [eu-ai-act-penalties](eu-ai-act-penalties.md) — Art. 50 breaches fall in the Art. 99(4) tier (up to €15M or 3% of turnover), not the Art. 5 7% tier
- [eu-ai-act-timeline](eu-ai-act-timeline.md) — Art. 50 applies from 2 August 2026

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "Art. 50 only covers deep fakes; our chatbot is fine." | Art. 50(1) applies to any system *intended to interact directly with natural persons* — users must be informed they are interacting with an AI unless it is obvious. Chatbots fall under 50(1). 50(4) deep-fake disclosure is a separate, additional duty. |
| "We're high-risk, so Art. 13 covers our transparency — Art. 50 doesn't apply too." | Art. 13 (transparency to *deployers*) and Art. 50 (transparency to *natural persons*) have different beneficiaries and can apply cumulatively. A high-risk system that also interacts with users owes both. But a *limited-risk* chatbot owes Art. 50(1) ALONE — do not import Art. 13 unless the system is independently high-risk. |
| "Labelling generated content is the deployer's job." | Art. 50(2) marking of synthetic outputs is a **provider** duty, machine-readable at generation. Art. 50(4) deep-fake *disclosure to the audience* is the **deployer** duty. They are different paragraphs and different actors; do not collapse them. |
| "Our GPAI just exposes an API, so consumer transparency doesn't apply." | Art. 50(2) binds the provider of a system generating synthetic content, including a GPAI system, by its own terms — independent of any UI. If the GPAI also interacts directly with persons, Art. 50(1) applies as well, and Art. 53 GPAI duties apply regardless. |
| "The AI-generated article is clearly ours, so no disclosure is needed." | Art. 50(4) requires disclosure for AI-generated/manipulated text published to inform the public on matters of public interest, unless the content underwent human review with a natural or legal person holding editorial responsibility. Ownership is not the test; editorial responsibility is. |
| "It's obvious it's an AI, so we can skip the notice." | The Art. 50(1) "obvious" carve-out is judged from the standpoint of a reasonably well-informed, observant, and circumspect natural person in the circumstances. Assert it only when genuinely unmistakable; when in doubt, disclose. This is a legal judgement call — recommend counsel review. |

## Source of truth

EU Regulation 2024/1689, Art. 50 (and Art. 99(4) for penalties, Art. 113 for application dates), published in the Official Journal of the European Union, 12 July 2024.
