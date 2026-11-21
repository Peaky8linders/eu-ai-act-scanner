---
name: eu-ai-act-reference
description: Use when the user names a specific EU AI Act article, annex, or obligation (e.g. "Art. 9", "Annex IV", "Art. 50 transparency", "systemic risk threshold"), asks "what does the Act say about X", or wants to understand which articles apply to their system. Serves legal counsel (who need precise article-to-obligation mapping), compliance officers (who read the Act in translation to their QMS), and engineers (who need to know which analyzer feeds which obligation). Surfaces the coverage map without claiming completeness on governance articles.
user_invocable: true
---

# EU AI Act Reference Map

Trace from regulation article → compliance dimension → scanner analyzer → evidence observable in code. Serves legal counsel, compliance officers, and engineers who need to know what this plugin can and cannot tell them about a specific article.

## When to invoke

- User names an article: "check Art. 9", "is Art. 13 done", "explain Annex IV"
- User asks about an obligation: "what does the Act say about logging", "do I need a QMS"
- User is deciding system scope: "is my chatbot high-risk", "do GPAI rules apply to me"
- User invokes `/ai-act-article` explicitly

## Applies to

- Any article in EU Regulation 2024/1689 and any Annex.
- **In scope**: article → dimension → analyzer mapping, coverage gaps in the scanner.
- **Out of scope**: legal opinions on ambiguous articles (e.g. the exact boundaries of Art. 6(3)) — flag open questions as open, do not resolve them for the user.

## What to do

1. Normalise the article identifier. Accept `art9`, `Art. 9`, `9`, `article 9`, `art 9`. Canonical lowercase form is `artNN`.
2. Look up the article in the coverage map below.
3. If the article is covered by one or more analyzers, invoke `/ai-act-article <id>` for a live report against the current codebase.
4. If the article is *not* covered (e.g. Art. 40 on harmonised standards, Art. 70 on national authorities), say so explicitly. Point at where the obligation actually lives: legal counsel, governance process, or a different tool.
5. Name grey zones. Art. 6(3), Art. 15(4), and several GPAI thresholds depend on delegated or implementing acts that are not yet published. Do not paper over that.

## Coverage map — code-observable articles

| Article | Title | Scanner dimensions | Static-analysis signal |
|---|---|---|---|
| Art. 4 | AI Literacy | `ai_literacy` | Training documentation, LMS references |
| Art. 9 | Risk Management | `risk_mgmt`, `decision_governance` | `RISKS.md`, risk register, hazard analyses |
| Art. 10 | Data Governance | `data_gov` | Data cards, fairness tests, provenance tracking |
| Art. 11 | Technical Documentation | `tech_docs` | README, MODEL_CARD, Annex IV pack |
| Art. 12 | Record-Keeping | `logging` | Structured logging, MLflow, audit trails |
| Art. 13 | Transparency (provider→deployer) | `transparency` | Inline disclosures, deployer-facing docs |
| Art. 14 | Human Oversight | `human_oversight`, `decision_governance` | HITL gates, confidence thresholds, overrides |
| Art. 15 | Accuracy, Robustness, Cybersecurity | `security`, `access_control`, `infra_mlops`, `supply_chain` | Auth, rate limiting, adversarial robustness |
| Art. 17 | Quality Management System | `quality_management` | CI/CD, release procedures, QMS docs |
| Art. 26 | Deployer obligations | `deployer_obligations` | Deployer runbooks, incident procedures |
| Art. 27 | Fundamental Rights Impact Assessment | `deployer_obligations` | FRIA docs for Annex III.5/.7/.8 deployers |
| Art. 43 | Conformity assessment | `conformity_assessment` | Internal control procedure or notified body engagement |
| Art. 47 | EU declaration of conformity | `conformity_assessment` | Annex V declaration file |
| Art. 48 | CE marking | `conformity_assessment` | CE marking evidence |
| Art. 50 | Transparency to natural persons / GenAI labelling | `transparency`, `content_transparency` | AI-interaction banners, synthetic-media labels |
| Art. 51 | GPAI systemic risk threshold | `gpai_systemic_risk` | Training-compute documentation |
| Art. 53 | GPAI provider obligations | `gpai` | Model card, training data summary |
| Art. 55 | GPAI systemic-risk-tier obligations | `gpai_systemic_risk` | Systemic evaluations, adversarial testing reports |
| Art. 72 | Post-market monitoring | `decision_governance` | PMMP, drift monitoring, incident hooks |
| Art. 95 | Voluntary Codes of Conduct | `voluntary_codes` | Self-binding documents |

## NOT code-observable (governance / procedural)

The scanner does not check the following. They require document review, organisational audit, or legal analysis. Surface them explicitly when the user asks — do not pretend they are covered by any dimension.

- **Art. 5** — prohibited practices. Requires semantic review of the use case. Route to [eu-ai-act-article-5-prohibited](../eu-ai-act-article-5-prohibited/SKILL.md).
- **Art. 6 + Annex III** — high-risk classification. Requires reading the system purpose. Route to [eu-ai-act-article-6-classification](../eu-ai-act-article-6-classification/SKILL.md).
- **Art. 40** — harmonised standards. Organisational adoption, not code-observable. **EN 18286:2026** (cited in OJ L, 2026/2274, 14 October 2026) confers presumption of conformity for **Art. 17(1)** and the **first sentence of Art. 11(1)** only; CEN-CENELEC JTC 21 technical standards (`prEN 18228`, `prEN 18229-1`, `prEN 18229-2`, `prEN 18282`, `prEN 18283`, `prEN 18284`) remain drafts.
- **Art. 52** — notification of conformity assessment bodies. Administrative.
- **Art. 56** — Code of Practice for GPAI. Organisational commitment.
- **Art. 64–70** — governance (AI Office, Board, panels, authorities). Not developers' concern.
- **Art. 73** — serious incident reporting. Requires an incident, a report, and a procedure — only part of which is code-observable.
- **Art. 85–94** — market surveillance, penalties. Regulator side.
- **Art. 99** — penalties. Not code. Route to [eu-ai-act-penalties](../eu-ai-act-penalties/SKILL.md) if that skill exists.
- **Art. 113** — entry into force and application timeline. Route to [eu-ai-act-timeline](../eu-ai-act-timeline/SKILL.md).

## Annex reference

| Annex | Content | Coverage |
|---|---|---|
| Annex I | List of Union harmonised legislation | — (cross-reference only) |
| Annex II | List of criminal offences for biometric identification exemption | — (Art. 5 scoping) |
| Annex III | High-risk use cases | **User must classify** — route to [eu-ai-act-article-6-classification](../eu-ai-act-article-6-classification/SKILL.md) |
| Annex IV | Technical documentation contents | **Partial** — `tech_docs` checks for README / model card but cannot verify Annex IV completeness |
| Annex V | EU declaration of conformity | Partial — `conformity_assessment` looks for declaration files |
| Annex VI | Conformity assessment based on internal control | — (procedure) |
| Annex VII | Conformity assessment based on QMS + technical documentation | — (procedure, involves notified body) |
| Annex VIII | Information to register in the EU database | — (administrative) |
| Annex IX | Information to be provided upon registration of GPAI with systemic risk | — (administrative) |
| Annex X | Union legislative acts on large-scale IT systems | — (cross-reference) |
| Annex XI | Technical documentation for GPAI models | Partial — `gpai` looks for model cards |
| Annex XII | Transparency information for GPAI (public summary) | Partial — `gpai` signal on public training-data summary |
| Annex XIII | Criteria for designation of systemic-risk GPAI | — (threshold calculation, not code) |

## Common article questions

Answer these precisely. Each answer must cite the article and name any open questions.

### "Does Art. 5 apply to my chatbot?"

Art. 5(1) lists prohibited practices. The ones most likely to be misread as matching a chatbot are:

- Art. 5(1)(a): subliminal techniques or purposefully manipulative/deceptive techniques that materially distort behaviour to cause significant harm
- Art. 5(1)(b): exploitation of vulnerabilities (age, disability, social/economic situation) to materially distort behaviour and cause significant harm
- Art. 5(1)(c): social-scoring AI by public or private actors that leads to detrimental/unfavourable treatment

A typical customer-service chatbot is not in these categories. But: a chatbot designed to manipulate purchase decisions from vulnerable populations could trigger Art. 5(1)(b). Route to [eu-ai-act-article-5-prohibited](../eu-ai-act-article-5-prohibited/SKILL.md) for the decision tree.

### "Do I need CE marking?"

CE marking under Art. 48 applies to high-risk AI systems only. Whether your system is high-risk is determined by Art. 6 + Annex III. If the system is not high-risk, Art. 48 does not apply. If the system is high-risk, CE marking is required after conformity assessment (Art. 43). Route to [eu-ai-act-article-6-classification](../eu-ai-act-article-6-classification/SKILL.md) to determine risk tier.

### "What's an FRIA?"

Fundamental Rights Impact Assessment (Art. 27). Required for **deployers** of **high-risk AI systems** in the domains listed in Annex III points 5(b), 5(c) (education access/assessment with risk of harm), 7 (employment decisions), 8(a) (access to essential public/private services). Providers do not perform FRIAs — deployers do. Route to [eu-ai-act-fria-guide](../eu-ai-act-fria-guide/SKILL.md) for the required contents and process.

### "Is my model a GPAI?"

A General-Purpose AI model (Art. 3(63)) is trained on broad data at scale for generality and can competently perform a wide range of distinct tasks. If you trained a foundation model yourself, Art. 53 provider obligations apply. If you use someone else's foundation model, you are a deployer — Art. 26 applies, Art. 53 does not. Systemic risk (additional obligations under Art. 55) is triggered when training compute is ≥10^25 FLOPs per Art. 51(2); the threshold may be adjusted by delegated act under Art. 51(3). Route to [eu-ai-act-gpai-classification](../eu-ai-act-gpai-classification/SKILL.md).

### "When do the obligations apply?"

Art. 113 (as amended by Digital Omnibus Regulation (EU) 2026/1744) sets staggered application dates: Art. 4 & Art. 5(1)(a)-(h) from **2 Feb 2025**; GPAI & governance from **2 Aug 2025**; Art. 50 transparency & Art. 101 GPAI fines from **2 Aug 2026** (with Art. 111(4) grace to **2 Dec 2026** for pre-2-Aug-2026 Art. 50(2) synthetic systems); Art. 5(1)(ba)-(bb) NCII/CSAM prohibitions from **2 Dec 2026**; Annex III high-risk from **2 Dec 2027**; and Annex I high-risk from **2 Aug 2028**. Route to [eu-ai-act-timeline](../eu-ai-act-timeline/SKILL.md).

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "Art. 6(3) says preparatory tasks are exempt, so our classifier is fine." | Art. 6(3) exempts only narrow categories (preparatory, narrow procedural, decision-pattern detection without replacing decisions, human-oversight-assistive). Profiling of natural persons is always high-risk (Art. 6(3) final paragraph). Check whether the classifier profiles individuals. |
| "Art. 50 only applies to deepfakes, we have a chatbot." | Art. 50(1) applies to any AI system *intended to interact directly with natural persons* — users must be informed they're interacting with AI unless obvious. Chatbots fall under Art. 50(1). Art. 50(2-4) covers generated content. Both subsections can apply to the same system. Route to [eu-ai-act-article-50-transparency](../eu-ai-act-article-50-transparency/SKILL.md) for the per-paragraph provider/deployer split. |
| "We registered an LLM-based customer service tool in the EU database." | Art. 49 EU database registration is required for providers of high-risk AI (Art. 6) and *deployers* that are public authorities. Non-public-authority deployers of limited-risk chatbots do not register. Registering a non-high-risk system is not harmful but suggests a misclassification — verify risk tier. |
| "The Commission hasn't published standards, so Art. 15 is not enforceable." | **EN 18286:2026** was cited in the OJ on **14 October 2026** (OJ L, 2026/2274) for **Art. 17(1)** and the **first sentence of Art. 11(1)** only. While Art. 15's JTC 21 deliverables (`prEN 18229-2`, `prEN 18282`) remain drafts, Art. 15 is directly applicable once its statutory date hits — harmonised standards confer presumption of conformity, and their absence does not suspend the obligation. |

## Cross-references

- [using-eu-ai-act-scanner](../using-eu-ai-act-scanner/SKILL.md) — when to scan and how
- [interpreting-findings](../interpreting-findings/SKILL.md) — how to read dimension scores
- [eu-ai-act-article-5-prohibited](../eu-ai-act-article-5-prohibited/SKILL.md)
- [eu-ai-act-article-6-classification](../eu-ai-act-article-6-classification/SKILL.md)
- [eu-ai-act-article-50-transparency](../eu-ai-act-article-50-transparency/SKILL.md)
- [eu-ai-act-fria-guide](../eu-ai-act-fria-guide/SKILL.md)
- [eu-ai-act-operator-roles](../eu-ai-act-operator-roles/SKILL.md)
- [eu-ai-act-gpai-classification](../eu-ai-act-gpai-classification/SKILL.md)
- [eu-ai-act-annex-iv-guide](../eu-ai-act-annex-iv-guide/SKILL.md)
- [eu-ai-act-timeline](../eu-ai-act-timeline/SKILL.md)

## Source of truth

EU Regulation (EU) 2024/1689 (OJ L, 12 July 2024), as amended by Digital Omnibus on AI Regulation (EU) 2026/1744 (OJ L, 2026/1744, 24 July 2026), and Commission Implementing Decision (EU) 2026/2274 (OJ L, 2026/2274, 14 October 2026) citing EN 18286:2026.
