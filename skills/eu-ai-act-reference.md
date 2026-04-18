---
name: eu-ai-act-reference
description: Use when the user names a specific EU AI Act article, annex, or obligation (e.g. "Art. 9", "Annex IV", "Art. 50 transparency", "systemic risk threshold"). Shows the article's scope, which scanner dimensions cover it, and which are out of scope for static analysis.
user_invocable: true
---

# EU AI Act Reference Map

Trace from regulation article → scanner dimension → analyzer → observable evidence.

## When to invoke

- User names an article: "check Art. 9", "is Art. 13 done", "explain Annex IV"
- User asks about an obligation: "what does the Act say about logging", "do I need a QMS"
- User is deciding whether a system is in scope: "is my chatbot high-risk", "do GPAI rules apply to me"

## What to do

1. Normalise the article identifier. Accept `art9`, `Art. 9`, `9`, `article 9`.
2. Read the mapping below to determine which scanner dimensions cover that article.
3. If the article is **covered**, invoke `/ai-act-article ARTN` to produce a live report against the current codebase.
4. If the article is **not covered** (e.g. Art. 40 on harmonised standards, Art. 70 on national authorities), say so explicitly and point to where the obligation lives (governance, not code).

## Coverage map

### Code-observable articles

| Article | Title | Dimensions | Static-analysis signal |
|---|---|---|---|
| Art. 4 | AI Literacy | `ai_literacy` | Training docs mentioning AI |
| Art. 9 | Risk Management | `risk_mgmt`, `decision_governance` | `RISKS.md`, risk register, hazard analyses |
| Art. 10 | Data Governance | `data_gov` | Data cards, fairness tests, provenance tracking |
| Art. 11 | Technical Documentation | `tech_docs` | README, MODEL_CARD, Annex IV pack |
| Art. 12 | Record-Keeping | `logging` | Structured logging, MLflow, audit trails |
| Art. 13 | Transparency (user-facing) | `transparency` | Inline disclosures, UX copy, terms of service |
| Art. 14 | Human Oversight | `human_oversight`, `decision_governance` | HITL gates, confidence thresholds, overrides |
| Art. 15 | Accuracy & Security | `security`, `access_control`, `infra_mlops`, `supply_chain` | Auth, rate limiting, adversarial robustness |
| Art. 17 | Quality Management System | `quality_management` | CI/CD, release procedures, QMS docs |
| Art. 26, 27 | Deployer Obligations | `deployer_obligations` | FRIA docs, deployer-specific runbooks |
| Art. 43, 47, 48 | Conformity Assessment | `conformity_assessment` | EU declaration, CE marking evidence |
| Art. 50 | Transparency for limited-risk + GenAI content | `transparency`, `content_transparency` | AI-interaction banners, synthetic-media labels |
| Art. 51, 55 | GPAI Systemic Risk | `gpai_systemic_risk` | FLOP documentation, red-team reports |
| Art. 53 | GPAI Provider Obligations | `gpai` | Model card, training data summary |
| Art. 72 | Post-Market Monitoring | `decision_governance` | PMMP, drift monitoring, incident hooks |
| Art. 95 | Voluntary Codes of Conduct | `voluntary_codes` | Self-binding documents |

### NOT code-observable (governance/procedural)

The scanner does not check these — they require document review or organisational audit:

- **Art. 5** (Prohibited practices) — requires semantic review of use case, not code patterns
- **Art. 6** (High-risk classification) — requires reading the system description, not the code
- **Art. 40** (Harmonised standards) — organisational adoption, not code-observable
- **Art. 52** (Conformity body notification) — administrative
- **Art. 56** (Code of Practice) — organisational
- **Art. 64–70** (Governance structures) — authorities, not developers
- **Art. 85–94** (Market surveillance, penalties) — regulator side

For these, point the user at their legal counsel or a dedicated governance tool.

### Annex reference

| Annex | Content | Coverage |
|---|---|---|
| Annex I | Definition of AI techniques (historical) | — (definitional) |
| Annex II | Union harmonised legislation | — (cross-references) |
| Annex III | High-risk use cases | **Use case classification** — user must self-declare which category applies |
| Annex IV | Technical documentation contents | Partial — `tech_docs` dimension checks for README / model card but cannot verify Annex IV completeness |
| Annex V | EU declaration of conformity | Partial — `conformity_assessment` looks for declaration files |
| Annex VI–VIII | Conformity assessment procedures | — (procedural) |
| Annex IX | EU database registration | — (administrative) |
| Annex XI | GPAI technical documentation | Partial — `gpai` looks for model cards |
| Annex XIII | GPAI systemic-risk criteria | — (threshold calculation, not code) |

## Answering common article questions

**"Does Art. 5 apply to my chatbot?"**
> Art. 5 prohibits specific use cases (social scoring by public authorities, real-time biometric ID in public spaces for law enforcement with narrow exceptions, exploitation of vulnerabilities, subliminal manipulation). Most chatbots are NOT prohibited under Art. 5. Check Art. 6 + Annex III for whether you are high-risk instead. The scanner cannot determine this — describe your use case and I can help you classify.

**"Do I need CE marking?"**
> Only high-risk AI systems (Art. 6 + Annex III) need CE marking via Art. 43 conformity assessment. Limited-risk and minimal-risk systems do not. If your scan's `conformity_assessment` dimension scores 0%, that may be fine — check your risk tier first.

**"What's an FRIA?"**
> Fundamental Rights Impact Assessment (Art. 27). Required for deployers of high-risk AI systems in public services, essential private services, law enforcement, migration/asylum, and justice (Annex III.5, .7, .8). The scanner cannot generate one — it requires human judgement about affected groups, rights at risk, and mitigation. Flag to the user if they're deploying in those domains.

**"Is my model a GPAI?"**
> A General-Purpose AI model (Art. 3(63)) is one trained on broad data for diverse tasks. If you use it for a specific purpose (e.g. RAG over your docs), you're a *deployer* of a GPAI — the obligations fall on the model provider, not you. If you trained a foundation model yourself, `gpai` applies. Systemic risk kicks in at ≥10^25 FLOPs of training compute (Art. 51(2)).

## Source of truth

Always cite the article number, not invented paragraph text. The authoritative source is EU Regulation 2024/1689 published in the Official Journal of the European Union, 12 July 2024.
