---
name: eu-ai-act-annex-iv-guide
description: Use when the user asks what goes in Annex IV technical documentation, mentions Art. 11, needs to assemble the technical file for conformity assessment, or is producing SME documentation under Art. 11(1) simplified form. Serves providers of high-risk AI (primary — Art. 11 is a provider obligation), their technical writers, and notified bodies reviewing the file. Lists the nine Annex IV items with concrete guidance on what counts as adequate evidence for each.
user_invocable: true
---

# Annex IV — Technical Documentation for High-Risk AI

Assemble and maintain the Art. 11 technical documentation for a high-risk AI system. Annex IV is the regulator's primary evidence source during conformity assessment and market surveillance. A thin Annex IV file is the single most common reason notified bodies return findings.

## When to invoke

- "What goes in Annex IV", "Art. 11 documentation"
- "We need a technical file for conformity assessment"
- "Notified body asked for our documentation"
- User is assembling or auditing the technical file
- User is a provider of high-risk AI and has completed development

## Applies to

- Providers of high-risk AI systems under Art. 6.
- **In scope**: the nine Annex IV items and their interaction with Art. 11(1) (SME simplified form per Art. 11(1) second subparagraph is noted but scoped).
- **Out of scope**: Annex XI (GPAI technical documentation — route to [eu-ai-act-gpai-classification](eu-ai-act-gpai-classification.md)). Annex V declaration of conformity (separate document).

## Regulation scope

Art. 11(1) requires the provider to draw up the technical documentation **before the system is placed on the market or put into service**, keep it up to date, and have it available to national competent authorities and notified bodies for at least 10 years after the system is placed on the market (Art. 18).

The content is defined by Annex IV. The structure is flexible; the content list is not.

## Annex IV — the nine required sections

### 1. General description of the AI system

Per Annex IV.1:

- (a) Intended purpose, provider name, system version
- (b) How the AI system interacts with, or can be used to interact with, hardware or software not part of the AI system itself
- (c) Relevant software/firmware versions, version management requirements
- (d) Description of all forms in which the AI system is placed on the market / put into service (packaged software, embedded in hardware, downloadable, API)
- (e) Description of hardware on which the AI system is intended to run
- (f) For AI embedded in products, photographs/illustrations showing external features, markings, internal layout
- (g) Basic description of the user interface for the deployer
- (h) Instructions for use for the deployer (cross-reference Art. 13)

### 2. Detailed description of the elements of the AI system and of the process for its development

Per Annex IV.2:

- (a) Methods and steps performed for development, including third-party pre-trained tools/systems and how they were used/integrated/modified
- (b) Design specifications, general logic, key design choices, rationale, assumptions including about persons/groups the system is intended to be used on, main classification choices, what the system is designed to optimise for, relevance of different parameters
- (c) Description of system architecture, how software components build on or feed into each other, integrate in processing, computational resources used, algorithms, trade-offs
- (d) Where relevant: data requirements in terms of datasheets describing training methodologies, techniques, datasets used — their provenance, scope, main characteristics, how data was obtained/selected, labelling procedures, data cleaning
- (e) Assessment of human oversight measures (Art. 14), including technical measures for interpretability by the deployer
- (f) Where applicable: detailed description of pre-determined changes to the system and its performance, and relevant information about continuous learning
- (g) Validation and testing procedures used, including information about validation/testing data characteristics, metrics used to measure accuracy, robustness, compliance with Art. 9 and Art. 15
- (h) Cybersecurity measures

### 3. Information about monitoring, functioning, and control

- Capabilities, performance, limitations; expected levels of accuracy per Art. 15, including in relation to intended purpose and persons/groups
- Foreseeable unintended outcomes and risk sources to health, safety, fundamental rights, discrimination
- Human oversight measures per Art. 14
- Specifications on input data

### 4. Description of appropriateness of performance metrics for the system

### 5. Description of the risk management system per Art. 9

Cross-reference the Art. 9 RMS documentation. See [eu-ai-act-reference](eu-ai-act-reference.md) and existing risk register.

### 6. Description of relevant changes made by the provider through the lifecycle

Update history, rationale for changes, impact on compliance.

### 7. List of harmonised standards applied in full or in part

References to the official journal of publications. Where standards were not applied, description of solutions adopted to meet requirements.

### 8. Copy of the EU declaration of conformity per Art. 47

### 9. Detailed description of the system in place to evaluate AI system performance in the post-market phase per Art. 72

Cross-reference post-market monitoring plan.

## SME simplified form — Art. 11(1) second subparagraph

SMEs including start-ups may provide elements of Annex IV in a simplified manner. The Commission is to establish a simplified form. Until published, assemble the full Annex IV content but scale the depth of each section to the complexity of the system. "Simplified" does not mean "incomplete" — every heading must be addressed.

## What to do

### Assembling the file

1. Create a single document (or linked collection) organised under the nine Annex IV sections.
2. For each section, link to the underlying evidence rather than duplicating:
   - Datasheets in `data/` → Annex IV.2(d)
   - Architecture diagrams in `docs/architecture/` → Annex IV.2(c)
   - Test reports in `reports/` → Annex IV.2(g)
   - Risk register in `risks/` → Annex IV.5
   - PMMP in `docs/pmmp.md` → Annex IV.9
3. Maintain a version number. Art. 11(1) requires keeping the documentation up to date.
4. Ensure the file is available to authorities within the timeframe specified in Art. 18 — 10 years after placing on market.

### Reviewing the file (audit mode)

For each of the nine sections, verify:

- Section is present
- Section is substantive (not just a heading with "see X")
- Cross-references resolve to real documents
- Version / date indicates the content is current
- Narrative addresses *this* system, not a generic template

A common failure: templates copy-pasted across products. Notified bodies detect this quickly. Annex IV must describe the specific system.

### Using the scanner

The `tech_docs` dimension of the scanner (`scanner/analyzers/documentation.py`) looks for README, model cards, and architecture docs as proxy evidence. It cannot verify Annex IV completeness on its own — the governance artefacts (risk register, PMMP, test reports) often live outside the code repository. Use the scanner as a starting point, then manually audit the file.

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "Our model card covers Annex IV." | A model card is a subset of Annex IV.1 and parts of IV.2. It does not substitute for IV.5 (risk management), IV.7 (standards), IV.8 (declaration), or IV.9 (post-market plan). Treat the model card as one input to Annex IV, not the whole. |
| "We can assemble Annex IV after the first deployment." | Art. 11(1) requires technical documentation **before** the system is placed on the market or put into service. Post-hoc assembly is non-compliant. The test is whether a notified body could audit the file at the moment of market placement. |
| "We're SMEs, so we can skip some sections." | Art. 11(1) second subparagraph permits *simplified* manner, not omissions. Every heading must be addressed. The Commission will publish a simplified form; until then, keep every section present. |
| "We'll only document the production version; dev versions don't matter." | Annex IV.2(a) requires description of development methods and steps, including third-party tools. Dev history is part of the file. |
| "The provider of the base model owes us the technical documentation." | If you fine-tuned or integrated a third-party model, Annex IV.2(a) requires you to describe *how* you used it. The GPAI provider owes you Art. 53(1)(b) documentation. Combining those into your own Annex IV is your responsibility, not theirs. |
| "We can redact sensitive training data details." | Notified bodies and market surveillance authorities are entitled to the full documentation under Art. 21 (access to data and documentation). Redaction to protect trade secrets is possible but does not remove the obligation to document. |

## Cross-references

- [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md) — Annex IV applies only to high-risk systems
- [eu-ai-act-reference](eu-ai-act-reference.md) — Art. 11 in the broader map
- [eu-ai-act-gpai-classification](eu-ai-act-gpai-classification.md) — GPAI models follow Annex XI, not Annex IV
- `/ai-act-scan --article art11` — scanner's view of documentation evidence

## Source of truth

EU Regulation 2024/1689, Art. 11, Art. 18, Annex IV, published in the Official Journal of the European Union, 12 July 2024.
