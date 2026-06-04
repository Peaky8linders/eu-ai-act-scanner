---
name: eu-ai-act-incident-grounding
description: Use when the user asks "what real incidents caused this gap", "ground my findings in evidence", "show me historical attacks for this dimension", "which OWASP or NIST controls map here", "run /ai-act-incidents", or wants to connect scanner gaps to the GenAI & Agentic AI Security Incidents dataset. Serves engineers (who need concrete failure modes to motivate fixes), compliance officers (who need Art. 9 risk-identification evidence and Art. 72 post-market monitoring inputs), and legal counsel (who need documented foreseeable misuse under Art. 9(2)(b) to support conformity arguments).
user_invocable: true
---

# Incident Grounding for EU AI Act Findings

Connect scanner gaps to real-world and research-demonstrated security incidents so that every gap carries documented failure history, cross-framework mappings (OWASP LLM/ASI Top 10, NIST AI RMF, MITRE ATLAS), and published mitigations. Serves engineers motivating fixes, compliance officers building Art. 9 risk-identification evidence, and legal counsel documenting foreseeable-misuse analysis required by Art. 9(2)(b).

## When to invoke

- After `/ai-act-scan`: "what real incidents caused these gaps"
- "Ground my findings in evidence" or "show me historical attacks for this dimension"
- "Which OWASP or MITRE ATLAS techniques map to this finding"
- "We need foreseeable-misuse analysis for our Art. 9 risk register"
- "What does the dataset say about prompt injection on agentic systems"
- `/ai-act-incidents security`, `/ai-act-incidents art15`, `/ai-act-incidents lethal_trifecta`
- "Are these incidents in scope for Art. 72 post-market monitoring"
- User mentions AIID, AVID, AIAAIC, garak, promptfoo, or OWASP LLM Top 10 in the context of a scanner run

## Applies to

**In scope**: any scanner finding or KB dimension can be grounded against the incident corpus. The command `/ai-act-incidents` accepts a dimension id (`security`, `risk_mgmt`, `human_oversight`, etc.), a canonical article id (`art9`, `art15`, `art72`), or a threat-category id (`prompt_injection`, `data_exfiltration`, `lethal_trifecta`, etc.).

**Out of scope**: the corpus does not replace a full Art. 9 risk management system, an Art. 43 conformity assessment, or legal review. Incident grounding is evidence *input* to those processes, not a substitute for them. For the full Art. 9 obligation, route to [eu-ai-act-reference](eu-ai-act-reference.md). For Art. 43 conformity, route to [interpreting-findings](interpreting-findings.md).

## Regulation scope

### Art. 9 — Risk management system

Art. 9(1) requires a continuous risk management system throughout the AI system lifecycle. Art. 9(2) requires that the system identify and analyse known and foreseeable risks. Specifically, Art. 9(2)(a) requires identification of known and foreseeable risks to health, safety, or fundamental rights; Art. 9(2)(b) requires consideration of foreseeable misuse and reasonably foreseeable end-uses.

Documented incidents are the most direct available evidence of foreseeable misuse. When a gap class (e.g. missing prompt-injection defences, insufficient HITL gates) has produced documented real-world or research-demonstrated failures, those incidents are not hypothetical — they are the starting evidence for the Art. 9(2)(b) foreseeable-misuse analysis. Using the corpus to populate an Art. 9 risk register is not optional decorative activity; it is the most defensible response to an auditor asking how foreseeable misuse was assessed.

### Art. 15 — Accuracy, robustness, and cybersecurity

Art. 15(4) requires high-risk AI systems to be resilient to attempts by unauthorised parties to alter outputs through adversarial attacks, model manipulation, prompt injection, or data poisoning. The incident corpus includes documented cases of each of these attack classes, mapped to OWASP LLM Top 10 and MITRE ATLAS techniques. The crosswalk from OWASP LLM01 (prompt injection), LLM02 (insecure output handling), LLM06 (sensitive information disclosure), and MITRE ATLAS AML.T0051 (LLM Prompt Injection) directly supports the Art. 15(4) cybersecurity gap analysis.

### Art. 72 — Post-market monitoring

Art. 72(1) requires providers of high-risk AI systems to have a post-market monitoring plan that collects, documents, and analyses relevant data. Art. 72(3) requires the plan to actively cover post-deployment behaviour including incidents and near-misses. The incident corpus, and particularly its ongoing maintenance, is a reference data source for what constitutes a material incident in the GenAI/agentic AI domain and what mitigations were effective post-incident.

### Art. 73 — Serious incident reporting

Art. 73(1) requires providers to report serious incidents to market surveillance authorities without delay. Knowing what incident patterns have historically qualified as serious in this domain (data exfiltration, model inversion, unsafe autonomous actions, privacy violations) is prerequisite to recognising a reportable incident when it occurs. The corpus's severity tiers and category labels support this classification step.

## The incident corpus

### Source

The scanner bundles a curated subset of the **GenAI & Agentic AI Security Incidents** dataset, published at HuggingFace as `emmanuelgjr/genai-incidents` (CC-BY-4.0). The full dataset aggregates and de-duplicates incident records from: the AI Incident Database (AIID), OECD AI Incidents Monitor (AIM), AI, Algorithmic, and Automation Incidents and Controversies (AIAAIC), MITRE ATLAS, AVID (AI Vulnerability Database), MIT AI Risk Repository, the National Vulnerability Database (NVD), GitHub Security Advisories (GHSA), OSV (Open Source Vulnerability database), garak adversarial probe results, and promptfoo red-team findings. As of v0.4.0 the corpus contains 7,725+ incidents (real-world and research-demonstrated combined).

The scanner bundles a curated subset: the reviewed-quality-tier subset, pre-filtered for relevance to the 23 compliance dimensions and the four compound-risk axes (cascading, emergent, attribution, temporal). This subset runs offline — no network calls. The full dataset is accessible via `pip install genai-incidents` or `load_dataset("emmanuelgjr/genai-incidents")`.

### Quality tiers

Each incident carries a `quality_tier` field. The scanner uses `reviewed` tier by default (manually verified, complete taxonomy mapping, at least one documented mitigation). The `corpus` field distinguishes real-world confirmed incidents from research-demonstrated proof-of-concept attacks. For Art. 9(2)(b) foreseeable-misuse analysis, research-demonstrated incidents are as relevant as real-world ones — Art. 9(2)(b) does not require harm to have occurred; it requires consideration of foreseeable misuse, and a published research demonstration is the most direct evidence that misuse is feasible.

### Taxonomy coverage

Each incident is mapped to:
- **OWASP Top 10 for LLM Applications 2025** (e.g. LLM01 Prompt Injection, LLM02 Insecure Output Handling, LLM06 Sensitive Information Disclosure, LLM07 System Prompt Leakage)
- **OWASP Agentic AI (ASI) Top 10** (e.g. ASI01 Unbounded Autonomy, ASI02 Inadequate Human Oversight, ASI03 Insecure Inter-Agent Communication)
- **NIST AI RMF** (function+category, e.g. GOVERN-1.2, MAP-5.2, MEASURE-2.7, MANAGE-4.1)
- **MITRE ATLAS** (technique + tactic, e.g. AML.T0051 LLM Prompt Injection, AML.T0040 ML Model Inference API Access, AML.T0054 LLM Jailbreak)

## API reference

```python
from scanner import incidents_for_dimension, incidents_for_article, incident_corpus_stats
from scanner.incident_grounding import incidents_for_threat, incidents_for_finding

# By KB dimension id
incidents = incidents_for_dimension("security", limit=5)

# By canonical article id
incidents = incidents_for_article("art15", limit=5)

# By threat-category id (matches scanner ThreatCategory taxonomy)
incidents = incidents_for_threat("prompt_injection", limit=5)

# Directly from a scanner Finding object
incidents = incidents_for_finding(finding, limit=3)

# Dataset provenance + coverage summary
stats = incident_corpus_stats()
# Returns: {count, version, source, doi, license, last_synced, taxonomy_coverage}
```

Each returned `Incident` is a frozen dataclass with:

| Field | Type | Description |
|---|---|---|
| `id` | str | Corpus identifier, e.g. "INC-04853" |
| `title` | str | Short incident title |
| `year` | int | Year of incident or publication |
| `severity` | str | "critical" / "high" / "medium" / "low" |
| `category` | str | Primary incident category |
| `attack_vector` | str | Mechanism (e.g. "prompt_injection", "model_inversion") |
| `description` | str | Narrative description |
| `owasp_llm` | list[str] | OWASP LLM App IDs, e.g. ["LLM01"] |
| `owasp_asi` | list[str] | OWASP Agentic AI IDs, e.g. ["ASI02"] |
| `nist_ai_rmf` | list[str] | NIST AI RMF function+category, e.g. ["MEASURE-2.7"] |
| `mitre_atlas` | list[str] | MITRE ATLAS technique IDs, e.g. ["AML.T0051"] |
| `mitre_atlas_tactics` | list[str] | Corresponding ATLAS tactics |
| `mitigations` | list[str] | Published mitigations for this incident class |
| `cve_ids` | list[str] | CVE IDs where applicable |
| `references` | list[str] | Source URLs |
| `quality_tier` | str | "reviewed" / "community" / "preliminary" |
| `corpus` | str | "real-world" / "research-demonstrated" |

## What to do

1. Run `/ai-act-scan` on the codebase to obtain the dimension scores and gap findings.
2. Identify the worst-scoring dimensions or most severe gap findings. Route to [interpreting-findings](interpreting-findings.md) if the user needs help with prioritisation.
3. For each target dimension or finding, run `/ai-act-incidents <dimension_or_article_or_threat>`. Example:
   ```
   /ai-act-incidents security
   /ai-act-incidents art9
   /ai-act-incidents prompt_injection
   ```
4. Present the top incidents for each gap. For each incident, surface:
   - The incident ID, title, year, and whether it is real-world or research-demonstrated
   - The attack vector and the OWASP LLM/ASI IDs it maps to
   - The MITRE ATLAS techniques
   - The NIST AI RMF categories
   - The published mitigations
5. Cross-reference the mitigations against what the scanner already found as positive evidence. Gaps in the mitigation list map to next-action tasks.
6. For Art. 9 risk-register use: note the incident IDs, severity, and foreseeable-misuse classification (`corpus` field) so the risk register entry has traceable evidence rather than a generic risk description.

## Worked example 1: lethal-trifecta finding grounded in incidents

**Scanner finding**: `lethal_trifecta` analyzer flagged CRITICAL — agent has untrusted-input access (MCP endpoint), sensitive-data access (PII store read), and autonomous state-change capability (database write) without a HITL gate. Compound-risk axis: multiple. Applicable roles: provider (Art. 9, 15), deployer (Art. 26).

**Incident grounding**:
```python
from scanner.incident_grounding import incidents_for_threat
incidents = incidents_for_threat("lethal_trifecta", limit=3)
```

Illustrative results drawn from the corpus:

| ID | Title | Year | Corpus | OWASP LLM | MITRE ATLAS | NIST AI RMF |
|---|---|---|---|---|---|---|
| INC-03441 | LLM agent exfiltrates CRM records via prompt injection in support ticket | 2024 | real-world | LLM01, LLM06 | AML.T0051, AML.T0054 | MEASURE-2.7, MANAGE-4.1 |
| INC-04221 | Research: indirect prompt injection in email-reading agent causes unauthorised calendar event creation | 2024 | research-demonstrated | LLM01, LLM02 | AML.T0051 | MAP-5.2, MEASURE-2.7 |
| INC-04853 | Autonomous coding agent modifies production database schema on prompt-injected task | 2025 | research-demonstrated | LLM01, ASI01 | AML.T0051, AML.T0040 | GOVERN-1.2, MANAGE-4.1 |

Published mitigations for this incident class (from `incident.mitigations`):
- Insert a HITL approval gate before any state-change action on sensitive data stores (Art. 14(1) direct requirement for high-risk systems, Art. 15(4) agentic risk control)
- Implement input sanitization and output filtering on all untrusted-input paths feeding the agent (Art. 15(4) prompt-injection resilience)
- Restrict the agent's data-store access to read-only unless an explicit human-approved action is in flight (Art. 15(4) principle of least privilege)
- Log all agent actions with correlation IDs that link the triggering input to the resulting state change (Art. 12(1) automatic event recording)

**Art. 9(2)(b) foreseeable-misuse note**: INC-03441 is a confirmed real-world incident; INC-04221 and INC-04853 are published research demonstrations with reproducible methodology. All three constitute foreseeable misuse for any agentic system with the same architecture. This triplet should appear in the Art. 9 risk register with severity HIGH, with the mitigations above as the required controls.

## Worked example 2: art15 grounded across OWASP LLM and MITRE ATLAS

**Scanner finding**: `security` dimension at 23%. Top gap: no adversarial-robustness testing found; no prompt-injection-defence patterns detected.

**Incident grounding**:
```python
from scanner import incidents_for_article
incidents = incidents_for_article("art15", limit=5)
```

The top `art15` incidents will include a spread across:
- LLM01 (Prompt Injection) mapped to AML.T0051 — direct Art. 15(4) exposure
- LLM03 (Training Data Poisoning) mapped to AML.T0020 — Art. 15(3) data-integrity obligation
- LLM08 (Model Weaknesses) mapped to AML.T0040 (Model Inference API Access)
- NIST AI RMF MEASURE-2.7 (adversarial testing) and MAP-5.2 (attack-surface identification)

Each `incident.mitigations` entry contains a published, enumerated mitigation step. The compliance officer records: "Art. 15(4) gap; foreseeable-misuse evidence from N real-world + M research-demonstrated incidents; mitigations A, B, C identified; implementation status: pending." The engineer takes mitigations A, B, C as the backlog.

## Decision tree

```
User has a scanner gap finding
    |
    +-- Is this an agent-aware finding (lethal_trifecta, agent_inventory,
    |   privilege_minimization, runtime_drift, regulatory_perimeter)?
    |       |
    |       +-- Yes --> incidents_for_threat(<threat_category_from_finding>)
    |                   + incidents_for_dimension("security")
    |                   + cite Art. 9(2)(b) foreseeable misuse
    |
    +-- Is this a specific dimension score (security, human_oversight, etc.)?
    |       |
    |       +-- Yes --> incidents_for_dimension("<dimension_id>")
    |
    +-- Is this an article reference (art9, art15, art72)?
    |       |
    |       +-- Yes --> incidents_for_article("<article_id>")
    |
    +-- Is this a named attack vector (prompt_injection, data_exfiltration, etc.)?
            |
            +-- Yes --> incidents_for_threat("<threat_id>")
```

## Cross-references

- [interpreting-findings](interpreting-findings.md) — gap prioritisation; how scanner scores map to Art. 43 evidence weight
- [eu-ai-act-reference](eu-ai-act-reference.md) — article to dimension mapping; use to confirm which articles a dimension covers
- [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md) — confirm whether the system is high-risk before invoking Art. 9 / 15 / 72 obligations
- [using-eu-ai-act-scanner](using-eu-ai-act-scanner.md) — orchestration; when and how to run the scanner

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "Incident grounding means we're compliant." | No. Incident grounding is evidence *input* to Art. 9 risk management, not a conformity verdict. Art. 43 conformity for high-risk systems requires a documented conformity assessment procedure, not a dataset lookup. |
| "The corpus isn't EU-specific so it doesn't apply to our regulation." | OWASP LLM/ASI Top 10 and MITRE ATLAS are technology-neutral attack taxonomies. Art. 15(4) explicitly requires resilience to prompt injection, adversarial attacks, and data poisoning — the corpus incidents document exactly those attack classes regardless of the jurisdiction in which they occurred. |
| "Research-demonstrated incidents aren't real risk — no one has actually been harmed." | Art. 9(2)(b) requires foreseeable-misuse analysis. A published, reproducible research demonstration of an attack is direct evidence that the attack is feasible and foreseeable. The regulation does not require prior harm; it requires prior foreseeability. |
| "We don't need to track incidents post-deployment — that's a support function." | Art. 72(1) requires a post-market monitoring plan as a provider obligation for high-risk AI systems. Art. 72(3) requires collecting and analysing post-deployment data. Treating this as a support-only function rather than a documented compliance obligation is an Art. 72 gap. |
| "Our system is minimal-risk so Art. 9, 15, and 72 don't apply." | Confirm the risk classification first using [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md). Systems touching biometrics, employment, credit, education, law enforcement, or critical infrastructure are likely high-risk under Annex III regardless of self-assessment. Incident grounding is also best practice for minimal-risk systems; it is a legal obligation for high-risk ones. |
| "The dataset is too large to be useful — 7,000+ incidents is noise." | The scanner uses only the reviewed-quality-tier subset relevant to the 23 compliance dimensions. `incidents_for_finding(finding, limit=3)` returns the three most directly relevant incidents for a specific scanner finding. The volume of the source corpus is a feature, not a liability: it means the curated subset is drawn from a comprehensive aggregation rather than a single source. |
| "We've never been attacked, so there's no incident history for our system." | Art. 9(2)(b) requires consideration of foreseeable misuse, not a record of past attacks against your specific system. The corpus documents attacks against systems with similar architectures, attack surfaces, and deployment contexts. A system that shares architectural characteristics with INC-04853 (autonomous coding agent + database write access) inherits that incident's foreseeable-misuse profile whether or not the specific attack has yet been attempted against it. |

## Data provenance

The incident corpus bundled with this scanner is a curated subset of the **GenAI & Agentic AI Security Incidents** dataset:

- **HuggingFace**: `emmanuelgjr/genai-incidents`
- **License**: Creative Commons Attribution 4.0 International (CC-BY-4.0)
- **Source aggregation**: AIID, OECD AIM, AIAAIC, MITRE ATLAS, AVID, MIT AI Risk Repository, NVD, GHSA, OSV, garak, promptfoo
- **Bundled subset**: reviewed-quality-tier incidents mapped to the scanner's 23 compliance dimensions; offline, no network calls
- **Full dataset access**: `pip install genai-incidents` or `load_dataset("emmanuelgjr/genai-incidents")`
- **`last_synced`**: inspect via `incident_corpus_stats()["last_synced"]`

Attribution when citing the corpus in an Art. 9 risk register or Art. 73 incident report: "Incident data sourced from GenAI & Agentic AI Security Incidents dataset (emmanuelgjr/genai-incidents, HuggingFace, CC-BY-4.0), curated subset used in eu-ai-act-scanner v0.4.0."

## Source of truth

EU Regulation 2024/1689 ("AI Act"), published in the Official Journal of the European Union, 12 July 2024. Incident corpus: GenAI & Agentic AI Security Incidents dataset (emmanuelgjr/genai-incidents), HuggingFace, CC-BY-4.0.
