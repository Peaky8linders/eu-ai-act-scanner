---
name: ai-act-incidents
description: Show real-world and research-demonstrated security incidents that map to a scanner dimension, EU AI Act article, or threat category. Surfaces OWASP LLM/ASI, NIST AI RMF, and MITRE ATLAS cross-references alongside published mitigations.
---

# /ai-act-incidents

Ground scanner gaps in documented incident history. Returns real-world and research-demonstrated incidents that map to the requested dimension, article, or threat category, with cross-framework taxonomy mappings (OWASP LLM Top 10 2025, OWASP Agentic AI Top 10, NIST AI RMF, MITRE ATLAS) and published mitigations.

## Arguments

- `$1` (required) — lookup key. Three accepted forms:
  - **Dimension id** — e.g. `security`, `risk_mgmt`, `human_oversight`, `logging`, `lethal_trifecta`
  - **Article id** — e.g. `art9`, `art15`, `art72`. Accepts the same normalisation as `/ai-act-article`: `art9`, `Art. 9`, `9`, `ART9`.
  - **Threat-category id** — e.g. `prompt_injection`, `data_exfiltration`, `model_inversion`, `privilege_escalation`
- `--limit N` (optional) — number of incidents to return. Defaults to 5.
- `--real-world-only` (optional) — restrict to `corpus="real-world"` incidents (excludes research-demonstrated).

## Behaviour

1. Normalise `$1` to determine lookup type (dimension / article / threat).
2. Call the appropriate corpus API:
   ```python
   from scanner import incidents_for_dimension, incidents_for_article
   from scanner.incident_grounding import incidents_for_threat

   # dimension
   incidents = incidents_for_dimension("security", limit=5)

   # article
   incidents = incidents_for_article("art15", limit=5)

   # threat
   incidents = incidents_for_threat("prompt_injection", limit=5)
   ```
3. Present results in this structure:

   ```
   # Incidents for: security (Art. 15 — accuracy, robustness, cybersecurity)

   Dataset: GenAI & Agentic AI Security Incidents (emmanuelgjr/genai-incidents, CC-BY-4.0)
   Showing 5 of N matching reviewed incidents.

   ## INC-03441 — LLM agent exfiltrates CRM records via prompt injection (2024)
   Corpus: real-world | Severity: critical
   OWASP LLM: LLM01, LLM06 | OWASP ASI: ASI01
   MITRE ATLAS: AML.T0051 (LLM Prompt Injection), AML.T0054 (LLM Jailbreak)
   NIST AI RMF: MEASURE-2.7, MANAGE-4.1
   
   Description: [one-sentence summary from incident.description]
   
   Mitigations:
   - Insert a HITL gate before write actions on sensitive data stores
   - Sanitize and validate all inputs from untrusted channels before passing to the LLM
   - Apply output filtering to detect and block exfiltration patterns

   EU AI Act relevance:
   - Art. 15(4): prompt-injection resilience is an explicit cybersecurity obligation
   - Art. 9(2)(b): this incident class constitutes foreseeable misuse for any agent with
     external-input access and data-store read capability
   ```

4. After presenting incidents, offer to:
   - Run `/ai-act-incidents` for a related dimension or threat
   - Ground a specific scanner `Finding` object using `incidents_for_finding(finding, limit=3)`
   - Proceed to `/ai-act-scan-fix` to generate remediation tasks from the mitigations

5. If `$1` is not recognised as a dimension, article, or threat id, list the accepted dimension ids and threat ids and ask the user to confirm. Do not guess.

## Composing with other commands

**After `/ai-act-scan`**: use `/ai-act-incidents` on the worst-scoring dimensions to turn abstract gaps into documented failure history.

```
/ai-act-scan ./my-agent
# result: security 23%, human_oversight 31%, risk_mgmt 28%

/ai-act-incidents security
/ai-act-incidents human_oversight
```

**After `/ai-act-article`**: if `/ai-act-article art15` surfaces gaps, `/ai-act-incidents art15` provides the incident evidence for those gaps.

**Before `/ai-act-scan-fix`**: the mitigations in each incident's `mitigations` field are the concrete fix targets. Feed them to `/ai-act-scan-fix` as the backlog source rather than relying on scanner-generated recommendations alone.

## Regulatory context

- **Art. 9(2)(b)** — foreseeable-misuse analysis. Documented incidents (both real-world and research-demonstrated) constitute foreseeable misuse for architecturally similar systems.
- **Art. 15(4)** — explicit cybersecurity obligation covering prompt injection, adversarial attacks, and data poisoning. OWASP LLM01 and MITRE ATLAS AML.T0051 map directly to this paragraph.
- **Art. 72** — post-market monitoring plan. The incident corpus is a reference source for what constitutes a material post-deployment incident in the GenAI domain.

## Notes

- The scanner bundles a reviewed-quality-tier curated subset offline — no network calls, no code leaves the machine.
- Full dataset: `pip install genai-incidents` or `load_dataset("emmanuelgjr/genai-incidents")`.
- `incident_corpus_stats()` returns `{count, version, source, last_synced, taxonomy_coverage}` for provenance records.
