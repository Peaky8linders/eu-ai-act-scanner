---
name: eu-ai-act-incident-grounding
description: "Links scanner gaps to documented real-world AI security incidents (OWASP, MITRE ATLAS, NIST). Use when asked why a gap matters or for evidence of past attacks."
user_invocable: true
---

# Incident Grounding for EU AI Act Findings

Turn a gap ("no prompt-injection defence") into evidence ("here are documented incidents where exactly that gap was exploited, and the mitigations that worked"). Useful to motivate a fix, to fill an Art. 9 risk register, and to show foreseeable misuse under Art. 9(2)(b).

## How to look up incidents

The key can be an area (`security`, `human_oversight`, `logging`, `lethal_trifecta`), an article (`art15`, `Art. 9`) or a threat (`prompt_injection`, `data_exfiltration`, `privilege_escalation`).

- With the scanner MCP server: `incidents(key="security")`. It returns compact entries; add `response_format="detailed"` for full records.
- Otherwise: `uvx --native-tls --python ">=3.14" --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan --incidents security --limit 5` (or `/ai-act-incidents security`).

Pick the key from the finding: an agent finding (lethal trifecta, privilege, runtime drift) maps to its threat, plus `security`; a low area score maps to the area id; an article question maps to the article; a named attack maps to the threat.

## How to present them

1. Run `/ai-act-scan` (or `founder_triage`) first and take the two or three worst gaps.
2. For each gap, show the top incidents: id, title, year, real-world or research, severity, a one-line summary, and the published mitigations. Add OWASP / MITRE ATLAS / NIST codes only if the user wants them.
3. Compare the mitigations with the positive evidence the scan found; the missing ones are the next tasks (`/ai-act-scan-fix` can draft them).
4. For a risk register, record incident ids, severity and whether each is real-world or research, so the entry has traceable evidence.

## Keep in mind

- Grounding is evidence *for* risk management (Art. 9) and conformity work, never a compliance verdict.
- Research demonstrations count: Art. 9(2)(b) asks for foreseeable misuse, not proof of harm.
- Confirm the risk class first ([eu-ai-act-article-6-classification](../eu-ai-act-article-6-classification/SKILL.md)); Art. 9, 15 and 72 bind high-risk systems.
- Cite the source when incidents go into a document: "GenAI & Agentic AI Security Incidents dataset (emmanuelgjr/genai-incidents, HuggingFace, CC-BY-4.0)". The scanner bundles a reviewed offline subset.

For the regulation background (Art. 9, 15, 72, 73), corpus details, the incident record fields, worked examples and rebuttals to common objections, read [reference.md](reference.md).
