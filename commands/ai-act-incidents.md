---
name: ai-act-incidents
description: "Shows documented real-world AI security incidents for a risk area, an article or a threat type."
argument-hint: "<security | art15 | prompt_injection> [--limit N]"
---

# /ai-act-incidents

Show documented incidents that make a gap concrete: what went wrong elsewhere, and what fixed it.

1. Look up `$1`, which can be an area (`security`, `human_oversight`, `logging`, `lethal_trifecta`), an article (`art15`, `Art. 9`) or a threat (`prompt_injection`, `data_exfiltration`, `privilege_escalation`). With the scanner MCP server, call `incidents(key="$1")`; otherwise run `uvx --native-tls --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan --incidents "$1" --limit 5`.
2. If nothing matches, say so, show the accepted examples above, and ask which one was meant. Do not guess.
3. For each incident give: id and title (year), real-world or research, severity, a one-sentence description, the published mitigations, and why it matters under the EU AI Act (prompt injection and data poisoning fall under Art. 15(4); documented incidents count as foreseeable misuse for Art. 9(2)(b) risk analysis). Mention OWASP / MITRE ATLAS codes only if the user wants them.
4. Offer next steps: look up a related area or threat, or turn the mitigations into fixes with `/ai-act-scan-fix`.

Source: a reviewed offline subset of the GenAI & Agentic AI Security Incidents dataset (emmanuelgjr/genai-incidents, CC-BY-4.0). Nothing leaves the machine.
