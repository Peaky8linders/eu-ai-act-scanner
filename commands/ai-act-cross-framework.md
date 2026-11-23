---
name: ai-act-cross-framework
description: "Maps scan results to SOC 2, ISO 27001 and 42001, NIST AI RMF, GDPR and OWASP, and finds single fixes that support several at once."
argument-hint: "[path]"
---

# /ai-act-cross-framework

Show how one EU AI Act scan maps onto the other frameworks customers ask about.

1. With the scanner MCP server, call `project_cross_framework(path="$1")`; otherwise run `uvx --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan "$1" --cross-framework --markdown` (default path: the current folder).
2. Present: evidence coverage per framework with its legal force (SOC 2, ISO/IEC 27002 and 42001, NIST AI RMF, OWASP LLM and Agentic, and the others in the output); GDPR and other binding law as "not assessed" with the related evidence; the top "satisfy once, comply everywhere" fixes, meaning single changes whose evidence supports controls in several frameworks at once, each with the finding behind it (file:line); and where documents can be reused (for example a FRIA alongside a GDPR DPIA).
3. Say plainly that coverage is code evidence, not compliance: auditors, certification bodies and lawyers decide that. Only EN 18286:2026 gives a presumption of conformity (for Art. 17); ISO/IEC 42001 certification does not.
