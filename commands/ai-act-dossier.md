---
name: ai-act-dossier
description: "Creates a tamper-evident compliance record of this release to share with customers or auditors."
argument-hint: "[path] [output.json]"
---

# /ai-act-dossier

Create a tamper-evident record of what this release contains and what the scan found.

1. Run `uvx --native-tls --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan "$1" --dossier compliance-dossier.json` (use the output name the user gave, if any), or call `generate_dossier(path="$1")` with the scanner MCP server.
2. Report the file path, the integrity hash, the git commit, the overall score and the number of files covered.
3. Explain in one or two sentences: the dossier binds SHA-256 digests of the scanned files, the git commit, the scores and gaps, and the legal basis (Reg. 2024/1689 as amended by Reg. 2026/1744) under one hash, so any later change to the code or the file is detectable. It is evidence for an auditor or customer, not a certificate of conformity.
