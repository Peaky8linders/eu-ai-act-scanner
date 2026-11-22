---
name: ai-act-quickstart
description: "Start here. A 60-second plain-English EU AI Act check for founders covering your role, what to fix before launch, what unblocks enterprise deals, and what can wait."
argument-hint: "[path] [--role deployer|provider]"
---

# /ai-act-quickstart

A 60-second, jargon-free EU AI Act and AI-security check for founders.

1. Get the founder triage for `$1` (default: the current folder). If the scanner MCP server is connected, call `founder_triage(path="$1")`; its default concise response is the ready-made brief. Otherwise run `eu-ai-act-scan "$1" --founder` (add `--role provider` or similar if the user names their role).
2. If it says no AI system was detected, say that EU AI Act obligations do not appear to apply and stop. Do not invent obligations or scores.
3. Otherwise present the brief in plain language, in this order:
   1. **Your role** and what would change it.
   2. **Fix before shipping**: live today (Art. 50 transparency since 2 Aug 2026, exposed secrets, dangerous MCP or Claude Code settings, prompt-injection paths). For each: what is wrong, where (file:line), effort.
   3. **Unblocks enterprise deals** (SOC 2 / GDPR / OWASP) and the top "satisfy once, comply everywhere" fixes; for deployers, the vendor-contract checklist.
   4. **Roadmap**: high-risk (Annex III) duties apply from 2 Dec 2027 under the Digital Omnibus (Reg. 2026/1744), Annex I products from 2 Aug 2028.
   Keep it short and avoid article numbers unless the user asks.
4. Offer next steps and ask which to run:
   1. Fix the top blocker now (`/ai-act-scan-fix --startup`).
   2. Print the copy-paste security brief for questionnaires or investors.
   3. Review this branch for security issues (`/ai-act-security-review`). For a deeper pass, use Claude Code Security (https://code.claude.com/docs/en/claude-security): install `claude-security@claude-plugins-official`, run `/threat-model` (writes `THREAT_MODEL.md`) and `/claude-security`, then add its report with `--ingest-claude-security <file>`.
   4. Block secrets from being written or committed: copy `hooks/sensitive_data_guard.py` and the `hooks` block of `hooks/sensitive-data-guard.json` from the scanner repo into this project's `.claude/`.
   5. Claude Enterprise or Team: add org audit evidence from the Claude Compliance API (`anthropic-version: 2026-10-21`, key in `ANTHROPIC_COMPLIANCE_ACCESS_KEY`). Run `python <scanner-clone>/scripts/fetch_claude_compliance.py --output compliance-api-export.json` (`<scanner-clone>` is where you cloned eu-ai-act-scanner), then `eu-ai-act-scan . --ingest-compliance-api compliance-api-export.json`.

The scan is local static analysis: no code leaves the machine, and results are evidence for human review, not a legal verdict.
