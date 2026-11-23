---
name: ai-act-security-review
description: "Security review of the current branch (secrets, MCP and Claude Code settings, prompt injection), optionally merging claude-security, SARIF or Claude Compliance API reports."
argument-hint: "[path] [--base REF] [--ingest-claude-security FILE] [--ingest-sarif FILE] [--ingest-compliance-api FILE]"
---

# /ai-act-security-review

A security review of the current branch that keeps only findings with real, line-level evidence.

1. **Collect evidence**
   - Changed files: `git diff origin/main...HEAD --name-only` (fall back to `main...HEAD` or `git status --short`; use `--base REF` if given).
   - Scanner: `uvx --native-tls --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan "$1" --markdown`, adding any reports the user has: `--ingest-claude-security FILE` (Claude Code Security JSONL, JSON, Markdown or SARIF), `--ingest-sarif FILE` (Semgrep, Bandit, Snyk, CodeQL), `--ingest-compliance-api FILE` (Claude Compliance API export, `anthropic-version: 2026-10-21`). With the scanner MCP server, `ingest_security_reports` does the same.
   - Read each changed file and check for: exposed secrets; prompt injection that can reach tools; MCP tool poisoning, SSRF or unauthenticated servers; `.claude/settings.json` with `Bash(*)` or `bypassPermissions`; `shell=True`, `eval`, or unsafe deserialization (`pickle`, `torch.load`, `yaml.load`); private data plus untrusted input plus an outbound action with no human approval step; unbounded agent loops; unpinned MCP servers, images or CI actions; AI endpoints without auth or timeouts.
2. **Filter false positives** in three passes:
   - **Finder**: list candidates with a severity. Critical: exposed production credentials, unauthenticated remote execution, injection reaching privileged tools, deserialization of untrusted input. High: command injection, `bypassPermissions` / `Bash(*)`, SSRF, unauthenticated AI endpoints, unbounded loops. Medium: unpinned dependencies, missing timeouts, silenced errors, missing audit logs. Low: hardening.
   - **Adversary**: drop anything in tests, fixtures, examples, generated code, migrations or `.env.example`; anything that is a comment, string or detection pattern rather than running code; and anything an upstream check you have read really prevents. List what you dropped under "Cleared false positives".
   - **Referee**: keep a finding only if it sits in shipped code or the developer security boundary (`.claude/`, `.mcp.json`, CI), has a concrete exploit path at a specific file:line, and has a minimal fix.
3. **Report**: a table of counts per severity, then each finding with file:line, its impact in one sentence, the fix, and the EU AI Act link (security issues map to Art. 15(4), missing approval gates to Art. 14). Redact secret values. If nothing survives, say: "Security review passed: no confirmed security findings in this diff."
4. **Go further** (offer, do not run unasked):
   - Claude Code Security (https://code.claude.com/docs/en/claude-security): install `claude-security@claude-plugins-official`, run `/threat-model` to keep a `THREAT_MODEL.md`, then `/claude-security`, and feed `CLAUDE-SECURITY-RESULTS.jsonl` back with `--ingest-claude-security`.
   - Claude Compliance API (Enterprise or Team): run `uv run --native-tls --no-project "${CLAUDE_PLUGIN_ROOT}/scripts/fetch_claude_compliance.py" --output compliance-api-export.json`, then add `--ingest-compliance-api compliance-api-export.json`.
   - CI: `--sarif` writes SARIF 2.1.0 for GitHub Code Scanning; the `anthropics/claude-code-security-review` Action can use `templates/security-scan-instructions.md` and `templates/false-positive-filter.md` from the scanner repo as custom instructions.

Local and defensive only: never run untrusted code or send repository contents anywhere.
