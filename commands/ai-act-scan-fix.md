---
name: ai-act-scan-fix
description: "Proposes concrete fixes for the top compliance gaps and shows the plan before changing anything."
argument-hint: "[path] [--top N] [--startup]"
---

# /ai-act-scan-fix

Turn the top compliance gaps into small, reviewable fixes. Always show the plan before editing anything.

1. Scan `$1` (default: the current folder) with the `scan_project` MCP tool or `uvx --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan "$1" --markdown`. To measure progress later, first run `uvx --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan "$1" --save-baseline`. If the project is not an AI system, stop: there is nothing to fix, and writing compliance "evidence" into a non-AI project would be fabricated.
2. Pick the top N gaps (default 3):
   - `--startup` (best for startups): live obligations and exploitable issues first, in this order: Art. 50 transparency, MCP and tool governance, security, Claude Code permissions, supply chain, logging. Annex III paperwork (due 2 Dec 2027) comes last.
   - Default: lowest score weighted by article importance (risk management, data governance, human oversight and logging first).
   If reading the cited code shows a gap is a false positive, skip it and say why.
3. Present one fix at a time as `[i/N] <PR title>` with: what is missing (one plain sentence), the article, where (file:line), a minimal diff, and how a re-scan will confirm it. Ask `apply / skip / edit / quit` before touching files.
4. After each approved fix, apply it, re-scan (`uvx --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan "$1" --diff-baseline` if a baseline exists) and report the score change and any regression. "Apply all" still means one fix at a time with a re-scan in between.

Evidence the scanner accepts, so aim fixes at these:

| Area | Accepted evidence |
|---|---|
| Logging (Art. 12) | `structlog` / `logging.getLogger()` with correlation IDs, or MLflow tracking |
| Human oversight (Art. 14) | an approval gate, confidence threshold or human-in-the-loop step before consequential actions |
| Transparency (Art. 50) | a visible "you are talking to an AI" notice; machine-readable marking (C2PA, watermark) on generated media |
| Security (Art. 15) | auth, rate limiting, and input validation (pydantic, zod, ...) on AI-serving endpoints |
| Tool governance (MCP) | host allowlist, per-tool scopes, pinned server versions in `.mcp.json` |
| Claude Code access | least-privilege `.claude/settings.json` that denies `.env`, keys and destructive shell commands |
| Documentation | `MODEL_CARD.md` / `DATA_CARD.md` with `<FILL IN: ...>` placeholders for facts only the user knows |

If `uvx --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan --settings` shows `mode: assisted`, you may design fixes for gaps without a standard pattern; with `auto_apply: true` you may apply an approved plan without asking per fix. For unattended runs, `antifragile-fix "$1" --profile startup` (a dry run unless `--apply`) loops scan, fix, re-scan, and rolls back any fix that lowers another score.

Never invent facts in compliance documents, never commit without the user's approval, and always ask before touching auth, secrets or database migrations.
