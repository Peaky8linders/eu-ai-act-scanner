---
name: ai-act-quickstart
description: 60-second founder and startup EU AI Act triage. Explains your operator role in plain English, splits findings into Fix Before Shipping / Enterprise Deals / 2027 Roadmap, surfaces cross-framework quick wins, and offers immediate next actions.
---

# /ai-act-quickstart

Run a 60-second, jargon-free EU AI Act & AI security triage designed for founders, CTOs, and startup engineering teams.

## Arguments

- `$1` (optional) — path to scan. Defaults to the current working directory.
- `--role ROLE` (optional) — override the inferred operator role (`deployer`, `provider`, `gpai_provider`, etc.).

## Behaviour

1. Run the founder triage via the CLI or MCP server:
   - **CLI**:
     ```bash
     eu-ai-act-scan "$1" --founder
     ```
     (Or request structured JSON with `eu-ai-act-scan "$1" --founder --json`.)
   - **MCP tool**: call `founder_triage(path="$1")` if connected to `eu-ai-act-scan-mcp`.
   If `$1` is empty, default to `.`.
2. **Check `is_ai_system` first.**
   - If `is_ai_system` is `false`, print the plain-English headline (`No AI/ML system detected — EU AI Act obligations do not appear to apply to this repository.`) and stop cleanly. Do not invent obligations or compliance scores.
3. Present the founder triage in this exact, scannable order:
   1. **Your Role in Plain English** (`operator_role` + `role_plain_english`) — e.g. whether calling third-party AI APIs makes you a **deployer** (Art. 26/50) versus a **provider** (Art. 3(3)), and what could flip your role under Art. 25(1).
   2. **Bucket 1 — Fix Before Shipping (Live Today)** (`ship_now`):
      - Art. 50 transparency gaps (live since **2 Aug 2026**)
      - MCP tool poisoning / SSRF / unauthenticated servers / hardcoded `.mcp.json` secrets
      - Dangerous `.claude/settings.json` settings (`Bash(*)`, `bypassPermissions`, unsafe hooks)
      - Lethal trifecta, hardcoded secrets, dynamic code execution (`eval`/`exec`/`shell=True`), unbounded agent loops
      - For each item: show **what is wrong**, **effort estimate**, **suggested PR title**, and **file:line**.
   3. **Bucket 2 — Unblocks Enterprise Deals (SOC 2 / GDPR / OWASP)** (`enterprise_deals`):
      - Missing PR security review, unpinned MCP servers / Dockerfiles / CI actions, missing structured audit logging, missing safety/fairness tests, access-control gaps
      - Top 3 **"Satisfy Once, Comply Everywhere"** levers (`top_cross_framework_levers`) showing which single engineering fixes unlock SOC 2, GDPR, OWASP LLM/Agentic, NIST AI RMF, and ISO 42001 simultaneously
      - If `operator_role == "deployer"`, show the **Top 3 Vendor Contract Checklist** items (and mention `playbooks/ai-act-contract-positions.yaml` for `/review-contract`).
   4. **Bucket 3 — Track on Roadmap (2 Dec 2027)** (`later_2027`):
      - Annex III high-risk governance & documentation gaps (Art. 9–11, 14, 17, 27)
      - Explicitly state that **Digital Omnibus (Reg. 2026/1744)** deferred Annex III obligations to **2 Dec 2027** (and Annex I safety-component products to **2 Aug 2028**), and flag whether any high-risk vertical signals were detected.
4. **Offer 5 immediate next actions** and ask which one the user wants to run:
   1. **Fix #1 blocker now** — draft a minimal PR for the top `ship_now` item (via `/ai-act-scan-fix`).
   2. **Copy-paste Customer / Investor Security Brief** — print `brief_markdown` verbatim (<50 lines, ready for security questionnaires, investor memos, or GitHub/Linear issues).
   3. **Install the opt-in secret-guard hook** — copy `hooks/sensitive_data_guard.py` to `.claude/hooks/` and merge the `hooks` object from `hooks/sensitive-data-guard.json` into `.claude/settings.json` to block `.env`/key writes and commits that add credentials.
   4. **Run a diff-aware security review** — run `/ai-act-security-review` on the current branch, or pair with **Claude Code Security** (`https://code.claude.com/docs/en/claude-security`: `claude-security@claude-plugins-official` -> `/threat-model` for `THREAT_MODEL.md` + `/claude-security` / `/security-review`, then ingest locally with `--ingest-claude-security <report>`).
   5. **Attach Claude org audit evidence (Enterprise / Team)** — pull an opt-in local snapshot from Anthropic's **Claude Compliance API** (`anthropic-version: 2026-10-21`, env `ANTHROPIC_COMPLIANCE_ACCESS_KEY`) and ingest it offline:
      ```bash
      python <scanner-clone>/scripts/fetch_claude_compliance.py --dry-run
      python <scanner-clone>/scripts/fetch_claude_compliance.py --output compliance-api-export.json
      eu-ai-act-scan . --ingest-compliance-api compliance-api-export.json --dossier release-dossier.json
      ```
      (`<scanner-clone>` is the folder where you cloned eu-ai-act-scanner; the fetcher is not part of the installed engine.)

## Claude Ecosystem Fast-Track (Optional)

- **Claude Code Security (`https://code.claude.com/docs/en/claude-security`)**: install `claude-security@claude-plugins-official` and `security-guidance@claude-plugins-official`, generate `THREAT_MODEL.md` via `/threat-model`, run `/claude-security` or `/security-review`, and feed the local report into `--ingest-claude-security` (honors the adversarial verification panel and maps confirmed findings to EU AI Act Art. 15(4) & Art. 9(2)).
- **Anthropic Claude Compliance API**: verify Art. 12(1)/26(6) audit trail & >=180-day log retention, Art. 26(2) group governance, Art. 14(1)/50(1) clean user preferences, and Art. 14(4) remote-session approvals from local JSON/JSONL exports — without ever uploading repository code.

## Setup Reminder

Install as a Claude Code plugin + local MCP server from this repository:

```bash
/plugin marketplace add Peaky8linders/eu-ai-act-scanner
/plugin install eu-ai-act-scanner@eu-ai-act-scanner
pip install -e ".[mcp]"
```

## Safety & Local-Only Guarantee

- 100% local static analysis — never sends source code, prompts, or secrets off-machine.
- Never fabricates findings or legal verdicts; static evidence supports human review and conformity assessment (Art. 43).
