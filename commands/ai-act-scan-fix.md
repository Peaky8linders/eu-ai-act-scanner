---
name: ai-act-scan-fix
description: Scan a codebase, then propose concrete remediation (code edits, new files, tests) for the top compliance gaps. Does NOT auto-apply — always shows the plan first.
---

# /ai-act-scan-fix

Run `/ai-act-scan`, then build a remediation plan for the top compliance gaps.

## Arguments

- `$1` (optional) — path to scan. Defaults to the current directory.
- `--top N` (default 3) — number of gaps to remediate.
- `--startup` — prioritize live startup ship-blockers first (**Art. 50 transparency** in force since 2 Aug 2026 + **MCP toolchain**, **Claude Code security**, and **Art. 15 cybersecurity** gaps) ahead of Annex III high-risk governance docs deferred to **2 Dec 2027** under Digital Omnibus (Reg. 2026/1744). Mirrors `python -m scanner.cli "$1" --fix --startup` / `eu-ai-act-fix --profile startup`.
- `--save-baseline [PATH]` / `--diff-baseline [PATH]` — snapshot before fixing and diff scores/gaps after each PR (`default: .eu-ai-act-baseline.json`).

> **New to EU AI Act compliance?** Run `/ai-act-quickstart` first for a 60-second plain-English triage (`Ship Now` / `Enterprise Deals` / `Later 2027`). For diff-aware vulnerability checks paired with `claude-security@claude-plugins-official` (`/claude-security` / `/threat-model`), run `/ai-act-security-review`.

## Behaviour

1. Invoke the scanner as in `/ai-act-scan` (optionally snapshot a baseline first with `--save-baseline`). **If the result has `is_ai_system: false`,
   stop**: the project is not an AI system (EU AI Act Art. 3(1)), so there is nothing
   to remediate. Surface `scope_note` and do not propose any fixes — writing
   compliance "evidence" into a non-AI project fabricates a story the Regulation
   does not ask for. (The `eu-ai-act-fix` CLI enforces this automatically: it
   short-circuits and writes nothing.)
2. Select the top `N` gap findings:
   - **Startup profile (`--startup`)**: prioritize live obligations & active exploit vectors first — `content_transparency` / `transparency` (Art. 50, live 2 Aug 2026) → `tool_governance` (MCP policy/allowlist) → `security` (Art. 15) → `access_control` (`.claude/settings.json` least privilege) → `supply_chain` → `logging` (Art. 12) → Annex III governance docs (deferred to 2 Dec 2027).
   - **Regulatory profile (default)**: rank by `(low score × article weight)`. Prioritisation order when scores are tied:
     1. `risk_mgmt` (Art. 9) — foundational, blocks conformity assessment
     2. `data_gov` (Art. 10) — training-data provenance affects all downstream
     3. `human_oversight` (Art. 14) — hard legal requirement for high-risk
     4. `logging` (Art. 12) — auditability
     5. Everything else
3. **Interactive `[1/N]` guided PR fix walkthrough** — present proposals one at a time in `[i/N]` format so the engineer can review each fix as a clean, reviewable PR:
   - **Header**: `[i/N] <Suggested PR Title>` (with effort estimate and bucket: `Ship Now` / `Enterprise Deals` / `Later 2027`)
   - **What**: one-sentence plain-English description of the missing control
   - **Article**: the obligation driving the fix (e.g. `Art. 50(1)`, `Art. 15(4)`, `Art. 14(1)`)
   - **Where**: exact file path(s) and line numbers to create or edit
   - **Minimal diff**: concrete code / YAML / JSON / markdown snippet
   - **Verification**: how the scanner (and `/ai-act-security-review` if applicable) verifies the fix on a re-scan
   - **Prompt**: ask `[a]pply / [s]kip / [e]dit / [q]uit` before touching disk
4. **Show the plan. Do NOT apply edits yet.** For each approved `[i/N]` proposal:
   - Apply the proposal cleanly
   - Re-run the scanner (or `python -m scanner.cli "$1" --diff-baseline`) immediately after each fix
   - Report the exact score delta per dimension and verify zero regressions
5. If the user says "apply all", still apply serially and re-scan between fixes so regressions are caught early.

## Remediation pattern library

When proposing fixes, lean on these canonical patterns — they are what the scanner's analyzers are looking for:

| Gap dimension | Minimal evidence the scanner will accept |
|---|---|
| `logging` | `structlog` or `logging.getLogger()` with correlation IDs, OR MLflow run tracking |
| `human_oversight` | A function/decorator named `human_review`, `approval_gate`, `confidence_threshold`, or `human_in_the_loop` |
| `tech_docs` | A `README.md` with ≥5 sections covering purpose, data, risks, monitoring, and contacts; or a `MODEL_CARD.md` |
| `test_suite` | A `tests/` directory with pytest files covering model behaviour (not just unit tests on utils) |
| `data_gov` | A `DATA_CARD.md` or `docs/data/` describing sources, collection, bias assessment |
| `security_controls` | Auth middleware, rate limiting, input validation on any AI-serving endpoint |
| `tool_governance` (MCP) | Execution-layer host allowlist (`validate_url`), explicit `@require_scope` tool registry, and pinned versions in `.mcp.json` |
| `access_control` (Claude Code Security) | Least-privilege `.claude/settings.json` (`permissions.deny` for `.env`/keys/destructive shell), `claude-security@claude-plugins-official`, and PR security review workflow |
| `fairness_testing` | Tests that import `aif360`, `fairlearn`, or compute disparate-impact metrics |
| `transparency` / `content_transparency` (Art. 50) | An AI-interaction disclosure string ("you are chatting with an AI"), an executable C2PA / watermark / SynthID marking call on generated output (disabled literals and roadmap comments do not count), an emotion/biometric exposure notice, or a visible "AI-generated" deep-fake label |

## Autonomous loop (`eu-ai-act-fix` / `--fix --startup`)

This command is the **human-in-the-loop** remediation flow. For unattended use there is a
programmatic counterpart, `eu-ai-act-fix` (or `python -m scanner.cli "$1" --fix --startup`) / `scanner.fix_loop.run_fix_loop(..., profile="startup")`, which
runs the same scan → propose → apply → **re-scan** → revert-on-regression → repeat cycle to
convergence. It defaults to a safe dry-run; `--apply` is required to write. Its deterministic
fixers are validated against the analyzers' own positive-detection patterns, and a
**regression guard** reverts any fix that lowers another dimension's score. Reach for it when
you want the loop to drive itself (e.g. CI, batch remediation); use this command when a human
should approve each `[1/N]` change.

## Assisted mode & auto-apply (use your own Claude Code power)

Check the mode + auto-apply flag: `python -m scanner.cli --settings`.

- **deterministic** (default) — behave exactly as above: propose, show the plan,
  apply only what the user approves.
- **assisted** — go beyond the deterministic fixers: for a gap with no canonical
  pattern, design a real, minimal fix yourself (you are the user's own Claude
  Code), read the surrounding code, and write it with your edit tools. Ground
  every regulatory claim with `/ai-act-ask`. Still show the plan first unless
  `auto_apply` is `true`.
- **assisted + `auto_apply: true`** — apply the approved plan directly with your
  own edit tools, re-running `python -m scanner.cli "$1" --json` after each change
  to confirm the dimension score moved and nothing regressed.

No API key or wrapper is needed for assisted mode — the command runs inside your
Claude Code (your existing subscription), so your session **is** the LLM. Outside
Claude Code, use the MCP server (`eu-ai-act-scan-mcp`) from any MCP client.

## Safety notes

- Never fabricate claims. If proposing a `MODEL_CARD.md`, leave content the user must fill in as `<FILL IN: …>` placeholders. Compliance documents with invented facts are worse than none.
- Never commit without explicit user approval. Compliance code changes can touch regulatory obligations — the human stays in the loop.
- Even with `auto_apply: true`, never modify auth, secrets, or database migrations without an explicit extra confirmation.
