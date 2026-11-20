# EU AI Act Scanner

> Scan any codebase for EU AI Act (Regulation 2024/1689 + Digital Omnibus 2026/1744) compliance evidence and gaps — from Claude Code, any MCP client, or a Python script.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
![Status: alpha](https://img.shields.io/badge/status-alpha-orange)
<!-- countdown-badge -->![Article 50 countdown](https://img.shields.io/badge/Art.%2050%20transparency-in%20force-brightgreen)<!-- /countdown-badge -->

## Startups & Founders: 60-Second Quickstart in Claude Code

Shipping an AI product or agent and need to know **what actually blocks launch today** versus what can wait until **2 December 2027**?

```bash
# 1. Install the Claude Code plugin + local offline engine (from this repo)
/plugin install Peaky8linders/eu-ai-act-scanner
git clone https://github.com/Peaky8linders/eu-ai-act-scanner && cd eu-ai-act-scanner && pip install -e ".[mcp]"

# 2. Run the 60-second plain-English triage in Claude Code
/ai-act-quickstart ./my-app
# (or from your terminal: eu-ai-act-scan ./my-app --founder)

# 3. Preview and fix live blockers first (Art. 50 + MCP / Claude Code / security)
eu-ai-act-scan ./my-app --fix --startup
```

`/ai-act-quickstart` (`--founder`) translates technical scan output into three jargon-free buckets — plus a <50-line copy-pasteable brief for customer security questionnaires and investor memos:

1. **Ship Now (Live Today)** — **Art. 50 transparency** (in force since 2 Aug 2026), MCP tool poisoning / SSRF / unauthenticated servers / hardcoded `.mcp.json` secrets, dangerous `.claude/settings.json` (`Bash(*)`, `bypassPermissions`), lethal trifecta, hardcoded credentials, and unbounded agent loops.
2. **Enterprise Deals (Unblock SOC 2 / GDPR / OWASP)** — missing PR security review, unpinned supply chains, structured audit logging, safety/bias tests, top 3 **"Satisfy Once, Comply Everywhere"** levers, and a **Deployer Vendor-Contract Checklist**.
3. **Later 2027 (Roadmap)** — Annex III high-risk governance & documentation deferred to **2 December 2027** by **Digital Omnibus (Regulation (EU) 2026/1744)** (and Annex I safety-component products to **2 August 2028**).

---

**One repo, three ways to run it:**
1. A **Claude Code plugin** — **11 slash commands** (`/ai-act-quickstart`, `/ai-act-scan`, `/ai-act-security-review`, `/ai-act-scan-fix`, `/ai-act-article`, `/ai-act-incidents`, `/ai-act-ask`, `/ai-act-graph`, `/ai-act-cross-framework`, `/ai-act-dossier`, `/ai-act-settings`) backed by **16 article-grounded skills**. Semantic depth comes from **your own Claude Code session** — your existing subscription, no API key, no wrapper.
2. A **Python library & CLI** (`from scanner import scan_project` / `eu-ai-act-scan`) — **24 deterministic analyzers** (including `mcp_toolchain`, `claude_code_security`, and AST-gated Art. 50 transparency), operator-role inference, incident grounding, offline SARIF 2.1.0, local baselines, autonomous startup/regulatory fix loop, deterministic precision/recall/F1 meta-benchmark, and a **versioned 12-framework projection** (including OJ-cited **EN 18286:2026** CEN/CENELEC JTC 21 QMS).
3. An **MCP server** (`eu-ai-act-scan-mcp`) — **17 hardened MCP tools** over stdio (or behind your own authenticated Streamable HTTP proxy), with validated paths, symlink/traversal guards, `openWorldHint=False`, destructive-action annotations, and stdout hygiene.

Every finding is **grounded twice**: in the regulation text (article + paragraph citations, EUR-Lex verbatim) and in **real-world incidents** — a vendored, reviewed-tier subset of the open [GenAI & Agentic AI Security Incidents dataset](https://huggingface.co/datasets/emmanuelgjr/genai-incidents) (CC-BY-4.0, mapped to OWASP LLM Top 10 2025, OWASP Agentic Top 10, NIST AI RMF, MITRE ATLAS). A gap stops being "you have no prompt-injection defence" and becomes "…and here are the documented incidents where exactly that gap was exploited, with the published mitigations."

---

## Works With Claude Code Security & Claude Compliance API

The core scanner is **100% offline** — zero network calls, zero telemetry — and plugs cleanly into Anthropic's Claude security/compliance ecosystem and standard AppSec tooling:

- **Claude Code Security ([`code.claude.com/docs/en/claude-security`](https://code.claude.com/docs/en/claude-security))**:
  - Pairs directly with Anthropic's official **`claude-security@claude-plugins-official`** (`/claude-security`, `/threat-model` → `THREAT_MODEL.md`, `/security-review`) and **`security-guidance@claude-plugins-official`**.
  - Audits `.claude/settings.json` for least-privilege permissions (`permissions.allow` / `permissions.deny`, `enableAllProjectMcpServers`, hooks, OpenTelemetry) and ships an opt-in pre-tool secret blocker at [`hooks/sensitive-data-guard.json`](hooks/sensitive-data-guard.json).
  - Run `/ai-act-security-review` or pass local JSON / Markdown / SARIF reports into `--ingest-claude-security <report>` (or MCP tool `ingest_claude_ecosystem`). Automatically **honors Claude Security's adversarial verification panel** (filtering mitigated/refuted/false-positive items) and maps confirmed issues to **EU AI Act Art. 15(4) & Art. 9(2)**.
- **Anthropic Claude Compliance API (Opt-In Offline Ingestion)**:
  - Enterprise and Team deployers can pull a local, read-only org snapshot via [`scripts/fetch_claude_compliance.py`](scripts/fetch_claude_compliance.py) (`anthropic-version: 2026-10-21`, env `ANTHROPIC_COMPLIANCE_ACCESS_KEY`) covering `/v1/compliance/activities`, `/v1/compliance/groups`, `/v1/compliance/organizations/{org_uuid}/user_preferences`, and `/v1/compliance/apps/sessions/remote/{id}/messages`.
  - Feed the local export into `--ingest-compliance-api compliance-api-export.json` (or MCP `ingest_claude_ecosystem`) to verify **Art. 12(1) / Art. 26(6) ≥180-day audit retention**, **Art. 26(2) group governance**, clean *Instructions for Claude* / *Cowork Global instructions* (**Art. 14(1) / Art. 50(1)**), and **Art. 14(4)** remote-session approvals — while keeping the scanner engine strictly offline.
- **SARIF 2.1.0 & Anthropic Legal Plugin Interop**:
  - **Two-way SARIF 2.1.0**: export offline SARIF (`--sarif eu-ai-act.sarif.json` / MCP `export_sarif`) to GitHub Code Scanning or VS Code, and ingest local SARIF (`--ingest-sarif semgrep.sarif` / MCP `ingest_sarif`) from **Semgrep, Bandit, Snyk, CodeQL, or GHAS** into EU AI Act Art. 15(4) scores and cryptographic release dossiers.
  - **Contract Review Playbook**: drop [`playbooks/ai-act-contract-positions.yaml`](playbooks/ai-act-contract-positions.yaml) into Anthropic's Legal Plugin (`/review-contract`) to check Art. 25(1) silent provider flips, Art. 26(6) 6-month audit logs, and Art. 73 incident notice clauses.

---

## ⏳ Enforcement countdown

The EU AI Act applies in waves. The **Digital Omnibus (Regulation 2026/1744, in force 27 July 2026)** deferred high-risk obligations — but deliberately **left Article 50 transparency untouched**, making it the sharpest live deadline.

<!-- countdown-table:start -->
| Milestone | Articles | Date | Status |
|---|---|---|---|
| Prohibited practices | Art. 5 | 2 Feb 2025 | ✅ in force |
| GPAI model obligations | Art. 53 / 55 | 2 Aug 2025 | ✅ in force |
| **Transparency** | Art. 50 | 2 Aug 2026 | ✅ in force |
| New prohibitions (NCII/CSAM) | Art. 5(1)(ba)/(bb) | 2 Dec 2026 | ⏳ T-44 days |
| High-risk (Annex III) | Art. 9-15 / 17 / 27 | 2 Dec 2027 | ⏳ T-409 days |

_Countdown generated 2026-10-19 by `scripts/update_readme_countdown.py` (refreshed weekly in CI). The Digital Omnibus deferred high-risk to Dec 2027 but left Article 50 at 2 Aug 2026._
<!-- countdown-table:end -->

**Run this to see where you stand:**

```python
from scanner import scan_project

result = scan_project("./my-ai-project")
if not result.is_ai_system:
    print(result.scope_note)  # not an AI system — out of scope, no score
else:
    print(f"Overall compliance score: {result.overall_compliance_pct}%")
    print("Worst-scoring dimensions (fix these first):")
    for dim_id, score in sorted(result.compliance_scores.items(), key=lambda x: x[1])[:5]:
        print(f"  [{score:>3}%] {dim_id}")
```

Or the one-line Claude Code versions:

```
/ai-act-quickstart ./my-app
/ai-act-scan ./my-app
```

---

## Why this scanner, not another checker

- **Versioned 12-framework projection, not label soup.** A pinned crosswalk catalogue maps **every** EU AI Act dimension and article across **12 frameworks** — NIST AI RMF 1.0, ISO/IEC 42001:2023, **CEN/CENELEC JTC 21 EN 18286:2026** (harmonised AI QMS standard, OJ-cited), OWASP LLM 2025, OWASP Agentic Top 10, GDPR, MITRE ATLAS, SOC 2, ISO 27002, NIST SP 800-53, CSA AICM, and EU Digital Omnibus alignment — with per-control status, readiness %, and **"Satisfy Once, Comply Everywhere" levers** showing which single fix closes gaps across the most frameworks. Control IDs are the published ones (no invented identifiers), and **every gap control names the real-world incidents that exploited its class**.
- **Evidence-linked, calibrated findings.** Every finding carries file, line number, article, confidence, and severity — and the scanner distinguishes code fact from inference. Scores are evidence measures, never compliance verdicts.
- **Incident-grounded gaps.** Each gap links to documented real-world incidents (OWASP/MITRE/NIST IDs + mitigations) — evidence input for Art. 9 risk management and Art. 72 post-market monitoring.
- **Role-aware obligations & Digital Omnibus applicability.** Deterministic provider / deployer / GPAI-provider inference scopes which articles *you* actually owe, backed by `regulatory_applicability` for exact as-of dates under Regulation (EU) 2026/1744.
- **Local-first, offline by default.** Pure static analysis, no network, no telemetry. Semantic review happens in *your* Claude Code session or MCP client — never a headless credential wrapper.
- **Closed loop with a regression guard & local baselines.** `eu-ai-act-fix` (`--fix --startup` or regulatory profile) proposes deterministic fixes, applies them, re-scans, and **reverts anything that regresses any dimension**. Track progress per PR with `--save-baseline` / `--diff-baseline`.

---

## What the scanner looks at

**24 analyzers**, all deterministic static analysis:

- **Baseline (14):** AI frameworks · data pipeline · human oversight (Art. 14) · security controls (with line numbers) · fairness testing · test suite · logging/monitoring (Art. 12) · documentation · configuration · agent cascade · adversarial robustness (Art. 15) · Terraform · CloudFormation/K8s (with test-fixture exclusion) · CI/Dockerfile.
- **Agent-aware (7)** — grounded in Nannini et al. (2026), *AI Agents under EU Law*: agent inventory · privilege minimization · runtime drift (Art. 3(23)) · regulatory perimeter (GDPR/Data Act/CRA/MDR/NIS2 adjacency) · lethal-trifecta (AEPD rule-of-2) · model typology · cloud deployment.
- **Agentic Supply Chain & Claude Code DevSecOps (2):** **`mcp_toolchain`** (MCP tool poisoning, SSRF, unpinned `npx -y`/`uvx`, hardcoded `.mcp.json` secrets, unauthenticated remote servers) · **`claude_code_security`** (`.claude/settings.json` least-privilege permissions, `enableAllProjectMcpServers`, unsafe hooks, `claude-security@claude-plugins-official` & PR review workflows).
- **Transparency (1):** **AST-gated Article 50** — chatbot disclosure (50(1)), executable synthetic-content C2PA/watermark marking (50(2), immune to disabled literals and roadmap comments), emotion/biometric notice (50(3)), deep-fake labelling (50(4)). In force since 2 August 2026.

Findings aggregate into **23 compliance dimensions** (`scanner/kb.py`), auto-tagged with compound-risk axis and operator roles. Run `eu-ai-act-scan --benchmark` to verify analyzer precision/recall/F1 deterministically offline.

---

## Semantic depth: your subscription, two paths

The scanner never calls an LLM headlessly. When you want more than deterministic scores:

- **In Claude Code (assisted mode):** `python -m scanner.cli --set mode=assisted` — slash commands use your host session (your existing subscription, no API key) for semantic review, grounded Q&A, and applying fixes. The deterministic scores stay the objective baseline.
- **Outside Claude Code:** run the **MCP server** (`eu-ai-act-scan-mcp`, installed from this repository — see [Install](#install)) from any MCP client — same engine, client's own model, no wrapper.

---

## Install

**Claude Code plugin** — the 11 commands and 16 article-grounded skills:

```bash
/plugin install Peaky8linders/eu-ai-act-scanner
```

The plugin drives the local Python engine, so install the engine once from this
repository:

```bash
git clone https://github.com/Peaky8linders/eu-ai-act-scanner
cd eu-ai-act-scanner
pip install -e ".[mcp]"
```

**MCP server** — same engine, any MCP client, the client's own model:

```bash
eu-ai-act-scan-mcp          # stdio transport
```

> **There is no PyPI package.** `pip install eu-ai-act-scanner` installs an
> unrelated third-party project that owns that name — always install from this
> repository. The package installed from this repository is
> `eu-ai-act-scanner-plugin`, and the console scripts are `eu-ai-act-scan`,
> `eu-ai-act-scan-mcp` and `eu-ai-act-fix`.

Register with any MCP client via [`.mcp.json`](.mcp.json):

```json
{ "mcpServers": { "eu-ai-act-scanner": { "command": "eu-ai-act-scan-mcp", "args": [] } } }
```

**17 MCP Tools:** `scan_project`, `founder_triage`, `export_sarif`, `ingest_sarif`, `ingest_claude_ecosystem`, `regulatory_applicability`, `project_cross_framework`, `generate_dossier`, `remediation_loop`, `generate_visual_graph`, `list_dimensions`, `get_article`, `incidents_for_dimension`, `incidents_for_threat`, `incidents_for_article`, `incident_corpus_stats`, `agentic_taxonomy`.

`scan_project` also returns `agentic_recommendations`: the compound-risk taxonomy mitigations and evidence for the agentic risk axes the scan detected, each tagged `act_required` (with the EU AI Act provision) or `paper_suggested` (with the paper line). `agentic_taxonomy` browses that catalogue directly, optionally filtered to one risk axis.

---

## Usage

**Claude Code:** `/ai-act-quickstart ./my-app` · `/ai-act-scan ./my-app` · `/ai-act-security-review` · `/ai-act-scan-fix --startup --top 3` · `/ai-act-article art50` · `/ai-act-incidents art15` · `/ai-act-ask "…"` · `/ai-act-graph` · `/ai-act-cross-framework` · `/ai-act-dossier` · `/ai-act-settings`

**Python:**

```python
from scanner import scan_project, incidents_for_article, run_fix_loop

result = scan_project("./my-app", cross_framework=True)
for inc in incidents_for_article("art15", limit=3):
    print(inc.id, inc.title)

fix = run_fix_loop("./my-app", apply=False, profile="startup")  # dry-run plan; --apply to write
```

**CLI:** `eu-ai-act-scan ./my-app --founder` · `--markdown` · `--article art50` · `--cross-framework` · `--sarif [FILE]` · `--ingest-sarif FILE` · `--ingest-compliance-api FILE` · `--ingest-claude-security FILE` · `--save-baseline [FILE]` · `--diff-baseline [FILE]` · `--fix [--startup] [--apply]` · `--benchmark` · `--incidents art15` · `--ask "…"` · `--dossier` · `--graph` · `--settings` / `--set mode=assisted`

---

## What the output means

- **0–29%**: clear gap · **30–59%**: partial, material gaps · **60–79%**: evidence present, needs docs · **80–100%**: broad evidence, still needs human verification.
- **Always check `is_ai_system` first.** Non-AI codebases are out of scope: no scores, just a `scope_note`.
- **Scores are not compliance verdicts.** Compliance is a legal determination (Art. 43 conformity assessment for high-risk). This is the static-analysis evidence layer underneath it.

## What it does NOT do

- **No LLM calls, no network, no telemetry.** Offline by default; only opt-in scripts (`scripts/fetch_claude_compliance.py` for Enterprise/Team users and `scripts/sync_incident_corpus.py` for maintainers) touch the network.
- **No risk-tier classification for you.** High-risk vs limited-risk (Art. 6 + Annex III) needs human judgment.
- **No legal advice.** Use alongside counsel, not instead of it.

## Contributing

Contributions are the point — new analyzer patterns, new analyzers, KB updates, fixtures. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

## Acknowledgements

Extracted from [CodexAI](https://antifragile-ai.net). Incident grounding built on the **GenAI & Agentic AI Security Incidents** dataset by Emmanuel G. (`emmanuelgjr/genai-incidents`, CC-BY-4.0).
