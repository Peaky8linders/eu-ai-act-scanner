# EU AI Act Scanner

> Scan any codebase for EU AI Act (Regulation 2024/1689 + Digital Omnibus 2026/1744) compliance evidence and gaps — from Claude Code, any MCP client, or a Python script.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
![Status: alpha](https://img.shields.io/badge/status-alpha-orange)
<!-- countdown-badge -->![Article 50 countdown](https://img.shields.io/badge/Art.%2050%20transparency-in%20force-brightgreen)<!-- /countdown-badge -->

**One repo, three ways to run it:**
1. A **Claude Code plugin** — `/ai-act-scan`, `/ai-act-scan-fix`, `/ai-act-article`, `/ai-act-incidents`, `/ai-act-ask`, `/ai-act-graph`, `/ai-act-cross-framework`, `/ai-act-dossier`, `/ai-act-settings`, backed by **14 article-grounded skills**. Semantic depth comes from **your own Claude Code session** — your existing subscription, no API key, no wrapper.
2. A **Python library** (`from scanner import scan_project`) — **22 deterministic analyzers**, operator-role inference, incident grounding, autonomous fix loop, and a **versioned cross-framework projection** (NIST AI RMF, ISO 42001, OWASP LLM/Agentic, GDPR, MITRE ATLAS, SOC 2, CSA AICM).
3. An **MCP server** (`eu-ai-act-scan-mcp`) — the same engine over the Model Context Protocol for any MCP-capable agent, hardened per the latest MCP spec (validated inputs, destructive-action annotations, stdout hygiene).

Every finding is **grounded twice**: in the regulation text (article + paragraph citations, EUR-Lex verbatim) and in **real-world incidents** — a vendored, reviewed-tier subset of the open [GenAI & Agentic AI Security Incidents dataset](https://huggingface.co/datasets/emmanuelgjr/genai-incidents) (CC-BY-4.0, mapped to OWASP LLM Top 10 2025, OWASP Agentic Top 10, NIST AI RMF, MITRE ATLAS). A gap stops being "you have no prompt-injection defence" and becomes "…and here are the documented incidents where exactly that gap was exploited, with the published mitigations."

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

Or the one-line Claude Code version:

```
/ai-act-scan ./my-app
```

---

## Why this scanner, not another checker

- **Versioned cross-framework projection, not label soup.** A pinned crosswalk catalogue (`2026.10.v2`) maps **every** EU AI Act dimension and article to NIST AI RMF 1.0, ISO/IEC 42001:2023, OWASP LLM 2025, OWASP Agentic Top 10, GDPR, MITRE ATLAS, SOC 2, ISO 27002, NIST SP 800-53 and CSA AICM — with per-control status, readiness %, and **"Satisfy Once, Comply Everywhere" levers** showing which single fix closes gaps across the most frameworks. Control IDs are the published ones (no invented identifiers), and **every gap control names the real-world incidents that exploited its class**.
- **Evidence-linked, calibrated findings.** Every finding carries file, article, confidence, and severity — and the scanner distinguishes code fact from inference. Scores are evidence measures, never compliance verdicts.
- **Incident-grounded gaps.** Each gap links to documented real-world incidents (OWASP/MITRE/NIST IDs + mitigations) — evidence input for Art. 9 risk management and Art. 72 post-market monitoring.
- **Role-aware obligations.** Deterministic provider / deployer / GPAI-provider inference scopes which articles *you* actually owe.
- **Local-first, offline by default.** Pure static analysis, no network, no telemetry. Semantic review happens in *your* Claude Code session or MCP client — never a headless credential wrapper.
- **Closed loop with a regression guard.** `eu-ai-act-fix` proposes deterministic fixes, applies them, re-scans, and **reverts anything that regresses any dimension**.

---

## What the scanner looks at

22 analyzers, all deterministic static analysis:

**Baseline (14):** AI frameworks · data pipeline · human oversight (Art. 14) · security controls · fairness testing · test suite · logging/monitoring (Art. 12) · documentation · configuration · agent cascade · adversarial robustness (Art. 15) · Terraform · CloudFormation/K8s · CI/Dockerfile.

**Agent-aware (7)** — grounded in Nannini et al. (2026), *AI Agents under EU Law*: agent inventory · privilege minimization · runtime drift (Art. 3(23)) · regulatory perimeter (GDPR/Data Act/CRA/MDR/NIS2 adjacency) · lethal-trifecta (AEPD rule-of-2) · model typology · cloud deployment.

**Transparency (1):** Article 50 — chatbot disclosure (50(1)), synthetic-content C2PA marking (50(2)), emotion/biometric notice (50(3)), deep-fake labelling (50(4)). In force since 2 August 2026.

Findings aggregate into **23 compliance dimensions** (`scanner/kb.py`), auto-tagged with compound-risk axis and operator roles.

---

## Semantic depth: your subscription, two paths

The scanner never calls an LLM headlessly. When you want more than deterministic scores:

- **In Claude Code (assisted mode):** `python -m scanner.cli --set mode=assisted` — slash commands use your host session (your existing subscription, no API key) for semantic review, grounded Q&A, and applying fixes. The deterministic scores stay the objective baseline.
- **Outside Claude Code:** run the **MCP server** (`eu-ai-act-scan-mcp`, installed from this repository — see [Install](#install)) from any MCP client — same engine, client's own model, no wrapper.

---

## Install

**Claude Code plugin** — the commands and the 14 article-grounded skills:

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

Tools: `scan_project`, `list_dimensions`, `get_article`, `incidents_for_dimension`, `incidents_for_threat`, `incidents_for_article`, `incident_corpus_stats`, `agentic_taxonomy`, `project_cross_framework`, `generate_dossier`, `remediation_loop`, `generate_visual_graph`.

`scan_project` also returns `agentic_recommendations`: the compound-risk taxonomy mitigations and evidence for the agentic risk axes the scan detected, each tagged `act_required` (with the EU AI Act provision) or `paper_suggested` (with the paper line). `agentic_taxonomy` browses that catalogue directly, optionally filtered to one risk axis.

---

## Usage

**Claude Code:** `/ai-act-scan ./my-app` · `/ai-act-article art50` · `/ai-act-scan-fix --top 3` · `/ai-act-incidents art15` · `/ai-act-ask "…"` · `/ai-act-graph` · `/ai-act-cross-framework` · `/ai-act-dossier` · `/ai-act-settings`

**Python:**

```python
from scanner import scan_project, incidents_for_article, run_fix_loop

result = scan_project("./my-app", cross_framework=True)
for inc in incidents_for_article("art15", limit=3):
    print(inc.id, inc.title)

fix = run_fix_loop("./my-app", apply=False)  # dry-run plan; --apply to write
```

**CLI:** `eu-ai-act-scan ./my-app --markdown` · `--article art50` · `--cross-framework` · `--incidents art15` · `--ask "…"` · `--dossier` · `--graph` · `--fix [--apply]` · `--settings` / `--set mode=assisted`

---

## What the output means

- **0–29%**: clear gap · **30–59%**: partial, material gaps · **60–79%**: evidence present, needs docs · **80–100%**: broad evidence, still needs human verification.
- **Always check `is_ai_system` first.** Non-AI codebases are out of scope: no scores, just a `scope_note`.
- **Scores are not compliance verdicts.** Compliance is a legal determination (Art. 43 conformity assessment for high-risk). This is the static-analysis evidence layer underneath it.

## What it does NOT do

- **No LLM calls, no network, no telemetry.** Offline by default; only `scripts/sync_incident_corpus.py` (maintainers) touches the network.
- **No risk-tier classification for you.** High-risk vs limited-risk (Art. 6 + Annex III) needs human judgment.
- **No legal advice.** Use alongside counsel, not instead of it.

## Contributing

Contributions are the point — new analyzer patterns, new analyzers, KB updates, fixtures. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

## Acknowledgements

Extracted from [CodexAI](https://antifragile-ai.net). Incident grounding built on the **GenAI & Agentic AI Security Incidents** dataset by Emmanuel G. (`emmanuelgjr/genai-incidents`, CC-BY-4.0).
