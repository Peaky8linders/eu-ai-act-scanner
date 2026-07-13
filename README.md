# EU AI Act Scanner

> Scan any codebase for EU AI Act (Regulation 2024/1689) compliance evidence and gaps — directly from Claude Code or a Python script.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
![Status: alpha](https://img.shields.io/badge/status-alpha-orange)
<!-- countdown-badge -->![Article 50 countdown](https://img.shields.io/badge/Art.%2050%20transparency-T--20%20days%20(2%20Aug%202026)-red)<!-- /countdown-badge -->

**Ships as three things in one repo:**
1. A **Claude Code plugin** with four commands (`/ai-act-scan`, `/ai-act-scan-fix`, `/ai-act-article`, `/ai-act-incidents`) and **13 article-grounded skills** covering classification, obligations, deployer duties, GPAI, Annex IV, timeline, penalties, and real-world incident grounding
2. A **Python library** (`from scanner import scan_project`) with **22 analyzers**, including a dedicated Article 50 transparency analyzer and 7 agent-aware analyzers grounded in Nannini et al. (2026), *AI Agents under EU Law* — covering the four compound-risk axes (cascading, emergent, attribution, temporal), AEPD lethal-trifecta detection, runtime drift, regulatory perimeter classification, and tool-permission minimization
3. An **MCP server** (`eu-ai-act-scan-mcp`) so non-Claude-Code agents can call the scanner and query the incident corpus over the Model Context Protocol

Every finding is **grounded in real-world incidents** (new in v0.4): the scanner crosswalks its gaps to a vendored, reviewed-tier subset of the open [GenAI & Agentic AI Security Incidents dataset](https://huggingface.co/datasets/emmanuelgjr/genai-incidents) (CC-BY-4.0, 7,725+ incidents mapped to OWASP LLM Top 10 2025, OWASP Agentic (ASI) Top 10, NIST AI RMF, and MITRE ATLAS). A gap stops being "you have no prompt-injection defence" and becomes "...and here are the documented incidents where exactly that gap was exploited, with the published mitigations." See [Incident grounding](#incident-grounding).

The skills are written to the same standard: every regulatory claim cites an article (and paragraph where relevant), every skill names its audience (engineer / compliance officer / legal counsel / deployer), every skill has a Common Rationalizations table that heads off the most common mistakes, and every skill ends with a citation to the Official Journal. See [`skills/authoring-eu-ai-act-skills.md`](skills/authoring-eu-ai-act-skills.md) for the authoring standard — new skills must meet it.

---

## ⏳ Enforcement countdown

The EU AI Act applies in waves. The **Digital Omnibus** (adopted 29 June 2026) deferred the high-risk Annex III regime to **2 December 2027** — but deliberately **left Article 50 transparency untouched**, making it the sharpest live deadline for anyone shipping a chatbot, generating synthetic content, or running emotion/biometric systems.

<!-- countdown-table:start -->
| Milestone | Articles | Date | Status |
|---|---|---|---|
| Prohibited practices | Art. 5 | 2 Feb 2025 | ✅ in force |
| GPAI model obligations | Art. 53 / 55 | 2 Aug 2025 | ✅ in force |
| **Transparency** | Art. 50 | 2 Aug 2026 | ⏳ **T-20 days** |
| High-risk (Annex III) | Art. 9-15 / 17 / 27 | 2 Dec 2027 | ⏳ T-507 days |

_Countdown generated 2026-07-13 by `scripts/update_readme_countdown.py` (refreshed weekly in CI). The Digital Omnibus deferred high-risk to Dec 2027 but left Article 50 at 2 Aug 2026._
<!-- countdown-table:end -->

If your system touches biometrics, critical infrastructure, education, employment, essential services, law enforcement, migration, or justice, the high-risk regime (Dec 2027) is in scope too. Most teams don't know what their code currently shows against the regulation.

**Run this to see where you stand against the live Article 50 deadline:**

```python
from datetime import date
from scanner import scan_project

result = scan_project("./my-ai-project")
days_left = (date(2026, 8, 2) - date.today()).days  # Article 50 transparency

print(f"T-{days_left} days to Article 50 transparency enforcement")
print(f"Overall compliance score: {result.overall_compliance_pct}%")
print()
print("Worst-scoring dimensions (fix these first):")
for dim_id, score in sorted(result.compliance_scores.items(), key=lambda x: x[1])[:5]:
    print(f"  [{score:>3}%] {dim_id}")
```

Sample output on a mid-compliance RAG app:

```
T-20 days to Article 50 transparency enforcement
Overall compliance score: 47%

Worst-scoring dimensions (fix these first):
  [ 12%] logging              — Art. 12 automatic record-keeping
  [ 25%] human_oversight      — Art. 14 HITL gates + override hooks
  [ 31%] fairness_testing     — Art. 10(2)(f) disparate-impact tests
  [ 44%] adversarial_robustness — Art. 15(3) prompt-injection defences
  [ 48%] tech_docs            — Art. 11 Annex IV technical file
```

Each gap maps to a specific article, so a compliance officer or legal counsel can route it into their Quality Management System or Art. 43 conformity-assessment checklist with no translation.

Or the one-line Claude Code version:

```
/ai-act-scan ./my-app
```

That runs the same scan and narrates the results in plain English, cites the articles, and offers to propose remediation tasks for the worst gaps via `/ai-act-scan-fix --top 3`.

---

## Why

The EU AI Act (Regulation 2024/1689) entered into force in August 2024. Prohibited practices (Art. 5) and GPAI obligations are already live; Article 50 transparency applies from 2 August 2026; and the high-risk regime — deferred by the Digital Omnibus — applies from 2 December 2027. Most teams are flying blind on what their code actually shows vs. what the regulation asks for.

This tool does one thing: **scan your repo and surface evidence and gaps against 23 compliance dimensions mapped to EU AI Act articles, grounded in the real-world incidents that exploited each gap class**. It does *not* replace a conformity assessment, legal review, or a Quality Management System. It is the static-analysis layer underneath all of those.

## What the scanner looks at

22 specialized analyzers, all deterministic static analysis (no LLM calls by default):

**Baseline analyzers (14):**

| Analyzer | Covers | Articles |
|---|---|---|
| `ai_frameworks` | PyTorch, TensorFlow, Hugging Face, OpenAI/Anthropic SDKs, LangChain | Art. 10, 11, 53 |
| `data_pipeline` | Training data handling, dataset loading, bias testing hooks | Art. 10 |
| `human_oversight` | HITL gates, confidence thresholds, approval gates, override hooks | Art. 14 |
| `security_controls` | Auth, rate limiting, input validation, RBAC | Art. 15 |
| `fairness_testing` | AIF360, Fairlearn, disparate-impact tests | Art. 10(2)(f) |
| `test_suite` | pytest / unittest coverage of AI code | Art. 9, 15 |
| `logging_monitoring` | Structured logging, MLflow, Prometheus, W&B | Art. 12, 15 |
| `documentation` | README, model cards, docstrings | Art. 11, 13 |
| `configuration` | Dockerfile, `pyproject.toml`, CI config | Art. 17 |
| `agent_cascade` | Multi-agent orchestration, tool use | Art. 15(4) |
| `adversarial_robustness` | ART, Foolbox, guardrails, prompt-injection defences | Art. 15(3) |
| `terraform` | Terraform HCL — IAM, networking, secret handling | Art. 15 |
| `cloudformation_k8s` | CloudFormation + Kubernetes manifests | Art. 15 |
| `cicd_dockerfile` | GitHub Actions, GitLab CI, Dockerfile security | Art. 17 |

**Agent-aware analyzers (7), added in v0.3 — grounded in Nannini et al. (2026), [*AI Agents under EU Law*](https://arxiv.org/abs/2504.06255):**

| Analyzer | Covers | Compound-risk axis |
|---|---|---|
| `agent_inventory` | MCP, OpenAI Assistants v2, browser agents, code-interpreter sandboxes, action-verb taxonomy | Attribution (paper §10.4) |
| `privilege_minimization` | Prompt-as-control antipattern, open exec on model output, long-lived creds, OAuth over-grant, permission registry | Cascading (OWASP Top 10 Agentic) |
| `runtime_drift` | Floating model IDs, inline prompts, tool-catalogue manifests, Art. 3(23) substantial-modification procedure | Temporal (Art. 3(23)) |
| `regulatory_perimeter` | GDPR / Data Act / CRA / MDR / NIS2 trigger detection, Step-9 adjacency artefact | Attribution (Art. 25) |
| `lethal_trifecta` | AEPD rule-of-2 — untrusted input + sensitive data + autonomous state-change without HITL | Multiple |
| `model_typology` | Foundation / generative / decision-support / perception model classification with Annex grounding | — |
| `cloud_deployment` | Cloud-provider-specific controls and shared-responsibility flags | — |

Findings are aggregated into **23 compliance dimensions** (see [`scanner/kb.py`](scanner/kb.py)), and gap findings from the four agent-aware analyzers are auto-tagged with their compound-risk axis, threat categories, and applicable operator roles via [`scanner/data/agentic_taxonomy.py`](scanner/data/agentic_taxonomy.py) and [`scanner/data/role_obligations.py`](scanner/data/role_obligations.py).

## Incident grounding

A normative gap ("you have no prompt-injection defence — Art. 15(4)") is easy to wave away. An *evidence-based* one is not: "...and here are the documented incidents where exactly that gap was exploited, mapped to OWASP LLM01 + MITRE ATLAS AML.T0051, with the published mitigations." That is what incident grounding does.

The scanner bundles a curated, reviewed-tier subset of the open **[GenAI & Agentic AI Security Incidents dataset](https://huggingface.co/datasets/emmanuelgjr/genai-incidents)** (`emmanuelgjr/genai-incidents`, **CC-BY-4.0**) — real-world and research incidents aggregated and de-duplicated from AIID, OECD AIM, AIAAIC, MITRE ATLAS, AVID, the MIT AI Risk Repository, NVD, GHSA, OSV, garak, promptfoo, and others. Every incident carries its native taxonomy: OWASP Top 10 for LLM Applications (2025), OWASP Agentic (ASI) Top 10, NIST AI RMF, and MITRE ATLAS techniques/tactics, plus documented mitigations and CVE IDs.

The crosswalk in [`scanner/data/incident_crosswalk.py`](scanner/data/incident_crosswalk.py) maps the scanner's own vocabulary — KB dimensions, agentic threat categories, and EU AI Act article refs — to that incident taxonomy. So:

- **Every gap finding** gets a `related_incidents` list (the documented incidents that exploited its class).
- **Every scan result** carries `incident_grounding` — the worst-scoring dimensions paired with real incidents.
- **The Python/CLI/MCP API** can surface incidents for any dimension, article, or threat category on demand.

```python
from scanner import incidents_for_dimension, incidents_for_article, incident_corpus_stats

for inc in incidents_for_article("art15", limit=3):
    print(f"{inc.id} [{inc.severity}] {inc.title}")
    print(f"   OWASP-LLM {inc.owasp_llm} | MITRE {inc.mitre_atlas[:2]} | NIST {inc.nist_ai_rmf[:2]}")
    if inc.mitigations:
        print(f"   mitigation: {inc.mitigations[0]}")

print(incident_corpus_stats()["count"], "incidents bundled, attribution:",
      incident_corpus_stats()["license"])
```

Or from Claude Code / the CLI:

```
/ai-act-incidents art15            # incidents for an article
/ai-act-incidents security         # incidents for a KB dimension
/ai-act-incidents prompt_injection # incidents for an agentic threat category
```

```bash
eu-ai-act-scan --incidents art15 --limit 5     # JSON
eu-ai-act-scan ./my-app --markdown             # scan report with a grounding section
```

**Offline by design.** The bundled subset ships in the wheel and needs no network. The full 7,725-incident dataset is one step away — `pip install genai-incidents` or `load_dataset("emmanuelgjr/genai-incidents")` — and the bundled snapshot is regenerated deterministically by [`scripts/sync_incident_corpus.py`](scripts/sync_incident_corpus.py) (`pip install eu-ai-act-scanner[sync]`). Incident grounding is **evidence input to your Art. 9 risk management and Art. 72 post-market monitoring — not a compliance verdict.** See the [`eu-ai-act-incident-grounding`](skills/eu-ai-act-incident-grounding.md) skill.

## Obligations & operator-role inference

A gap only matters if *you* owe the obligation. The scanner deterministically infers which EU AI Act role(s) the scanned codebase occupies — **provider** (you build/train/publish a model), **deployer** (you use someone else's), **GPAI provider** (you train a general-purpose model) — from a closed vocabulary of code signals, with no LLM and no network. Every **gap** finding is then back-filled with `applicable_roles`: the roles that actually owe its articles, drawn from the [role-obligation registry](scanner/data/role_obligations.py). `ScanResult.inferred_roles` carries the project-level profile.

```python
from scanner import scan_project

result = scan_project("./my-app")
print(result.inferred_roles)   # e.g. ["provider"] — drives which obligations apply
```

Article citations are normalised through a single source of truth ([`scanner/refs.py`](scanner/refs.py)) so the same article reads identically everywhere — internal `Art. 14(4)`, user-facing `Article 14.4`, or KB key `art14`. Obligation text is grounded in the verbatim EUR-Lex prose ([`scanner/grounding.py`](scanner/grounding.py)), and a citation guard drops any LLM-generated sentence not supported by its cited articles.

## Autonomous fix loop

`eu-ai-act-fix` closes the loop: scan → rank gaps → propose a remediation → (optionally) apply → **re-scan** → keep the fix only if it doesn't regress anything → repeat until convergence.

```bash
eu-ai-act-fix ./my-app                 # safe dry-run: proposals only, nothing written
eu-ai-act-fix ./my-app --apply         # write fixes, re-scan, revert any regression
eu-ai-act-fix ./my-app --top 5 --json  # widen the gap set, machine-readable output
```

Each deterministic remediation is validated against the analyzers' own positive-detection patterns, so applying it demonstrably raises the score on re-scan. The **regression guard** is the antifragile property: because the overall score averages across dimensions and adding a file can activate another analyzer, a "good" fix can lower a sibling dimension — so every applied fix is re-scanned and **reverted if any dimension drops**. Compliance documents (`MODEL_CARD.md`, `DATA_CARD.md`) are scaffolded with `<FILL IN: …>` placeholders — the loop never fabricates regulatory claims. The default mode writes nothing; `--apply` is required to touch the tree.

```python
from scanner import run_fix_loop

res = run_fix_loop("./my-app", top_n=3, apply=False)
print(res.baseline_overall, "->", res.final_overall, f"({res.overall_delta:+})")
for p in res.proposals:
    print(p.dimension, p.article, p.title)
```

## Claude Max bridge (optional LLM)

The scanner is local-first and runs fully without an LLM. When you *do* want the optional LLM-assisted paths (richer documentation scoring, LLM-drafted fixes for gaps with no deterministic fixer), the [Claude Max bridge](scanner/llm_bridge.py) routes them through a local [Claude-Code subscription wrapper](https://github.com/) (Anthropic-compatible) instead of a metered API key — so they run on your **Claude Max subscription**. The wrapper defaults to `http://127.0.0.1:8000` and is also reachable over a Cloudflare tunnel for remote/CI use.

```bash
export EU_AI_ACT_SCANNER_LLM=true                              # opt in
export EU_AI_ACT_SCANNER_LLM_BASE_URL=http://127.0.0.1:8000    # local wrapper (default)
# or, remote:  https://wrapper.<your-domain>      + EU_AI_ACT_SCANNER_LLM_API_KEY=...
export EU_AI_ACT_SCANNER_LLM_MODEL=claude-sonnet-4-6           # optional model override

eu-ai-act-scan --llm-status        # report bridge config + probe wrapper /health
```

The bridge is **graceful by construction** — a disabled flag, a missing `anthropic` SDK, or an unreachable wrapper degrades to an inert result and never blocks a scan. It ports the multi-strategy JSON extractor and structural-truncation heuristic battle-tested in the `regenold-eu-ai-act-rag` system.

## Install

### As a Claude Code plugin

```bash
# From Claude Code
/plugin install Peaky8linders/eu-ai-act-scanner
```

Then invoke `/ai-act-scan` inside Claude Code on any codebase.

### As a Python package

```bash
git clone https://github.com/Peaky8linders/eu-ai-act-scanner
cd eu-ai-act-scanner
pip install -e .
```

Or (once published):

```bash
pip install eu-ai-act-scanner
```

### As an MCP server

For non-Claude-Code agents (or any MCP client), install the optional MCP extra and run the server:

```bash
pip install "eu-ai-act-scanner[mcp]"
eu-ai-act-scan-mcp          # stdio MCP server
```

Register it with an MCP client using the bundled [`.mcp.json`](.mcp.json):

```json
{ "mcpServers": { "eu-ai-act-scanner": { "command": "eu-ai-act-scan-mcp", "args": [] } } }
```

It exposes seven tools: `scan_project`, `list_dimensions`, `get_article`, `incidents_for_dimension`, `incidents_for_threat`, `incidents_for_article`, and `incident_corpus_stats` — the same engine as the library and CLI.

## Usage

### In Claude Code (recommended)

```
/ai-act-scan ./my-app                # full scan + narration + article cites
/ai-act-article art50                # Art. 50 transparency deep-dive
/ai-act-scan-fix --top 3             # propose fixes for the worst gaps
/ai-act-incidents art15              # real-world incidents for an article/dimension/threat
/ai-act-ask "..."                    # grounded Q&A over the bundled EU AI Act text
/ai-act-settings                     # view / set mode (deterministic | assisted)
```

The plugin narrates the output in plain English, cites the articles, and offers remediation tasks. The 13 shipped skills (Art. 5 prohibited, Art. 6 classification, FRIA, operator roles, GPAI, Annex IV, timeline, penalties, incident grounding, and three meta-skills) become automatically invocable once the plugin is installed — ask "is this prohibited under Art. 5?", "what goes in Annex IV?", or "what real incidents map to this gap?" and Claude pulls the right skill.

### Article 50 example

Article 50 transparency — chatbot disclosure, synthetic-content marking, deep-fakes, emotion/biometric notice — is **enforceable 2 August 2026**, the one obligation the Digital Omnibus did *not* defer. The dedicated `article_50_transparency` analyzer checks all four duties:

```
/ai-act-scan ./my-chatbot
#  art50-no-ai-disclosure   (Art. 50(1)) — a chat surface with no "you're talking to an AI" notice
#  art50-unmarked-synthetic (Art. 50(2)) — image/audio generation with no C2PA / watermark

/ai-act-ask "What are a deployer's Article 50 duties for deepfakes?"
#  cited answer from the bundled statute text — Art. 50(3) emotion/biometric, 50(4) deep-fake + AI-text

/ai-act-scan-fix --top 3
#  proposes the disclosure / marking fixes, shows the plan, applies only what you approve
```

### Use your own Claude Code (assisted mode)

The scan is 100% local and deterministic by default. Opt into a deeper pass driven by **your own Claude Code** — no API key, no wrapper needed:

```
python -m scanner.cli --set mode=assisted            # persist to .eu-ai-act-scanner.toml
python -m scanner.cli --set auto-apply=true          # let it apply approved fixes too
```

In `assisted` mode the commands use the host Claude Code session to review findings semantically, answer grounded questions, and (with `auto-apply`) apply fixes with its own edit tools. The deterministic scores stay the objective baseline.

### Python

```python
from scanner import scan_project

result = scan_project("./my-ai-project")
print(f"Overall compliance: {result.overall_compliance_pct}%")

for dim_id, score in sorted(result.compliance_scores.items(), key=lambda x: x[1]):
    print(f"  {dim_id}: {score}%")

for gap in result.risk_indicators[:5]:
    print(f"  ! {gap}")
```

See the [enforcement countdown](#-enforcement-countdown) above for a ready-to-run snippet that surfaces your worst-scoring dimensions sorted by urgency.

## What the output means

Scores are on a 0–100 scale:
- **0–29%**: clear gap, little to no evidence
- **30–59%**: partial evidence, material gaps
- **60–79%**: evidence present, may need documentation
- **80–100%**: broad evidence; still requires human verification

**Scores are not compliance verdicts.** Compliance is a legal determination that requires a conformity assessment (Art. 43) for high-risk systems, or documented self-assessment for other risk tiers. This scanner surfaces evidence — a human (ideally with legal counsel) draws the conclusion.

## What it does NOT do

- **No LLM calls by default.** Pure local static analysis. Opt-in only: `assisted` mode uses your own Claude Code (`/ai-act-settings`), or the headless LLM bridge (`EU_AI_ACT_SCANNER_LLM=true`) — both off unless you enable them.
- **No network requests, no telemetry.** Your code never leaves your machine. The incident corpus is vendored offline; only `scripts/sync_incident_corpus.py` (run by maintainers, never at scan time) reaches the network to regenerate it.
- **No risk-tier classification.** Whether your system is high-risk, limited-risk, or minimal-risk depends on use case (Art. 6 + Annex III) — a human has to decide.
- **No legal advice.** Use this alongside legal counsel, not instead of it.

## Contributing

This started as the code-scanner layer of a proprietary compliance product ([CodexAI](https://antifragile-ai.net)) and has been extracted to share publicly. **Contributions are the point** — the regulation is new, the patterns are evolving, and every false negative you teach the scanner helps everyone else.

Good first contributions:
- **New analyzer patterns** — if the scanner misses a legitimate control pattern you use, add it to the relevant analyzer
- **New analyzers** — if there's a whole dimension we don't cover (e.g. federated learning specifics, RAG-specific controls)
- **KB updates** — the dimension → article mapping in `scanner/kb.py` is a living document
- **Fixtures** — more sample AI projects make the tests stronger

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev loop.

## Roadmap

- **v0.1**: Plugin + library (Apr 2026)
- **v0.2**: 11 article-grounded skill harness for law practitioners (Apr 2026)
- **v0.3**: 7 agent-aware analyzers per Nannini et al. (2026) + 4 new compliance dimensions + four-axis compound-risk taxonomy (May 2026)
- **v0.4**: Real-world incident grounding (GenAI-incidents corpus crosswalked to OWASP LLM/ASI, NIST AI RMF, MITRE ATLAS) + MCP server + `/ai-act-incidents` command (Jun 2026)
- **v0.6**: Deterministic operator-role inference + autonomous fix loop + Claude Max bridge (Jun 2026)
- **v0.7**: AI-system scope gate — stop scoring/fixing non-AI projects (Jul 2026)
- **v0.8**: Article 50 transparency analyzer + grounded Q&A (`/ai-act-ask`) + assisted mode (`/ai-act-settings`) that uses your own Claude Code (this release, Jul 2026)
- **Next**: baseline / diff mode (scan twice, report only what changed); opt-in live `genai-incidents` enrichment

## License

Apache-2.0. See [LICENSE](LICENSE).

## Acknowledgements

Extracted from [CodexAI](https://antifragile-ai.net) — the full EU AI Act compliance platform. CodexAI adds risk classification, maturity scoring, roadmap generation, Annex IV / FRIA / Art. 13 documentation, cross-framework mapping, and audit evidence chains on top of this scanner.

Incident grounding is built on the **GenAI & Agentic AI Security Incidents** dataset by Emmanuel G. ([`emmanuelgjr/genai-incidents`](https://huggingface.co/datasets/emmanuelgjr/genai-incidents)), licensed **CC-BY-4.0** and aggregated/de-duplicated from AIID, OECD AIM, AIAAIC, MITRE ATLAS, AVID, the MIT AI Risk Repository, NVD, GHSA, OSV, garak, promptfoo, and others. The bundled subset under `scanner/data/incidents.json` is a curated, reviewed-tier derivative used for offline grounding; the full dataset is available via `pip install genai-incidents`. Thank you to the maintainer for making AI-security evidence open and citable.
