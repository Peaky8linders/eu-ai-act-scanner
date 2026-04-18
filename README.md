# EU AI Act Scanner

> Scan any codebase for EU AI Act (Regulation 2024/1689) compliance evidence and gaps — directly from Claude Code, your terminal, or a Python script.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
![Status: alpha](https://img.shields.io/badge/status-alpha-orange)

**Ships as three things in one repo:**
1. A **Claude Code plugin** with three commands (`/ai-act-scan`, `/ai-act-scan-fix`, `/ai-act-article`) and three skills
2. A **Python library** (`from scanner import scan_project`)
3. A **CLI** (`eu-ai-act-scan ./my-project`)

Roadmap item: FastAPI router (Phase 2, additive).

---

## Why

The EU AI Act (Regulation 2024/1689) entered into force in August 2024, with high-risk obligations applying from August 2026. Most teams are flying blind on what their code actually shows vs. what the regulation asks for.

This tool does one thing: **scan your repo and surface evidence and gaps against 19 compliance dimensions mapped to EU AI Act articles**. It does *not* replace a conformity assessment, legal review, or a Quality Management System. It is the static-analysis layer underneath all of those.

## What the scanner looks at

14 specialized analyzers, all deterministic static analysis (no LLM calls by default):

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

Findings are aggregated into **19 compliance dimensions** (see [`scanner/kb.py`](scanner/kb.py)).

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

## Usage

### CLI

```bash
# Scan current directory, emit JSON
eu-ai-act-scan .

# Human-readable markdown summary
eu-ai-act-scan ./my-rag-app --markdown

# Filter to a specific article
eu-ai-act-scan . --article art15
```

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

### In Claude Code

```
/ai-act-scan ./my-app                # full scan + narration
/ai-act-article art14                # Art. 14 human-oversight deep-dive
/ai-act-scan-fix --top 3             # propose fixes for worst 3 gaps
```

## What the output means

Scores are on a 0–100 scale:
- **0–29%**: clear gap, little to no evidence
- **30–59%**: partial evidence, material gaps
- **60–79%**: evidence present, may need documentation
- **80–100%**: broad evidence; still requires human verification

**Scores are not compliance verdicts.** Compliance is a legal determination that requires a conformity assessment (Art. 43) for high-risk systems, or documented self-assessment for other risk tiers. This scanner surfaces evidence — a human (ideally with legal counsel) draws the conclusion.

## What it does NOT do

- **No LLM calls by default.** Pure local static analysis. (Optional LLM mode behind `EU_AI_ACT_SCANNER_LLM=true` for README quality scoring.)
- **No network requests, no telemetry.** Your code never leaves your machine.
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

- **v0.1**: Plugin + library + CLI (this release)
- **v0.2**: FastAPI router behind `[api]` extra for integrating into existing dev-platform backends
- **v0.3**: MCP server so non-Claude-Code agents can call the scanner
- **v0.4**: Baseline / diff mode — scan twice, report only what changed

## License

Apache-2.0. See [LICENSE](LICENSE).

## Acknowledgements

Extracted from [CodexAI](https://antifragile-ai.net) — the full EU AI Act compliance platform. CodexAI adds risk classification, maturity scoring, roadmap generation, Annex IV / FRIA / Art. 13 documentation, cross-framework mapping, and audit evidence chains on top of this scanner.
