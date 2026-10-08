---
name: ai-act-graph
description: Generate an interactive visual context graph browser for the codebase. Browse architecture components, inspect each node for compliance gaps, and view copyable recommended fixes.
---

# /ai-act-graph

Generate and explore a standalone, interactive visual context graph of the audited AI system.

## Usage

```bash
/ai-act-graph [PATH]
```

Or via CLI:
```bash
python -m scanner.cli [PATH] --graph context-graph.html
```

## What it does

1. Scans the codebase at `PATH` (defaults to current directory).
2. Generates an interactive, self-contained visual context graph (`context-graph.html`).
3. Renders a node-link visual diagram where:
   - **Nodes** represent discovered architecture components, agent runtimes, and governance gates.
   - **Badges** indicate compliance status:
     - <span style="color: #10b981;">●</span> **Compliant** (evidence verified in codebase)
     - <span style="color: #f59e0b;">●</span> **Partial** (partial controls found; extra evidence recommended)
     - <span style="color: #f43f5e;">●</span> **Gap** (immediate statutory remediation required)
   - **Inspector Panel**: Clicking any node opens a comprehensive drilldown:
     - Exact EU AI Act Article & Paragraph grounding
     - Enacted timeline under Digital Omnibus Regulation (EU) 2026/1744
     - Contributing project source files
     - Detected gaps
     - Cross-framework synergies (NIST AI RMF, ISO 42001, OWASP LLM / ASI, GDPR)
     - **Recommended Fix**: Target file path, rationale, and a production-ready, copyable code patch
     - Grounded real-world incident case studies from the vendored incident corpus
4. Presents a summary in chat with the path to the interactive HTML artifact and highlights the top gap nodes needing attention.
