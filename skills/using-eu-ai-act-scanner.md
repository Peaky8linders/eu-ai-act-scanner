---
name: using-eu-ai-act-scanner
description: Use when the user asks to scan their AI system for EU AI Act compliance, check Regulation 2024/1689 readiness, audit a repo for AI Act gaps, prepare a codebase for conformity assessment, or invokes `/ai-act-scan`. Serves engineers (who run the scanner), compliance officers (who read the output), and legal counsel (who validate the article mapping). Dispatches to `/ai-act-scan` and narrates results.
user_invocable: true
---

# Using the EU AI Act Scanner

Orchestrates the scanner for users asking to "scan my AI system", "check EU AI Act compliance", "audit this repo", or "am I ready for the conformity assessment". Primarily serves engineers who run scans and compliance officers who consume the output. Legal counsel can use the scan as evidence input but should read the [interpreting-findings](interpreting-findings.md) skill before drawing conclusions.

## When to invoke

- "scan my repo", "run the AI Act scanner", "check compliance", "audit this codebase"
- "am I ready for conformity assessment" (Art. 43)
- "where are our compliance gaps"
- User invokes `/ai-act-scan` explicitly
- A file under `scanner/analyzers/` was just edited and the user wants to test the change

## Applies to

- Any local codebase the user has read access to.
- **In scope**: static analysis of source code, configuration, IaC, documentation files.
- **Out of scope**: live-system probing, production log analysis, compliance verdicts. If the user asks "is this compliant", route to [interpreting-findings](interpreting-findings.md) so the non-verdict nature of the scan is explained.

## Regulation scope

The scanner surfaces evidence and gaps across 19 compliance dimensions mapped to EU AI Act articles. It is **not** a conformity assessment. A conformity assessment (Art. 43) is a legal procedure that, for high-risk systems, may require a notified body (Art. 43(1)). Static analysis is an *input* to that procedure, not a substitute for it.

## What to do

### Before running the scanner

1. Confirm the user wants to scan **this** repo and not a subdirectory or a different path. Ask once if ambiguous — never guess a path.
2. Check that the path exists. If it does not, stop and ask rather than attempting a scan that will fail.
3. If the directory contains obvious secrets (`.env`, `*.pem`, `credentials.json`, `.aws/credentials`), warn the user. Even though the scanner is local-only and does not transmit data, those files will be read into memory. Ask explicit confirmation before proceeding.
4. If the user is on a branch that is not the branch of record (main/master), ask whether they want to scan the current branch or stash and scan the base.

### Running the scanner

Invoke `/ai-act-scan` with the target path. The command shells out to `python -m scanner.cli <path> --json` and parses the output.

### After running

1. Lead with the **overall compliance percentage and file count**. This anchors expectations before any dimension scores.
2. Show the **three lowest-scoring dimensions** with their article references. This is what the user acts on.
3. Do NOT dump the full JSON. Summarise and offer drill-down via `/ai-act-article`.
4. If the user asks "what does this mean", route to [interpreting-findings](interpreting-findings.md).
5. If the user names an article, route to `/ai-act-article` or [eu-ai-act-reference](eu-ai-act-reference.md).

## Decision tree — routing intent

| User says | Route to |
|---|---|
| "scan", "audit", "check compliance" | `/ai-act-scan` |
| "fix the gaps", "make me compliant" | `/ai-act-scan-fix` |
| "tell me about Art. X", names an article | `/ai-act-article X` + [eu-ai-act-reference](eu-ai-act-reference.md) |
| "what does this finding mean" | [interpreting-findings](interpreting-findings.md) |
| "why does my score matter" | [interpreting-findings](interpreting-findings.md) |
| "are we compliant" | [interpreting-findings](interpreting-findings.md), then explain the scan is evidence not verdict |
| "do I need an FRIA" | [eu-ai-act-fria-guide](eu-ai-act-fria-guide.md) |
| "is my system high-risk" | [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md) |
| "is my use case prohibited" | [eu-ai-act-article-5-prohibited](eu-ai-act-article-5-prohibited.md) |

## Escalation criteria

If the scan shows **overall compliance < 30%** AND the user mentions a high-risk use case or an Annex III category, stop summarising and surface this warning verbatim:

> Your current scan shows major gaps on what you describe as a high-risk AI system. Static analysis cannot establish compliance. Under the EU AI Act, a high-risk AI system requires a documented Risk Management System (Art. 9), a Quality Management System (Art. 17), and — for deployers in Annex III.5/.7/.8 — a Fundamental Rights Impact Assessment (Art. 27), before it can undergo conformity assessment (Art. 43). The scanner points at technical controls. The governance artefacts must be written by humans with legal review.

That disclaimer protects the user from treating scanner output as a compliance green light.

## Common rationalizations

| Excuse | Rebuttal |
|---|---|
| "The scanner said we passed, so we're compliant." | The scanner surfaces evidence of technical controls. Compliance is a legal determination under Art. 43. For high-risk systems (Art. 6), a notified body may be required. Route to [interpreting-findings](interpreting-findings.md) before drawing any verdict. |
| "80% is great — we can ship." | An 80% dimension score means broad evidence for that dimension. It says nothing about the dimensions not scored (most governance articles), and nothing about whether the evidence was genuine or theatrical. |
| "We don't need to scan the IaC repo — the AI Act is about models." | Art. 15 explicitly requires accuracy, robustness, and cybersecurity "throughout the lifecycle". IaC misconfigurations (public S3 buckets holding training data, unauthenticated inference endpoints) are Art. 15 failures. Include the IaC repo. |
| "The user didn't specify a risk tier, so I'll assume limited-risk to avoid being pushy." | Unknown risk tier is a gap, not an assumption. Ask. Or route to [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md). Classifying as limited-risk without evidence skips Art. 9/10/11/14/15/17 obligations and is a compliance fraud risk. |
| "GPAI obligations don't apply — we're just using OpenAI's API." | That makes you a *deployer* of a GPAI (Art. 3(63)), not a provider. Deployer obligations (Art. 26) and the downstream transparency duties (Art. 50) still apply. Route to [eu-ai-act-operator-roles](eu-ai-act-operator-roles.md). |

## Cross-references

- [interpreting-findings](interpreting-findings.md) — after a scan, how to read dimension scores and prioritise fixes
- [eu-ai-act-reference](eu-ai-act-reference.md) — article → dimension → analyzer map
- [eu-ai-act-article-5-prohibited](eu-ai-act-article-5-prohibited.md) — prohibited practices classification
- [eu-ai-act-article-6-classification](eu-ai-act-article-6-classification.md) — high-risk classification
- [eu-ai-act-fria-guide](eu-ai-act-fria-guide.md) — when an FRIA is required

## Source of truth

EU Regulation 2024/1689, published in the Official Journal of the European Union, 12 July 2024.
