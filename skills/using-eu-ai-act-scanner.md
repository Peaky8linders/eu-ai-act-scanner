---
name: using-eu-ai-act-scanner
description: Use when the user asks to scan their AI system for EU AI Act compliance, check Regulation 2024/1689 readiness, audit a repo for AI Act gaps, or prepare a codebase for a conformity assessment. Dispatches to the /ai-act-scan command and narrates results.
user_invocable: true
---

# Using the EU AI Act Scanner

This skill orchestrates the scanner for users who say "scan my AI system", "check EU AI Act compliance", "audit this repo", or "am I ready for the conformity assessment".

## Decision tree

```
user intent                                   → action
-----------------------------------------------+-------------------
"scan", "audit", "check compliance"           → /ai-act-scan
"fix the gaps", "make me compliant"           → /ai-act-scan-fix
"tell me about Art. X"                        → /ai-act-article X
"what does this finding mean"                 → interpreting-findings skill
"why does my score matter"                    → interpreting-findings skill
```

## What to do before running the scanner

1. Confirm the user wants to scan **this** repo, not a subdirectory or a different one. Ask once if ambiguous.
2. Check that the path exists. If it doesn't, stop and ask rather than guessing.
3. Do NOT run the scanner on directories that look like they contain secrets (`.env`, `credentials.json`, `*.pem`). Ask for confirmation first — even though the scanner is local-only, it will still read those files into memory.

## What to do after running the scanner

1. Always lead with the **overall compliance percentage** and the number of files scanned. This sets expectations.
2. Immediately show the **three lowest-scoring dimensions** with their article references. This is what the user actually needs to act on.
3. Do NOT dump the full JSON. Summarise. Offer to drill down.
4. If the user asks "what do I do about this", route to the `interpreting-findings` skill.
5. If the user names an article, route to `/ai-act-article`.

## What NOT to do

- Never claim the codebase is "compliant" or "not compliant" based on a scan alone. Compliance is a legal determination that requires a conformity assessment by a notified body (for high-risk systems) or self-assessment with documentation (for other risk tiers). The scanner surfaces *evidence and gaps* — it is not a compliance verdict.
- Never invent article paragraphs. If you're unsure of an obligation's exact text, say so and point to the article number. Regulation 2024/1689 is the source of truth.
- Never present GPAI obligations (Art. 53, 55) as mandatory for non-GPAI systems. Check the user's risk tier first.

## When to escalate

If the user's codebase scores below 30% and they mention "high-risk" or "Annex III", flag this:

> "Your current scan shows major gaps on a high-risk AI system. Static analysis alone cannot establish compliance — you likely need a documented Quality Management System (Art. 17), a Risk Management System (Art. 9), and potentially a Fundamental Rights Impact Assessment (Art. 27) before conformity assessment. The scanner can point at the technical controls, but the governance artefacts must be written by humans with legal review."

That disclaimer protects the user from taking scanner output as a compliance green light.
