---
name: ai-act-ask
description: "Answers an EU AI Act question from the bundled law text, citing the articles it relies on."
argument-hint: "<question>"
---

# /ai-act-ask

Answer an EU AI Act question from the bundled law text (Regulation (EU) 2024/1689 as amended by Reg. 2026/1744), with citations.

1. Run `antifragile-scan --ask "$1"` (add `--top-k 6` for broad questions). It runs locally and prints an answer, the cited articles and the source excerpts.
2. Answer in plain language and keep every citation. Do not add obligations the cited text does not support. If `antifragile-scan --settings` shows `mode: assisted`, you may write a fuller answer over the returned excerpts, still citing each claim by article.
3. For "does my code comply?" questions, run `/ai-act-scan` too and combine both.

This is compliance information, not legal advice.
