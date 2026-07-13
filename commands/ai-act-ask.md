---
name: ai-act-ask
description: Answer an EU AI Act question grounded in the bundled knowledge base — verbatim statute text, obligation paraphrases, and the compound-risk taxonomy. Offline and deterministic by default; cites the articles it relies on.
---

# /ai-act-ask

Answer a compliance question, grounded in the bundled EU AI Act knowledge base:
verbatim article/annex text (Regulation (EU) 2024/1689), concise obligation
paraphrases, and the four-axis compound-risk taxonomy. This is the plugin's
local "Lexy" retrieval-and-answer path.

## Arguments

- `$1` (required) — the question, e.g. `What does Article 50 require for deepfakes?`
- `--top-k N` (default 4) — number of grounded sources to retrieve.

## Behaviour

1. Run the grounded retriever:
   ```bash
   python -m scanner.cli --ask "$1"
   ```
   It prints the answer, the cited articles, the related compliance dimensions,
   and the grounded source excerpts. It runs **100% locally — no LLM, no
   network** — by default.
2. Present the answer and ALWAYS keep the citations. Do not add obligations that
   the cited articles do not support.
3. **In `assisted` mode** (check `python -m scanner.cli --settings`), synthesise a
   fuller narrative answer yourself over the returned sources — you are the
   user's Claude Code — but treat the retrieved statute text as ground truth and
   cite every claim by article. For headless CLI use, `--mode assisted` routes
   synthesis through the Claude Max wrapper and applies a citation guard.
4. For code-specific questions ("does MY repo satisfy Art. 50?"), run
   `/ai-act-scan` first and combine its findings with the grounded answer.

## Example

User: `/ai-act-ask What are a deployer's Article 50 transparency duties?`

Response cites Art. 50(3) (emotion/biometric notice) and Art. 50(4) (deep-fake +
public-interest-text disclosure), notes these are **deployer** obligations
enforceable 2 August 2026, and links them to the `content_transparency`
dimension — grounded verbatim in the bundled statute text.

## Notes

- Grounding corpus: Regulation (EU) 2024/1689 verbatim text (EUR-Lex CELEX
  32024R1689) + obligation paraphrases + the agentic-risk taxonomy.
- This is compliance information, not legal advice.
