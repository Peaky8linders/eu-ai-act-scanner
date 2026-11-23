---
name: ai-act-article
description: "Shows which checks and current findings relate to one EU AI Act article, for example art50."
argument-hint: "<art50 | Art. 9 | 15>"
---

# /ai-act-article

Trace one EU AI Act article from the law to the scanner's checks and to what this codebase shows.

1. Run `uvx --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan . --article "$1"` (it accepts `art9`, `Art. 9`, `9` or `article 9`). With the scanner MCP server, `get_article(article="$1")` gives the article's areas, framework controls and incidents without scanning.
2. Present: the article title and what it requires in one sentence; the scanner areas it maps to with this repo's score for each; evidence found (area and file); and the gaps (title and file:line).
3. If the article maps to no scanner area, say the scanner only covers obligations visible in code and configuration (Art. 4, 9-15, 17, 26-27, 43-48, 50, 51-55, 72, 95); governance and procedural articles need a human review.
