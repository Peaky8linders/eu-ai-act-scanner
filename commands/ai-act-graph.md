---
name: ai-act-graph
description: "Generates an interactive map of the codebase showing where each compliance gap sits and how to fix it."
argument-hint: "[path] [output.html]"
---

# /ai-act-graph

Generate an interactive, offline HTML map of the scanned system.

1. Run `eu-ai-act-scan "$1" --graph context-graph.html` (use the output name the user gave, if any), or call `generate_visual_graph(path="$1")` with the scanner MCP server.
2. Give the file path and say how to use it: open it in a browser; green nodes have evidence, amber are partial, red are gaps; clicking a node shows the article, the source files, the gaps, related frameworks and a copyable suggested fix.
3. Name the two or three red nodes that matter most. The file is self-contained and makes no network requests.
