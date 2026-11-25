# Contributing to Antifragile Harness

Thanks for considering a contribution. The regulation is moving fast and the patterns teams use for compliance evidence evolve with it — we need the community's help to keep the analyzers sharp.

## Quick dev loop

```bash
git clone https://github.com/Peaky8linders/antifragile-harness
cd antifragile-harness
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .

# Try the CLI against the fixture
antifragile-scan tests/fixtures/sample_project --markdown
```

## What makes a good contribution

### Adding / extending an analyzer

The single most valuable kind of contribution. If the scanner missed a legitimate control pattern you use, add it.

1. Find the relevant analyzer under `scanner/analyzers/` (or create a new one).
2. Add the pattern — regex for text patterns, AST for Python semantics.
3. Emit a `Finding` with the appropriate `compliance_dimensions`.
4. Add a fixture case under `tests/fixtures/sample_project/` that contains the pattern.
5. Add a test asserting the finding is produced, and a benchmark case for it (see below).
6. Open a PR with a 1-sentence description of what the pattern is and which regulation obligation it supports.

**Please include an article reference** (e.g. "Art. 14(4)") so reviewers can verify the mapping.

### Turning a report into a regression test

Users report problems with `/ai-act-feedback` or the issue forms. Titles start with `[false positive]`, `[missed gap]`, `[confusing]` or `[install]`. A confirmed false positive or missed gap is fixed through the benchmark, so the fix is measured and cannot quietly come back:

1. **Reproduce it with a small, made-up sample.** Never use a reporter's code; the forms ask for a made-up example for this reason.
2. **Add a `BenchmarkSample` to `_BENCHMARK_CORPUS`** in `scanner/benchmark.py`, with an id that says what it guards:
   - a false positive becomes a decoy: `expect_finding=False`, the `analyzer_id` that misfired, and `expected_finding_id` set to the finding (or a prefix ending in `*`);
   - a missed gap becomes a positive case: `expect_finding=True` with the finding the analyzer should emit.

   Put the reporter's reasoning in `rationale`, in one sentence.
3. **Fix the analyzer** under `scanner/analyzers/` until `antifragile-scan --benchmark` is back to full precision and recall. `tests/test_scanner_precision_upgrades.py` fails on any miss.
4. **Reference the issue in the PR**, and note in the CHANGELOG which pattern no longer misfires or is now caught.

Reasons that users give in `[[suppress]]` entries (see the README's "Feedback and exceptions") are the same kind of evidence. When several teams suppress one rule for the same reason, that rule needs a benchmark case.

`[confusing]` reports usually mean a fix to the brief's wording in `scanner/founder_triage.py` or to a skill under `skills/`. `[install]` reports go to the README's troubleshooting notes, or to the CI job that starts the plugin's MCP server (`scripts/check_plugin_mcp.py`).

### Adding a new dimension or article mapping

The KB (`scanner/kb.py`) maps dimensions to articles. If an article is missing or mis-mapped:

1. Open an issue first so we can align on the mapping.
2. If agreed, submit a PR updating `DIMENSIONS` and `ARTICLE_TO_DIMENSIONS` together.
3. Include a citation — specific article paragraph number, not a general reference.

### Documentation / README / skill improvements

Especially welcome for the `skills/` content — those drive how Claude Code narrates findings to end users, and clearer narration means fewer misinterpretations.

## Guardrails

- **No network calls in analyzers.** The scanner's privacy guarantee is that code never leaves the user's machine. Don't break that. Semantic depth lives in the host Claude Code session (assisted mode, your existing subscription) or an MCP client — never a headless wrapper. Generated artifacts are held to the same bar: the context graph inlines its own CSS, `tests/test_offline_artifacts.py` fails on any remote asset in any report (and on a URL outside a provenance field in JSON), and an AST guard forbids outbound HTTP clients in `scanner/`.
- **Don't let generated artifacts go stale.** `scanner/data/graph.css` is compiled from the page template; if you add a utility class, regenerate it and commit the CSS with the template change.
- **Don't invent regulation content.** If you're unsure of an article's exact requirement, cite the article number and describe what you observed, not what you remember or assume.
- **Scores must be in [0, 100].** There's a regression test for this — a previous version of the scanner let negative scores through.
- **Tests must pass.** `pytest` is the gate. If you're changing analyzer output intentionally, update the fixture assertions.

## PR template

When you open a PR, include:

1. **What** — one sentence describing the change
2. **Why** — regulatory obligation or issue this addresses (with article reference when relevant)
3. **How the scanner sees it** — what fixture or user-visible scan output changes
4. **Risk** — any known edge cases or false-positive risks

## Code of conduct

Be kind. Assume good faith. Regulation is hard, compliance is harder, and everyone here is trying to help teams ship AI responsibly.

## Questions

Open an issue at [github.com/Peaky8linders/antifragile-harness/issues](https://github.com/Peaky8linders/antifragile-harness/issues). Label with `question` if you're not sure whether something is a bug.
