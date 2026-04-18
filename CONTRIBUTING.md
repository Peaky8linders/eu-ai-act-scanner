# Contributing to EU AI Act Scanner

Thanks for considering a contribution. The regulation is moving fast and the patterns teams use for compliance evidence evolve with it — we need the community's help to keep the analyzers sharp.

## Quick dev loop

```bash
git clone https://github.com/Peaky8linders/eu-ai-act-scanner
cd eu-ai-act-scanner
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .

# Try the CLI against the fixture
eu-ai-act-scan tests/fixtures/sample_project --markdown
```

## What makes a good contribution

### Adding / extending an analyzer

The single most valuable kind of contribution. If the scanner missed a legitimate control pattern you use, add it.

1. Find the relevant analyzer under `scanner/analyzers/` (or create a new one).
2. Add the pattern — regex for text patterns, AST for Python semantics.
3. Emit a `Finding` with the appropriate `compliance_dimensions`.
4. Add a fixture case under `tests/fixtures/sample_project/` that contains the pattern.
5. Add a test asserting the finding is produced.
6. Open a PR with a 1-sentence description of what the pattern is and which regulation obligation it supports.

**Please include an article reference** (e.g. "Art. 14(4)") so reviewers can verify the mapping.

### Fixing a false positive

If the scanner flags something as a gap that isn't actually a gap, we want to know.

1. Provide the minimal reproducer (file content + scanner output).
2. Explain why it's a false positive.
3. Either submit a fix or open an issue with the context.

### Adding a new dimension or article mapping

The KB (`scanner/kb.py`) maps dimensions to articles. If an article is missing or mis-mapped:

1. Open an issue first so we can align on the mapping.
2. If agreed, submit a PR updating `DIMENSIONS` and `ARTICLE_TO_DIMENSIONS` together.
3. Include a citation — specific article paragraph number, not a general reference.

### Documentation / README / skill improvements

Especially welcome for the `skills/` content — those drive how Claude Code narrates findings to end users, and clearer narration means fewer misinterpretations.

## Guardrails

- **No network calls in analyzers.** The scanner's privacy guarantee is that code never leaves the user's machine. Don't break that. LLM features live behind the `EU_AI_ACT_SCANNER_LLM` flag and are opt-in.
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

Open an issue at [github.com/Peaky8linders/eu-ai-act-scanner/issues](https://github.com/Peaky8linders/eu-ai-act-scanner/issues). Label with `question` if you're not sure whether something is a bug.
