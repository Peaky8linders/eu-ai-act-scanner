"""Precision regression tests — the scanner must not flag prose, comments,
or its own detector definitions as code evidence.

Grounded in a real self-scan of this repo, which surfaced:
- framework/runtime detections from README/CHANGELOG prose,
- `torch.load` "unsafe loading" gaps whose evidence was the analyzer's own
  pattern table,
- classical-ML detection from a `# .fit(` code comment,
- 11 agent runtimes aggregated from vendored-docs keyword soup,
- findings reported against a stale `.claude/worktrees` copy of deleted code.
"""

from __future__ import annotations

from scanner.analyzers import AnalyzerContext
from scanner.analyzers._base import search_code_files, search_files


def _ctx(files: dict[str, str]) -> AnalyzerContext:
    return AnalyzerContext(
        files=files,
        file_list=sorted(files),
        binary_files={},
        languages={},
    )


def test_prose_files_never_count_as_code_evidence() -> None:
    ctx = _ctx({
        "README.md": "| `langchain` | agents | Art. 15 |\nWe use crewai and ag2 heavily.\n",
        "CHANGELOG.md": "- `agent_inventory` detects MCP clients, OpenAI Assistants v2\n",
        "src/app.py": "print('hello')\n",
    })
    assert search_files(ctx, r"\blangchain\b")  # prose DOES match the broad helper
    assert search_code_files(ctx, r"\blangchain\b") == []
    assert search_code_files(ctx, r"\bcrewai\b") == []
    assert search_code_files(ctx, r"\bag2\b") == []


def test_full_line_comments_are_not_implementations() -> None:
    ctx = _ctx({
        "src/notes.py": "# don't use .fit( here — use .train() instead\nx = 1\n",
        "src/model.py": "model.fit(X, y)\n",
    })
    hits = search_code_files(ctx, r"\.fit\s*\(")
    assert [p for p, _ in hits] == ["src/model.py"]


def test_detector_definitions_are_not_evidence() -> None:
    ctx = _ctx({
        "scanner/analyzers/example.py": (
            "_UNSAFE_LOAD = [\n"
            '    (r\"torch\\.load\\s*\\(\", \"torch.load (pickle-based, unsafe)\"),\n'
            "]\n"
            "matches = search_files(ctx, pat)\n"
        ),
        "src/safe.py": "x = 1\n",
    })
    assert search_code_files(ctx, r"torch\.load\s*\(") == []
    assert search_code_files(ctx, r"search_files") == []


def test_docstring_prose_is_not_code_evidence() -> None:
    ctx = _ctx({
        "src/agents.py": '"""Emerging multi-agent stacks (AG2, OpenDevin, MetaGPT) live here."""\nimport os\n',
        "src/real.py": "import crewai\n",
    })
    assert search_code_files(ctx, r"\bmetagpt\b") == []
    assert search_code_files(ctx, r"\bag2\b") == []
    assert [p for p, _ in search_code_files(ctx, r"\bcrewai\b")] == ["src/real.py"]


def test_ai_frameworks_does_not_flag_its_own_pattern_table(tmp_path=None) -> None:
    from scanner.analyzers.ai_frameworks import analyze_ai_frameworks

    ctx = _ctx({
        "scanner/analyzers/ai_frameworks.py": (
            "_UNSAFE_LOAD = [\n"
            '    (r\"torch\\.load\\s*\\(\", \"torch.load (pickle-based, unsafe)\"),\n'
            '    (r\"pickle\\.load\\s*\\(\", \"pickle.load\"),\n'
            "]\n"
        ),
    })
    result = analyze_ai_frameworks(ctx)
    unsafe = [f for f in result.findings if f.id.startswith("af-unsafe-")]
    assert unsafe == []
    assert not result.metadata["detected"]


def test_model_typology_ignores_commented_fit_and_detector_table() -> None:
    from scanner.analyzers.model_typology import analyze_model_typology

    ctx = _ctx({
        "src/notes.py": "# .fit( and .predict( describe the heuristic below\n",
        "scanner/analyzers/model_typology.py": (
            "_CML_REGEX_PATTERNS = [\n"
            '    (r\"\\.fit\\s*\\(|\\.predict\\s*\\(\", \"fit/predict call\"),\n'
            "]\n"
        ),
    })
    result = analyze_model_typology(ctx)
    assert result.metadata["typology"] == "none"
    assert [f for f in result.findings if f.id == "mt-no-ml-signals"]


def test_agent_inventory_ignores_prose_runtime_mentions() -> None:
    from scanner.analyzers.agent_inventory import analyze_agent_inventory

    ctx = _ctx({
        "README.md": "We evaluated crewai, ag2, metagpt and opendevin for the roadmap.\n",
        "src/main.py": "print('no agents here')\n",
    })
    result = analyze_agent_inventory(ctx)
    assert result.metadata["runtime_signals"] == []
    assert result.metadata["autonomy_axis"] == "none"
    assert result.score == 80.0
