"""Scanner base models shared by all specialized analyzers.

Provides:
- Pydantic models (Finding, AnalyzerResult, AnalyzerContext)
- Regex/file helpers (search_files, has_file, etc.)
- AST helpers (parse_python_imports, parse_python_functions, etc.)
- Optional LLM helper (llm_assess) gated by EU_AI_ACT_SCANNER_LLM env var
"""

from __future__ import annotations

import ast
import os
import re
from typing import Literal

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)


class Finding(BaseModel):
    """A single piece of evidence discovered by an analyzer.

    Agentic-AI taxonomy fields (added in v0.3, all default empty):

    * ``compound_risk_type`` — one of
      :class:`scanner.data.agentic_taxonomy.CompoundRiskType` values
      (cascading / emergent / attribution / temporal). Empty when the
      finding is not specifically agentic.
    * ``applicable_roles`` — operator-role IDs that owe the related
      obligation. Empty = applies to every role (legacy behaviour).
    * ``threat_categories`` — IDs from
      :class:`scanner.data.agentic_taxonomy.ThreatCategory`.
    """
    id: str = Field(description="Unique within analyzer, e.g. 'af-version-pin'")
    category: str = Field(description="Analyzer ID, e.g. 'ai_frameworks'")
    title: str
    description: str
    file_path: str
    confidence: float = Field(ge=0.0, le=1.0)
    compliance_impact: Literal["positive", "neutral", "gap"]
    compliance_dimensions: list[str] = Field(default_factory=list)
    evidence_snippet: str = Field(default="", max_length=200)
    kb_question_ids: list[str] = Field(default_factory=list)
    suggested_answer: Literal["yes", "partial", "no"] | None = None
    article_paragraphs: list[str] = Field(default_factory=list)
    iac_artifact_type: Literal["terraform", "cloudformation", "kubernetes",
                               "github_actions", "dockerfile", "compose"] | None = None
    # ── Agentic-AI compound-risk grounding (paper §10.4) ────────────────
    compound_risk_type: str = Field(default="", max_length=64)
    applicable_roles: list[str] = Field(default_factory=list, max_length=16)
    threat_categories: list[str] = Field(default_factory=list, max_length=16)


class AnalyzerResult(BaseModel):
    """Return type of every specialized analyzer."""
    analyzer_id: str
    label: str
    findings: list[Finding] = Field(default_factory=list)
    score: float = Field(ge=0.0, le=100.0, default=0.0)
    file_count: int = Field(ge=0, default=0)
    graph_node_type: str = "model"
    graph_icon: str = ""
    connected_categories: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class AnalyzerContext(BaseModel):
    """Shared input to all analyzers — constructed once from the scanned project tree."""
    model_config = {"arbitrary_types_allowed": True}

    files: dict[str, str] = Field(default_factory=dict, description="path → content (text only)")
    file_list: list[str] = Field(default_factory=list, description="All paths including binary")
    binary_files: dict[str, int] = Field(default_factory=dict, description="path → size")
    languages: dict[str, int] = Field(default_factory=dict, description="lang → count")


# ─── Helpers for analyzers ──────────────────────────────────────────────


def search_files(ctx: AnalyzerContext, pattern: str, flags: int = re.IGNORECASE) -> list[tuple[str, str]]:
    """Search all text files for a regex pattern. Returns [(file_path, matched_line)]."""
    try:
        compiled = re.compile(pattern, flags)
    except re.error:
        logger.warning("search_files_bad_pattern", pattern=pattern[:50])
        return []
    results = []
    for path, content in ctx.files.items():
        for line in content.split("\n"):
            if compiled.search(line):
                results.append((path, line.strip()[:200]))
                break  # one match per file is enough
    return results


def has_file(ctx: AnalyzerContext, pattern: str) -> list[str]:
    """Find files matching a regex pattern (case-insensitive)."""
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error:
        logger.warning("has_file_bad_pattern", pattern=pattern[:50])
        return []
    return [p for p in ctx.file_list if compiled.search(p)]


def count_matches(ctx: AnalyzerContext, pattern: str) -> int:
    """Count files containing a pattern."""
    return len(search_files(ctx, pattern))


def file_content(ctx: AnalyzerContext, path: str) -> str | None:
    """Get content of a specific file (case-insensitive match)."""
    path_lower = path.lower()
    for p, content in ctx.files.items():
        if p.lower() == path_lower or p.lower().endswith("/" + path_lower):
            return content
    return None


def any_file_contains(ctx: AnalyzerContext, filenames: list[str]) -> list[str]:
    """Check which of the given filenames exist in the project."""
    found = []
    file_list_lower = {p.lower(): p for p in ctx.file_list}
    for name in filenames:
        name_lower = name.lower()
        for path_lower, path in file_list_lower.items():
            if path_lower.endswith(name_lower) or path_lower.endswith("/" + name_lower):
                found.append(path)
                break
    return found


# ─── AST Helpers (Python files only) ────────────────────────────────────


class PythonImport(BaseModel):
    """A resolved Python import from AST analysis."""
    module: str
    names: list[str] = Field(default_factory=list)
    is_from: bool = False
    file_path: str = ""
    line: int = 0


class PythonFunction(BaseModel):
    """A Python function/method extracted from AST."""
    name: str
    file_path: str = ""
    line: int = 0
    decorators: list[str] = Field(default_factory=list)
    has_docstring: bool = False
    arg_count: int = 0
    is_test: bool = False
    is_async: bool = False


class PythonClass(BaseModel):
    """A Python class extracted from AST."""
    name: str
    file_path: str = ""
    line: int = 0
    bases: list[str] = Field(default_factory=list)
    method_count: int = 0
    has_docstring: bool = False


def _safe_parse_ast(content: str) -> ast.Module | None:
    """Parse Python source into AST, returning None on syntax errors."""
    try:
        return ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        return None


def parse_python_imports(ctx: AnalyzerContext) -> list[PythonImport]:
    """Extract all imports from Python files using AST."""
    imports: list[PythonImport] = []
    for path, content in ctx.files.items():
        if not path.endswith(".py"):
            continue
        tree = _safe_parse_ast(content)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(PythonImport(
                        module=alias.name,
                        names=[alias.asname or alias.name],
                        is_from=False,
                        file_path=path,
                        line=node.lineno,
                    ))
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(PythonImport(
                        module=node.module,
                        names=[a.name for a in (node.names or [])],
                        is_from=True,
                        file_path=path,
                        line=node.lineno,
                    ))
    return imports


def parse_python_functions(ctx: AnalyzerContext) -> list[PythonFunction]:
    """Extract all function/method definitions from Python files using AST."""
    functions: list[PythonFunction] = []
    for path, content in ctx.files.items():
        if not path.endswith(".py"):
            continue
        tree = _safe_parse_ast(content)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decorators = []
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Name):
                        decorators.append(dec.id)
                    elif isinstance(dec, ast.Attribute):
                        decorators.append(ast.dump(dec))
                    elif isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Name):
                            decorators.append(dec.func.id)
                        elif isinstance(dec.func, ast.Attribute):
                            decorators.append(dec.func.attr)

                has_docstring = (
                    isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, (ast.Constant, ast.Str))
                    if node.body else False
                )

                functions.append(PythonFunction(
                    name=node.name,
                    file_path=path,
                    line=node.lineno,
                    decorators=decorators,
                    has_docstring=has_docstring,
                    arg_count=len(node.args.args),
                    is_test=node.name.startswith("test_") or node.name.startswith("test"),
                    is_async=isinstance(node, ast.AsyncFunctionDef),
                ))
    return functions


def parse_python_classes(ctx: AnalyzerContext) -> list[PythonClass]:
    """Extract all class definitions from Python files using AST."""
    classes: list[PythonClass] = []
    for path, content in ctx.files.items():
        if not path.endswith(".py"):
            continue
        tree = _safe_parse_ast(content)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                bases = []
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        bases.append(base.id)
                    elif isinstance(base, ast.Attribute):
                        bases.append(f"{ast.dump(base)}")
                methods = sum(1 for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
                has_docstring = (
                    isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, (ast.Constant, ast.Str))
                    if node.body else False
                )
                classes.append(PythonClass(
                    name=node.name,
                    file_path=path,
                    line=node.lineno,
                    bases=bases,
                    method_count=methods,
                    has_docstring=has_docstring,
                ))
    return classes


def get_docstring_coverage(ctx: AnalyzerContext) -> tuple[int, int]:
    """Count functions with/without docstrings across all Python files.

    Returns (documented_count, total_count) for non-test, non-private functions.
    """
    fns = parse_python_functions(ctx)
    public_fns = [f for f in fns if not f.is_test and not f.name.startswith("_")]
    documented = sum(1 for f in public_fns if f.has_docstring)
    return documented, len(public_fns)


def get_import_modules(ctx: AnalyzerContext) -> set[str]:
    """Get the set of all top-level imported module names (e.g. 'torch' not 'torch.nn')."""
    imports = parse_python_imports(ctx)
    return {imp.module.split(".")[0] for imp in imports}


# ─── LLM Helpers (optional semantic analysis) ───────────────────────────


_LLM_ENABLED = os.getenv("EU_AI_ACT_SCANNER_LLM", "false").lower() in ("true", "1", "yes")
_LLM_MODEL = os.getenv("EU_AI_ACT_SCANNER_LLM_MODEL", "claude-haiku-4-5-20251001")
_LLM_MAX_INPUT = 4000


class LLMAssessment(BaseModel):
    """Result of LLM-based semantic analysis."""
    score: float = Field(ge=0.0, le=1.0, default=0.5)
    reasoning: str = ""
    findings: list[str] = Field(default_factory=list)
    error: str | None = None


def llm_assess(prompt: str, content: str, max_input: int = _LLM_MAX_INPUT) -> LLMAssessment:
    """Run optional LLM assessment on content.

    Only runs if EU_AI_ACT_SCANNER_LLM=true. Uses Haiku by default.
    Falls back gracefully — never blocks the scan.
    """
    if not _LLM_ENABLED:
        return LLMAssessment(error="LLM scanner disabled (EU_AI_ACT_SCANNER_LLM=false)")

    try:
        import anthropic

        client = anthropic.Anthropic()
        truncated = content[:max_input]

        response = client.messages.create(
            model=_LLM_MODEL,
            max_tokens=500,
            system=prompt,
            messages=[{"role": "user", "content": truncated}],
        )

        text = response.content[0].text if response.content else ""

        import json
        try:
            parsed = json.loads(text)
            return LLMAssessment(
                score=min(max(float(parsed.get("score", 0.5)), 0), 1),
                reasoning=str(parsed.get("reasoning", "")),
                findings=list(parsed.get("findings", [])),
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            return LLMAssessment(score=0.5, reasoning=text[:200])

    except ImportError:
        return LLMAssessment(error="anthropic SDK not installed")
    except Exception as exc:
        logger.warning("llm_assess_failed", error=str(exc)[:100])
        return LLMAssessment(error=f"LLM call failed: {str(exc)[:100]}")
