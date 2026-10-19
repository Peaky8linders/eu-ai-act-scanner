"""Scanner base models shared by all specialized analyzers.

Provides:
- Pydantic models (Finding, AnalyzerResult, AnalyzerContext)
- Regex/file helpers (search_files, has_file, etc.)
- AST helpers (parse_python_imports, parse_python_functions, etc.)
- Compatibility stub (llm_assess) — semantic review lives in the host Claude Code / MCP client
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
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
    # ── Real-world incident grounding (v0.4) ────────────────────────────
    # IDs from the vendored GenAI-incidents corpus (e.g. "INC-00671") that
    # exploited this gap class. Populated post-analysis by
    # ``scanner.incident_grounding`` — empty when the finding has no
    # crosswalkable threat/dimension signal, or for positive evidence.
    related_incidents: list[str] = Field(default_factory=list, max_length=8)


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


# Extensions treated as source/config code by search_code_files.
_CODE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".rs", ".go",
    ".r", ".jl", ".rb", ".c", ".cpp", ".cs", ".swift", ".kt",
    ".scala", ".sh", ".yaml", ".yml", ".toml", ".cfg", ".ini",
    ".tf", ".hcl", ".dockerfile",
})

# Lines that define a detector rather than exhibit a pattern.
_DETECTOR_DEF_RE = re.compile(r"_(PATTERNS?|SIGNALS?|REGEX)\s*[:=]")

# Single-line string-literal spans (raw or not) — detector tables mention
# patterns inside string literals (`(r"torch\\.load...", "torch.load ...")`)
# while real operational calls live outside them. Masking literals before
# matching stops table self-matches. Detectors that intentionally look *inside*
# string content (e.g. `model = "gpt-4"` literals) must use search_files
# directly instead of this helper.
_STR_LITERAL_RE = re.compile(r"[rR]?(\"[^\"\n]*\"|'[^'\n]*')")

# Triple-quoted spans — module/class docstrings are prose, not code. The
# analyzer's own docstring ("emerging stacks (AG2, OpenDevin, MetaGPT)")
# must not count as a runtime dependency. Blanked line-preservingly so
# evidence snippets still align with original lines.
_TRIPLE_QUOTED_RE = re.compile(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'')


def search_code_files(
    ctx: AnalyzerContext,
    pattern: str,
    flags: int = re.IGNORECASE,
    *,
    mask_strings: bool = True,
) -> list[tuple[str, str]]:
    """Search code/config files for a regex pattern — prose- and self-match-free.

    Same contract as :func:`search_files` (one ``(path, line)`` per file) but:

    * only source/config extensions (``_CODE_EXTENSIONS``) — README/CHANGELOG/
      vendored-JSON prose never counts as code evidence;
    * full-line comments (``#``, ``//``) are skipped — a heuristic description
      is not an implementation;
    * trailing comments are stripped too (extension-aware: ``#`` for
      Python/TOML/YAML/shell, ``//`` for JS/TS/C-family — never Python's ``//``
      floor division or a ``://`` URL). A comment that documents a pattern next
      to the detector table was matching as evidence.
    * detector-definition lines are skipped — a ``search_files(...)`` call or a
      ``*_PATTERNS``/``*_SIGNALS``/``*_REGEX`` assignment inside an analyzer
      is the detector describing itself, not target code exhibiting the pattern.
    """
    try:
        compiled = re.compile(pattern, flags)
    except re.error:
        logger.warning("search_code_files_bad_pattern", pattern=pattern[:50])
        return []
    results = []
    for path, content in ctx.files.items():
        suffix = Path(path).suffix.lower()
        if suffix not in _CODE_EXTENSIONS:
            continue
        masked = _TRIPLE_QUOTED_RE.sub(
            lambda m: "\n" * m.group(0).count("\n"), content
        )
        for line, mline in zip(content.split("\n"), masked.split("\n"), strict=True):
            stripped = mline.strip()
            if not stripped:
                continue
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if "search_files(" in mline:
                continue
            if _DETECTOR_DEF_RE.search(mline):
                continue
            # Patterns that themselves look inside string content (they contain
            # a quote) match against the raw line — e.g. `model = "gpt-4"`
            # literals. All other patterns match against the literal-masked
            # line so detector-table strings never count as code evidence.
            # Table self-match stays impossible either way: tables spell
            # patterns with regex escapes (`\\s`), which never satisfy the
            # live pattern adjacent to the quote.
            if not mask_strings or '"' in pattern or "'" in pattern:
                probe = mline
            else:
                probe = _STR_LITERAL_RE.sub(lambda m: " " * len(m.group(0)), mline)
            probe = _strip_trailing_comment(probe, suffix)
            if compiled.search(probe):
                results.append((path, line.strip()[:200]))
                break
    return results


# Comment syntax per extension family. Only these two styles are handled; a
# line-continuation comment (`/* */`) is not stripped because our detector
# tables do not use it and stripping it could cut real code.
_HASH_COMMENT_EXTENSIONS = frozenset({
    ".py", ".rb", ".sh", ".toml", ".yaml", ".yml", ".cfg", ".ini",
    ".tf", ".hcl", ".dockerfile", ".r", ".jl", ".pl", ".ps1",
})
_SLASH_COMMENT_EXTENSIONS = frozenset({
    ".js", ".jsx", ".ts", ".tsx", ".java", ".rs", ".go", ".c", ".cpp",
    ".h", ".cs", ".swift", ".kt", ".scala",
})
_HASH_COMMENT_RE = re.compile(r"(?:^|(?<=\s))#")


# `//` that is not `://` and not Python's floor-division operator (Python never
# reaches this branch — it is not in _SLASH_COMMENT_EXTENSIONS).
_SLASH_COMMENT_RE = re.compile(r"(?<!:)//")


def _strip_trailing_comment(line: str, suffix: str) -> str:
    """Drop a line's trailing comment, honouring the file's comment syntax.

    Called after string literals are masked, so a ``#`` or ``//`` that survives
    is (almost always) a real comment marker rather than text inside a string.
    """
    if suffix in _HASH_COMMENT_EXTENSIONS:
        marker = _HASH_COMMENT_RE.search(line)
        if marker:
            return line[: marker.start()]
    elif suffix in _SLASH_COMMENT_EXTENSIONS:
        marker = _SLASH_COMMENT_RE.search(line)
        if marker:
            return line[: marker.start()]
    return line


# Test/fixture trees: synthetic code (test harnesses, sample projects, string
# fixtures) describes a system, it does not run it. Using it as runtime
# evidence inflates detections (a fixture importing torch made the scanner
# classify itself as a classical-ML project) and raises phantom gaps.
_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|specs?|fixtures?|testdata|test_data|examples?)(/|$)"
    r"|(^|/)test_[^/]*\.py$"
    r"|(^|/)(conftest|setup_tests)\.py$"
    r"|_test\.py$"
    r"|\.(test|spec)\.[cm]?[jt]sx?$",
    re.IGNORECASE,
)


# Prompt assets are runtime artefacts even though they hold no SDK calls.
_PROMPT_ASSET_RE = re.compile(
    r"(^|/)(prompts?|prompt_templates?)/|\.(prompt|jinja2?|j2|mustache|tmpl)$",
    re.IGNORECASE,
)


def is_test_path(path: str) -> bool:
    """True for test/spec/fixture paths (synthetic code, not runtime evidence)."""
    return bool(_TEST_PATH_RE.search(path or ""))


def is_prompt_asset(path: str) -> bool:
    """True for prompt/template asset paths (md, txt, jinja, ...)."""
    return bool(_PROMPT_ASSET_RE.search(path or ""))


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
                    and isinstance(node.body[0].value, ast.Constant)
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
                    and isinstance(node.body[0].value, ast.Constant)
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

_LLM_MAX_INPUT = 4000


class LLMAssessment(BaseModel):
    """Result of LLM-based semantic analysis."""
    score: float = Field(ge=0.0, le=1.0, default=0.5)
    reasoning: str = ""
    findings: list[str] = Field(default_factory=list)
    error: str | None = None


def llm_assess(prompt: str, content: str, max_input: int = _LLM_MAX_INPUT) -> LLMAssessment:
    """Compatibility stub — always defers to host Claude Code / MCP.

    The Claude Max subscription wrapper was removed. Semantic assessment now
    runs in the host Claude Code session (assisted mode, your existing
    subscription) or an MCP client over the scanner tools. Kept so existing
    analyzer call sites keep working without network calls.
    """
    return LLMAssessment(
        error=(
            "Semantic assessment lives in the host Claude Code session "
            "(assisted mode) or an MCP client — no headless bridge."
        )
    )
