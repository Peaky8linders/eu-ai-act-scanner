"""Article 50 transparency analyzer — AST/TS use-vs-mention synthetic-content & disclosure detector.

Detects Article 50 transparency conformance deterministically over ``ctx.files``.
Art. 50 is one of the few obligations fully fine-enforceable from **2 Aug 2026**
— the Digital Omnibus deferred the high-risk Annex III regime to 2 Dec 2027 but
left Art. 50 untouched — and the June-2026 Transparency Code of Practice points
implementers at C2PA content credentials and IPTC DigitalSourceType provenance
metadata for the machine-readable marking required by Art. 50(2).

Five transparency obligations are checked over ``ctx.files``:

* **Art. 50(1)** — a natural-person-facing chatbot / assistant must disclose
  it is an AI system (provider).
* **Art. 50(2)** — synthetically generated image/audio/video/text must be
  marked machine-readably (C2PA / watermark / IPTC provenance) — provider,
  including GPAI.
* **Art. 50(3)** — an emotion-recognition / biometric-categorisation system
  must notify the natural persons exposed to it (deployer).
* **Art. 50(4)** — deep-fake / synthetic-media content must be labelled, and
  AI-generated text published to inform the public on matters of public
  interest must be disclosed as artificially generated (deployer).

Grounds to the ``content_transparency`` + ``transparency`` KB dimensions.

**Asymmetric detection (use vs. mention):**
* **Surfaces** (chat / generation / deep-fake / emotion / public-interest text)
  are scanned over code regions (AST callsites with ``include_declarations=False``
  + live single-line string literals, TS/JS lexical tokens, and dependency
  manifests), skipping prose docs, comments, test fixtures, and self-references.
* **Controls** (Art. 50(2) marking, Art. 50(1)/(4) disclosure, Art. 50(3)
  exposure notice) are scanned with a hard gate: executable constructs (excluding
  disabled-literal assignments like ``c2pa_marking = False`` / ``"disabled"``)
  or live, non-deferred single-line string literals in non-test product source
  only. A README mentioning "C2PA on roadmap" or a disabled config flag can
  never manufacture a false pass.
"""

from __future__ import annotations

import ast
import re

import structlog
from pydantic import BaseModel, Field

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    _cached_ast,
)
from scanner.data.role_obligations import ROLE_DEPLOYER, ROLE_PROVIDER

logger = structlog.get_logger(__name__)


# ─── Signal models — reusable seam ───────────────────────────────────────


class Art50Signal(BaseModel):
    """One detected Art. 50 surface or control, with the region that proved it."""

    present: bool = False
    file_path: str = ""
    snippet: str = ""


class Art50GenerationSignal(Art50Signal):
    """The synthetic-content generation surface, plus the modalities proven.

    ``modalities`` carries ONLY the modalities that the matched pattern itself
    names (image / audio / video). Vendor patterns (``dall-e``, ``elevenlabs``,
    ``sora``, ``stable-diffusion``) prove the surface but contribute no
    modality because brands are multi-modal.
    """

    modalities: list[str] = Field(default_factory=list)


class Art50Signals(BaseModel):
    """The nine Art. 50 surfaces and controls ``analyze_article_50_transparency`` decides on."""

    chat: Art50Signal
    generation: Art50GenerationSignal
    deepfake: Art50Signal
    emotion: Art50Signal
    ai_text: Art50Signal
    marking: Art50Signal
    disclosure: Art50Signal
    ai_generated_label: Art50Signal
    emotion_notice: Art50Signal


# ─── Surface banks — region-gated; a mention is not a use ────────────────

_CHAT_PATTERNS = [
    r"chat\.completions|ChatCompletion|messages\.create|responses\.create",
    r"\b(chatbot|assistant|conversation(al)?)\b",
    r"langchain|llama[-_]?index|llm\.(invoke|chat|complete)",
]

# ``(pattern, modality)`` — modality populated only where every alternative names it.
_GENERATION_PATTERNS: list[tuple[str, str]] = [
    (
        r"generate_image|images?\.generate|images?/generations?|image\.create"
        r"|text[-_]?to[-_]?image",
        "image",
    ),
    (r"\btts\b|text[-_]?to[-_]?speech|speech[-_]?synth", "audio"),
    (r"text[-_]?to[-_]?video|video\.generate", "video"),
    (r"dall[-_ ]?e|stable[-_ ]?diffusion|midjourney|flux\.1|imagen", ""),
    (r"elevenlabs|sora\b|runwayml|runway[-_.]ml", ""),
]

_MANIFESTS = (
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "pipfile",
    "package.json", "go.mod", "cargo.toml", "gemfile", "build.gradle",
)

_DEEPFAKE_PATTERNS = [
    r"face[-_ ]?swap|faceswap|deep[-_ ]?fake|deepfake",
    r"voice[-_ ]?clon|voice[-_ ]?conversion|speaker[-_ ]?adapt",
    r"lip[-_ ]?sync|wav2lip|sadtalker|\broop\b|reenact",
]

# ─── Control banks — hard-gated (over-fire => false pass => never) ───────

# Art. 50(2) marking CONTROL — executable constructs only (C2PA, SynthID,
# steganographic/invisible watermarks, IPTC DigitalSourceType / content_provenance).
_MARKING_CALLSITE = [
    r"\bc2pa\b|contentcredentials|content_credential",
    r"\bsynthid\b",
    r"imwatermark|invisible[-_]?watermark|blind[-_]?watermark|stegan",
    r"add_watermark|embed_watermark|apply_watermark|sign_manifest",
    r"content_provenance|contentprovenance",
    r"digital[-_]?source[-_]?type|trainedalgorithmicmedia",
]

# Art. 50(1)/50(4) disclosure CONTROL — live copy literals only.
# (pattern, mode): "sentence" = re.search inside literal;
#                  "label"    = re.fullmatch of the whole literal.
_DISCLOSURE_COPY = [
    (r"you\s+are\s+(chatting|talking|interacting|speaking)\s+with\s+an?\s+ai", "sentence"),
    (r"this\s+is\s+an?\s+ai\b(?![-\w])|i(\s+a|')m\s+an?\s+ai|not\s+a\s+human", "sentence"),
    (r"\bai\s+assistant\b|\bautomated\s+assistant\b", "sentence"),
    (r"\s*ai[-\s]?generated\s*", "label"),
]

# Label-mode subset of _DISCLOSURE_COPY for Art. 50(4) ct-3 gating.
_DISCLOSURE_LABEL = [(pattern, mode) for pattern, mode in _DISCLOSURE_COPY if mode == "label"]

# Art. 50(3) emotion-recognition / biometric-categorisation surface.
_EMOTION_BIOMETRIC_PATTERNS = [
    r"emotion[-_ ]?recogni|affect(ive)?[-_ ]?comput|facial[-_ ]?expression|micro[-_ ]?expression",
    r"biometric[-_ ]?categor|\bdeepface\b|fer[-_ ]?2013|ferplus|py[-_ ]?feat|\baffectnet\b",
    r"(emotion|mood|affect)[-_ ]?(from|detect|classif|analy).{0,12}(face|voice|webcam|camera|speech)",
]

# Art. 50(3) exposure notice CONTROL — copy-only (a notice is shown, never called).
_EMO_NOTICE_COPY = [
    (r"you\s+are\s+being\s+(analy[sz]ed|assessed|recorded|scanned)", "sentence"),
]

# Art. 50(4) 2nd limb — AI-generated public-interest text (gated on chat/gen).
_AI_TEXT_PUBLIC_PATTERNS = [
    r"news[-_ ]?(article|story|room|desk|generat)|newsroom|auto[-_ ]?journal|journalism",
    r"press[-_ ]?release",
    r"public[-_ ]?interest[-_ ]?(text|content|article)",
    r"(article|op[-_ ]?ed|editorial)[-_ ]?(generat|writer|bot)",
]

_MAX_FINDINGS = 25
_ROLES = [ROLE_PROVIDER, ROLE_DEPLOYER]

_CODE_EXTS = (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs")
_DOC_EXTS = (".md", ".mdx", ".rst", ".txt", ".ipynb")

_NON_PRODUCT_SEGMENTS = frozenset({
    "test", "tests", "__tests__", "fixture", "fixtures", "example", "examples",
    "sample", "samples", "doc", "docs", "script", "scripts", "demo", "demos",
    "benchmark", "benchmarks", "node_modules", "dist", "build",
})
_NON_PRODUCT_FILE_RE = re.compile(
    r"(^|/)(test_[^/]+|conftest)\.py$|[^/]*\.(spec|test)\.[jt]sx?$", re.IGNORECASE
)

_DEFERRAL_RE = re.compile(
    r"roadmap|out[-\s]of[-\s]scope|not in scope|\bTODO\b|\bFIXME\b|planned|"
    r"not yet|coming soon|future work|we (plan|intend)",
    re.IGNORECASE,
)

_MAX_LITERAL_LEN = 200

# Self-reference guard so scanning this module never self-flags its own pattern banks.
_SELF_SENTINEL = "_MARKING_CALLSITE = ["


def _is_simulation(path: str, content: str = "") -> bool:
    """True when a file depicts another system (test fixture or detector source)."""
    low = path.lower().replace("\\", "/")
    if _SELF_SENTINEL in content:
        return True
    if _NON_PRODUCT_FILE_RE.search(low):
        return True
    return any(
        seg in {"test", "tests", "__tests__", "fixture", "fixtures"}
        for seg in low.split("/")[:-1]
    )


def _compile_surface(patterns: list[str]) -> list[re.Pattern[str]]:
    """Compile a surface bank, skipping any unusable pattern."""
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error:
            logger.debug("art50_bad_surface_pattern", pattern=pattern)
    return compiled


def _surface_regions(
    ctx: AnalyzerContext, path: str, content: str
) -> list[tuple[int, str]]:
    """The regions of ``path`` a SURFACE scan may read. Empty = not scannable."""
    low = path.lower().replace("\\", "/")
    if _is_simulation(path, content):
        return []
    # Check dependency manifests BEFORE the doc-extension skip (requirements.txt!).
    if low.rsplit("/", 1)[-1] in _MANIFESTS:
        return list(enumerate(content.splitlines(), start=1))
    if low.endswith(_DOC_EXTS):
        return []
    if low.endswith(".py"):
        tree = _cached_ast(ctx, path, content)
        if tree is None:
            return []
        # A string assigned to a KB label, detector regex, or schema field is
        # only a mention. Runtime calls/imports prove an actual surface; visible
        # disclosure copy is checked separately by the control scan.
        return _py_callsites(tree, include_declarations=False)
    if low.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs")):
        calls, copy = _ts_tokens(content)
        return calls + copy
    return []


def _scan_generation(ctx: AnalyzerContext) -> tuple[bool, str, str, list[str]]:
    """SURFACE scan for synthetic-content generation — modality-aware."""
    compiled: list[tuple[re.Pattern[str], str]] = []
    for pattern, modality in _GENERATION_PATTERNS:
        for rx in _compile_surface([pattern]):
            compiled.append((rx, modality))

    present, hit_file, hit_snippet = False, "", ""
    modalities: list[str] = []
    for path, content in ctx.files.items():
        regions = _surface_regions(ctx, path, content)
        if not regions:
            continue
        for rx, modality in compiled:
            for _lineno, text in regions:
                if rx.search(text):
                    if not present:
                        present, hit_file = True, path
                        hit_snippet = text.strip()[:200]
                    if modality and modality not in modalities:
                        modalities.append(modality)
                    break
    return present, hit_file, hit_snippet, modalities


def _scan_first(ctx: AnalyzerContext, patterns: list[str]) -> tuple[bool, str, str]:
    """SURFACE scan. Return (matched?, file_path, matched_snippet) for the first hit."""
    compiled = _compile_surface(patterns)
    for path, content in ctx.files.items():
        regions = _surface_regions(ctx, path, content)
        if not regions:
            continue
        for rx in compiled:
            for _lineno, text in regions:
                if rx.search(text):
                    return True, path, text.strip()[:200]
    return False, "", ""


def _is_product_code(path: str) -> bool:
    """A control may only be evidenced from non-test product source."""
    low = path.lower().replace("\\", "/")
    if not low.endswith(_CODE_EXTS):
        return False
    if _NON_PRODUCT_FILE_RE.search(low):
        return False
    return not any(seg in _NON_PRODUCT_SEGMENTS for seg in low.split("/")[:-1])


def _dotted(node: ast.AST) -> str:
    """Flatten a Name/Attribute/Call target to its dotted identifier."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


_DISABLED_LITERALS = frozenset({
    False, None, "", "disabled", "false", "off", "none", "absent",
    "n/a", "not_applicable", "no", "unmarked",
})


def _is_disabled_ast_value(val: ast.AST | None) -> bool:
    """True when an assigned value explicitly turns off or disables a control."""
    if val is None:
        return False
    if isinstance(val, ast.Constant):
        if val.value in _DISABLED_LITERALS:
            return True
        if isinstance(val.value, str) and val.value.strip().lower() in _DISABLED_LITERALS:
            return True
    elif isinstance(val, ast.UnaryOp) and isinstance(val.op, ast.Not):
        return True
    return False


def _py_callsites(
    tree: ast.Module, *, include_declarations: bool = True
) -> list[tuple[int, str]]:
    """(lineno, identifier) for executable constructs only.

    ``include_declarations=False`` is passed by SURFACE scans so schema field
    declarations (e.g. ``biometric_categorisation: bool = False``) do not raise
    phantom surfaces. CONTROLS keep ``include_declarations=True`` while still
    excluding explicitly disabled assignments via :func:`_is_disabled_ast_value`.
    """
    out: list[tuple[int, str]] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out += [(n.lineno, a.name) for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            out.append((n.lineno, n.module or ""))
            out += [(n.lineno, a.name) for a in n.names]
        elif isinstance(n, ast.Call):
            out.append((n.lineno, _dotted(n.func)))
        elif isinstance(n, ast.Attribute):
            out.append((n.lineno, n.attr))
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.append((n.lineno, n.name))
            out += [(n.lineno, _dotted(d)) for d in n.decorator_list]
        elif include_declarations and isinstance(n, ast.Assign):
            if not _is_disabled_ast_value(n.value):
                out += [(n.lineno, _dotted(t)) for t in n.targets]
        elif include_declarations and isinstance(n, ast.AnnAssign):
            if not _is_disabled_ast_value(n.value):
                out.append((n.lineno, _dotted(n.target)))
    return [(ln, s) for ln, s in out if s]


def _py_copy(tree: ast.Module) -> list[tuple[int, str]]:
    """(lineno, text) for live, short, single-line string literals only."""
    out: list[tuple[int, str]] = []

    def take(v: ast.AST | None) -> None:
        if (
            isinstance(v, ast.Constant)
            and isinstance(v.value, str)
            and "\n" not in v.value
            and len(v.value) <= _MAX_LITERAL_LEN
        ):
            out.append((v.lineno, v.value))

    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.Return)):
            take(n.value)
        elif isinstance(n, ast.Call):
            for a in n.args:
                take(a)
            for kw in n.keywords:
                take(kw.value)
    return out


_TS_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_TS_CALLSITE_RE = re.compile(
    r"\b([A-Za-z_$][\w$.]*)\s*\(|from\s+['\"]([^'\"]+)['\"]|require\(\s*['\"]([^'\"]+)['\"]"
    r"|<([A-Z][\w]*)|\b(?:const|let|var|function|class)\s+([A-Za-z_$][\w$]*)"
)
_TS_COPY_RE = re.compile(r"['\"`]([^'\"`\n]{1,200})['\"`]|>([^<>{}\n]{4,200})<")


def _ts_tokens(content: str) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """Lexical TS/JS tokeniser stripping comments first. Returns (callsites, copy)."""
    stripped = _TS_COMMENT_RE.sub(lambda m: " " * len(m.group(0)), content)
    calls: list[tuple[int, str]] = []
    copy: list[tuple[int, str]] = []
    for m in _TS_CALLSITE_RE.finditer(stripped):
        if m.group(5):
            after = stripped[m.end():m.end() + 60]
            if re.match(
                r"^\s*(?::\s*[\w<>[\]]+\s*)?=\s*(?:false|null|undefined|['\"](?:disabled|none|off|false|n/a)['\"])",
                after,
                re.IGNORECASE,
            ):
                continue
        tok = next((g for g in m.groups() if g), "")
        if tok:
            calls.append((stripped.count("\n", 0, m.start()) + 1, tok))
    for m in _TS_COPY_RE.finditer(stripped):
        tok = m.group(1) or m.group(2) or ""
        if tok.strip():
            copy.append((stripped.count("\n", 0, m.start()) + 1, tok.strip()))
    return calls, copy


def _scan_control(
    ctx: AnalyzerContext,
    callsite_patterns: list[str],
    copy_patterns: list[tuple[str, str]],
) -> tuple[bool, str, str]:
    """CONTROL scan — hard-gated: product code -> not simulation -> executable/live -> not deferred."""
    compiled_calls = [re.compile(p, re.IGNORECASE) for p in callsite_patterns]
    compiled_copy = [(re.compile(p, re.IGNORECASE), mode) for p, mode in copy_patterns]

    for path, content in ctx.files.items():
        if not _is_product_code(path):
            continue
        if _is_simulation(path, content):
            continue
        if path.lower().endswith(".py"):
            tree = _cached_ast(ctx, path, content)
            if tree is None:
                continue
            calls, copy = _py_callsites(tree), _py_copy(tree)
        else:
            calls, copy = _ts_tokens(content)

        for _ln, tok in calls:
            if any(rx.search(tok) for rx in compiled_calls):
                return True, path, tok[:200]
        for _ln, lit in copy:
            if _DEFERRAL_RE.search(lit):
                continue
            for rx, mode in compiled_copy:
                hit = rx.fullmatch(lit) if mode == "label" else rx.search(lit)
                if hit:
                    return True, path, lit[:200]
    return False, "", ""


def detect_art50_signals(ctx: AnalyzerContext) -> Art50Signals:
    """Detect the Art. 50 surfaces and hard-gated controls over ``ctx.files``."""
    has_chat, chat_file, chat_line = _scan_first(ctx, _CHAT_PATTERNS)
    has_gen, gen_file, gen_line, gen_modalities = _scan_generation(ctx)
    has_deepfake, df_file, df_line = _scan_first(ctx, _DEEPFAKE_PATTERNS)
    has_emotion, emo_file, emo_line = _scan_first(ctx, _EMOTION_BIOMETRIC_PATTERNS)
    has_ai_text, txt_file, txt_line = _scan_first(ctx, _AI_TEXT_PUBLIC_PATTERNS)

    has_marking, mark_file, mark_line = _scan_control(ctx, _MARKING_CALLSITE, [])
    has_disclosure, disc_file, disc_line = _scan_control(ctx, [], _DISCLOSURE_COPY)
    has_ai_label, lab_file, lab_line = _scan_control(ctx, [], _DISCLOSURE_LABEL)
    has_emo_notice, emon_file, emon_line = _scan_control(ctx, [], _EMO_NOTICE_COPY)

    return Art50Signals(
        chat=Art50Signal(present=has_chat, file_path=chat_file, snippet=chat_line),
        generation=Art50GenerationSignal(
            present=has_gen, file_path=gen_file, snippet=gen_line,
            modalities=gen_modalities,
        ),
        deepfake=Art50Signal(present=has_deepfake, file_path=df_file, snippet=df_line),
        emotion=Art50Signal(present=has_emotion, file_path=emo_file, snippet=emo_line),
        ai_text=Art50Signal(present=has_ai_text, file_path=txt_file, snippet=txt_line),
        marking=Art50Signal(present=has_marking, file_path=mark_file, snippet=mark_line),
        disclosure=Art50Signal(
            present=has_disclosure, file_path=disc_file, snippet=disc_line
        ),
        ai_generated_label=Art50Signal(
            present=has_ai_label, file_path=lab_file, snippet=lab_line
        ),
        emotion_notice=Art50Signal(
            present=has_emo_notice, file_path=emon_file, snippet=emon_line
        ),
    )


def analyze_article_50_transparency(ctx: AnalyzerContext) -> AnalyzerResult:
    """Detect Art. 50 transparency gaps (chatbot disclosure, synthetic marking,
    emotion/biometric notice, deep-fake / AI-text labelling).

    Detection is aggregate across the repo: a surface is a gap only when no
    hard-gated control is present anywhere. With no surface at all the analyzer
    returns a neutral high score and no findings so a backend-only repo is not
    falsely flagged.
    """
    findings: list[Finding] = []

    signals = detect_art50_signals(ctx)
    has_chat, chat_file, chat_line = (
        signals.chat.present, signals.chat.file_path, signals.chat.snippet
    )
    has_gen, gen_file, gen_line = (
        signals.generation.present, signals.generation.file_path,
        signals.generation.snippet,
    )
    has_deepfake, df_file, df_line = (
        signals.deepfake.present, signals.deepfake.file_path, signals.deepfake.snippet
    )
    has_emotion, emo_file, emo_line = (
        signals.emotion.present, signals.emotion.file_path, signals.emotion.snippet
    )
    has_ai_text, txt_file, txt_line = (
        signals.ai_text.present, signals.ai_text.file_path, signals.ai_text.snippet
    )
    has_marking, mark_file, mark_line = (
        signals.marking.present, signals.marking.file_path, signals.marking.snippet
    )
    has_disclosure, disc_file, disc_line = (
        signals.disclosure.present, signals.disclosure.file_path,
        signals.disclosure.snippet,
    )
    has_ai_label = signals.ai_generated_label.present
    has_emo_notice, emon_file, emon_line = (
        signals.emotion_notice.present, signals.emotion_notice.file_path,
        signals.emotion_notice.snippet,
    )

    # A CONTROL is not a SURFACE — never let a mention of C2PA declare a surface.
    surface = has_chat or has_gen or has_deepfake or has_emotion or has_ai_text
    surface_files: set[str] = {
        f for f in (chat_file, gen_file, df_file, emo_file, txt_file) if f
    }

    if not surface:
        return AnalyzerResult(
            analyzer_id="article_50_transparency",
            label="Art. 50 Transparency",
            findings=[],
            score=80.0,
            file_count=0,
            graph_node_type="control",
            graph_icon="🏷",
            connected_categories=["documentation", "human_oversight"],
            metadata={"modalities": []},
        )

    # Art. 50(1) — conversational AI with no AI-interaction disclosure.
    if has_chat and not has_disclosure:
        findings.append(Finding(
            id="art50-no-ai-disclosure",
            category="article_50_transparency",
            title="Conversational AI surface with no Art. 50(1) AI-interaction disclosure",
            description=(
                "A chatbot / assistant surface interacts with natural persons but no "
                "disclosure that they are dealing with an AI system was found in the "
                "Python/TypeScript sources. Art. 50(1) requires the AI-interaction "
                "disclosure at first contact (enforceable 2 Aug 2026). Add a clear "
                "'you are interacting with an AI' notice. (A disclosure that lives only "
                "in an i18n/locale file or a Markdown template is not scanned.)"
            ),
            file_path=chat_file, confidence=0.6,
            compliance_impact="gap",
            compliance_dimensions=["content_transparency", "transparency"],
            evidence_snippet=chat_line,
            kb_question_ids=["tr-1", "ct-6"], suggested_answer="no",
            article_paragraphs=["50(1)"],
            matched_pattern="art50_no_ai_disclosure",
            applicable_roles=_ROLES,
        ))

    # Art. 50(2) — synthetic content generated with no machine-readable marking.
    if has_gen and not has_marking:
        findings.append(Finding(
            id="art50-unmarked-synthetic",
            category="article_50_transparency",
            title="Synthetic content generated with no Art. 50(2) machine-readable marking",
            description=(
                "Code generates synthetic image/audio/video/text but no C2PA / watermark "
                "/ IPTC provenance marking of the output was found. Art. 50(2) requires "
                "machine-readable marking (the June-2026 Transparency Code of Practice "
                "points at C2PA content credentials). Embed a robust, interoperable mark "
                "on the generated output."
            ),
            file_path=gen_file, confidence=0.6,
            compliance_impact="gap",
            compliance_dimensions=["content_transparency"],
            evidence_snippet=gen_line,
            kb_question_ids=["ct-1", "ct-2"], suggested_answer="no",
            article_paragraphs=["50(2)"],
            matched_pattern="art50_unmarked_synthetic",
            applicable_roles=_ROLES,
        ))

    # Art. 50(4) — deep-fake / synthetic media with no disclosure label.
    if has_deepfake and not (has_marking or has_disclosure):
        findings.append(Finding(
            id="art50-unlabelled-deepfake",
            category="article_50_transparency",
            title="Deep-fake / synthetic-media surface with no Art. 50(4) disclosure label",
            description=(
                "A face-swap / voice-clone / synthetic-media surface was found with no "
                "'AI-generated' label or provenance marking. Art. 50(4) requires deep-fake "
                "content to be disclosed as artificially generated or manipulated. Add a "
                "visible label and a machine-readable mark to the output."
            ),
            file_path=df_file, confidence=0.65,
            compliance_impact="gap",
            compliance_dimensions=["content_transparency"],
            evidence_snippet=df_line,
            kb_question_ids=["ct-3"], suggested_answer="no",
            article_paragraphs=["50(4)"],
            matched_pattern="art50_unlabelled_deepfake",
            applicable_roles=_ROLES,
        ))

    # Art. 50(3) — emotion recognition / biometric categorisation with no exposure notice.
    if has_emotion and not has_emo_notice:
        findings.append(Finding(
            id="art50-emotion-no-notice",
            category="article_50_transparency",
            title="Emotion / biometric-categorisation surface with no Art. 50(3) exposure notice",
            description=(
                "An emotion-recognition or biometric-categorisation surface was found with "
                "no notice informing exposed persons that the system operates on them. "
                "Art. 50(3) requires deployers to inform the natural persons exposed "
                "(enforceable 2 Aug 2026), and the biometric processing must have a GDPR "
                "lawful basis. Add a clear exposure notice at the point of capture."
            ),
            file_path=emo_file, confidence=0.6,
            compliance_impact="gap",
            compliance_dimensions=["content_transparency"],
            evidence_snippet=emo_line,
            kb_question_ids=["ct-5"], suggested_answer="no",
            article_paragraphs=["50(3)"],
            matched_pattern="art50_emotion_no_notice",
            applicable_roles=[ROLE_DEPLOYER],
        ))

    # Art. 50(4), 2nd limb — AI-generated public-interest text with no disclosure.
    if has_ai_text and (has_chat or has_gen) and not (has_marking or has_disclosure):
        findings.append(Finding(
            id="art50-unlabelled-ai-text",
            category="article_50_transparency",
            title="AI-generated public-interest text with no Art. 50(4) disclosure",
            description=(
                "A news / press / public-interest text surface is paired with an LLM or "
                "generation surface but no 'AI-generated' disclosure was found. Art. 50(4) "
                "requires text published to inform the public on matters of public interest "
                "to be disclosed as artificially generated or manipulated, unless it "
                "underwent human review with editorial responsibility. Add the disclosure "
                "or record the editorial-review exception."
            ),
            file_path=txt_file, confidence=0.5,
            compliance_impact="gap",
            compliance_dimensions=["content_transparency"],
            evidence_snippet=txt_line,
            kb_question_ids=["ct-4"], suggested_answer="no",
            article_paragraphs=["50(4)"],
            matched_pattern="art50_unlabelled_ai_text",
            applicable_roles=[ROLE_DEPLOYER],
        ))

    # Positives — a control is only creditable against a surface it can mark.
    if has_marking and (has_gen or has_deepfake):
        findings.append(Finding(
            id="art50-marking-present",
            category="article_50_transparency",
            title="Machine-readable synthetic-content marking present (C2PA / watermark / IPTC)",
            description=(
                "C2PA / watermark / IPTC provenance marking of generated content was found — "
                "the Art. 50(2) machine-readable-marking obligation is being addressed."
            ),
            file_path=mark_file, confidence=0.65,
            compliance_impact="positive",
            compliance_dimensions=["content_transparency"],
            evidence_snippet=mark_line,
            kb_question_ids=["ct-1", "ct-2"], suggested_answer="yes",
            article_paragraphs=["50(2)"],
            matched_pattern="art50_marking_present",
        ))
    if has_disclosure and (has_chat or has_gen or has_deepfake or has_ai_text):
        findings.append(Finding(
            id="art50-disclosure-present",
            category="article_50_transparency",
            title="Explicit AI-interaction / AI-generated disclosure present",
            description=(
                "An explicit AI-interaction or AI-generated disclosure string was found — "
                "the Art. 50(1)/50(4) disclosure obligation is being addressed."
            ),
            file_path=disc_file, confidence=0.6,
            compliance_impact="positive",
            compliance_dimensions=["content_transparency", "transparency"],
            evidence_snippet=disc_line,
            kb_question_ids=(
                ["tr-1"] + (["ct-3"] if (has_deepfake and has_ai_label) else [])
            ),
            suggested_answer="yes",
            article_paragraphs=["50(1)"],
            matched_pattern="art50_disclosure_present",
        ))
    if has_emotion and has_emo_notice:
        findings.append(Finding(
            id="art50-emotion-notice-present",
            category="article_50_transparency",
            title="Emotion / biometric exposure notice present (Art. 50(3))",
            description=(
                "An emotion-recognition / biometric-categorisation exposure notice was "
                "found alongside the analysis surface — the Art. 50(3) obligation to "
                "inform exposed persons is being addressed."
            ),
            file_path=emon_file, confidence=0.6,
            compliance_impact="positive",
            compliance_dimensions=["content_transparency"],
            evidence_snippet=emon_line,
            kb_question_ids=["ct-5"], suggested_answer="yes",
            article_paragraphs=["50(3)"],
            matched_pattern="art50_emotion_notice_present",
            applicable_roles=[ROLE_DEPLOYER],
        ))

    findings = findings[:_MAX_FINDINGS]

    gaps = [f for f in findings if f.compliance_impact == "gap"]
    pos = [f for f in findings if f.compliance_impact == "positive"]
    if gaps and not pos:
        score = max(15.0, 50.0 - len(gaps) * 20)
    elif gaps and pos:
        score = max(35.0, 65.0 - len(gaps) * 15 + len(pos) * 5)
    elif pos:
        score = min(95.0, 80.0 + len(pos) * 5)
    else:
        score = 75.0

    score = max(0.0, min(100.0, score))
    return AnalyzerResult(
        analyzer_id="article_50_transparency",
        label="Art. 50 Transparency",
        findings=findings,
        score=round(score, 1),
        file_count=len(surface_files),
        graph_node_type="control",
        graph_icon="🏷",
        connected_categories=["documentation", "human_oversight"],
        metadata={"modalities": signals.generation.modalities},
    )
