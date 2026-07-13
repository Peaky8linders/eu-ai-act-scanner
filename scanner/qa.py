"""Grounded, offline-first EU AI Act Q&A — the plugin's "Lexy" retrieval path.

Answers a compliance question by retrieving over the bundled knowledge base:

* verbatim article / annex text — :data:`scanner.data.official_eu_ai_act.OFFICIAL_ARTICLE_TEXT`,
* concise obligation paraphrases — :data:`scanner.grounding.OBLIGATION_TEXT`,
* the four-axis compound-risk **taxonomy** and its threat categories —
  :mod:`scanner.data.agentic_taxonomy`.

Every answer cites the articles it draws from. This mirrors the *deterministic*
retrieval + render path Lexy (the CodexAI RAG assistant) falls back to whenever
no graph DB / LLM key is configured, so it runs with **no LLM and no network**
by default — preserving the scanner's offline guarantee.

When the LLM bridge is enabled (``EU_AI_ACT_SCANNER_LLM=true``) or the caller
passes ``use_llm=True`` (``assisted`` mode with a reachable wrapper), the same
retrieved grounding is handed to :func:`scanner.llm_bridge.complete` for prose
synthesis, then run through :func:`scanner.grounding.filter_unsupported_sentences`
so no sentence survives that its cited articles do not support. Any bridge
failure degrades cleanly to the deterministic answer.

The richer typed ontology (:mod:`scanner.data.ontology`) is bundled alongside
this module for the host Claude Code (``assisted`` mode) to traverse; the
deterministic path here stays focused on the article + obligation + taxonomy
corpus that a token-overlap retriever handles well.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from scanner import grounding, llm_bridge
from scanner.data.agentic_taxonomy import COMPOUND_RISK_TYPES, THREAT_CATEGORIES
from scanner.data.official_eu_ai_act import OFFICIAL_ARTICLE_TEXT
from scanner.kb import ARTICLE_TO_DIMENSIONS, DIMENSIONS

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOP = frozenset(
    "the a an and or of to in on for with by is are be that this it as at from "
    "must shall may can will should would which who whom what when where how why "
    "into under over per any all its their our your his her they them we you i".split()
)

# Recognise an explicit article / annex reference in the question so a direct
# "what does article 50 require?" boosts Art. 50 to the top regardless of the
# lexical overlap of the surrounding words.
_ARTICLE_Q_RE = re.compile(r"\b(?:art(?:icle)?\.?\s*)(\d{1,3})", re.IGNORECASE)
_PARAGRAPH_Q_RE = re.compile(r"\b(\d{1,3})\s*\(\s*\d+\s*\)")
_ANNEX_Q_RE = re.compile(r"\bannex\s+([ivxlc]+|\d+)\b", re.IGNORECASE)
_ROMAN = {1: "I", 2: "II", 3: "III", 4: "IV", 5: "V", 6: "VI", 7: "VII",
          8: "VIII", 9: "IX", 10: "X", 11: "XI", 12: "XII", 13: "XIII"}


def _tokenize(text: str) -> frozenset[str]:
    return frozenset(
        w for w in _TOKEN_RE.findall((text or "").lower()) if len(w) > 2 and w not in _STOP
    )


class _Doc(BaseModel):
    ref: str          # display id: "Art. 50", "Annex III", "Risk: cascading"
    title: str
    body: str         # retrieval + excerpt text
    cite_refs: tuple[str, ...]  # article refs used for citation + the guard
    kind: str         # "article" | "annex" | "taxonomy"
    tokens: frozenset[str] = Field(default_factory=frozenset)


class QASource(BaseModel):
    ref: str
    title: str
    excerpt: str


class QAResult(BaseModel):
    question: str
    answer: str
    mode: str  # "deterministic" | "llm"
    citations: list[str] = Field(default_factory=list)
    dimensions: list[str] = Field(default_factory=list)
    sources: list[QASource] = Field(default_factory=list)


def _article_key_to_canonical(key: str) -> str:
    """``"Article 50"`` -> ``"Art. 50"``; annex keys pass through unchanged."""
    m = re.match(r"Article\s+(\d+)", key)
    return f"Art. {m.group(1)}" if m else key


def _art_number(ref: str) -> str | None:
    m = re.match(r"Art\.?\s*(\d+)", ref)
    return m.group(1) if m else None


_CORPUS: list[_Doc] | None = None


def _build_corpus() -> list[_Doc]:
    merged: dict[str, dict] = {}

    # 1. Verbatim article / annex text (richest grounding).
    for key, text in OFFICIAL_ARTICLE_TEXT.items():
        ref = _article_key_to_canonical(key)
        entry = merged.setdefault(ref, {"title": key, "verbatim": "", "paraphrase": ""})
        entry["verbatim"] = text
        entry["title"] = key

    # 2. Concise obligation paraphrases (focused, the guard's token pool).
    for ref, text in grounding.OBLIGATION_TEXT.items():
        entry = merged.setdefault(ref, {"title": ref, "verbatim": "", "paraphrase": ""})
        entry["paraphrase"] = text

    docs: list[_Doc] = []
    for ref, d in merged.items():
        body = (d["paraphrase"] + "\n\n" + d["verbatim"]).strip()
        kind = "annex" if ref.lower().startswith("annex") else "article"
        docs.append(_Doc(
            ref=ref, title=d["title"], body=body,
            cite_refs=(ref,) if kind == "article" else (),
            kind=kind, tokens=_tokenize(f"{ref} {d['title']} {body}"),
        ))

    # 3. Compound-risk taxonomy + threat categories (agentic Q&A).
    for entry in COMPOUND_RISK_TYPES:
        body = " ".join([
            entry.get("summary", ""),
            " ".join(entry.get("failure_modes", [])),
            " ".join(entry.get("mitigation_pattern", [])),
        ]).strip()
        label = entry.get("label", entry.get("id", "risk"))
        docs.append(_Doc(
            ref=f"Risk: {label}", title=f"Compound risk — {label}", body=body,
            cite_refs=tuple(entry.get("article_refs", [])), kind="taxonomy",
            tokens=_tokenize(f"{label} {body} " + " ".join(entry.get("article_refs", []))),
        ))
    for entry in THREAT_CATEGORIES:
        body = entry.get("description", "")
        label = entry.get("label", entry.get("id", "threat"))
        docs.append(_Doc(
            ref=f"Threat: {label}", title=f"Threat category — {label}", body=body,
            cite_refs=tuple(entry.get("article_refs", [])), kind="taxonomy",
            tokens=_tokenize(f"{label} {body} " + " ".join(entry.get("article_refs", []))),
        ))
    return docs


def _corpus() -> list[_Doc]:
    global _CORPUS
    if _CORPUS is None:
        _CORPUS = _build_corpus()
    return _CORPUS


def _boosted_refs(question: str) -> set[str]:
    """Canonical refs explicitly named in the question (heavy retrieval boost)."""
    refs: set[str] = set()
    for m in _ARTICLE_Q_RE.finditer(question):
        refs.add(f"Art. {int(m.group(1))}")
    for m in _PARAGRAPH_Q_RE.finditer(question):
        refs.add(f"Art. {int(m.group(1))}")
    for m in _ANNEX_Q_RE.finditer(question):
        raw = m.group(1).upper()
        if raw.isdigit() and int(raw) in _ROMAN:
            raw = _ROMAN[int(raw)]
        refs.add(f"Annex {raw}")
    return refs


def _excerpt(doc: _Doc, limit: int = 360) -> str:
    text = " ".join(doc.body.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _dimensions_for(refs: list[str]) -> list[str]:
    out: list[str] = []
    for ref in refs:
        num = _art_number(ref)
        if num is None:
            continue
        for dim in ARTICLE_TO_DIMENSIONS.get(f"art{num}", []):
            label = DIMENSIONS[dim].label if dim in DIMENSIONS else dim
            if label not in out:
                out.append(label)
    return out


def _render_deterministic(top: list[tuple[_Doc, float]], dimensions: list[str]) -> str:
    parts = ["Based on the bundled EU AI Act knowledge base:\n"]
    for doc, _ in top:
        parts.append(f"- **{doc.ref}** ({doc.title}) — {_excerpt(doc)}")
    if dimensions:
        parts.append("\nRelated compliance dimensions: " + ", ".join(dimensions) + ".")
    parts.append(
        "\nThis is a deterministic retrieval over verbatim statute text, obligation "
        "paraphrases and the compound-risk taxonomy — not legal advice. Enable "
        "assisted mode (`/ai-act-settings`) to have your own Claude Code synthesise "
        "a narrative answer over the same grounding."
    )
    return "\n".join(parts)


def _answer_with_llm(question: str, top: list[tuple[_Doc, float]], refs: list[str]) -> str | None:
    grounding_block = "\n\n".join(f"{doc.ref}: {_excerpt(doc, 700)}" for doc, _ in top)
    system = (
        "You are an EU AI Act compliance assistant. Answer the question using ONLY "
        "the authoritative EU AI Act text provided below as ground truth. Cite the "
        "articles you rely on as 'Art. N'. If the provided text does not cover the "
        "question, say so plainly rather than inventing an obligation.\n\n"
        f"AUTHORITATIVE TEXT:\n{grounding_block}"
    )
    result = llm_bridge.complete(system, question, max_tokens=700)
    if result.error is not None or not result.text.strip():
        return None
    # Citation guard: drop any sentence unsupported by the cited article pool.
    article_refs = tuple(r for r in refs if _art_number(r) is not None)
    guarded = grounding.filter_unsupported_sentences(result.text.strip(), article_refs)
    return guarded.strip() or None


def answer_question(
    question: str,
    *,
    top_k: int = 4,
    use_llm: bool | None = None,
) -> QAResult:
    """Answer an EU AI Act question, grounded in the bundled corpus.

    ``use_llm`` — ``None`` (default) auto-detects the LLM bridge
    (:func:`scanner.llm_bridge.is_enabled`); ``True``/``False`` forces the path.
    Falls back to the deterministic answer whenever the bridge is off,
    unreachable, or returns nothing after the citation guard.
    """
    q = (question or "").strip()
    if not q:
        return QAResult(question=question, answer="Ask a question about the EU AI Act.",
                        mode="deterministic")

    q_tokens = _tokenize(q)
    boosted = _boosted_refs(q)
    scored: list[tuple[_Doc, float]] = []
    for doc in _corpus():
        score = float(len(q_tokens & doc.tokens))
        if doc.ref in boosted:
            score += 100.0
        if score > 0:
            scored.append((doc, score))

    # Deterministic ordering: score desc, then a stable ref tie-break.
    scored.sort(key=lambda t: (-t[1], t[0].ref))
    top = scored[:top_k]

    if not top:
        return QAResult(
            question=q, mode="deterministic", answer=(
                "No matching EU AI Act provision was found in the bundled corpus. "
                "Try naming an article (e.g. 'What does Article 50 require?') or a "
                "topic (e.g. 'deepfake disclosure', 'human oversight')."
            ),
        )

    refs: list[str] = []
    for doc, _ in top:
        for r in (doc.cite_refs or (doc.ref,)):
            if r not in refs:
                refs.append(r)
    article_refs = [r for r in refs if _art_number(r) is not None or r.lower().startswith("annex")]
    dimensions = _dimensions_for(refs)
    sources = [QASource(ref=d.ref, title=d.title, excerpt=_excerpt(d)) for d, _ in top]

    want_llm = llm_bridge.is_enabled() if use_llm is None else use_llm
    if want_llm:
        llm_answer = _answer_with_llm(q, top, refs)
        if llm_answer:
            return QAResult(question=q, answer=llm_answer, mode="llm",
                            citations=article_refs, dimensions=dimensions, sources=sources)

    return QAResult(
        question=q, answer=_render_deterministic(top, dimensions), mode="deterministic",
        citations=article_refs, dimensions=dimensions, sources=sources,
    )
