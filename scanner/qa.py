"""Grounded, offline-first EU AI Act Q&A — the plugin's "Lexy" retrieval path.

Answers a compliance question by retrieving over the bundled knowledge base:

* verbatim article / annex text — :data:`scanner.data.official_eu_ai_act.OFFICIAL_ARTICLE_TEXT`
  merged with :data:`scanner.data.official_text_patches.OFFICIAL_TEXT_PATCHES`,
* concise obligation paraphrases — :data:`scanner.grounding.OBLIGATION_TEXT`,
* the four-axis compound-risk **taxonomy** and its threat categories —
  :mod:`scanner.data.agentic_taxonomy`.

Every answer cites the articles it draws from. This runs deterministically with
**no LLM and no network**, preserving the scanner's offline guarantee.
Excerpts use paragraph-targeted verbatim extraction (with UK/US ``-ize``/``-ise``
folding, within-provision rarity weighting, and explicit paragraph/point
resolution) rather than blind head-clipping, and explicit reference parsing
guards against foreign-statute citations (e.g. ``GDPR Art. 9``) and
out-of-range provision numbers.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from scanner import grounding
from scanner.data.agentic_taxonomy import COMPOUND_RISK_TYPES, SOURCE_LABELS, THREAT_CATEGORIES
from scanner.data.official_eu_ai_act import (
    OFFICIAL_ANNEX_TITLES,
    OFFICIAL_ARTICLE_TEXT,
    OFFICIAL_ARTICLE_TITLES,
)
from scanner.data.official_text_patches import OFFICIAL_TEXT_PATCHES
from scanner.kb import ARTICLE_TO_DIMENSIONS, DIMENSIONS

# Patches win over generated EUR-Lex text (e.g. Article 113 paragraph markers).
_OFFICIAL_TEXT: dict[str, str] = {**OFFICIAL_ARTICLE_TEXT, **OFFICIAL_TEXT_PATCHES}
_OFFICIAL_TITLES: dict[str, str] = {**OFFICIAL_ARTICLE_TITLES, **OFFICIAL_ANNEX_TITLES}

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOP = frozenset(
    "the a an and or of to in on for with by is are be that this it as at from "
    "must shall may can will should would which who whom what when where how why "
    "into under over per any all its their our your his her they them we you i "
    "do does did doing say says said about also between".split()
)
_PARA_STOP = _STOP | frozenset(
    "eu ai act article articles annex regulation system systems".split()
)

# Closed-world annexes (Regulation (EU) 2024/1689 has exactly 13 annexes).
_ANNEX_ROMAN: tuple[str, ...] = (
    "I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII", "XIII",
)
_ROMAN = {i + 1: r for i, r in enumerate(_ANNEX_ROMAN)}

# ── ReDoS-safe plural multi-provision list extraction ────────────────────────
# Matches "Articles 13 and 50", "Art. 9, 10, and 15", "Annexes I, III and IV".
# Leading \s* is factored outside the (?:sep)+ run so whitespace never splits
# ambiguously across iterations (linear time on adversarial input).
_MULTI_ART_RE = re.compile(
    r"\bart(?:icles?)?\.?\s*"
    r"(\d{1,3}(?:\s*(?:(?:,|&|/|\band\b|\bor\b)\s*)+\d{1,3}){0,8})",
    re.IGNORECASE,
)
_MULTI_ANNEX_RE = re.compile(
    r"\bannex(?:es)?\s+"
    r"((?:[ivx]{1,5}|\d{1,2})\b(?:\s*(?:(?:,|&|/|\band\b|\bor\b)\s*)+(?:[ivx]{1,5}|\d{1,2})\b){0,8})",
    re.IGNORECASE,
)
_PARAGRAPH_Q_RE = re.compile(r"\b(\d{1,3})\s*\(\s*\d{1,2}\s*\)")

# ── Foreign-statute guard ────────────────────────────────────────────────────
# "GDPR Art. 9", "Article 6(1) of the GDPR", "Art. 2(c) of Directive 2011/93/EU"
# cite another legal instrument and must not boost EU AI Act articles.
_OTHER_INSTRUMENT = (
    r"\b(?:GDPR|DORA|NIS\s?2|MDR|IVDR|CRA|DSA|DMA|Directive"
    r"|Regulation\s*\(EU\)\s*(?!2024/1689)\d{4}/\d+)"
)
_OTHER_BEFORE = re.compile(rf"{_OTHER_INSTRUMENT}\s*,?\s*$", re.IGNORECASE)
# Allow optional trailing paragraph/subpoint qualifiers like "(1)(a)" or
# ", paragraph 1" between the article number and "of (the) GDPR".
_QUALIFIER_TAIL = re.compile(
    r"(?:\s*\(\s*[a-z0-9]{1,3}\s*\)|"
    r"\s*,?\s*(?:paragraphs?|para\.?|points?)\s*(?:\([a-z0-9]{1,3}\)|\d{1,2})"
    r"(?:\s*(?:,|and|or)\s*(?:\([a-z0-9]{1,3}\)|\d{1,2}))*)*",
    re.IGNORECASE,
)
_OTHER_AFTER = re.compile(
    rf"\s*,?\s*(?:of\s+(?:the\s+)?)?{_OTHER_INSTRUMENT}",
    re.IGNORECASE,
)

# ── Citation sub-point / paragraph parsers ───────────────────────────────────
_LIST_ITEM = re.compile(
    r"\s*(,|;|and|or|to|-|–|/)\s*\(\s*(\d{1,2}|[a-z]{1,2})\s*\)",
    re.IGNORECASE,
)
_RANGE = {"to", "-", "–"}

# ── Paragraph / annex / sub-point splitters (verbatim corpus structure) ──────
_PARA_RE = re.compile(r"(?:^|(?<=[\n;.!?])\s+)(\d{1,2})\.\s+")
_SUBPOINT_RE = re.compile(r"[:;]\s+(?:or\s+|and\s+)?\(([a-z]{1,4})\)\s")
_ANNEX_SECTION_RE = re.compile(
    r"(?:^|(?<=[.;:])\s+)Section\s+([A-Z]|\d{1,2})\b[.:\s–—-]*"
)
_ANNEX_ITEM_RE = re.compile(r"(?:^|[.:;]\s)(\d{1,2})\.\s+(?=[A-Z])")
_ANNEX_ITEM_LOOSE_RE = re.compile(r"(?:^|(?<=[\s.:;]))(\d{1,2})\.\s+(?=[A-Z])")

# ── Topic anchor regexes ─────────────────────────────────────────────────────
_TIMELINE_RE = re.compile(
    r"\b("
    r"enter(?:s|ed)?\s+into\s+force|entry\s+into\s+force|in\s+force"
    r"|application\s+dates?|deadlines?|timelines?|phased|transition(?:al)?"
    r"|grandfather(?:ed|ing)?|digital\s+omnibus|deferr(?:ed|al)"
    r"|when\s+(?:do|does|will|must|are|is)\b[^?.!]{0,60}\b(?:appl(?:y|ies|icable)|take\s+effect|come\s+into|comply)"
    r"|before\s+2\s+august|before\s+august\s+2|2\s+(?:february|august|december)\s+20\d\d"
    r"|placed\s+on\s+the\s+market\s+before|put\s+into\s+service\s+before"
    r"|already\s+(?:placed|on\s+the\s+market|in\s+service)"
    r")\b",
    re.IGNORECASE,
)
_INCIDENT_RE = re.compile(
    r"\bserious\s+(?:[\w-]+\s+){0,2}incidents?\b"
    r"|\bincidents?\s+(?:report|notif)"
    r"|\b(?:report|notif)\w*\s+(?:\w+\s+){0,4}incidents?\b",
    re.IGNORECASE,
)
_EMOTION_RE = re.compile(
    r"\bemotion\s+(?:recognition|detection|inference)\b"
    r"|\binfer\w*\s+emotions?\b",
    re.IGNORECASE,
)
_PENALTIES_RE = re.compile(
    r"\b(penalt(?:y|ies)|fines?|sanctions?|turnover\s+cap|administrative\s+fines?)\b",
    re.IGNORECASE,
)


def _oxford_z(w: str) -> str:
    """Fold ``-ize``/``-ise`` orthographic split onto one form (prefix >= 4 chars).

    The adopted EUR-Lex English text uses ``-ise`` (``jeopardise``,
    ``harmonised``, ``authorisation``, ``categorisation``) while user questions
    frequently use ``-ize`` (``jeopardize``, ``harmonized``). Folding both sides
    repairs exact token matching without changing semantics.
    """
    for suf, repl in (("ization", "isation"), ("ize", "ise"), ("iz", "is")):
        if w.endswith(suf) and len(w) - len(suf) >= 4:
            return w[: -len(suf)] + repl
    return w


def _stem(w: str) -> str:
    """Light symmetric suffix strip + UK/US ``-ize``/``-ise`` fold."""
    if w.endswith("ies") and len(w) > 5:
        w = w[:-3] + "y"
    elif w.endswith("sses") and len(w) > 6:
        w = w[:-2]
    elif w.endswith("s") and not w.endswith("ss") and len(w) > 3:
        w = w[:-1]
    if w.endswith("ition") and len(w) > 7:
        return _oxford_z(w[:-5] + "it")
    for suf in ("ing", "ment", "ed"):
        if len(w) > len(suf) + 2 and w.endswith(suf):
            return _oxford_z(w[: -len(suf)])
    return _oxford_z(w)


def _tokenize(text: str) -> frozenset[str]:
    return frozenset(
        _oxford_z(w)
        for w in _TOKEN_RE.findall((text or "").lower())
        if len(w) > 2 and w not in _STOP
    )


def _para_tokens(text: str) -> set[str]:
    return {
        _stem(w)
        for w in _TOKEN_RE.findall((text or "").lower())
        if len(w) > 2 and w not in _PARA_STOP
    }


def _normalise_ws(text: str) -> str:
    return " ".join((text or "").replace("\xa0", " ").split())


def _canonical_article_ref(n: int) -> str | None:
    """``111`` -> ``"Art. 111"`` iff 1 <= n <= 113 (closed-world Act range)."""
    return f"Art. {n}" if 1 <= n <= 113 else None


def _canonical_annex_ref(token: str) -> str | None:
    """``"iv"`` / ``"4"`` -> ``"Annex IV"`` iff within the 13 real annexes."""
    raw = (token or "").strip().upper()
    if raw.isdigit():
        num = int(raw)
        return f"Annex {_ROMAN[num]}" if num in _ROMAN else None
    return f"Annex {raw}" if raw in _ANNEX_ROMAN else None


def _another_instruments(text: str, start: int, end: int) -> bool:
    """True when the citation spanning ``start:end`` belongs to another statute."""
    if _OTHER_BEFORE.search(text[max(0, start - 40) : start]):
        return True
    tail_match = _QUALIFIER_TAIL.match(text, end)
    after_pos = tail_match.end() if tail_match else end
    return bool(_OTHER_AFTER.match(text, after_pos))


def _list_items(text: str, end: int, *, digits: bool) -> tuple[list[tuple[str, str]], int]:
    """The ``(separator, value)`` items continuing a citation ending at ``end``."""
    items: list[tuple[str, str]] = []
    while (match := _LIST_ITEM.match(text, end)) and match.group(2).isdigit() == digits:
        items.append((match.group(1).lower(), match.group(2)))
        end = match.end()
    return items, end


def _expand(first: str, items: list[tuple[str, str]]) -> list[str]:
    """Expand a citation's first value plus any list items / ranges."""
    out = [first]
    for separator, value in items:
        start, stop = out[-1].lower(), value.lower()
        if (
            separator in _RANGE
            and start.isdigit()
            and stop.isdigit()
            and 0 < int(stop) - int(start) <= 20
        ):
            out.extend(str(n) for n in range(int(start) + 1, int(stop) + 1))
        elif (
            separator in _RANGE
            and len(start) == len(stop) == 1
            and start.isalpha()
            and stop.isalpha()
            and start < stop
        ):
            out.extend(chr(c) for c in range(ord(start) + 1, ord(stop) + 1))
        else:
            out.append(value)
    return out


def cited_paragraphs(article_number: int, question: str) -> list[int]:
    """Paragraph numbers ``question`` explicitly names for ``article_number``.

    Recognises ``"Art. 26(6)"``, ``"Article 26, paragraph 6"``,
    ``"paragraph 6 of Article 26"``, and lists/ranges such as ``"Art. 50(2)-(4)"``.
    Skips citations belonging to other instruments (e.g. ``GDPR Art. 6(1)``).
    """
    n = rf"0*{article_number}"
    patterns = (
        rf"\bart(?:icle)?\.?\s*{n}\s*\(\s*(\d{{1,2}})\s*\)",
        rf"\bart(?:icle)?\.?\s*{n}\s*,?\s*(?:paragraph|para\.?)\s*(\d{{1,2}})\b",
        rf"\b(?:paragraph|para\.?)\s*(\d{{1,2}})\s+of\s+art(?:icle)?\.?\s*{n}\b",
    )
    found: list[int] = []
    for index, pattern in enumerate(patterns):
        for match in re.finditer(pattern, question or "", re.IGNORECASE):
            items, end = (
                _list_items(question, match.end(), digits=True)
                if index == 0
                else ([], match.end())
            )
            if _another_instruments(question, match.start(), end):
                continue
            for number in _expand(match.group(1), items):
                val = int(number)
                if val not in found:
                    found.append(val)
    return found


def cited_points(article_number: int, text: str) -> list[tuple[int, str]]:
    """``(paragraph, point_letter)`` pairs ``text`` names for ``article_number``."""
    pattern = (
        rf"\bart(?:icle)?\.?\s*0*{article_number}"
        r"\s*\(\s*(\d{1,2})\s*\)\s*\(\s*([a-z]{1,2})\s*\)"
    )
    found: list[tuple[int, str]] = []
    for match in re.finditer(pattern, text or "", re.IGNORECASE):
        items, end = _list_items(text, match.end(), digits=False)
        if _another_instruments(text, match.start(), end):
            continue
        for letter in _expand(match.group(2), items):
            pair = (int(match.group(1)), letter.lower())
            if pair not in found:
                found.append(pair)
    return found


def extract_refs(text: str) -> list[str]:
    """Return canonical EU AI Act refs named in ``text`` (articles then annexes).

    Captures plural multi-provision lists (``"Articles 13 and 50"``,
    ``"Art. 9, 10, and 15"``, ``"Annexes I, III and IV"``), enforces the
    closed-world range (``Art. 1..113``, ``Annex I..XIII``), and skips
    foreign-statute citations (``"GDPR Art. 9"``, ``"Article 6(1) of the GDPR"``).
    """
    refs: list[str] = []
    seen: set[str] = set()
    body = text or ""

    for m in _MULTI_ART_RE.finditer(body):
        if _another_instruments(body, m.start(), m.end()):
            continue
        for num in re.findall(r"\d{1,3}", m.group(1)):
            key = _canonical_article_ref(int(num))
            if key and key not in seen:
                seen.add(key)
                refs.append(key)

    for m in _PARAGRAPH_Q_RE.finditer(body):
        if _another_instruments(body, m.start(), m.end()):
            continue
        key = _canonical_article_ref(int(m.group(1)))
        if key and key not in seen:
            seen.add(key)
            refs.append(key)

    for m in _MULTI_ANNEX_RE.finditer(body):
        if _another_instruments(body, m.start(), m.end()):
            continue
        for tok in re.findall(r"[ivx]+|\d{1,2}", m.group(1), re.IGNORECASE):
            key = _canonical_annex_ref(tok)
            if key and key not in seen:
                seen.add(key)
                refs.append(key)

    return refs


# ── Verbatim paragraph & sub-point extraction ────────────────────────────────


def _strip_title(official_key: str, text: str) -> str:
    title = (_OFFICIAL_TITLES.get(official_key, "") or "").strip()
    body = (text or "").strip()
    if title and body.startswith(title):
        body = body[len(title) :].strip()
    return body


def _article_body(official_key: str) -> str | None:
    raw = _OFFICIAL_TEXT.get(official_key)
    if not raw:
        return None
    return _strip_title(official_key, raw)


def _paragraphs(body: str) -> dict[int, str]:
    """Map ``{paragraph_number: text}`` for strictly ascending ``1., 2., ...`` blocks."""
    ms = list(_PARA_RE.finditer(body))
    if not ms:
        return {}
    start_i = next((i for i, m in enumerate(ms) if int(m.group(1)) == 1), None)
    if start_i is None:
        return {}
    seq: list[re.Match[str]] = []
    expected = 1
    for m in ms[start_i:]:
        if int(m.group(1)) == expected:
            seq.append(m)
            expected += 1
    out: dict[int, str] = {}
    for j, m in enumerate(seq):
        n = int(m.group(1))
        end = seq[j + 1].start() if j + 1 < len(seq) else len(body)
        out[n] = body[m.end() : end].strip()
    return out


def _subpoints(paragraph_text: str) -> dict[str, str]:
    """Map ``{letter: text}`` for ``(a)(b)(c)...`` list items in a paragraph."""
    ms = list(_SUBPOINT_RE.finditer(paragraph_text))
    out: dict[str, str] = {}
    for j, m in enumerate(ms):
        letter = m.group(1)
        end = ms[j + 1].start() if j + 1 < len(ms) else len(paragraph_text)
        out[letter] = paragraph_text[m.end() : end].strip().rstrip(" ;.")
    return out


def _annex_sections(body: str) -> list[tuple[str | None, str]]:
    ms = list(_ANNEX_SECTION_RE.finditer(body))
    if not ms:
        return [(None, body)]
    out: list[tuple[str | None, str]] = []
    head = body[: ms[0].start()].strip()
    if head:
        out.append((None, head))
    for j, m in enumerate(ms):
        end = ms[j + 1].start() if j + 1 < len(ms) else len(body)
        out.append((m.group(1), body[m.end() : end].strip()))
    return out


def _recover_leading_item(segment: str, ms: list[re.Match[str]]) -> list[re.Match[str]]:
    if not ms:
        return ms
    want = int(ms[0].group(1)) - 1
    if want < 1:
        return ms
    for m in _ANNEX_ITEM_LOOSE_RE.finditer(segment[: ms[0].start()]):
        if int(m.group(1)) == want:
            return [m, *ms]
    return ms


def _items_in(segment: str) -> dict[int, str]:
    ms = _recover_leading_item(segment, list(_ANNEX_ITEM_RE.finditer(segment)))
    out: dict[int, str] = {}
    for j, m in enumerate(ms):
        n = int(m.group(1))
        end = ms[j + 1].start() if j + 1 < len(ms) else len(segment)
        out[n] = segment[m.end() : end].strip()
    return out


def _annex_items(body: str) -> dict[int, str]:
    """Section-aware flat ``{item_no: text}`` (first section wins on collision)."""
    out: dict[int, str] = {}
    for _label, segment in _annex_sections(body):
        for n, text in _items_in(segment).items():
            out.setdefault(n, text)
    return out


def _sibling_idf(units: dict[int, str]) -> dict[str, int]:
    """Within-provision document frequency across sibling paragraphs/items."""
    df: dict[str, int] = {}
    for txt in units.values():
        for tok in _para_tokens(txt):
            df[tok] = df.get(tok, 0) + 1
    return df


def _overlap_score(
    q_tok: set[str], u_tok: set[str], weights: dict[str, int] | None
) -> float:
    shared = q_tok & u_tok
    if weights is None:
        return float(len(shared))
    return sum(1.0 / weights.get(tok, 1) for tok in shared)


def _drill_subpoints(
    num: int | None,
    paragraph_text: str,
    q_tok: set[str],
    max_chars: int,
    *,
    preferred_letters: tuple[str, ...] = (),
) -> str | None:
    """Quote a paragraph's preamble + relevant/cited lettered sub-point(s), verbatim."""
    subs = _subpoints(paragraph_text)
    if not subs:
        return None
    first = _SUBPOINT_RE.search(paragraph_text)
    preamble = paragraph_text[: first.start() + 1].strip() if first else ""

    if preferred_letters:
        picked = [(lt, subs[lt]) for lt in preferred_letters if lt in subs]
        if picked:
            lead = f"{num}. {preamble}".strip() if num is not None else preamble
            return (
                lead + "".join(f" ({lt}) {txt}" for lt, txt in picked)
            ).strip()

    scored = sorted(
        ((letter, txt, len(q_tok & _para_tokens(txt))) for letter, txt in subs.items()),
        key=lambda x: (-x[2], x[0]),
    )
    top = scored[0][2]
    second = scored[1][2] if len(scored) > 1 else 0
    confident = bool(q_tok) and top >= 1 and (top - second) >= 1
    order = (
        [(letter, t) for letter, t, _ in scored]
        if confident
        else sorted(subs.items(), key=lambda kv: kv[0])
    )

    lead = f"{num}. {preamble}".strip() if num is not None else preamble
    out = lead
    added = 0
    for letter, txt in order:
        frag = f" ({letter}) {txt}"
        if added >= 1 and len(out) + len(frag) > max_chars:
            break
        out += frag
        added += 1
    return out.strip()


def _ref_to_official_key(ref: str) -> str | None:
    s = (ref or "").strip()
    if s.startswith("Art. "):
        return "Article " + s[len("Art. ") :].strip()
    if s.startswith(("Article ", "Annex ")):
        return s
    return None


def select_relevant_paragraphs(
    ref: str,
    question: str = "",
    max_chars: int = 500,
) -> str | None:
    """Return verbatim, question-relevant paragraph(s) of an article or annex.

    Honours explicit paragraph / sub-point citations (e.g. ``Art. 26(6)``,
    ``Art. 5(1)(f)``) first, then ranks sibling numbered paragraphs using
    within-provision IDF + UK/US ``-ize``/``-ise`` folding. Always emits whole
    paragraphs or sub-points rather than mid-sentence head-clips. Returns
    ``None`` when ``ref`` does not resolve in the official corpus.
    """
    official_key = _ref_to_official_key(ref)
    if not official_key:
        return None
    body = _article_body(official_key)
    if body is None:
        return None
    body = _normalise_ws(body)
    is_annex = official_key.startswith("Annex ")

    art_num: int | None = None
    if not is_annex:
        tail = official_key.split()[-1]
        if tail.isdigit():
            art_num = int(tail)

    units = (
        _annex_items(body)
        if is_annex
        else ({} if art_num == 3 else _paragraphs(body))
    )

    q_tok = _para_tokens(question)

    # 1. Explicit paragraph / point citation wins unconditionally.
    if art_num is not None and question and units:
        explicit_points = cited_points(art_num, question)
        if explicit_points:
            parts: list[str] = []
            by_para: dict[int, list[str]] = {}
            for pnum, letter in explicit_points:
                by_para.setdefault(pnum, []).append(letter)
            for pnum, letters in by_para.items():
                ptxt = units.get(pnum)
                if not ptxt:
                    continue
                drilled = _drill_subpoints(
                    pnum, ptxt, q_tok, max_chars, preferred_letters=tuple(letters)
                )
                parts.append(drilled or f"{pnum}. {ptxt}")
            if parts:
                return " ".join(parts)

        explicit_paras = cited_paragraphs(art_num, question)
        if explicit_paras:
            cited_out = [
                f"{pnum}. {units[pnum]}" for pnum in explicit_paras if pnum in units
            ]
            if cited_out:
                return " ".join(cited_out)

    # 2. Short body fits whole.
    if len(body) <= max_chars:
        return body

    # 3. Single-block article (no numbered paragraphs): try sub-point drill.
    if not units:
        drilled = _drill_subpoints(None, body, q_tok, max_chars)
        return drilled if drilled is not None else body

    # 4. Score sibling paragraphs with within-provision rarity weighting.
    weights = _sibling_idf(units)
    scored = [
        (num, txt, _overlap_score(q_tok, _para_tokens(txt), weights))
        for num, txt in sorted(units.items())
    ]
    ranked = sorted(scored, key=lambda x: (-x[2], x[0]))
    if q_tok and ranked[0][2] == 0:
        ranked = sorted(scored, key=lambda x: x[0])

    top_num, top_txt, _top_score = ranked[0]
    if len(top_txt) > max_chars:
        drilled = _drill_subpoints(top_num, top_txt, q_tok, max_chars)
        if drilled is not None:
            return drilled

    chosen: dict[int, str] = {}
    total = 0
    for num, txt, _score in ranked:
        rendered_len = len(txt) + 4
        if chosen and total + rendered_len > max_chars:
            continue
        chosen[num] = txt
        total += rendered_len
        if total >= max_chars:
            break
    if not chosen:
        chosen = {top_num: top_txt}
    return " ".join(f"{num}. {chosen[num]}" for num in sorted(chosen))


# ── Models & Corpus ──────────────────────────────────────────────────────────


class _Doc(BaseModel):
    ref: str  # display id: "Art. 50", "Annex III", "Risk: cascading"
    title: str
    body: str  # retrieval + fallback excerpt text
    cite_refs: tuple[str, ...]  # article refs used for citation + the guard
    kind: str  # "article" | "annex" | "taxonomy"
    tokens: frozenset[str] = Field(default_factory=frozenset)


class QASource(BaseModel):
    ref: str
    title: str
    excerpt: str


class QAResult(BaseModel):
    question: str
    answer: str
    mode: str  # always "deterministic" — synthesis lives in the caller
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

    # 1. Verbatim article / annex text (with curated patches merged on top).
    for key, text in _OFFICIAL_TEXT.items():
        ref = _article_key_to_canonical(key)
        sub_title = _OFFICIAL_TITLES.get(key)
        full_title = f"{key} — {sub_title}" if sub_title else key
        entry = merged.setdefault(
            ref, {"title": full_title, "verbatim": "", "paraphrase": ""}
        )
        entry["verbatim"] = text
        entry["title"] = full_title

    # 2. Concise obligation paraphrases (focused, the guard's token pool).
    for ref, text in grounding.OBLIGATION_TEXT.items():
        entry = merged.setdefault(ref, {"title": ref, "verbatim": "", "paraphrase": ""})
        entry["paraphrase"] = text

    docs: list[_Doc] = []
    for ref, d in merged.items():
        body = (d["paraphrase"] + "\n\n" + d["verbatim"]).strip()
        kind = "annex" if ref.lower().startswith("annex") else "article"
        docs.append(
            _Doc(
                ref=ref,
                title=d["title"],
                body=body,
                cite_refs=(ref,) if kind == "article" else (),
                kind=kind,
                tokens=_tokenize(f"{ref} {d['title']} {body}"),
            )
        )

    # 3. Compound-risk taxonomy + threat categories (agentic Q&A).
    for risk_entry in COMPOUND_RISK_TYPES:
        labelled_recs = [
            f"{rec['text']} [{SOURCE_LABELS.get(rec['source'], rec['source'])}: {rec['ref']}]"
            for rec in risk_entry.get("recommendations", [])
        ]
        body = " ".join(
            [
                risk_entry.get("summary", ""),
                " ".join(risk_entry.get("failure_modes", [])),
                " ".join(labelled_recs),
            ]
        ).strip()
        label = risk_entry.get("label", risk_entry.get("id", "risk"))
        docs.append(
            _Doc(
                ref=f"Risk: {label}",
                title=f"Compound risk — {label}",
                body=body,
                cite_refs=tuple(risk_entry.get("article_refs", [])),
                kind="taxonomy",
                tokens=_tokenize(
                    f"{label} {body} " + " ".join(risk_entry.get("article_refs", []))
                ),
            )
        )
    for threat_entry in THREAT_CATEGORIES:
        body = threat_entry.get("description", "")
        label = threat_entry.get("label", threat_entry.get("id", "threat"))
        docs.append(
            _Doc(
                ref=f"Threat: {label}",
                title=f"Threat category — {label}",
                body=body,
                cite_refs=tuple(threat_entry.get("article_refs", [])),
                kind="taxonomy",
                tokens=_tokenize(
                    f"{label} {body} " + " ".join(threat_entry.get("article_refs", []))
                ),
            )
        )
    return docs


def _corpus() -> list[_Doc]:
    global _CORPUS
    if _CORPUS is None:
        _CORPUS = _build_corpus()
    return _CORPUS


def _boosted_refs(question: str) -> dict[str, float]:
    """Canonical refs explicitly named or topic-anchored, with tiered boost weights."""
    boosts: dict[str, float] = {}

    # 1. Explicit EU AI Act provision mentions (plural-safe, closed-world,
    #    foreign-statute guarded).
    for ref in extract_refs(question):
        boosts[ref] = 200.0

    # 2. Operator role anchors.
    q_lower = question.lower()
    if re.search(r"\b(importers?)\b", q_lower):
        boosts.setdefault("Art. 23", 100.0)
        boosts.setdefault("Art. 3", 50.0)
    if re.search(r"\b(distributors?)\b", q_lower):
        boosts.setdefault("Art. 24", 100.0)
        boosts.setdefault("Art. 3", 50.0)
    if re.search(r"\b(deployers?)\b", q_lower):
        boosts.setdefault("Art. 26", 100.0)
        boosts.setdefault("Art. 27", 80.0)
        boosts.setdefault("Art. 3", 50.0)
    if re.search(r"\b(authori[sz]ed\s+representatives?)\b", q_lower):
        boosts.setdefault("Art. 22", 100.0)
        boosts.setdefault("Art. 54", 90.0)
        boosts.setdefault("Art. 3", 50.0)
    if re.search(r"\b(product\s+manufacturers?)\b", q_lower):
        boosts.setdefault("Art. 25", 100.0)
        boosts.setdefault("Art. 16", 90.0)
        boosts.setdefault("Art. 3", 50.0)
    if re.search(r"\b(gpai|general[\s-]purpose\s+ai)\b", q_lower):
        boosts.setdefault("Art. 53", 100.0)
        boosts.setdefault("Art. 51", 90.0)

    # 3. Topic anchors.
    if re.search(r"\b(prohibited|unacceptable\s+risk)\b", q_lower):
        boosts.setdefault("Art. 5", 100.0)
    if re.search(r"\b(deepfake|synthetic\s+media|c2pa)\b", q_lower):
        boosts.setdefault("Art. 50", 100.0)
    if re.search(r"\b(post[\s-]market\s+monitoring)\b", q_lower):
        boosts.setdefault("Art. 72", 100.0)
    if _INCIDENT_RE.search(question):
        boosts.setdefault("Art. 73", 100.0)
    if re.search(r"\b(market\s+surveillance)\b", q_lower):
        boosts.setdefault("Art. 74", 100.0)
    if _EMOTION_RE.search(question):
        boosts.setdefault("Art. 5", 100.0)
        boosts.setdefault("Art. 50", 90.0)
        boosts.setdefault("Annex III", 85.0)
    if _PENALTIES_RE.search(question):
        boosts.setdefault("Art. 99", 100.0)
        boosts.setdefault("Art. 101", 90.0)
    if _TIMELINE_RE.search(question):
        boosts.setdefault("Art. 113", 95.0)
        boosts.setdefault("Art. 111", 85.0)
        boosts.setdefault("Art. 6", 65.0)

    return boosts


def _excerpt(doc: _Doc, question: str = "", limit: int = 500) -> str:
    """Paragraph-targeted excerpt for articles/annexes; bounded clip for taxonomy."""
    if doc.kind in ("article", "annex"):
        selected = select_relevant_paragraphs(doc.ref, question, max_chars=limit)
        if selected:
            cleaned = _normalise_ws(selected)
            # Only clip truly enormous single-block bodies (e.g. Art. 3 definitions)
            # that have no paragraph structure and far exceed budget.
            if len(cleaned) <= limit * 3:
                return cleaned
            return cleaned[: limit - 1].rsplit(" ", 1)[0].rstrip() + "…"
    text = _normalise_ws(doc.body)
    if len(text) <= limit:
        return text
    return text[: limit - 1].rsplit(" ", 1)[0].rstrip() + "…"


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


def _render_deterministic(
    top: list[tuple[_Doc, float]],
    dimensions: list[str],
    sources: list[QASource],
) -> str:
    parts = ["Based on the bundled EU AI Act knowledge base:\n"]
    for (doc, _), src in zip(top, sources, strict=True):
        parts.append(f"- **{doc.ref}** ({doc.title}) — {src.excerpt}")
    if dimensions:
        parts.append("\nRelated compliance dimensions: " + ", ".join(dimensions) + ".")
    parts.append(
        "\nThis is a deterministic retrieval over verbatim statute text, obligation "
        "paraphrases and the compound-risk taxonomy — not legal advice. Enable "
        "assisted mode (`/ai-act-settings`) to have your own Claude Code synthesise "
        "a narrative answer over the same grounding."
    )
    return "\n".join(parts)


def answer_question(
    question: str,
    *,
    top_k: int = 4,
    use_llm: bool | None = None,
) -> QAResult:
    """Answer an EU AI Act question, grounded in the bundled corpus.

    ``use_llm`` is accepted for backwards compatibility and ignored: synthesis
    is the caller's job (host Claude Code session or MCP client). This function
    always returns the deterministic grounded answer.
    """
    q = (question or "").strip()
    if not q:
        return QAResult(
            question=question,
            answer="Ask a question about the EU AI Act.",
            mode="deterministic",
        )

    q_tokens = _tokenize(q)
    boosted = _boosted_refs(q)
    scored: list[tuple[_Doc, float]] = []
    for doc in _corpus():
        score = float(len(q_tokens & doc.tokens))
        score += boosted.get(doc.ref, 0.0)
        if score > 0:
            scored.append((doc, score))

    # Deterministic ordering: score desc, then a stable ref tie-break.
    scored.sort(key=lambda t: (-t[1], t[0].ref))
    top = scored[:top_k]

    if not top:
        return QAResult(
            question=q,
            mode="deterministic",
            answer=(
                "No matching EU AI Act provision was found in the bundled corpus. "
                "Try naming an article (e.g. 'What does Article 50 require?') or a "
                "topic (e.g. 'deepfake disclosure', 'human oversight')."
            ),
        )

    refs: list[str] = []
    for doc, _ in top:
        for r in doc.cite_refs or (doc.ref,):
            if r not in refs:
                refs.append(r)
    article_refs = [
        r for r in refs if _art_number(r) is not None or r.lower().startswith("annex")
    ]
    dimensions = _dimensions_for(refs)
    sources = [
        QASource(ref=d.ref, title=d.title, excerpt=_excerpt(d, question=q))
        for d, _ in top
    ]

    return QAResult(
        question=q,
        answer=_render_deterministic(top, dimensions, sources),
        mode="deterministic",
        citations=article_refs,
        dimensions=dimensions,
        sources=sources,
    )
