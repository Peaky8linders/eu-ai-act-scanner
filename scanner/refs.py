"""Single-source EU AI Act citation-form converter.

The scanner juggles **three** citation vocabularies. This module is the one
place that bridges them so future shape extensions touch a single file:

(a) **Finding bare form** — ``Finding.article_paragraphs`` entries such as
    ``"14(4)"``, ``"50(2-4)"``, ``"15(3)"``. A bare article number plus
    paren-wrapped paragraph tokens (a token may itself be a range like
    ``"2-4"``).

(b) **KB display form** — ``kb.Dimension.article`` strings such as
    ``"Art. 13 & 50"``, ``"Art. 9, 14, 15, 72"``, ``"Art. 15 / ISO 27002"``,
    ``"Art. 50(2-4)"``, ``"Art. 3(23)"``. Compound, human-authored, and
    sometimes carrying non-AI-Act framework tokens (ISO / NIST / OWASP) or an
    ``Annex IV`` mention that must be stripped when projecting to articles.

(c) **role_obligations canonical form** — ``"Art. 9"``, ``"Art. 25(4)"``,
    ``"Art. 74"``. The internal canonical form this module also emits.

Public API:
    RefSpec(article_number, annex_roman, paragraphs)   — frozen dataclass
    parse(ref) -> RefSpec
    to_internal(ref) -> str            # "Art. 14(4)"
    to_user_facing(ref) -> str         # "Article 14.4" / "Annex IV.1"
    normalise(ref) -> str              # idempotent canonical == to_internal
    article_key(ref) -> str            # "art14" / "annex_IV" / "" (junk)
    split_dimension_articles(field)    # compound display -> ["Art. N", ...]

Pure / deterministic / offline. Standard library only (no scanner.* imports).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)

__all__ = [
    "RefSpec",
    "parse",
    "to_internal",
    "to_user_facing",
    "normalise",
    "article_key",
    "split_dimension_articles",
]


@dataclass(frozen=True)
class RefSpec:
    """Parsed representation of a single EU AI Act citation.

    Exactly one of :attr:`article_number` / :attr:`annex_roman` is set for a
    valid ref; the other is ``None``. A wholly-unparseable ref yields an empty
    spec (both ``None``, empty :attr:`paragraphs`).

    :attr:`paragraphs` holds the paren/dot paragraph chain in left-to-right
    order — e.g. ``("4",)`` for ``"Art. 14(4)"`` or ``("2-4",)`` for
    ``"Art. 50(2-4)"``. Range tokens are preserved verbatim.
    """

    article_number: int | None = None
    annex_roman: str | None = None
    paragraphs: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_annex(self) -> bool:
        """True when this spec refers to an Annex rather than an Article."""
        return self.annex_roman is not None

    @property
    def is_empty(self) -> bool:
        """True when nothing parseable was found (article and annex both unset)."""
        return self.article_number is None and self.annex_roman is None


# ── Compiled regexes ─────────────────────────────────────────────────────────
#
# Accept any input prefix (``Art.`` / ``Article`` / bare / ``art14``). Emit the
# strict internal form (``Art. N``) or wire form (``Article N``) on output.

_PREFIX_ARTICLE = r"(?:Art\.?|Article)"
_ROMAN = r"[IVXLCDM]+"

# A paragraph/sub-point token: alphanumerics optionally carrying a single
# hyphen range (``2-4``). Matched inside ``(...)`` or after ``.``.
_TOKEN = r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)?"
_TAIL = rf"(?P<tail>(?:\.{_TOKEN}|\({_TOKEN}\))*)"

# Article in any input form. ``art14`` (no space) and ``Art. 14`` both match.
_ARTICLE_FULL_RE = re.compile(
    r"^\s*" + _PREFIX_ARTICLE + r"\s*(?P<num>\d{1,3})" + _TAIL + r"\s*$",
    re.IGNORECASE,
)
# Bare form: a leading number with no article prefix, e.g. "14(4)" / "50(2-4)".
_BARE_ARTICLE_RE = re.compile(
    r"^\s*(?P<num>\d{1,3})" + _TAIL + r"\s*$",
)
_ANNEX_FULL_RE = re.compile(
    r"^\s*Annex\s*_?\s*(?P<rom>" + _ROMAN + r")" + _TAIL + r"\s*$",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(r"\.(" + _TOKEN + r")|\((" + _TOKEN + r")\)")


def _extract_paragraphs(tail: str) -> tuple[str, ...]:
    """Pull paragraph tokens from a tail like ``(4)``, ``(2-4)``, ``.2.a``, mixed.

    Returns tokens left-to-right, range tokens (``2-4``) preserved verbatim.
    Returns ``()`` for an empty tail.
    """
    if not tail:
        return ()
    tokens: list[str] = []
    for dot_tok, paren_tok in _TOKEN_RE.findall(tail):
        raw = (dot_tok or paren_tok).strip()
        if raw:
            tokens.append(raw)
    return tuple(tokens)


def parse(ref: str) -> RefSpec:
    """Parse a citation in any of the three forms into a :class:`RefSpec`.

    Accepts:
        * ``"Art. 14(4)"`` / ``"Article 14.4"`` — article with paragraphs
        * ``"14(4)"`` / ``"50(2-4)"`` / ``"15(3)"`` — bare finding form
        * ``"art14"`` / ``"Art. 9"`` — canonical / role-obligation form
        * ``"Annex IV"`` / ``"Annex IV(1)"`` / ``"Annex IV.1"`` — annex variants
        * mixed-case Roman (``"annex iv"`` is uppercased)

    Unparseable input (``None``, empty, junk, framework tokens like
    ``"ISO 27002"``) returns an **empty** :class:`RefSpec` rather than raising —
    callers downstream treat empty as "no AI-Act ref here" and skip it.
    """
    if not ref:
        return RefSpec()
    raw = ref.strip()
    if not raw:
        return RefSpec()

    m = _ARTICLE_FULL_RE.match(raw)
    if m:
        return RefSpec(
            article_number=int(m.group("num")),
            paragraphs=_extract_paragraphs(m.group("tail")),
        )

    m = _BARE_ARTICLE_RE.match(raw)
    if m:
        return RefSpec(
            article_number=int(m.group("num")),
            paragraphs=_extract_paragraphs(m.group("tail")),
        )

    m = _ANNEX_FULL_RE.match(raw)
    if m:
        return RefSpec(
            annex_roman=m.group("rom").upper(),
            paragraphs=_extract_paragraphs(m.group("tail")),
        )

    logger.debug("refs.parse: unparseable ref treated as empty", ref=ref)
    return RefSpec()


def to_internal(ref: str) -> str:
    """Render a ref in internal canonical form: ``"14(4)"`` -> ``"Art. 14(4)"``.

    Annexes render as ``"Annex IV(1)"``. An unparseable ref returns ``""``.
    Idempotent on already-internal input.
    """
    return _format_internal(parse(ref))


def to_user_facing(ref: str) -> str:
    """Render a ref in user-facing wire form: ``"Art. 14(4)"`` -> ``"Article 14.4"``.

    Annexes render as ``"Annex IV.1"`` (dot-separated, never parens). An
    unparseable ref returns ``""``. Idempotent on already-user-facing input.
    """
    return _format_user_facing(parse(ref))


def normalise(ref: str) -> str:
    """Return the idempotent canonical form (alias of :func:`to_internal`).

    ``normalise(normalise(x)) == normalise(x)`` for every input. Used as the
    "one true form" for set-membership checks across call sites that emit the
    same citation in different shapes.
    """
    return to_internal(ref)


def article_key(ref: str) -> str:
    """Return the ``kb.ARTICLE_TO_DIMENSIONS`` key for a ref.

    ``"Art. 14(4)"`` / ``"14(4)"`` / ``"Article 14.4"`` -> ``"art14"``;
    ``"Annex IV"`` -> ``"annex_IV"``; junk / empty -> ``""`` (safe sentinel
    that never matches a real key). Paragraphs are dropped — the key is
    article-granular.
    """
    spec = parse(ref)
    if spec.article_number is not None:
        return f"art{spec.article_number}"
    if spec.annex_roman is not None:
        return f"annex_{spec.annex_roman}"
    return ""


# Framework / cross-walk tokens that may appear in a KB display string but are
# NOT EU AI Act articles. Matching is by parse() returning empty, so this set
# is documentation only — kept for the module docstring's promise to be
# explicit about what gets dropped.
_NON_AI_ACT_HINTS = (
    "ISO",
    "NIST",
    "OWASP",
    "SOC",
    "GDPR",
    "MITRE",
    "CSA",
    "CEN",
)

# Split a compound display string on the human separators KB authors use:
# comma, ampersand, slash. Whitespace around each is tolerated.
_COMPOUND_SPLIT_RE = re.compile(r"\s*[,&/]\s*")


def split_dimension_articles(article_field: str) -> list[str]:
    """Project a KB compound display string onto canonical ``"Art. N"`` refs.

    Parses ``kb.Dimension.article`` strings, carrying the leading ``"Art. "``
    prefix forward across bare continuation numbers, and STRIPS every
    non-AI-Act token (``ISO 27002``, ``NIST SP 800-53``, ``NIST SP 800-161``,
    ``OWASP Top-10 Agentic``, any ``Annex`` mention, ...). Paragraphs are
    dropped — output is article-granular and de-duplicated in first-seen order.

    Examples:
        ``"Art. 9, 14, 15, 72"``        -> ``["Art. 9", "Art. 14", "Art. 15", "Art. 72"]``
        ``"Art. 15 / ISO 27002"``       -> ``["Art. 15"]``
        ``"Art. 13 & 50"``              -> ``["Art. 13", "Art. 50"]``
        ``"Art. 11 / Annex IV"``        -> ``["Art. 11"]``
        ``"Art. 25 / Art. 25(4) / Art. 3(23)"`` -> ``["Art. 25", "Art. 3"]``
        ``""`` / junk                   -> ``[]``
    """
    if not article_field or not article_field.strip():
        return []

    out: list[str] = []
    seen: set[int] = set()
    for chunk in _COMPOUND_SPLIT_RE.split(article_field):
        token = chunk.strip()
        if not token:
            continue
        spec = parse(token)
        # parse() of a bare continuation number ("14") yields an article; of an
        # annex or framework token it yields empty -> skipped, which is exactly
        # the stripping behaviour the caller wants.
        if spec.article_number is None:
            continue
        if spec.article_number in seen:
            continue
        seen.add(spec.article_number)
        out.append(f"Art. {spec.article_number}")
    return out


# ── Internal formatters ──────────────────────────────────────────────────────


def _format_internal(spec: RefSpec) -> str:
    """Render a :class:`RefSpec` in internal canonical form (parens, ``Art.``)."""
    if spec.is_empty:
        return ""
    if spec.is_annex:
        head = f"Annex {spec.annex_roman}"
    else:
        head = f"Art. {spec.article_number}"
    tail = "".join(f"({t})" for t in spec.paragraphs)
    return head + tail


def _format_user_facing(spec: RefSpec) -> str:
    """Render a :class:`RefSpec` in user-facing wire form (dots, ``Article``)."""
    if spec.is_empty:
        return ""
    if spec.is_annex:
        head = f"Annex {spec.annex_roman}"
    else:
        head = f"Article {spec.article_number}"
    tail = "".join(f".{t}" for t in spec.paragraphs)
    return head + tail
