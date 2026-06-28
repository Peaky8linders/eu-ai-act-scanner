"""Deterministic operator-role + obligation inference engine.

This module enriches scanner findings with two pieces of regulatory context
that a raw analyzer finding lacks:

1. **Operator role** — which EU AI Act role(s) (provider / deployer / GPAI
   provider / ...) the *scanned codebase* most plausibly occupies, inferred
   from a closed vocabulary of code signals (distributable-artifact markers,
   external-model SDK clients, training/fine-tuning code, large-model training
   scale). The closed-vocabulary keyword→role idea is ported from
   ``regenold-eu-ai-act-rag``'s ``entity_extractor.py`` (typed role + concept
   maps with word-boundary-safe matching). Here the signals scan *source code*
   rather than natural-language questions, but the discipline is the same:
   a fixed alias table, regex-compiled once, deterministic, fail-soft.

2. **Per-finding obligations** — for any individual :class:`~scanner.analyzers
   ._base.Finding`, the EU AI Act articles it implicates (from its compliance
   dimensions + any explicit article-paragraph citations), the operator roles
   that owe those articles (via :mod:`scanner.data.role_obligations`), and the
   authoritative obligation text for the primary article (via
   :mod:`scanner.grounding`).

The two combine in :func:`enrich_findings`, which back-fills the
``applicable_roles`` field on *gap* findings only, intersecting the inferred
role profile with the roles that actually owe the finding's articles. It is
idempotent and never overwrites a non-empty ``applicable_roles`` — matching the
contract of ``_apply_default_taxonomy_tags`` in
:mod:`scanner.analyzers.__init__`.

Pure, deterministic, offline. No network, no mutable module state (beyond the
``lru_cache`` of compiled signal tables and the reverse KB map, both derived
once from static data).
"""

from __future__ import annotations

import re
from functools import lru_cache

import structlog
from pydantic import BaseModel, Field

from scanner import grounding, refs
from scanner.analyzers._base import AnalyzerContext, Finding
from scanner.data.role_obligations import (
    CANONICAL_ROLE_IDS,
    ROLE_DEPLOYER,
    ROLE_GPAI_PROVIDER,
    ROLE_PROVIDER,
    compute_applicable_roles,
)
from scanner.kb import ARTICLE_TO_DIMENSIONS

logger = structlog.get_logger(__name__)

__all__ = [
    "ROLE_SIGNALS",
    "CONCEPT_SIGNALS",
    "RoleProfile",
    "infer_role_profile",
    "infer_roles",
    "obligations_for_finding",
    "enrich_findings",
]


# ── Closed-vocabulary role signals ─────────────────────────────────────────
#
# Each role id maps to a list of regex signals. A signal firing anywhere in the
# concatenated scanned source is evidence the codebase occupies that role.
# Ported in spirit from regenold's ROLES table — a fixed alias table compiled
# once. Signals here target *code* (imports, build manifests, API calls) rather
# than NL question text.
#
# The role ids are the canonical EU AI Act NLF ids from
# :mod:`scanner.data.role_obligations`.
ROLE_SIGNALS: dict[str, list[str]] = {
    # Provider — develops/commissions and places on market under own name.
    # Distributable-artifact markers (a published package, a console-script
    # entrypoint, a container image) OR first-party training/fine-tuning code.
    # NOTE: signals are deliberately *specific*. Bare markers like ``name = "…"``
    # (any quoted assignment), ``.fit(`` (any sklearn/pandas call), or ``.train()``
    # (any object) were dropped because they fire on ordinary deployer/data-science
    # code and would over-attribute the high-obligation provider role. Art. 3(3)
    # provider status is about placing a system on the market / first-party model
    # production — the markers below are the defensible proxies for that.
    ROLE_PROVIDER: [
        r"\[project\.scripts\]",
        r"\bsetup\s*\(",  # setup.py call
        r"\bentry_points\b",
        r"console_scripts",
        # First-party model building / training (framework-specific markers).
        r"\btorch\.save\b",
        r"\btrainer\.train\b",
        r"\bfine[_-]?tune\b",
        r"\bpeft\b",
        r"\blora\b",
        r"\bSFTTrainer\b",
        r"\bTrainingArguments\b",
    ],
    # Deployer — uses an external AI system under its own authority without
    # building/training it. External-model SDK clients.
    ROLE_DEPLOYER: [
        r"\bimport\s+openai\b",
        r"\bfrom\s+openai\b",
        r"\bimport\s+anthropic\b",
        r"\bfrom\s+anthropic\b",
        r"\bimport\s+cohere\b",
        r"\bfrom\s+cohere\b",
        r"\bOpenAI\s*\(",
        r"\bAnthropic\s*\(",
        r"\bchat\.completions\b",
        r"\bmessages\.create\b",
        r"\bgenerativeai\b",
    ],
    # GPAI model provider — training a general-purpose / foundation model at
    # transformers / large-model scale (own model + transformers training).
    ROLE_GPAI_PROVIDER: [
        r"\bfrom\s+transformers\b",
        r"\bimport\s+transformers\b",
        r"\bAutoModelForCausalLM\b",
        r"\bfoundation\s+model\b",
        r"\bpretrain\w*\b",
        r"\bfrom_pretrained\b.*\btrain\b",
        r"\bgpai\b",
        r"\bgeneral[- ]purpose\s+(?:ai\s+)?model\b",
    ],
}


# ── Closed-vocabulary concept signals ──────────────────────────────────────
#
# Concept keyword → list of canonical "Art. N" refs. Ported from regenold's
# CONCEPTS table, projected onto the scanner's canonical citation form. These
# let a free-text finding description / category surface the articles it
# implicates even when the finding carries no explicit compliance dimension.
CONCEPT_SIGNALS: dict[str, list[str]] = {
    "conformity_ce_mark": ["Art. 43", "Art. 47", "Art. 48"],
    "post_market_incident": ["Art. 72", "Art. 73"],
    "fundamental_rights": ["Art. 27"],
    "substantial_modification": ["Art. 25"],
    "gpai_foundation_model": ["Art. 53"],
}


# Aliases that map a concept keyword to its signal phrases. Kept separate from
# CONCEPT_SIGNALS (which is the public keyword→articles contract) so the public
# surface stays a clean keyword→articles map.
_CONCEPT_ALIASES: dict[str, tuple[str, ...]] = {
    "conformity_ce_mark": (
        "conformity assessment",
        "ce mark",
        "ce marking",
        "declaration of conformity",
    ),
    "post_market_incident": (
        "post-market",
        "post market",
        "incident report",
        "serious incident",
    ),
    "fundamental_rights": (
        "fundamental rights",
        "fria",
    ),
    "substantial_modification": (
        "substantial modification",
        "substantially modified",
        "fine-tune",
        "fine tune",
        "fine_tune",
    ),
    "gpai_foundation_model": (
        "gpai",
        "general-purpose ai model",
        "general purpose ai model",
        "foundation model",
    ),
}


_REGEX_SPECIAL_CHARS = frozenset(".*+?{}()|[]\\^$")


def _compile_signal(signal: str) -> re.Pattern[str]:
    """Compile one signal into a case-insensitive regex.

    Pure literals (no regex metacharacters) are wrapped in ``\\b`` word
    boundaries so ``"lora"`` does not match ``"explorator"``; signals that
    already contain metacharacters are compiled verbatim (they are
    hand-authored regexes). Mirrors regenold ``entity_extractor._compile_alias``.
    """
    has_special = any(c in _REGEX_SPECIAL_CHARS for c in signal)
    if has_special:
        return re.compile(signal, re.IGNORECASE)
    return re.compile(r"\b" + re.escape(signal) + r"\b", re.IGNORECASE)


@lru_cache(maxsize=1)
def _compiled_role_signals() -> tuple[tuple[str, tuple[re.Pattern[str], ...]], ...]:
    """Compile every role signal once, in :data:`ROLE_SIGNALS` order."""
    out: list[tuple[str, tuple[re.Pattern[str], ...]]] = []
    for role_id, signals in ROLE_SIGNALS.items():
        out.append((role_id, tuple(_compile_signal(s) for s in signals)))
    return tuple(out)


@lru_cache(maxsize=1)
def _compiled_concept_signals() -> tuple[tuple[str, tuple[re.Pattern[str], ...]], ...]:
    """Compile every concept alias once, in :data:`CONCEPT_SIGNALS` order."""
    out: list[tuple[str, tuple[re.Pattern[str], ...]]] = []
    for concept_id in CONCEPT_SIGNALS:
        aliases = _CONCEPT_ALIASES.get(concept_id, ())
        out.append((concept_id, tuple(_compile_signal(a) for a in aliases)))
    return tuple(out)


@lru_cache(maxsize=1)
def _dimension_to_articles() -> dict[str, tuple[str, ...]]:
    """Reverse :data:`scanner.kb.ARTICLE_TO_DIMENSIONS` → ``dim → ("Art. N", ...)``.

    Each dimension can be owed by multiple articles (e.g. ``decision_governance``
    routes to Art. 9, 14, 15, 72). Articles are returned in canonical
    :data:`CANONICAL_ROLE_IDS`-independent numeric order so the result is
    deterministic. Derived once from static KB data.
    """
    out: dict[str, list[str]] = {}
    for art_key, dim_ids in ARTICLE_TO_DIMENSIONS.items():
        ref = refs.to_internal(art_key)  # "art14" → "Art. 14"
        if not ref:
            continue
        for dim_id in dim_ids:
            out.setdefault(dim_id, []).append(ref)
    # Sort each dimension's articles by article number for determinism.
    return {
        dim_id: tuple(sorted(article_refs, key=_article_sort_key))
        for dim_id, article_refs in out.items()
    }


def _article_sort_key(ref: str) -> int:
    """Sort key by article number; non-article refs sort last."""
    spec = refs.parse(ref)
    return spec.article_number if spec.article_number is not None else 10_000


# ── Role inference ─────────────────────────────────────────────────────────


class RoleProfile(BaseModel):
    """The inferred operator-role profile for a scanned codebase.

    ``roles`` is ordered by :data:`CANONICAL_ROLE_IDS` and always has at least
    one entry. ``primary_role`` is the first role in that canonical order (the
    highest-obligation role wins, matching the NLF hierarchy provider >
    deployer). ``signals_matched`` records which signal strings fired per role,
    for traceability.
    """

    roles: list[str] = Field(default_factory=list)
    primary_role: str = ""
    signals_matched: dict[str, list[str]] = Field(default_factory=dict)


def _scan_source(ctx: AnalyzerContext) -> str:
    """Concatenate all text file contents into one corpus for signal scanning.

    File paths are included too so build-manifest filenames (``setup.py``,
    ``Dockerfile``, ``pyproject.toml``) themselves count as distributable-artifact
    evidence even when their content carries no other signal.
    """
    parts: list[str] = list(ctx.file_list)
    parts.extend(ctx.files.values())
    return "\n".join(parts)


def infer_role_profile(ctx: AnalyzerContext) -> RoleProfile:
    """Infer the operator-role profile from a scanned codebase.

    Deterministic. Scans the concatenated source for every role signal and
    records which fired. The returned ``roles`` list is ordered by
    :data:`CANONICAL_ROLE_IDS` and ALWAYS contains at least one role:

    * Any build / train / publish signal (provider or GPAI-provider signals)
      ⇒ that role is present.
    * Only external-model SDK usage and nothing else ⇒ defaults to
      ``"deployer"``.
    * No signal at all ⇒ defaults to ``"deployer"`` (the most conservative
      assumption — a codebase that merely uses AI is at minimum a deployer).

    GPAI-provider always implies provider as well (training a GPAI model is a
    provider activity), so the two are returned together when GPAI signals fire.
    """
    corpus = _scan_source(ctx)
    matched: dict[str, list[str]] = {}

    for role_id, patterns in _compiled_role_signals():
        hits: list[str] = []
        # Pair each compiled pattern back to its source signal string for the
        # traceability record.
        for pattern, source in zip(
            patterns, ROLE_SIGNALS[role_id], strict=True
        ):
            if pattern.search(corpus):
                hits.append(source)
        if hits:
            matched[role_id] = hits

    detected: set[str] = set(matched.keys())

    # GPAI provider implies provider (training a GPAI model is provider work).
    if ROLE_GPAI_PROVIDER in detected:
        detected.add(ROLE_PROVIDER)

    # Default-role logic: never return an empty profile.
    if not detected:
        detected.add(ROLE_DEPLOYER)

    roles = [r for r in CANONICAL_ROLE_IDS if r in detected]
    primary = roles[0] if roles else ROLE_DEPLOYER
    return RoleProfile(roles=roles, primary_role=primary, signals_matched=matched)


def infer_roles(ctx: AnalyzerContext) -> list[str]:
    """Return just the inferred role id list (``infer_role_profile(ctx).roles``)."""
    return infer_role_profile(ctx).roles


# ── Per-finding obligation inference ───────────────────────────────────────


def _articles_for_finding(finding: Finding) -> list[str]:
    """Collect the canonical ``"Art. N"`` refs a finding implicates.

    Sources, unioned and de-duplicated in first-seen canonical order:

    1. Each compliance dimension reversed through
       :data:`scanner.kb.ARTICLE_TO_DIMENSIONS`.
    2. Each explicit ``article_paragraphs`` entry, normalised via
       :mod:`scanner.refs` to its article-level canonical form.
    3. Concept signals firing on the finding's title + description (a finding
       that names "conformity assessment" but carries no dimension still gets
       Art. 43/47/48).
    """
    dim_map = _dimension_to_articles()
    seen: set[str] = set()
    out: list[str] = []

    def _add(ref: str) -> None:
        if ref and ref not in seen:
            seen.add(ref)
            out.append(ref)

    for dim_id in finding.compliance_dimensions:
        for ref in dim_map.get(dim_id, ()):  # already canonical
            _add(ref)

    for para in finding.article_paragraphs:
        # article_paragraphs are bare form ("14(4)"); reduce to article level.
        key = refs.article_key(para)  # "art14"
        _add(refs.to_internal(key))

    text = f"{finding.title}\n{finding.description}"
    for concept_id, patterns in _compiled_concept_signals():
        for pattern in patterns:
            if pattern.search(text):
                for ref in CONCEPT_SIGNALS[concept_id]:
                    _add(ref)
                break

    out.sort(key=_article_sort_key)
    return out


def obligations_for_finding(finding: Finding) -> dict:
    """Return the obligation context for a single finding.

    The returned dict has three keys:

    * ``articles`` — canonical ``"Art. N"`` refs the finding implicates, in
      ascending article-number order (see :func:`_articles_for_finding`).
    * ``applicable_roles`` — union of every operator role that owes any of
      those articles, ordered by :data:`CANONICAL_ROLE_IDS`.
    * ``obligation_text`` — authoritative EU AI Act obligation text for the
      *primary* (lowest-numbered) article, via
      :func:`scanner.grounding.obligation_text`. Empty string when no article
      resolves or the primary article has no grounding stub.

    Pure and deterministic; never raises on a well-formed :class:`Finding`.
    """
    articles = _articles_for_finding(finding)

    role_set: set[str] = set()
    for ref in articles:
        role_set.update(compute_applicable_roles(ref))
    applicable_roles = [r for r in CANONICAL_ROLE_IDS if r in role_set]

    primary_article = articles[0] if articles else ""
    text = grounding.obligation_text(primary_article) if primary_article else ""

    return {
        "articles": articles,
        "applicable_roles": applicable_roles,
        "obligation_text": text,
    }


def enrich_findings(
    findings: list[Finding], ctx: AnalyzerContext
) -> list[Finding]:
    """Back-fill ``applicable_roles`` on GAP findings, in place.

    For each finding with ``compliance_impact == "gap"`` and an EMPTY
    ``applicable_roles`` field, this sets ``applicable_roles`` to the
    intersection of:

    * the inferred role profile for the scanned codebase
      (:func:`infer_role_profile`), and
    * the roles that actually owe the finding's articles
      (:func:`obligations_for_finding`).

    If that intersection is empty (the codebase's inferred roles don't owe the
    finding's articles — e.g. a deployer-only codebase hit by a provider-only
    obligation), it falls back to the full set of article-owed roles, so the
    field is never left empty when articles resolve.

    Idempotent and non-destructive: a finding that already carries a non-empty
    ``applicable_roles`` (analyzer-level or a prior enrichment pass) is left
    untouched. Non-gap findings are never modified — matching the
    ``_apply_default_taxonomy_tags`` contract that ``applicable_roles`` is a
    gap-only obligation marker. Returns the same list it mutates.
    """
    profile_roles = set(infer_role_profile(ctx).roles)

    for f in findings:
        if f.compliance_impact != "gap":
            continue
        if f.applicable_roles:  # never overwrite — guarantees idempotency
            continue
        owed = obligations_for_finding(f)["applicable_roles"]
        if not owed:
            continue
        intersection = [r for r in owed if r in profile_roles]
        chosen = intersection if intersection else owed
        f.applicable_roles = [r for r in CANONICAL_ROLE_IDS if r in set(chosen)]

    return findings
