"""Verbatim AI-Act obligation text + a sentence-level citation guard.

This is the anti-hallucination layer for any LLM surface the scanner drives.
It serves two jobs:

1. **Authoritative grounding** — :data:`OBLIGATION_TEXT` carries a concise,
   faithful 2-4 sentence statement of each EU AI Act article's core
   obligation, paraphrased directly from the Official Journal prose
   (Regulation (EU) 2024/1689, EUR-Lex CELEX 32024R1689). Every article that
   appears in :data:`scanner.kb.ARTICLE_TO_DIMENSIONS` has an entry, so a
   prompt built from a KB dimension always has authoritative text to inject.
   :func:`ground_prompt` packages that text into a labelled block suitable for
   an LLM system prompt.

2. **Citation guard** — :func:`filter_unsupported_sentences` is a
   post-generation parser (ported from
   ``app/integrations/regenold/citation_guard.py``). It drops sentences from a
   candidate answer whose tokens do not overlap the obligation-text token pool
   of the cited articles, on the principle that an unsupported sentence is a
   hallucination risk. It is purely subtractive — the output is a subsequence
   of the input — and it NEVER returns an empty string: when every sentence is
   unsupported it keeps the single best-overlap one as a floor (the Round-16
   finding that an over-broad answer beats an empty one).

Citation parsing (reducing any reference shape to its canonical article and
splitting a compound KB ``Dimension.article`` field) is delegated to
:mod:`scanner.refs` — the single source of truth for the codebase's three
citation vocabularies — so the grounding block can never disagree with the
citation guard's article pool.

Pure, deterministic, offline. No network, no mutable module state.

Public API:
    OBLIGATION_TEXT: dict[str, str]
    obligation_text(article_ref) -> str
    dimension_grounding(dim_id) -> str
    ground_prompt(dim_id) -> str
    filter_unsupported_sentences(answer, refs, *, min_overlap_tokens=1) -> str
"""

from __future__ import annotations

import re
from functools import lru_cache

import structlog

from scanner import refs
from scanner.kb import DIMENSIONS

logger = structlog.get_logger(__name__)


# ── Authoritative obligation text ──────────────────────────────────────────
#
# Keyed by canonical ``"Art. N"``. Each value is a faithful 2-4 sentence
# paraphrase of the article's core obligation, grounded in the verbatim
# EUR-Lex prose (Regulation (EU) 2024/1689). The wording stays close to the
# statute so it can anchor an LLM against invention without quoting at length.
# MUST cover every article in :data:`scanner.kb.ARTICLE_TO_DIMENSIONS`.
OBLIGATION_TEXT: dict[str, str] = {
    "Art. 4": (
        "Providers and deployers of AI systems must take measures to ensure, to "
        "their best extent, a sufficient level of AI literacy among their staff and "
        "other persons operating or using the systems on their behalf. The measures "
        "must take into account those persons' technical knowledge, experience, "
        "education and training, and the context in which the systems are used. In "
        "force since February 2025."
    ),
    "Art. 9": (
        "A risk management system must be established, implemented, documented and "
        "maintained for high-risk AI systems. It is a continuous, iterative process "
        "run throughout the entire lifecycle, requiring regular systematic review "
        "and updating. It must identify and analyse known and reasonably foreseeable "
        "risks to health, safety and fundamental rights and adopt targeted risk "
        "management measures to address them."
    ),
    "Art. 10": (
        "High-risk AI systems that train models with data must use training, "
        "validation and testing data sets that meet quality criteria and are subject "
        "to appropriate data governance and management practices. Those practices "
        "cover design choices, data collection and origin, preparation, assumptions, "
        "availability, and examination for possible biases that could affect health, "
        "safety or fundamental rights. Data sets must be relevant, sufficiently "
        "representative, and as far as possible free of errors and complete for the "
        "intended purpose."
    ),
    "Art. 11": (
        "Technical documentation for a high-risk AI system must be drawn up before "
        "the system is placed on the market or put into service and kept up to date. "
        "It must demonstrate that the system complies with the requirements of "
        "Section 2 and give national competent authorities and notified bodies the "
        "information needed to assess compliance, containing at a minimum the "
        "elements set out in Annex IV."
    ),
    "Art. 12": (
        "High-risk AI systems must technically allow for the automatic recording of "
        "events (logs) over the lifetime of the system. The logging capabilities "
        "must enable a level of traceability appropriate to the intended purpose, "
        "including identifying situations that may present a risk or a substantial "
        "modification, facilitating post-market monitoring, and monitoring the "
        "system's operation."
    ),
    "Art. 13": (
        "High-risk AI systems must be designed and developed so that their operation "
        "is sufficiently transparent to enable deployers to interpret a system's "
        "output and use it appropriately. They must be accompanied by instructions "
        "for use that include concise, complete, correct and clear information that "
        "is relevant, accessible and comprehensible to deployers, covering the "
        "provider's identity, the system's characteristics, capabilities and "
        "limitations of performance, and human oversight measures."
    ),
    "Art. 14": (
        "High-risk AI systems must be designed and developed, including with "
        "appropriate human-machine interface tools, so that they can be effectively "
        "overseen by natural persons during the period in which they are in use. "
        "Human oversight must aim to prevent or minimise risks to health, safety and "
        "fundamental rights, and must enable the assigned persons to understand the "
        "system, monitor its operation, correctly interpret output, decide not to "
        "use it, and intervene or stop it."
    ),
    "Art. 15": (
        "High-risk AI systems must be designed and developed to achieve an "
        "appropriate level of accuracy, robustness and cybersecurity, and to perform "
        "consistently in those respects throughout their lifecycle. They must be "
        "resilient to errors, faults and inconsistencies, and to attempts by "
        "unauthorised third parties to alter their use, outputs or performance by "
        "exploiting vulnerabilities, including measures to address data poisoning, "
        "model poisoning, adversarial examples and model evasion."
    ),
    "Art. 17": (
        "Providers of high-risk AI systems must put in place a quality management "
        "system that ensures compliance with the Regulation, documented "
        "systematically in written policies, procedures and instructions. It must "
        "include at least a strategy for regulatory compliance, techniques and "
        "procedures for design, development, testing and validation, examination "
        "and quality control, data management, risk management, post-market "
        "monitoring, incident reporting, record-keeping and an accountability "
        "framework."
    ),
    "Art. 25": (
        "Any distributor, importer, deployer or other third party is considered a "
        "provider of a high-risk AI system, and subject to the provider's "
        "obligations, where they put their name or trademark on it, make a "
        "substantial modification to it, or modify its intended purpose so that it "
        "becomes high-risk. Where such a change occurs the original provider must "
        "cooperate closely and make available the information needed to fulfil the "
        "obligations, in particular for conformity assessment."
    ),
    "Art. 26": (
        "Deployers of high-risk AI systems must take appropriate technical and "
        "organisational measures to use them in accordance with the accompanying "
        "instructions for use. They must assign human oversight to competent, "
        "trained and authorised natural persons, ensure input data is relevant and "
        "sufficiently representative where they control it, monitor operation, keep "
        "the automatically generated logs, and inform affected persons and "
        "authorities as required."
    ),
    "Art. 27": (
        "Before deploying certain high-risk AI systems, deployers that are public "
        "bodies or private entities providing public services (and deployers of "
        "specified Annex III systems) must perform a fundamental rights impact "
        "assessment. The assessment must describe the deployment processes, the "
        "period and frequency of use, the categories of persons likely to be "
        "affected, the specific risks of harm to them, the human oversight measures, "
        "and the measures to be taken if those risks materialise."
    ),
    "Art. 43": (
        "Providers of high-risk AI systems must ensure the system undergoes the "
        "relevant conformity assessment procedure before it is placed on the market "
        "or put into service, demonstrating compliance with the requirements of "
        "Section 2. Depending on the system and whether harmonised standards were "
        "applied, this is either an internal-control procedure (Annex VI) or an "
        "assessment involving a notified body (Annex VII). A new conformity "
        "assessment is required whenever the system is substantially modified."
    ),
    "Art. 47": (
        "The provider must draw up a written, machine-readable EU declaration of "
        "conformity for each high-risk AI system and keep it at the disposal of "
        "national competent authorities for 10 years after the system is placed on "
        "the market or put into service. The declaration must state that the system "
        "meets the requirements of Section 2, identify the system, and be kept up to "
        "date and submitted to authorities on request."
    ),
    "Art. 48": (
        "The CE marking must be affixed visibly, legibly and indelibly to a "
        "high-risk AI system to indicate its conformity with the Regulation, or to "
        "its packaging or accompanying documentation where that is not possible. For "
        "systems provided digitally, a digital CE marking is used where it can be "
        "easily accessed. Where a notified body is involved in conformity "
        "assessment, its identification number must accompany the marking."
    ),
    "Art. 50": (
        "Providers must ensure AI systems intended to interact directly with natural "
        "persons disclose that fact, unless it is obvious. Providers of generative "
        "systems must mark synthetic audio, image, video or text outputs as "
        "artificially generated or manipulated in a machine-readable way. Deployers "
        "of emotion-recognition or biometric-categorisation systems, and deployers "
        "generating or manipulating deep-fake or public-interest text, must disclose "
        "that to the persons concerned."
    ),
    "Art. 51": (
        "A general-purpose AI model is classified as a model with systemic risk if "
        "it has high-impact capabilities, evaluated using appropriate technical "
        "tools, methodologies, indicators and benchmarks, or if the Commission so "
        "decides on the basis of equivalent capabilities or impact. A model is "
        "presumed to have high-impact capabilities when the cumulative compute used "
        "for its training exceeds the threshold set in the Regulation."
    ),
    "Art. 53": (
        "Providers of general-purpose AI models must draw up and keep up to date the "
        "technical documentation of the model, including its training and testing "
        "process and evaluation results, for the AI Office and national competent "
        "authorities. They must also make information and documentation available to "
        "downstream providers integrating the model, put in place a policy to comply "
        "with Union copyright law, and publish a sufficiently detailed summary of "
        "the content used for training. In force since August 2025."
    ),
    "Art. 55": (
        "In addition to the obligations on general-purpose AI model providers, "
        "providers of models with systemic risk must perform model evaluation "
        "according to standardised protocols, including conducting and documenting "
        "adversarial testing to identify and mitigate systemic risks. They must "
        "assess and mitigate possible systemic risks at Union level, track, document "
        "and report serious incidents and corrective measures, and ensure an "
        "adequate level of cybersecurity for the model and its physical "
        "infrastructure."
    ),
    "Art. 72": (
        "Providers must establish and document a post-market monitoring system "
        "proportionate to the nature and risks of the high-risk AI system. The "
        "system must actively and systematically collect, document and analyse "
        "relevant data on the performance of the system throughout its lifetime, "
        "enabling the provider to evaluate continuous compliance with the "
        "requirements of Chapter III, Section 2, and must be based on a post-market "
        "monitoring plan."
    ),
    "Art. 95": (
        "The AI Office and the Member States must encourage and facilitate the "
        "drawing up of codes of conduct, including governance mechanisms, intended "
        "to foster the voluntary application to non-high-risk AI systems of some or "
        "all of the requirements set out in Chapter III, Section 2. The codes may "
        "also cover voluntary commitments on environmental sustainability, AI "
        "literacy, inclusive and diverse design, and the impact on vulnerable "
        "persons."
    ),
}


# Tokeniser for the citation guard. Lowercase alphanumeric runs of length > 2,
# minus a small stopword pool of high-frequency function words that would
# otherwise dominate token-overlap.
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOP = frozenset(
    "the a an of to in on for and or as is are be by with that this which "
    "what when who how do does shall must may any all its their our we us "
    "eu ai act article articles annex regulation system systems".split()
)


def _to_canonical(article_ref: str) -> str:
    """Normalise any article reference shape to canonical ``"Art. N"``.

    Accepts ``"Art. 14"``, ``"14"``, ``"art14"``, ``"Article 14"``,
    ``"14(4)"``, ``"Art. 9(2)(a)"`` etc. Delegates to :func:`scanner.refs.parse`
    so a framework token like ``"SOC 2"`` (no Act article) resolves to ``""``
    rather than a spurious ``"Art. 2"``. Annex refs (no article number) also
    return ``""``. Returns ``""`` when no Act article can be parsed.
    """
    spec = refs.parse(article_ref or "")
    if spec.article_number is None:
        return ""
    return f"Art. {spec.article_number}"


def obligation_text(article_ref: str) -> str:
    """Return the authoritative obligation text for an article reference.

    ``article_ref`` may be any shape — ``"Art. 14"``, ``"14"``, ``"art14"``,
    ``"Article 14"``, ``"14(4)"``, ``"Art. 9(2)(a)"`` — and is reduced to its
    article number before lookup. Returns ``""`` when the article is unknown or
    no number can be parsed.
    """
    canonical = _to_canonical(article_ref)
    if not canonical:
        return ""
    return OBLIGATION_TEXT.get(canonical, "")


def dimension_grounding(dim_id: str) -> str:
    """Return the joined obligation text for every article of a KB dimension.

    Looks up ``dim_id`` in :data:`scanner.kb.DIMENSIONS`, splits its compound
    ``article`` field with :func:`scanner.refs.split_dimension_articles` (the
    canonical converter — it strips framework crosswalk tails like ``ISO 27002``
    and never leaks paragraph/sub-point numbers as fake articles), and joins the
    obligation text of each resolvable EU AI Act article (in document order,
    blank-line separated). Returns ``""`` for an unknown dimension or one whose
    articles have no obligation text (e.g. a pure framework-crosswalk dimension).
    """
    dim = DIMENSIONS.get(dim_id)
    if dim is None:
        logger.debug("dimension_grounding.unknown_dimension", dim_id=dim_id)
        return ""
    parts: list[str] = []
    for ref in refs.split_dimension_articles(dim.article):
        text = OBLIGATION_TEXT.get(ref, "")
        if text:
            parts.append(f"{ref}: {text}")
    return "\n\n".join(parts)


def ground_prompt(dim_id: str) -> str:
    """Return a labelled grounding block for injection into an LLM prompt.

    Wraps :func:`dimension_grounding` in a header naming the dimension so an
    LLM system prompt can present authoritative statute text as the ground
    truth the model must not contradict. Returns ``""`` when the dimension is
    unknown or has no grounding text (so the caller can omit the block).
    """
    dim = DIMENSIONS.get(dim_id)
    if dim is None:
        return ""
    grounding = dimension_grounding(dim_id)
    if not grounding:
        return ""
    return f"Authoritative EU AI Act text for {dim.label} ({dim.article}):\n{grounding}"


# ── Citation guard (ported from regenold citation_guard.py) ────────────────


def _tokenize(text: str) -> set[str]:
    """Lowercase content-token set, stopwords and short tokens removed."""
    return {
        w
        for w in _TOKEN_RE.findall((text or "").lower())
        if len(w) > 2 and w not in _STOP
    }


@lru_cache(maxsize=256)
def _reference_token_pool(article_ref: str) -> frozenset[str]:
    """Token pool for a single article ref — its obligation text + the ref itself.

    Cached per ref so the guard's hot path is a set lookup. Accepts any ref
    shape (normalised via :func:`obligation_text`). Returns an EMPTY set when
    the ref has no obligation text (unknown article): an unknown citation must
    carry no verification weight, so the caller treats it as "no support" and
    falls into the keep-everything / keep-best-one fallback rather than letting
    a bare article number anchor sentences.
    """
    text = obligation_text(article_ref)
    if not text:
        return frozenset()
    tokens: set[str] = set(_tokenize(text))
    # Fold in the canonical ref tokens so a sentence naming "Article 14"
    # registers as overlap on the bare article number.
    canonical = _to_canonical(article_ref)
    tokens.update(_tokenize(canonical))
    return frozenset(tokens)


def _reference_pool(refs: tuple[str, ...]) -> frozenset[str]:
    """Union token pool over a tuple of refs (small; not cached itself)."""
    if not refs:
        return frozenset()
    out: set[str] = set()
    for ref in refs:
        out.update(_reference_token_pool(ref))
    return frozenset(out)


# Sentence splitter — abbreviation-aware so legal abbreviations ("Art.",
# "e.g.", "i.e.", "No.") do not trigger false splits. Splits on sentence-final
# punctuation followed by whitespace and an uppercase / opening-paren start.
_ABBREV = frozenset({"art", "arts", "no", "nos", "e.g", "i.e", "cf", "para", "annex", "reg"})
_SENT_BOUNDARY_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z(])")


def _split_sentences(text: str) -> list[str]:
    """Split an answer into sentences, preserving punctuation.

    Abbreviation-aware: a boundary candidate is rejected when the token
    immediately before the punctuation is a known legal abbreviation (so
    "Art. 5 ..." stays one sentence). Falls back to the whole text as a single
    sentence when no boundary is found. Pure stdlib.
    """
    if not text or not text.strip():
        return []
    raw = _SENT_BOUNDARY_RE.split(text.strip())
    sentences: list[str] = []
    for chunk in raw:
        chunk = chunk.strip()
        if not chunk:
            continue
        # Re-merge with the previous sentence if the previous one ended in a
        # known abbreviation (the boundary was a false positive).
        if sentences:
            prev = sentences[-1]
            last_word = re.split(r"\s+", prev.rstrip("."))[-1].lower()
            if last_word in _ABBREV:
                sentences[-1] = f"{prev} {chunk}"
                continue
        sentences.append(chunk)
    return sentences


def filter_unsupported_sentences(
    answer: str,
    refs: tuple[str, ...],
    *,
    min_overlap_tokens: int = 1,
) -> str:
    """Return ``answer`` with sentences unsupported by the cited refs removed.

    A sentence is **supported** when at least ``min_overlap_tokens`` of its
    content tokens appear in the union obligation-text token pool of the cited
    ``refs``. Unsupported sentences are dropped — but the guard NEVER returns
    an empty string when ``answer`` was non-empty:

    * Empty / whitespace ``answer`` → returned unchanged.
    * No ``refs`` → returned unchanged (nothing to verify against).
    * Single sentence → returned unchanged (the "never drop the only
      sentence" floor).
    * Refs resolve to an empty token pool → returned unchanged (can't verify).
    * Multiple sentences, all unsupported → keep the best-overlap one only.
    * Multiple sentences, some supported → keep the supported ones in document
      order.

    The default ``min_overlap_tokens=1`` is deliberately lenient: a single
    shared content token keeps a sentence. Pure function; never raises. The
    output is always a subsequence of the input sentences.
    """
    if not answer or not answer.strip():
        return answer
    if not refs:
        return answer

    sentences = _split_sentences(answer)
    if len(sentences) <= 1:
        return answer

    pool = _reference_pool(tuple(refs))
    if not pool:
        # No references resolved → can't verify → keep everything.
        return answer

    # Score each sentence by token overlap with the obligation-text pool.
    sentence_overlap: list[tuple[int, int]] = []  # (idx, overlap_count)
    supported_idx: list[int] = []
    for i, sent in enumerate(sentences):
        overlap = len(_tokenize(sent) & pool)
        sentence_overlap.append((i, overlap))
        if overlap >= min_overlap_tokens:
            supported_idx.append(i)

    if not supported_idx:
        # All sentences below the bar — keep the best-overlap one as the floor.
        best = max(sentence_overlap, key=lambda t: t[1])
        return sentences[best[0]]

    kept = [sentences[i] for i in supported_idx]
    return " ".join(kept)


__all__ = [
    "OBLIGATION_TEXT",
    "obligation_text",
    "dimension_grounding",
    "ground_prompt",
    "filter_unsupported_sentences",
]
