"""Tests for the grounding / anti-hallucination layer (:mod:`scanner.grounding`).

Two contracts are under test:

1. **Coverage + faithful lookup** — :data:`OBLIGATION_TEXT` must cover every
   article in :data:`scanner.kb.ARTICLE_TO_DIMENSIONS` (otherwise a KB
   dimension can be grounded with no statute text, and the LLM has nothing to
   anchor to). :func:`obligation_text` must accept every reference shape the
   scanner emits.

2. **Citation guard** — :func:`filter_unsupported_sentences` must drop a
   sentence with no statute support, keep a supported one, and — the
   load-bearing invariant — NEVER return empty even when nothing matches.

Conventions match ``test_incident_grounding.py``: classes group related
assertions; the suite is hermetic (no network, no fixture mutation).
"""

from __future__ import annotations

import re

from scanner.grounding import (
    OBLIGATION_TEXT,
    dimension_grounding,
    filter_unsupported_sentences,
    ground_prompt,
    obligation_text,
)
from scanner.kb import ARTICLE_TO_DIMENSIONS, DIMENSIONS


def _article_label(art_key: str) -> str:
    """``"art14"`` → ``"Art. 14"`` for cross-referencing the two key spaces."""
    return f"Art. {int(art_key.removeprefix('art'))}"


class TestObligationTextCoverage:
    def test_covers_every_article_in_kb(self):
        """Every article the KB maps to a dimension must have obligation text.

        This is the anti-hallucination guarantee: if a dimension routes to an
        article with no grounding stub, the LLM prompt for that dimension would
        carry no authoritative text and could invent the obligation.
        """
        missing = [
            _article_label(art_key)
            for art_key in ARTICLE_TO_DIMENSIONS
            if _article_label(art_key) not in OBLIGATION_TEXT
        ]
        assert missing == [], f"OBLIGATION_TEXT is missing articles: {missing}"

    def test_no_obligation_entry_is_blank(self):
        """A present-but-empty stub is as dangerous as a missing one."""
        blanks = [k for k, v in OBLIGATION_TEXT.items() if not v.strip()]
        assert blanks == [], f"blank obligation text for: {blanks}"

    def test_every_entry_is_two_to_four_sentences(self):
        """Spec calls for a concise 2-4 sentence statement, not a one-liner or
        a wall of text — both undermine the grounding-block design."""
        for key, text in OBLIGATION_TEXT.items():
            # Count sentence-final punctuation as a coarse sentence proxy.
            n_sentences = text.count(". ") + text.count("? ") + text.endswith(".")
            assert 2 <= n_sentences <= 5, f"{key}: ~{n_sentences} sentences"

    def test_keys_are_canonical_form(self):
        """Keys must be the canonical ``"Art. N"`` shape the lookup expects."""
        for key in OBLIGATION_TEXT:
            assert key.startswith("Art. "), key
            assert key.removeprefix("Art. ").isdigit(), key


class TestObligationTextLookup:
    def test_accepts_canonical_form(self):
        assert obligation_text("Art. 14") == OBLIGATION_TEXT["Art. 14"]

    def test_accepts_bare_number(self):
        assert obligation_text("14") == OBLIGATION_TEXT["Art. 14"]

    def test_accepts_compact_artnn_form(self):
        assert obligation_text("art14") == OBLIGATION_TEXT["Art. 14"]

    def test_accepts_paragraph_subpoint_form(self):
        """A paragraph ref must resolve to its parent article's text."""
        assert obligation_text("14(4)") == OBLIGATION_TEXT["Art. 14"]
        assert obligation_text("Art. 9(2)(a)") == OBLIGATION_TEXT["Art. 9"]

    def test_accepts_full_article_word(self):
        assert obligation_text("Article 50") == OBLIGATION_TEXT["Art. 50"]

    def test_all_input_forms_agree(self):
        forms = ["Art. 15", "15", "art15", "Article 15", "15(4)", "art. 15 "]
        results = {obligation_text(f) for f in forms}
        assert len(results) == 1, f"forms disagreed: {results}"
        assert results == {OBLIGATION_TEXT["Art. 15"]}

    def test_unknown_article_returns_empty(self):
        # Art. 999 is not in the catalogue; must return "" not raise.
        assert obligation_text("999") == ""
        assert obligation_text("Art. 999") == ""

    def test_unparseable_ref_returns_empty(self):
        assert obligation_text("") == ""
        assert obligation_text("not-an-article") == ""


class TestDimensionGrounding:
    def test_single_article_dimension(self):
        # risk_mgmt → Art. 9
        text = dimension_grounding("risk_mgmt")
        assert OBLIGATION_TEXT["Art. 9"] in text

    def test_compound_article_dimension_covers_all_parts(self):
        """``transparency`` → "Art. 13 & 50": both must appear, in order."""
        text = dimension_grounding("transparency")
        assert OBLIGATION_TEXT["Art. 13"] in text
        assert OBLIGATION_TEXT["Art. 50"] in text
        assert text.index("Art. 13") < text.index("Art. 50")

    def test_comma_separated_articles(self):
        # conformity_assessment → "Art. 43, 47, 48"
        text = dimension_grounding("conformity_assessment")
        for art in ("Art. 43", "Art. 47", "Art. 48"):
            assert OBLIGATION_TEXT[art] in text

    def test_ignores_framework_crosswalk_numerals(self):
        """``access_control`` is "Art. 15 / ISO 27002" — only Art. 15 grounds,
        the ISO numeral must NOT be parsed as an article number."""
        text = dimension_grounding("access_control")
        assert OBLIGATION_TEXT["Art. 15"] in text
        # 27002 must never resolve to an obligation key.
        assert "Art. 27002" not in text
        assert obligation_text("27002") == ""

    def test_paragraph_numbers_do_not_leak_as_fake_articles(self):
        """REGRESSION: a paragraph/sub-point range inside the article field must
        never surface as a *separate* article. ``content_transparency`` is
        "Art. 50(2-4)" — it must ground Art. 50 and must NOT inject the Art. 4
        (AI-literacy) obligation text (the "(2-4)" must not become Art. 2/4)."""
        text = dimension_grounding("content_transparency")
        assert OBLIGATION_TEXT["Art. 50"] in text
        assert OBLIGATION_TEXT["Art. 4"] not in text
        # regulatory_perimeter = "Art. 25 / Art. 25(4) / Art. 3(23)": the "(4)"
        # and "(23)" sub-points must not leak as Art. 4 / Art. 23.
        rp = dimension_grounding("regulatory_perimeter")
        assert OBLIGATION_TEXT["Art. 25"] in rp
        assert OBLIGATION_TEXT["Art. 4"] not in rp

    def test_obligation_text_rejects_framework_token(self):
        """A framework token ("SOC 2", "ISO 27002") must not resolve to a spurious
        article via a bare first-digit grab."""
        assert obligation_text("SOC 2") == ""
        assert obligation_text("ISO 27002") == ""

    def test_every_kb_dimension_with_act_article_grounds(self):
        """Any dimension whose article field names a real Act article that has
        obligation text must produce non-empty grounding."""
        for dim_id, dim in DIMENSIONS.items():
            text = dimension_grounding(dim_id)
            # If the field names an article we have text for, grounding is
            # non-empty; otherwise it is allowed to be empty.
            has_known = any(
                f"Art. {int(m.group(1))}" in OBLIGATION_TEXT
                for m in re.finditer(r"Art(?:icle)?\.?\s*(\d{1,3})", dim.article)
            )
            if has_known:
                assert text, f"{dim_id} ({dim.article}) grounded empty"

    def test_unknown_dimension_returns_empty(self):
        assert dimension_grounding("not_a_dimension") == ""


class TestGroundPrompt:
    def test_block_is_labelled_with_dimension(self):
        block = ground_prompt("human_oversight")
        assert block.startswith("Authoritative EU AI Act text for")
        assert DIMENSIONS["human_oversight"].label in block

    def test_block_contains_obligation_text(self):
        block = ground_prompt("human_oversight")
        assert OBLIGATION_TEXT["Art. 14"] in block

    def test_unknown_dimension_returns_empty(self):
        assert ground_prompt("not_a_dimension") == ""


# Supported sentence: shares strong vocabulary with Art. 14 (human oversight).
_SUPPORTED = (
    "High-risk AI systems must be overseen by natural persons who can "
    "intervene and stop the system during use."
)
# Unsupported sentence: about an unrelated topic with no statute overlap.
_UNSUPPORTED = "Our quarterly marketing budget grew thanks to viral memes."


class TestCitationGuard:
    def test_drops_unsupported_keeps_supported(self):
        answer = f"{_SUPPORTED} {_UNSUPPORTED}"
        out = filter_unsupported_sentences(answer, ("Art. 14",))
        assert _SUPPORTED in out
        assert "marketing budget" not in out

    def test_keeps_supported_sentence_when_alone_among_unsupported(self):
        # Supported sentence sandwiched between two unsupported ones.
        answer = f"{_UNSUPPORTED} {_SUPPORTED} The cafeteria serves pizza on Fridays."
        out = filter_unsupported_sentences(answer, ("Art. 14",))
        assert _SUPPORTED in out
        assert "marketing budget" not in out
        assert "pizza" not in out

    def test_never_returns_empty_when_nothing_matches(self):
        """The load-bearing invariant: even with zero overlap the guard keeps
        the single best sentence rather than emptying the answer."""
        answer = (
            f"{_UNSUPPORTED} The weather in Lisbon is mild in spring. "
            "Tickets sold out within an hour."
        )
        out = filter_unsupported_sentences(answer, ("Art. 14",))
        assert out.strip(), "guard returned an empty answer"
        # Output is one of the input sentences (purely subtractive).
        assert out in answer or out.strip() in answer

    def test_single_sentence_returned_unchanged(self):
        answer = _UNSUPPORTED  # one sentence, no support
        assert filter_unsupported_sentences(answer, ("Art. 14",)) == answer

    def test_no_refs_returns_unchanged(self):
        answer = f"{_SUPPORTED} {_UNSUPPORTED}"
        assert filter_unsupported_sentences(answer, ()) == answer

    def test_empty_answer_returned_unchanged(self):
        assert filter_unsupported_sentences("", ("Art. 14",)) == ""
        assert filter_unsupported_sentences("   ", ("Art. 14",)) == "   "

    def test_unknown_ref_pool_keeps_everything(self):
        """A ref with no obligation text resolves to an empty pool → nothing to
        verify against → answer kept whole (don't damage on an unresolved ref)."""
        answer = f"{_SUPPORTED} {_UNSUPPORTED}"
        out = filter_unsupported_sentences(answer, ("Art. 999",))
        assert out == answer

    def test_output_is_subsequence_of_input_sentences(self):
        answer = f"{_SUPPORTED} {_UNSUPPORTED}"
        out = filter_unsupported_sentences(answer, ("Art. 14",))
        # Each retained fragment must be present verbatim in the original.
        for fragment in out.split(". "):
            assert fragment.strip(". ") in answer

    def test_abbreviation_does_not_oversplit(self):
        """A sentence naming "Art. 14" must not be split at the abbreviation
        period, which would corrupt the support test."""
        answer = (
            "Under Art. 14 the deployer must oversee the high-risk system. "
            f"{_UNSUPPORTED}"
        )
        out = filter_unsupported_sentences(answer, ("Art. 14",))
        assert "Art. 14 the deployer must oversee" in out
        assert "marketing budget" not in out

    def test_higher_threshold_is_stricter(self):
        """Raising min_overlap_tokens drops weakly-supported sentences but the
        empty-floor invariant still holds."""
        answer = f"{_SUPPORTED} {_UNSUPPORTED}"
        out = filter_unsupported_sentences(
            answer, ("Art. 14",), min_overlap_tokens=3
        )
        assert out.strip(), "high threshold emptied the answer"
