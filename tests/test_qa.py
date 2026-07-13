"""Tests for the grounded offline Q&A engine (scanner.qa).

The Q&A path is the plugin's local "Lexy" — it must (1) run deterministically
with no LLM/network, (2) lead with the article a user explicitly names, and
(3) never cite an obligation it can't ground. These tests pin all three.
"""

from __future__ import annotations

from scanner.qa import _corpus, answer_question


def test_article_question_leads_with_that_article():
    r = answer_question(
        "What does Article 50 require for deepfakes and chatbots?", use_llm=False
    )
    assert r.mode == "deterministic"
    assert "Art. 50" in r.citations
    # An explicitly named article is boosted to the top source.
    assert r.sources[0].ref == "Art. 50"
    assert "Transparency" in r.dimensions


def test_deterministic_by_default_and_cites_only_provisions():
    r = answer_question("human oversight obligations for high-risk AI", use_llm=False)
    assert r.mode == "deterministic"
    assert r.answer.strip()
    # Citations are article / annex refs only — never a raw taxonomy label.
    assert r.citations
    assert all(c.startswith(("Art.", "Annex")) for c in r.citations)


def test_taxonomy_question_retrieves_taxonomy_source():
    r = answer_question("what is a cascading multi-agent risk", use_llm=False)
    assert any(s.ref.startswith(("Risk:", "Threat:")) for s in r.sources)
    # Even taxonomy hits ground their citations in real articles.
    assert r.citations


def test_empty_question_is_graceful():
    r = answer_question("   ", use_llm=False)
    assert r.mode == "deterministic"
    assert r.answer.strip()
    assert r.citations == []


def test_no_match_is_graceful_not_a_crash():
    r = answer_question("zqxwv plooomph vbnmzx", use_llm=False)
    assert r.sources == []
    assert "No matching" in r.answer


def test_corpus_covers_article_50_and_taxonomy():
    refs = {d.ref for d in _corpus()}
    assert "Art. 50" in refs
    assert any(r.startswith(("Risk:", "Threat:")) for r in refs)
