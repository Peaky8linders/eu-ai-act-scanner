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


def test_operator_role_questions_boost_appropriate_articles():
    # Importer query must retrieve Art. 23 and Art. 3 at the top
    r_imp = answer_question("Who is the importer under the AI Act and what must they verify?", use_llm=False)
    imp_refs = [s.ref for s in r_imp.sources[:2]]
    assert "Art. 23" in imp_refs
    assert "Art. 3" in imp_refs

    # Distributor query must retrieve Art. 24 and Art. 3
    r_dist = answer_question("What are the distributor verification obligations?", use_llm=False)
    dist_refs = [s.ref for s in r_dist.sources[:2]]
    assert "Art. 24" in dist_refs

    # Deployer query must retrieve Art. 26 and Art. 3
    r_dep = answer_question("What duties apply to deployers of high-risk AI?", use_llm=False)
    dep_refs = [s.ref for s in r_dep.sources[:2]]
    assert "Art. 26" in dep_refs


def test_sources_include_official_article_titles():
    r = answer_question("What does Article 23 say about importers?", use_llm=False)
    top_source = r.sources[0]
    assert top_source.ref == "Art. 23"
    assert "Obligations of importers" in top_source.title


def test_article_113_patch_is_merged_and_paragraph_addressable():
    r = answer_question("What does Article 113(3) say about application dates?", use_llm=False)
    assert r.sources[0].ref == "Art. 113"
    excerpt = r.sources[0].excerpt
    assert "3. However:" in excerpt
    assert "2 February 2025" in excerpt
    assert "binding in its entirety" in excerpt


def test_paragraph_targeted_excerpt_reaches_art_26_paragraph_6():
    """Art. 26(6) starts past char 2300 — blind 360-char head-clip missed 'six months'."""
    r = answer_question("How long must deployers keep logs under Art. 26(6)?", use_llm=False)
    assert r.sources[0].ref == "Art. 26"
    assert "6." in r.sources[0].excerpt
    assert "six months" in r.sources[0].excerpt.lower()


def test_oxford_z_spelling_fold_targets_art_24_paragraph_3():
    """US spelling 'jeopardize' must match EUR-Lex 'jeopardise' in Art. 24(3)."""
    from scanner.qa import select_relevant_paragraphs

    extract = select_relevant_paragraphs(
        "Art. 24",
        "What is a distributor's obligation not to jeopardize conformity during storage or transport?",
        max_chars=500,
    )
    assert extract is not None
    assert "3." in extract
    assert "jeopardise" in extract.lower()


def test_plural_multi_provision_lists_and_closed_world_range():
    import time

    from scanner.qa import extract_refs

    assert extract_refs("Compare Articles 13 and 50") == ["Art. 13", "Art. 50"]
    assert extract_refs("Explain Art. 9, 10, and 15 requirements") == [
        "Art. 9",
        "Art. 10",
        "Art. 15",
    ]
    assert extract_refs("See Annexes I, III and IV") == [
        "Annex I",
        "Annex III",
        "Annex IV",
    ]
    # Out-of-range provisions are rejected by the closed-world guard.
    assert extract_refs("What does Article 999 or Annex XX require?") == []

    # ReDoS guard: adversarial space-padded separator chain stays linear.
    adversarial = "Articles 9" + " , " * 500 + "x"
    t0 = time.monotonic()
    extract_refs(adversarial)
    assert time.monotonic() - t0 < 0.25


def test_foreign_statute_guard_blocks_gdpr_article_boosting():
    from scanner.qa import _boosted_refs, extract_refs

    assert extract_refs("Does GDPR Art. 9 allow biometric processing?") == []
    assert extract_refs("How does Article 6(1) of the GDPR interact with AI?") == []
    assert "Art. 9" not in _boosted_refs("Does GDPR Art. 9 allow this?")
    assert "Art. 6" not in _boosted_refs("How does Article 6(1) of the GDPR work?")
    # EU AI Act ref alongside GDPR ref still resolves the EU AI Act article only.
    assert extract_refs(
        "How does Article 6(1) of the GDPR interact with EU AI Act Article 10?"
    ) == ["Art. 10"]


def test_topic_anchors_boost_timeline_incidents_emotion_and_penalties():
    r_time = answer_question("What are the transitional grandfathering deadlines?", use_llm=False)
    time_refs = {s.ref for s in r_time.sources}
    assert "Art. 113" in time_refs
    assert "Art. 111" in time_refs

    r_inc = answer_question(
        "Within what timeframe must a provider notify authorities of an AI incident?",
        use_llm=False,
    )
    assert "Art. 73" in [s.ref for s in r_inc.sources[:2]]

    r_emo = answer_question(
        "Are emotion recognition systems allowed in workplaces?", use_llm=False
    )
    emo_refs = {s.ref for s in r_emo.sources}
    assert {"Art. 5", "Art. 50", "Annex III"} <= emo_refs

    r_pen = answer_question(
        "What are the maximum administrative fines and turnover caps?", use_llm=False
    )
    pen_refs = {s.ref for s in r_pen.sources[:2]}
    assert "Art. 99" in pen_refs and "Art. 101" in pen_refs

