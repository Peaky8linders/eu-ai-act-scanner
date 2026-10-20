# Deep Code Review: test/taxonomy-citation-resolution

**Date:** 2026-10-20 09:01:46
**Branch:** test/taxonomy-citation-resolution -> main
**Commit:** 80816c67 (`origin/main` at `0551c1b` holds the same tree as a squash of this commit)
**Files changed:** 3 uncommitted | **Lines changed:** +85 / -0
**Diff size category:** Medium (small enough to expand scope to the whole `grounding` module and the catalogue test file)

Scope note: `git diff origin/main...HEAD` reports 53 lines, but that is merge-base
noise — the branch's committed tree is identical to the squash already on `main`.
No unreviewed committed work exists; the review target is the uncommitted diff
(`scanner/grounding.py`, `tests/test_crosswalk_catalogue.py`, `CHANGELOG.md`).

## Executive Summary

The mechanism is sound: the resolution check cannot be satisfied by an unknown
article, the shape guard closes the GDPR/Act number collision, and no production
caller feeds a foreign-framework ref into `obligation_text()`. The defect is
content, not code — the three statutory paraphrases added to make the check pass
are inaccurate in ways that matter, because this text is injected into LLM
prompts and the QA corpus as *authoritative*. One is a Critical fabrication (a
deployer class that Article 49(3) does not create).

## Critical Issues

### [C1] `Art. 49` paraphrase invents a deployer- registration duty and drops the Annex III limit

- **File:** `scanner/grounding.py:267`
- **Bug:** The text says "Deployers that are public authorities, and private
  deployers of Annex III systems used for public services, must also register
  themselves". Article 49(3) binds deployers that are "public authorities, Union
  institutions, bodies, offices or agencies or persons acting on their behalf" —
  there is no public-service private-deployer category, and that narrowing
  exempts private contractors acting on a public authority's behalf. The
  paragraph also requires the deployer to "select the system and register its
  use", which is missing. Paragraph 1 covers "a high-risk AI system listed in
  Annex III, with the exception of high-risk AI systems referred to in point 2 of
  Annex III"; the paraphrase says "a high-risk AI system", pulling Annex I
  product systems into a registration duty Article 49 does not impose.
- **Impact:** `OBLIGATION_TEXT` is the anti-hallucination layer — it is injected
  by `ground_prompt()` and merged into the QA corpus with the verbatim text. A
  wrong answer here is indistinguishable from a correct one at every surface,
  and it is scannable by the citation guard as support.
- **Suggested fix:** restrict paragraph 1 to Annex III systems except point 2;
  list the Article 49(3) deployers exactly (public authorities, Union
  institutions/bodies/offices/agencies, persons acting on their behalf); add
  "select the system and register its use".
- **Confidence:** High
- **Found by:** External legal verification (`researcher-web`) + Logic & Correctness; confirmed against the repo's own verbatim text in `scanner/data/official_eu_ai_act.py` (`Article 49`)

## Important Issues

### [I1] `Art. 6(3)` derogation stated as a disjunction, and condition (c) is truncated

- **File:** `scanner/grounding.py:90`
- **Bug:** "unless the provider demonstrates that the system poses no significant
  risk … **because** it performs a narrow procedural task, …" reads the listed
  task types as the whole test. Article 6(3) is conjunctive: the system "shall
  not be considered to be high-risk where it does not pose a significant risk of
  harm … **including by not materially influencing the outcome of decision
  making**" **and** one of (a)-(d) applies. Condition (c) is also shortened: it
  is "detect decision-making patterns **or deviations** from prior
  decision-making patterns and is not meant to **replace or influence** the
  previously completed human assessment, **without proper human review**".
- **Impact:** A reader — or an LLM grounded on this text — can conclude that
  performing a narrow procedural task is sufficient, which is the exact
  misclassification Article 6(3) is written to prevent.
- **Suggested fix:** state both limbs ("does not pose a significant risk of harm
  …, including by not materially influencing the outcome of decision making, and
  one of the following applies: …"), and restore "deviations" and "replace or
  influence … without proper human review" in (c). Keep the existing
  documentation-timing sentence (Art. 6(4)) — that part is right.
- **Confidence:** High
- **Found by:** External legal verification + Logic & Correctness

### [I2] `Art. 5` paraphrase drops the operative elements of the manipulation limb and one of the two social-scoring limbs

- **File:** `scanner/grounding.py:75`
- **Bug:** Three losses against Article 5(1). (a) The manipulation limb requires
  techniques "beyond a person's consciousness" that distort behaviour "**by
  appreciably impairing their ability to make an informed decision, thereby
  causing them to take a decision that they would not have otherwise taken**";
  the paraphrase keeps only "materially distort behaviour and cause significant
  harm". (c) Social scoring has two alternative limbs — treatment "in social
  contexts that are unrelated to the contexts in which the data was originally
  generated" **or** treatment "unjustified or disproportionate to their social
  behaviour or its gravity"; only the first survives, and "groups of persons" is
  dropped. (d) Predictive policing is "based solely on the profiling of a natural
  person **or on assessing their personality traits and characteristics**", and
  (e) scrapes facial images "from the internet **or CCTV footage**".
- **Impact:** This text is the token pool the citation guard scores candidate
  sentences against and the block injected into prompts; missing operative
  elements means a correct answer about Art. 5 can be filtered as unsupported,
  and an incomplete answer can look fully grounded.
- **Suggested fix:** add the informed-decision clause to (a); state both
  social-scoring limbs; add the personality-trait limb and the CCTV source.
- **Confidence:** High
- **Found by:** External legal verification + Error Handling & Edge Cases (token-pool consequences)

## Suggestions

- `Art. 49`: mention the secure non-public database section for Annex III points 1, 6 and 7 (Art. 49(4)) and that point 2 systems are registered nationally (Art. 49(5)).
- `Art. 5`: name the traits Art. 5(1)(g) enumerates instead of "protected characteristics", and add "strictly necessary" plus authorisation/FRIA to the (h) sentence.
- `tests/test_crosswalk_catalogue.py:1` module docstring still scopes the file to ID grammar; it now also pins citation resolution (new tests at :306 and :325).
- `scanner/cross_framework.py` `evidence_reuse_opportunities` cites Art. 10/12/14/27 in prose and is outside the new check (all four resolve today).

## Plan Alignment

No plan or design documents exist in this repository (`docs/plans/`, `aidlc-docs/` absent), so no alignment assessment applies.

## Review Metadata

- **Agents dispatched:** `researcher-web` (Article 5/6/49 verification against EUR-Lex and the Commission AI Act Service Desk). The five specialist lenses in the skill — Logic & Correctness, Error Handling & Edge Cases, Contract & Integration, Concurrency & State, Security — were run by the single reviewing agent: this session can only spawn `researcher-web`, and no tool here registers additional agent types. This is a deviation from the skill's parallel-dispatch phase.
- **Scope:** `scanner/grounding.py` (whole module), `tests/test_crosswalk_catalogue.py` (whole file), `scanner/data/frameworks.py` (catalogue under test), `tests/test_grounding.py`, `tests/test_qa.py`, `scanner/qa.py:118`, `scanner/obligations.py:399`, `scanner/mcp_server.py` `get_article`, `scanner/cross_framework.py` prose refs.
- **Raw findings:** 9 (before verification)
- **Verified findings:** 7 (after verification)
- **Filtered out:** 2 — a claim that the new shape guard duplicates the existing KB-coverage check (rejected: that check exempts Art. 5/6/49 and constrains nothing about key shape), and a claim that the CHANGELOG overstates coverage (editorial, and true as written).
- **Steering files consulted:** none found (`CLAUDE.md`, `AGENTS.md`, `.cursor/rules` absent).
- **Plan/design docs consulted:** none found.

## Checks observed during review

- `pytest -q`: 443 passed (after the final wording edit).
- `ruff check scanner tests`: clean. `mypy scanner`: clean, 48 files.
- `OBLIGATION_TEXT` now covers all 24 `ARTICLE_FRAMEWORK_CROSSWALK` keys; negative controls reproduce exactly `['Art. 5', 'Art. 6', 'Art. 49']` when the new entries are removed, and reject a planted `Art. 5(2)` key.
- Confirmed no KB dimension cites Art. 5/6/49, so `dimension_grounding()` / `ground_prompt()` behaviour is unchanged by the additions.
- Confirmed no caller passes a GDPR `Art. N(p)` ref to `obligation_text()`; the collision existed only as a future hazard, which the shape guard now blocks.
