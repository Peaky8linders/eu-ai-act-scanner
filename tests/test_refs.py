"""Tests for scanner.refs — the single-source EU AI Act citation converter.

Covers round-trips across all three citation vocabularies (Finding bare form,
KB compound display form, role_obligations canonical form), annex parsing,
idempotency of normalise, and safe handling of junk/empty input. The KB
compound-string assertions read the *real* values from ``scanner.kb`` so they
stay in lock-step with the source of truth rather than restating literals.
"""

from __future__ import annotations

import pytest

from scanner import refs
from scanner.kb import DIMENSIONS
from scanner.refs import RefSpec

# ── parse: the three input forms ─────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # (a) Finding bare form
        ("14(4)", RefSpec(article_number=14, paragraphs=("4",))),
        ("50(2-4)", RefSpec(article_number=50, paragraphs=("2-4",))),
        ("15(3)", RefSpec(article_number=15, paragraphs=("3",))),
        # (b) KB display form
        ("Art. 50(2-4)", RefSpec(article_number=50, paragraphs=("2-4",))),
        ("Art. 3(23)", RefSpec(article_number=3, paragraphs=("23",))),
        ("Art. 9", RefSpec(article_number=9)),
        # (c) role_obligations canonical form
        ("Art. 25(4)", RefSpec(article_number=25, paragraphs=("4",))),
        ("Art. 74", RefSpec(article_number=74)),
        # extra accepted shapes
        ("Article 14.4", RefSpec(article_number=14, paragraphs=("4",))),
        ("art14", RefSpec(article_number=14)),
        ("Article 14", RefSpec(article_number=14)),
    ],
)
def test_parse_article_forms(raw: str, expected: RefSpec) -> None:
    """parse() reduces every article vocabulary to the same RefSpec."""
    assert refs.parse(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Annex IV", RefSpec(annex_roman="IV")),
        ("Annex IV(1)", RefSpec(annex_roman="IV", paragraphs=("1",))),
        ("Annex IV.1", RefSpec(annex_roman="IV", paragraphs=("1",))),
        ("annex iv", RefSpec(annex_roman="IV")),  # mixed case uppercased
        ("Annex III", RefSpec(annex_roman="III")),
    ],
)
def test_parse_annex_forms(raw: str, expected: RefSpec) -> None:
    """Annex variants parse to an annex spec with uppercased Roman numeral."""
    assert refs.parse(raw) == expected


@pytest.mark.parametrize("junk", ["", "   ", "ISO 27002", "NIST SP 800-53", "garbage", "Article III"])
def test_parse_junk_is_empty(junk: str) -> None:
    """Junk / framework tokens / Roman article numbers yield an empty spec, not a raise."""
    spec = refs.parse(junk)
    assert spec.is_empty
    assert spec == RefSpec()


def test_parse_none_is_empty() -> None:
    """parse(None) is safe and returns an empty spec."""
    assert refs.parse(None) == RefSpec()  # type: ignore[arg-type]


# ── to_internal / to_user_facing round-trips ─────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "internal", "user_facing"),
    [
        ("14(4)", "Art. 14(4)", "Article 14.4"),
        ("50(2-4)", "Art. 50(2-4)", "Article 50.2-4"),
        ("15(3)", "Art. 15(3)", "Article 15.3"),
        ("Art. 3(23)", "Art. 3(23)", "Article 3.23"),
        ("Art. 9", "Art. 9", "Article 9"),
        ("Article 14.4", "Art. 14(4)", "Article 14.4"),
        ("Annex IV(1)", "Annex IV(1)", "Annex IV.1"),
        ("Annex IV", "Annex IV", "Annex IV"),
    ],
)
def test_to_internal_and_user_facing(raw: str, internal: str, user_facing: str) -> None:
    """Both formatters emit the strict target shape from any input form."""
    assert refs.to_internal(raw) == internal
    assert refs.to_user_facing(raw) == user_facing


def test_internal_user_facing_are_inverses() -> None:
    """Converting to one form then back recovers the other form."""
    raw = "14(4)"
    internal = refs.to_internal(raw)
    user = refs.to_user_facing(raw)
    assert refs.to_user_facing(internal) == user
    assert refs.to_internal(user) == internal


@pytest.mark.parametrize("junk", ["", "ISO 27002", "garbage", "   "])
def test_formatters_safe_on_junk(junk: str) -> None:
    """Unparseable input formats to empty string, never raises."""
    assert refs.to_internal(junk) == ""
    assert refs.to_user_facing(junk) == ""


# ── normalise idempotency ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw",
    ["14(4)", "Art. 14(4)", "Article 14.4", "Annex IV.1", "Annex IV(1)", "art9", "50(2-4)"],
)
def test_normalise_idempotent(raw: str) -> None:
    """normalise(normalise(x)) == normalise(x), and equals to_internal."""
    once = refs.normalise(raw)
    assert refs.normalise(once) == once
    assert once == refs.to_internal(raw)


def test_normalise_collapses_equivalent_forms() -> None:
    """Different surface forms of the same citation normalise identically."""
    forms = ["14(4)", "Art. 14(4)", "Article 14.4"]
    canon = {refs.normalise(f) for f in forms}
    assert canon == {"Art. 14(4)"}


# ── article_key ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "key"),
    [
        ("Art. 14(4)", "art14"),
        ("14(4)", "art14"),
        ("Article 14.4", "art14"),
        ("Art. 9", "art9"),
        ("art15", "art15"),
        ("Art. 3(23)", "art3"),
        ("Annex IV", "annex_IV"),
        ("Annex IV(1)", "annex_IV"),
        ("", ""),
        ("ISO 27002", ""),
        ("garbage", ""),
    ],
)
def test_article_key(raw: str, key: str) -> None:
    """article_key collapses to the kb.ARTICLE_TO_DIMENSIONS key, junk -> ''."""
    assert refs.article_key(raw) == key


def test_article_key_matches_kb_keys() -> None:
    """Keys produced for known articles match real ARTICLE_TO_DIMENSIONS keys."""
    from scanner.kb import ARTICLE_TO_DIMENSIONS

    for raw in ("Art. 15", "Art. 9", "15(3)", "Article 50.2"):
        key = refs.article_key(raw)
        assert key in ARTICLE_TO_DIMENSIONS


# ── split_dimension_articles ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("field_str", "expected"),
    [
        # The spec's worked examples.
        ("Art. 9, 14, 15, 72", ["Art. 9", "Art. 14", "Art. 15", "Art. 72"]),
        ("Art. 15 / ISO 27002", ["Art. 15"]),
        ("Art. 13 & 50", ["Art. 13", "Art. 50"]),
        # Framework tokens stripped.
        ("Art. 15 / NIST SP 800-53", ["Art. 15"]),
        ("Art. 15 / NIST SP 800-161", ["Art. 15"]),
        ("Art. 14 / Art. 15(4) / OWASP Top-10 Agentic", ["Art. 14", "Art. 15"]),
        # Annex mention stripped.
        ("Art. 11 / Annex IV", ["Art. 11"]),
        # Paragraphs dropped, duplicates collapsed (25 appears twice).
        ("Art. 25 / Art. 25(4) / Art. 3(23)", ["Art. 25", "Art. 3"]),
        # Single bare article.
        ("Art. 4", ["Art. 4"]),
        ("Art. 50(2-4)", ["Art. 50"]),
        # Junk / empty.
        ("", []),
        ("ISO 27002", []),
        ("   ", []),
    ],
)
def test_split_dimension_articles(field_str: str, expected: list[str]) -> None:
    """Compound KB display strings project to canonical bare 'Art. N' refs."""
    assert refs.split_dimension_articles(field_str) == expected


def test_split_every_real_kb_dimension_is_safe() -> None:
    """Every real kb.Dimension.article string parses to valid, AI-Act-only refs.

    This is the lock-step assertion: reads the actual DIMENSIONS source of truth
    so a future KB edit that introduces an unparseable display string fails here
    instead of silently emitting junk downstream.
    """
    for dim in DIMENSIONS.values():
        result = refs.split_dimension_articles(dim.article)
        # Every emitted ref must round-trip cleanly to a kb article key.
        for ref in result:
            assert ref.startswith("Art. ")
            assert refs.article_key(ref).startswith("art")
        # A display string that names at least one "Art." must yield >=1 ref.
        if "Art." in dim.article:
            assert result, f"{dim.id!r} ({dim.article!r}) produced no article refs"


def test_split_strips_known_framework_tokens_from_real_kb() -> None:
    """The real access_control / infra_mlops / supply_chain dims drop framework tokens."""
    assert refs.split_dimension_articles(DIMENSIONS["access_control"].article) == ["Art. 15"]
    assert refs.split_dimension_articles(DIMENSIONS["infra_mlops"].article) == ["Art. 15"]
    assert refs.split_dimension_articles(DIMENSIONS["supply_chain"].article) == ["Art. 15"]
    assert refs.split_dimension_articles(DIMENSIONS["transparency"].article) == ["Art. 13", "Art. 50"]
    assert refs.split_dimension_articles(DIMENSIONS["decision_governance"].article) == [
        "Art. 9",
        "Art. 14",
        "Art. 15",
        "Art. 72",
    ]


# ── RefSpec is frozen / hashable ─────────────────────────────────────────────


def test_refspec_is_frozen_and_hashable() -> None:
    """RefSpec is frozen (immutable) and usable in sets."""
    spec = RefSpec(article_number=14, paragraphs=("4",))
    with pytest.raises(AttributeError):
        spec.article_number = 15  # type: ignore[misc]
    assert spec in {spec}
