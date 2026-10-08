"""Role determination: registry validated against official text + role-scoped output."""
import re
from pathlib import Path

import pytest

from scanner.data import official_eu_ai_act as O
from scanner.data.role_obligations import CANONICAL_ROLE_IDS, ROLE_OBLIGATIONS
from scanner.orchestrator import scan_project

FIXTURE = Path(__file__).parent / "fixtures" / "sample_project"


def _article_numbers(ref: str) -> int | None:
    m = re.match(r"Art\. (\d+)", ref)
    return int(m.group(1)) if m else None


def test_every_registry_article_exists_in_official_text():
    for entry in ROLE_OBLIGATIONS:
        for ref in entry.get("primary_articles", []) + entry.get("secondary_articles", []):
            n = _article_numbers(ref)
            assert n is not None, ref
            assert f"Article {n}" in O.OFFICIAL_ARTICLE_TEXT, (entry["id"], ref)


@pytest.mark.parametrize(
    "role_id,para,keyword",
    [
        ("provider", 3, "provider"),
        ("deployer", 4, "deployer"),
        ("importer", 6, "importer"),
        ("distributor", 7, "distributor"),
    ],
)
def test_art3_definition_citations_match_official_text(role_id, para, keyword):
    entry = next(e for e in ROLE_OBLIGATIONS if e["id"] == role_id)
    assert f"Art. 3({para})" in entry["art_3_definition"]
    m = re.search(rf"\({para}\)\s*\W{keyword}\W", O.OFFICIAL_ARTICLE_TEXT["Article 3"])
    assert m, f"official Art. 3({para}) is not '{keyword}'"


def test_provider_owes_art16_and_deployer_does_not_owe_art72():
    from scanner.data.role_obligations import applies_to_role

    assert applies_to_role("Art. 16", "provider")
    assert not applies_to_role("Art. 72", "deployer")
    assert applies_to_role("Art. 54", "authorized_representative")


def test_unknown_role_rejected():
    with pytest.raises(ValueError):
        scan_project(FIXTURE, role="wizard")


@pytest.mark.parametrize("role_id", CANONICAL_ROLE_IDS)
def test_every_canonical_role_accepted_and_scoped(role_id):
    r = scan_project(FIXTURE, role=role_id)
    assert r.active_role == role_id
    assert r.role_scope["source"] == "explicit"
    assert r.role_scope["articles"]


def test_explicit_role_defers_dimensions_owed_only_by_other_roles():
    prov = scan_project(FIXTURE, role="provider")
    dist = scan_project(FIXTURE, role="distributor")
    deferred = set(dist.role_scope["out_of_scope_dimensions"])
    assert deferred, "distributor should not owe every dimension"
    for rec in dist.recommendations:
        assert not any(f" {d}:" in rec for d in deferred)
    assert len(dist.recommendations) <= len(prov.recommendations)


def test_inferred_role_maps_but_never_hides():
    base = scan_project(FIXTURE)
    assert base.role_scope["source"] == "inferred"
    explicit_none = scan_project(FIXTURE, role=None)
    assert base.recommendations == explicit_none.recommendations


def test_distributor_keeps_registry_dimensions():
    dist = scan_project(FIXTURE, role="distributor")
    assert not {"tech_docs", "supply_chain"} & set(dist.role_scope["out_of_scope_dimensions"])
