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


def test_deployer_does_not_owe_art13_and_refined_role_citations():
    from scanner.data.role_obligations import (
        ROLE_AUTHORIZED_REPRESENTATIVE,
        ROLE_DEPLOYER,
        ROLE_PRODUCT_MANUFACTURER,
        ROLE_PROVIDER,
        applies_to_role,
        articles_for_role,
        get_role_obligation,
    )

    # Art. 13 is provider-only; Art. 72 stays removed from deployer; provider keeps 16, 18-21.
    assert not applies_to_role("Art. 13", ROLE_DEPLOYER)
    assert not applies_to_role("Art. 72", ROLE_DEPLOYER)
    assert applies_to_role("Art. 50", ROLE_DEPLOYER)
    prov_prim = set(articles_for_role(ROLE_PROVIDER, include_secondary=False))
    assert {"Art. 16", "Art. 18", "Art. 19", "Art. 20", "Art. 21"} <= prov_prim

    pm = get_role_obligation(ROLE_PRODUCT_MANUFACTURER)
    assert pm is not None
    assert "Art. 2(1)(e)" in pm["art_3_definition"]
    assert "Art. 25(3)" in pm["art_3_definition"]
    assert "Recital 87" in pm["art_3_definition"]

    ar = get_role_obligation(ROLE_AUTHORIZED_REPRESENTATIVE)
    assert ar is not None
    assert "Art. 3(5)" in ar["art_3_definition"]
    assert "Art. 22" in ar["art_3_definition"]
    assert "Art. 54" in ar["art_3_definition"]


def test_compute_role_scope_chapter_iii_tier_floor_and_duty_floor():
    from scanner.obligations import compute_role_scope

    scores = {
        "ai_literacy": 50.0,
        "risk_mgmt": 40.0,
        "transparency": 30.0,
        "content_transparency": 30.0,
        "human_oversight": 20.0,
        "deployer_obligations": 20.0,
        "voluntary_codes": 10.0,
    }

    # Limited-risk deployer: Chapter III (Art. 6-49, incl. Art. 13 inside "Art. 13 & 50") never leaks.
    lim_dep = compute_role_scope(["deployer"], scores, explicit=True, risk_tier="limited")
    assert lim_dep["risk_tier"] == "limited"
    assert "Art. 50" in lim_dep["articles"]
    assert "Art. 4" in lim_dep["articles"]
    assert lim_dep["primary_articles"] == ["Art. 50"]
    assert not any(a in lim_dep["articles"] for a in ("Art. 13", "Art. 14", "Art. 26", "Art. 27"))
    assert "transparency" in lim_dep["owed_dimensions"]
    assert "ai_literacy" in lim_dep["owed_dimensions"]
    assert {"risk_mgmt", "human_oversight", "deployer_obligations"} <= set(
        lim_dep["out_of_scope_dimensions"]
    )

    # Minimal-risk provider: neither Chapter III nor Art. 50 transparency leaks.
    min_prov = compute_role_scope(["provider"], scores, explicit=True, risk_tier="minimal")
    assert "Art. 4" in min_prov["articles"]
    assert "Art. 13" not in min_prov["articles"]
    assert "Art. 50" not in min_prov["articles"]
    assert "transparency" in min_prov["out_of_scope_dimensions"]
    assert "ai_literacy" in min_prov["owed_dimensions"]

    # High-risk deployer: known-role duty floor explicitly exposes Art. 26, 27, 50.
    hr_dep = compute_role_scope(["deployer"], scores, explicit=True, risk_tier="high")
    assert hr_dep["primary_articles"] == ["Art. 26", "Art. 27", "Art. 50"]
    assert "deployer_obligations" in hr_dep["owed_dimensions"]
    assert "transparency" in hr_dep["owed_dimensions"]

    # Backwards compatibility when risk_tier=None.
    default_dep = compute_role_scope(["deployer"], scores, explicit=True)
    assert default_dep["risk_tier"] is None
    assert default_dep["primary_articles"] == ["Art. 26", "Art. 27", "Art. 50"]
    assert "transparency" in default_dep["owed_dimensions"]
