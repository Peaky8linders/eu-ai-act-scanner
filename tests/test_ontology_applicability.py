"""Tests for ontology corrections, official text patches, and Digital Omnibus applicability."""

from __future__ import annotations

from datetime import date

import pytest

from scanner.data.official_text_patches import (
    OFFICIAL_TEXT_PATCHES,
    get_official_article_text,
)
from scanner.data.omnibus import (
    AI_ACT_CONSOLIDATED_CELEX,
    AMENDMENTS,
    OMNIBUS_CELEX,
    OMNIBUS_DATE_IN_FORCE,
    UNAMENDED,
    amended_article_numbers,
    amendments_for,
    is_unamended,
    live_phase,
    resolve_applicability,
)
from scanner.data.ontology import (
    EVERY_RISK_CLASS_OBLIGATIONS,
    MODEL_RISK_CLASSES,
    OPERATOR_ROLES,
    PHASE_REGISTRY,
    RISK_CLASS_PHASE,
    ROLE_OBLIGATIONS,
    ActorRole,
    RiskClass,
    obligations_for,
)


class TestOfficialTextPatches:
    def test_article_113_patch_restores_paragraph_numbers_and_binding_clause(self) -> None:
        patched = OFFICIAL_TEXT_PATCHES["Article 113"]
        assert "1. This Regulation shall enter into force" in patched
        assert "2. It shall apply from 2 August 2026." in patched
        assert "3. However:" in patched
        assert "(a) Chapters I and II shall apply from 2 February 2025;" in patched
        assert "(b) Chapter III Section 4" in patched
        assert "(c) Article 6(1)" in patched
        assert (
            "This Regulation shall be binding in its entirety and directly "
            "applicable in all Member States." in patched
        )

    def test_get_official_article_text_merges_patches_and_accepts_short_ref(self) -> None:
        full = get_official_article_text("Article 113")
        short = get_official_article_text("Art. 113")
        assert full == short == OFFICIAL_TEXT_PATCHES["Article 113"]
        assert "Classification rules for high-risk AI systems" in get_official_article_text("Art. 6")
        assert get_official_article_text("Art. 999") == ""
        assert get_official_article_text("") == ""


class TestOntologyRoleObligationsCorrections:
    """Pin the four #1342 statutory corrections in ROLE_OBLIGATIONS."""

    def test_annex_i_provider_does_not_owe_art_49_registration(self) -> None:
        annex_i = obligations_for(ActorRole.PROVIDER, RiskClass.HIGH_RISK_ANNEX_I)
        annex_iii = obligations_for(ActorRole.PROVIDER, RiskClass.HIGH_RISK_ANNEX_III)
        assert "Art. 49" not in annex_i
        assert "Art. 49" in annex_iii

    def test_deployer_does_not_owe_art_13_in_either_high_risk_route(self) -> None:
        for rc in (RiskClass.HIGH_RISK_ANNEX_I, RiskClass.HIGH_RISK_ANNEX_III):
            duties = obligations_for(ActorRole.DEPLOYER, rc)
            assert "Art. 13" not in duties
            assert "Art. 26" in duties

    def test_importer_and_distributor_owe_nothing_for_limited_risk(self) -> None:
        assert ROLE_OBLIGATIONS[ActorRole.IMPORTER][RiskClass.LIMITED_RISK] == ()
        assert ROLE_OBLIGATIONS[ActorRole.DISTRIBUTOR][RiskClass.LIMITED_RISK] == ()

    def test_as_of_metadata_tables_are_consistent(self) -> None:
        assert set(RISK_CLASS_PHASE) == set(RiskClass) - {RiskClass.PROHIBITED}
        for phase_id in RISK_CLASS_PHASE.values():
            assert phase_id in PHASE_REGISTRY
        assert PHASE_REGISTRY["phase_2026_08_02_general"] == PHASE_REGISTRY[
            "phase_2026_08_02_transparency"
        ]
        assert MODEL_RISK_CLASSES == frozenset({RiskClass.GPAI, RiskClass.GPAI_SYSTEMIC})
        assert ActorRole.PROVIDER in EVERY_RISK_CLASS_OBLIGATIONS
        assert ActorRole.DEPLOYER in EVERY_RISK_CLASS_OBLIGATIONS
        assert ActorRole.NOTIFIED_BODY not in OPERATOR_ROLES
        assert ActorRole.AFFECTED_PERSON not in OPERATOR_ROLES


class TestOmnibusMetadataAndLivePhase:
    def test_omnibus_identifiers_and_amendments(self) -> None:
        assert OMNIBUS_CELEX == "32026R1744"
        assert OMNIBUS_DATE_IN_FORCE == "2026-07-27"
        assert AI_ACT_CONSOLIDATED_CELEX == "02024R1689-20260727"
        assert len(AMENDMENTS) >= 15
        assert len(UNAMENDED) >= 8

        art113 = amendments_for("Art. 113")
        assert len(art113) == 3
        assert any(a.applies_from == "2027-12-02" for a in art113)
        assert is_unamended("Annex III")
        assert is_unamended("Art. 50")
        assert is_unamended("Art. 999") == ""
        nums = amended_article_numbers()
        assert "113" in nums and "4a" in nums and "5" in nums

    def test_live_phase_follows_superseded_by_chain(self) -> None:
        assert live_phase("phase_2026_08_02").id == "phase_omnibus_2027_12_02"
        assert live_phase("phase_2026_08_02").effective_date == date(2027, 12, 2)
        assert live_phase("phase_2027_08_02").id == "phase_omnibus_2028_08_02"
        assert live_phase("phase_2027_08_02").effective_date == date(2028, 8, 2)
        assert live_phase("phase_2026_08_02_general").effective_date == date(2026, 8, 2)
        assert live_phase("phase_2026_08_02_transparency").effective_date == date(2026, 8, 2)


class TestResolveApplicability:
    def test_annex_iii_deployer_on_2026_08_02(self) -> None:
        res = resolve_applicability(
            date(2026, 8, 2), RiskClass.HIGH_RISK_ANNEX_III, ActorRole.DEPLOYER
        )
        in_force_refs = {d.ref for d in res.duties_in_force}
        pending_refs = {d.ref for d in res.duties_pending}

        # Art. 4, Art. 50, and original Art. 5(1)(a)-(h) are live on 2 Aug 2026.
        assert "Art. 4" in in_force_refs
        assert "Art. 50" in in_force_refs
        assert "Art. 5(1)(a)" in in_force_refs
        assert "Art. 5(1)(f)" in in_force_refs

        # NCII/CSAM apply 2 Dec 2026; Annex III Chapter III deployer duties 2 Dec 2027.
        assert "Art. 5(1)(ba)" in pending_refs
        assert "Art. 5(1)(bb)" in pending_refs
        assert {"Art. 26", "Art. 27", "Art. 86"} <= pending_refs
        # Art. 13 is provider-only and must never appear for a deployer.
        assert "Art. 13" not in in_force_refs | pending_refs

        # Superseded 2 Aug 2026 Annex III phase is tracked as replaced.
        art26 = next(d for d in res.duties_pending if d.ref == "Art. 26")
        assert art26.applies_from == "2027-12-02"
        assert any(r.id == "phase_2026_08_02" for r in art26.replaces)

    def test_annex_i_provider_stays_pending_until_2028_08_02_and_has_no_art_49(self) -> None:
        before = resolve_applicability(
            date(2027, 12, 2), RiskClass.HIGH_RISK_ANNEX_I, ActorRole.PROVIDER
        )
        pending_refs = {d.ref for d in before.duties_pending}
        all_refs = pending_refs | {d.ref for d in before.duties_in_force}
        assert "Art. 9" in pending_refs
        assert "Art. 49" not in all_refs
        art9 = next(d for d in before.duties_pending if d.ref == "Art. 9")
        assert art9.applies_from == "2028-08-02"
        assert any(r.id == "phase_2027_08_02" for r in art9.replaces)

        after = resolve_applicability(
            date(2028, 8, 2), RiskClass.HIGH_RISK_ANNEX_I, ActorRole.PROVIDER
        )
        assert after.duties_pending == []
        assert "Art. 9" in {d.ref for d in after.duties_in_force}

    def test_gpai_model_provider_dated_on_chapter_v_alone(self) -> None:
        res = resolve_applicability(
            date(2026, 8, 2), RiskClass.GPAI, ActorRole.PROVIDER
        )
        refs = {d.ref for d in res.duties_in_force}
        assert "Art. 53" in refs
        # Model risk classes do not pull in AI-system-level Arts. 4, 5, 50.
        assert "Art. 4" not in refs
        assert "Art. 50" not in refs
        assert not any(r.startswith("Art. 5(") for r in refs)
        assert res.duties_pending == []

    def test_limited_risk_importer_and_distributor_have_no_ch_iii_duties(self) -> None:
        for role in (ActorRole.IMPORTER, ActorRole.DISTRIBUTOR):
            res = resolve_applicability(date(2026, 8, 2), RiskClass.LIMITED_RISK, role)
            all_refs = {d.ref for d in res.duties_in_force + res.duties_pending}
            assert "Art. 23" not in all_refs
            assert "Art. 24" not in all_refs

    def test_non_operator_role_rejected(self) -> None:
        with pytest.raises(ValueError, match="not a value-chain operator"):
            resolve_applicability(
                date(2026, 8, 2), RiskClass.HIGH_RISK_ANNEX_III, ActorRole.NOTIFIED_BODY
            )
