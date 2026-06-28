"""Tests for the operator-role + obligation inference engine
(:mod:`scanner.obligations`).

Four contracts are under test:

1. **Role inference** — :func:`infer_role_profile` reads a closed vocabulary of
   code signals off a synthetic :class:`AnalyzerContext` and resolves >=1 role
   deterministically. Provider/training signals → ``"provider"``; external-model
   SDK usage only → ``"deployer"``; nothing → ``"deployer"`` (conservative
   default).

2. **Per-finding obligations** — :func:`obligations_for_finding` projects a
   finding's compliance dimensions (and explicit article-paragraph citations)
   onto canonical articles, the roles that owe them, and the primary article's
   authoritative obligation text.

3. **Enrichment back-fill** — :func:`enrich_findings` fills ``applicable_roles``
   on a gap finding with an empty field, leaves a pre-set list untouched, and
   never touches non-gap findings.

4. **Idempotency** — running :func:`enrich_findings` twice yields the same
   result (the empty-only guard is the mechanism).

The suite is hermetic: every :class:`AnalyzerContext` / :class:`Finding` is
built in-memory, no fixtures are mutated, no network is touched.
"""

from __future__ import annotations

from scanner.analyzers._base import AnalyzerContext, Finding
from scanner.data.role_obligations import (
    ROLE_DEPLOYER,
    ROLE_GPAI_PROVIDER,
    ROLE_PROVIDER,
)
from scanner.obligations import (
    CONCEPT_SIGNALS,
    ROLE_SIGNALS,
    RoleProfile,
    enrich_findings,
    infer_role_profile,
    infer_roles,
    obligations_for_finding,
)


def _ctx(files: dict[str, str]) -> AnalyzerContext:
    """Build a synthetic AnalyzerContext from a {path: content} mapping."""
    return AnalyzerContext(files=files, file_list=list(files.keys()))


def _gap_finding(**overrides: object) -> Finding:
    """A minimal gap Finding with sensible defaults, override-friendly."""
    defaults: dict[str, object] = {
        "id": "test-finding",
        "category": "logging",
        "title": "No event logging",
        "description": "The system records no events.",
        "file_path": "app/main.py",
        "confidence": 0.8,
        "compliance_impact": "gap",
        "compliance_dimensions": ["logging"],
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


# ── Public-surface sanity ──────────────────────────────────────────────────


class TestPublicSurface:
    def test_role_signals_keys_are_canonical_role_ids(self):
        """Every key in ROLE_SIGNALS is a real canonical role id."""
        from scanner.data.role_obligations import CANONICAL_ROLE_IDS

        for role_id in ROLE_SIGNALS:
            assert role_id in CANONICAL_ROLE_IDS, role_id

    def test_concept_signals_map_to_article_refs(self):
        """Every CONCEPT_SIGNALS value is a list of 'Art. N' refs."""
        for concept_id, articles in CONCEPT_SIGNALS.items():
            assert articles, concept_id
            for ref in articles:
                assert ref.startswith("Art. "), ref


# ── Role inference ─────────────────────────────────────────────────────────


class TestInferRoleProfile:
    def test_provider_signal_yields_provider(self):
        """A codebase with training / build signals is a provider."""
        ctx = _ctx(
            {
                "train.py": "import torch\n\ndef run():\n    torch.save(model, 'm.pt')\n    trainer.train()\n",
                "pyproject.toml": "[project.scripts]\nmycli = 'pkg:main'\n",
            }
        )
        profile = infer_role_profile(ctx)
        assert isinstance(profile, RoleProfile)
        assert ROLE_PROVIDER in profile.roles
        assert profile.primary_role == ROLE_PROVIDER
        assert profile.signals_matched.get(ROLE_PROVIDER)

    def test_fine_tune_signal_yields_provider(self):
        """Fine-tuning / PEFT / LoRA code flips the codebase to provider."""
        ctx = _ctx(
            {
                "ft.py": "from peft import LoraConfig\n\ndef fine_tune():\n    ...\n",
            }
        )
        profile = infer_role_profile(ctx)
        assert ROLE_PROVIDER in profile.roles

    def test_external_model_client_yields_deployer(self):
        """Only external-model SDK usage (no training) → deployer."""
        ctx = _ctx(
            {
                "bot.py": (
                    "import openai\n\n"
                    "client = openai.OpenAI()\n"
                    "resp = client.chat.completions.create(model='gpt-4', messages=[])\n"
                ),
            }
        )
        profile = infer_role_profile(ctx)
        assert profile.roles == [ROLE_DEPLOYER]
        assert profile.primary_role == ROLE_DEPLOYER
        # No provider / GPAI signal should have fired.
        assert ROLE_PROVIDER not in profile.roles
        assert ROLE_GPAI_PROVIDER not in profile.roles

    def test_deployer_app_with_packaging_metadata_stays_deployer(self):
        """REGRESSION: a deployer app that merely has packaging metadata
        (``name = "x"`` in pyproject) or ordinary ML preprocessing (``.fit(``)
        must NOT be mislabelled provider — provider needs a real distributable /
        training signal (Art. 3(3)). Over-broad signals were dropped."""
        ctx = _ctx(
            {
                "bot.py": (
                    "import openai\n"
                    "from sklearn.preprocessing import StandardScaler\n"
                    "scaler = StandardScaler().fit(X)\n"
                    "client = openai.OpenAI()\n"
                ),
                "pyproject.toml": '[project]\nname = "my-deployer-bot"\nversion = "0.1.0"\n',
            }
        )
        profile = infer_role_profile(ctx)
        assert profile.roles == [ROLE_DEPLOYER]
        assert ROLE_PROVIDER not in profile.roles

    def test_no_signal_defaults_to_deployer(self):
        """A codebase with no AI signal at all still resolves >=1 role."""
        ctx = _ctx({"readme.md": "# A plain project\nNothing to see here.\n"})
        profile = infer_role_profile(ctx)
        assert profile.roles == [ROLE_DEPLOYER]
        assert profile.signals_matched == {}

    def test_gpai_training_implies_provider(self):
        """Large-model transformers training implies BOTH gpai_provider and
        provider, and roles come back in canonical order (provider first)."""
        ctx = _ctx(
            {
                "pretrain.py": (
                    "from transformers import AutoModelForCausalLM, TrainingArguments\n\n"
                    "def pretrain():\n    model.train()\n"
                ),
            }
        )
        profile = infer_role_profile(ctx)
        assert ROLE_GPAI_PROVIDER in profile.roles
        assert ROLE_PROVIDER in profile.roles
        # Canonical order: provider precedes gpai_provider.
        assert profile.roles.index(ROLE_PROVIDER) < profile.roles.index(
            ROLE_GPAI_PROVIDER
        )

    def test_infer_roles_matches_profile(self):
        """infer_roles is the .roles projection of infer_role_profile."""
        ctx = _ctx({"bot.py": "import anthropic\nc = anthropic.Anthropic()\n"})
        assert infer_roles(ctx) == infer_role_profile(ctx).roles

    def test_deterministic(self):
        """Same input → identical profile across calls (no hidden state)."""
        ctx = _ctx({"train.py": "import torch\ntorch.save(m, 'x')\n"})
        a = infer_role_profile(ctx)
        b = infer_role_profile(ctx)
        assert a.model_dump() == b.model_dump()


# ── Per-finding obligations ────────────────────────────────────────────────


class TestObligationsForFinding:
    def test_logging_gap_resolves_art12_roles_and_text(self):
        """A logging gap maps to Art. 12, the roles that owe it, and non-empty
        authoritative text."""
        finding = _gap_finding(
            category="logging",
            compliance_dimensions=["logging"],
            compliance_impact="gap",
        )
        result = obligations_for_finding(finding)
        assert result["articles"] == ["Art. 12"]
        assert ROLE_PROVIDER in result["applicable_roles"]
        assert result["obligation_text"].strip()

    def test_article_paragraphs_are_normalised_in(self):
        """Explicit article_paragraphs ('14(4)') fold into the article set."""
        finding = _gap_finding(
            compliance_dimensions=[],
            article_paragraphs=["14(4)"],
            title="Oversight gap",
            description="No human override.",
        )
        result = obligations_for_finding(finding)
        assert "Art. 14" in result["articles"]

    def test_articles_sorted_ascending(self):
        """Articles come back in ascending numeric order regardless of source
        ordering (dimension feeding multiple articles)."""
        finding = _gap_finding(
            category="decision_governance",
            compliance_dimensions=["decision_governance"],
        )
        articles = obligations_for_finding(finding)["articles"]
        nums = [int(a.removeprefix("Art. ")) for a in articles]
        assert nums == sorted(nums)
        assert len(set(nums)) == len(nums)  # de-duplicated

    def test_concept_signal_in_text_adds_articles(self):
        """A finding naming 'conformity assessment' in its text picks up
        Art. 43/47/48 even with no compliance dimension."""
        finding = _gap_finding(
            category="docs",
            compliance_dimensions=[],
            title="Missing conformity assessment",
            description="No conformity assessment procedure was run.",
        )
        articles = obligations_for_finding(finding)["articles"]
        assert "Art. 43" in articles

    def test_empty_finding_returns_empty_context(self):
        """A finding with no dimensions, paragraphs, or concept hits returns an
        empty-but-well-formed context."""
        finding = _gap_finding(
            compliance_dimensions=[],
            article_paragraphs=[],
            title="Generic note",
            description="nothing regulatory here",
        )
        result = obligations_for_finding(finding)
        assert result["articles"] == []
        assert result["applicable_roles"] == []
        assert result["obligation_text"] == ""


# ── Enrichment ─────────────────────────────────────────────────────────────


class TestEnrichFindings:
    def test_fills_empty_applicable_roles_on_gap(self):
        """A gap with empty applicable_roles gets back-filled."""
        ctx = _ctx({"train.py": "import torch\ntrainer.train()\n"})  # provider
        finding = _gap_finding(
            compliance_dimensions=["logging"], applicable_roles=[]
        )
        out = enrich_findings([finding], ctx)
        assert out[0] is finding  # mutated in place
        assert finding.applicable_roles  # now non-empty
        assert ROLE_PROVIDER in finding.applicable_roles

    def test_intersects_with_inferred_profile(self):
        """The back-filled roles intersect the codebase's inferred role
        profile when that intersection is non-empty."""
        ctx = _ctx({"train.py": "import torch\ntrainer.train()\n"})  # provider only
        finding = _gap_finding(
            compliance_dimensions=["logging"], applicable_roles=[]
        )
        enrich_findings([finding], ctx)
        # Art. 12 is owed by provider + product_manufacturer; profile is
        # provider-only, so the intersection narrows to provider.
        assert finding.applicable_roles == [ROLE_PROVIDER]

    def test_does_not_overwrite_preset_roles(self):
        """A gap that already carries applicable_roles is left untouched."""
        ctx = _ctx({"train.py": "import torch\ntrainer.train()\n"})
        preset = [ROLE_DEPLOYER]
        finding = _gap_finding(
            compliance_dimensions=["logging"], applicable_roles=list(preset)
        )
        enrich_findings([finding], ctx)
        assert finding.applicable_roles == preset

    def test_non_gap_findings_untouched(self):
        """Positive / neutral findings never receive applicable_roles."""
        ctx = _ctx({"train.py": "import torch\ntrainer.train()\n"})
        positive = _gap_finding(
            compliance_impact="positive",
            compliance_dimensions=["logging"],
            applicable_roles=[],
        )
        enrich_findings([positive], ctx)
        assert positive.applicable_roles == []

    def test_idempotent(self):
        """Running enrich_findings twice yields the same applicable_roles."""
        ctx = _ctx({"train.py": "import torch\ntrainer.train()\n"})
        finding = _gap_finding(
            compliance_dimensions=["logging"], applicable_roles=[]
        )
        enrich_findings([finding], ctx)
        first = list(finding.applicable_roles)
        enrich_findings([finding], ctx)
        assert finding.applicable_roles == first

    def test_fallback_to_owed_roles_when_no_intersection(self):
        """When the inferred profile doesn't owe the finding's articles, the
        back-fill falls back to the full article-owed role set rather than
        leaving the field empty."""
        # Deployer-only codebase, but a provider-only obligation (Art. 12).
        ctx = _ctx({"bot.py": "import openai\nc = openai.OpenAI()\n"})
        assert infer_roles(ctx) == [ROLE_DEPLOYER]
        finding = _gap_finding(
            compliance_dimensions=["logging"], applicable_roles=[]
        )
        enrich_findings([finding], ctx)
        # Art. 12 is owed by provider + product_manufacturer (not deployer);
        # intersection is empty → fall back to the owed roles.
        assert ROLE_PROVIDER in finding.applicable_roles
        assert ROLE_DEPLOYER not in finding.applicable_roles
