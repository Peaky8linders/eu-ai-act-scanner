"""Suppressions: gaps a team marks not applicable in .antifragile-harness.toml, with a reason.

A suppressed gap must leave scores and briefs but stay visible (with its reason)
in the scan result, the founder brief, the CLI report and the sealed dossier.
Positive evidence and the AI-system scope gate are never affected, and saving
settings must not wipe the entries.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from scanner import scan_project
from scanner.agent_views import concise_scan
from scanner.cli import _format_markdown
from scanner.dossier import generate_dossier
from scanner.founder_triage import build_founder_triage
from scanner.models import ScanResult, SuppressionRule
from scanner.settings import load_settings, save_settings
from scanner.suppressions import load_rules, rule_matches

CHATBOT = '''"""Support chatbot for a small SaaS product."""
from fastapi import FastAPI
from openai import OpenAI

app = FastAPI()
client = OpenAI()


@app.post("/chat")
def chat(message: str) -> dict:
    reply = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are Ava, the support assistant."},
            {"role": "user", "content": message},
        ],
    )
    return {"reply": reply.choices[0].message.content}
'''

DISCLOSURE_RULE = '''
[[suppress]]
title = "AI-interaction disclosure"
path = "app.py"
reason = "The disclosure banner is rendered by our web frontend (separate repo)."
'''


def _project(tmp_path: Path, config: str | None = None) -> Path:
    (tmp_path / "app.py").write_text(CHATBOT, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("fastapi\nopenai\n", encoding="utf-8")
    if config is not None:
        (tmp_path / ".antifragile-harness.toml").write_text(config, encoding="utf-8")
    return tmp_path


def _gap_titles(result: ScanResult) -> list[str]:
    return [c.name for c in result.components if c.compliance_impact == "gap"]


# --- loading -----------------------------------------------------------------


def test_no_config_means_no_rules_and_no_problems(tmp_path: Path) -> None:
    assert load_rules(tmp_path) == ([], [])


def test_valid_rules_load_and_invalid_ones_are_explained(tmp_path: Path) -> None:
    (tmp_path / ".antifragile-harness.toml").write_text(
        DISCLOSURE_RULE
        + '\n[[suppress]]\ntitle = "README"\n'  # no reason
        + '\n[[suppress]]\nreason = "nothing to match"\n'  # no matcher
        + '\n[[suppress]]\narea = "not_an_area"\nreason = "typo"\n'  # unknown area
        + '\n[[suppress]]\ntitle = 3\nreason = "not text"\n'  # wrong type
        + '\n[[suppress]]\narea = "logging"\nreason = "Logs go to our SIEM."\nseverity = "low"\n',
        encoding="utf-8",
    )
    rules, problems = load_rules(tmp_path)
    assert [(r.title, r.path, r.area) for r in rules] == [
        ("AI-interaction disclosure", "app.py", ""),
        ("", "", "logging"),
    ]
    assert len(problems) == 5
    assert "entry 2 has no reason" in problems[0]
    assert "entry 3 sets none of" in problems[1]
    assert "unknown area 'not_an_area'" in problems[2]
    assert "not text" in problems[3]
    assert "unknown key(s) severity" in problems[4]


def test_broken_toml_is_reported_not_raised(tmp_path: Path) -> None:
    (tmp_path / ".antifragile-harness.toml").write_text("[[suppress]\n", encoding="utf-8")
    rules, problems = load_rules(tmp_path)
    assert rules == []
    assert problems and "not valid TOML" in problems[0]


def test_pre_rename_config_file_is_read_when_it_is_the_only_one(tmp_path: Path) -> None:
    (tmp_path / ".eu-ai-act-scanner.toml").write_text(DISCLOSURE_RULE, encoding="utf-8")
    rules, _ = load_rules(tmp_path)
    assert [r.title for r in rules] == ["AI-interaction disclosure"]


# --- matching ----------------------------------------------------------------


def test_every_set_matcher_must_match() -> None:
    rule = SuppressionRule(title="disclosure", path="src/*", area="transparency", reason="r")
    title, path, dims = "No AI Disclosure here", "src/app.py", ["transparency"]
    assert rule_matches(rule, title=title, file_path=path, dimensions=dims)
    assert not rule_matches(rule, title=title, file_path="lib/app.py", dimensions=dims)
    assert not rule_matches(rule, title=title, file_path=path, dimensions=["logging"])
    assert not rule_matches(rule, title="Unrelated", file_path=path, dimensions=dims)


def test_folder_paths_and_windows_separators_match() -> None:
    rule = SuppressionRule(path="vendor/", reason="third-party code")
    assert rule_matches(rule, title="x", file_path="vendor\\lib\\client.py")
    assert not rule_matches(rule, title="x", file_path="src/vendor.py")


def test_an_analyzer_rule_never_matches_an_item_without_an_analyzer() -> None:
    rule = SuppressionRule(analyzer="logging_monitoring", reason="r")
    assert rule_matches(rule, title="t", analyzer="logging_monitoring")
    assert not rule_matches(rule, title="t", analyzer=None)


# --- scan, brief and reports ---------------------------------------------------


def test_a_suppressed_gap_leaves_the_scan_but_stays_on_record(tmp_path: Path) -> None:
    before = scan_project(_project(tmp_path))
    assert any("AI-interaction disclosure" in t for t in _gap_titles(before))

    (tmp_path / ".antifragile-harness.toml").write_text(DISCLOSURE_RULE, encoding="utf-8")
    after = scan_project(tmp_path)

    assert after.is_ai_system is before.is_ai_system is True
    assert not any("AI-interaction disclosure" in t for t in _gap_titles(after))
    assert [s.file_path for s in after.suppressed_findings] == ["app.py"]
    assert after.suppressed_findings[0].reason.startswith("The disclosure banner")
    assert after.suppression_problems == []
    # Positive evidence is untouched.
    positives = lambda r: sorted(c.name for c in r.components if c.compliance_impact == "positive")  # noqa: E731
    assert positives(after) == positives(before)


def test_the_founder_brief_leaves_it_out_and_says_why(tmp_path: Path) -> None:
    triage = build_founder_triage(scan_project(_project(tmp_path, DISCLOSURE_RULE)))
    assert not any("AI-interaction disclosure" in i.title for i in triage.ship_now)
    assert triage.summary_counts["suppressed"] == 1
    assert "marked not applicable in `.antifragile-harness.toml`" in triage.brief_markdown
    assert "rendered by our web frontend" in triage.brief_markdown


def test_ignored_entries_are_surfaced_in_the_brief(tmp_path: Path) -> None:
    triage = build_founder_triage(scan_project(_project(tmp_path, '[[suppress]]\ntitle = "x"\n')))
    assert triage.suppression_problems
    assert "Suppression ignored:" in triage.brief_markdown


def test_area_level_items_from_low_scores_can_be_suppressed() -> None:
    result = ScanResult(
        project_name="demo",
        compliance_scores={"logging": 10.0},
        inferred_roles=["deployer"],
        suppression_rules=[SuppressionRule(title="audit logging", reason="Logs go to our SIEM.")],
    )
    triage = build_founder_triage(result)
    assert not any("audit logging" in i.title.lower() for i in triage.enterprise_deals)
    assert triage.suppressed == ["Add structured AI audit logging: Logs go to our SIEM."]


def test_cli_report_concise_view_and_dossier_list_the_exception(tmp_path: Path) -> None:
    result = scan_project(_project(tmp_path, DISCLOSURE_RULE))
    assert "## Marked not applicable" in _format_markdown(result)
    view = concise_scan(result)
    assert view["suppressed_count"] == 1
    dossier = generate_dossier(result, tmp_path)
    assert len(dossier.marked_not_applicable) == 1
    assert dossier.marked_not_applicable[0].startswith(result.suppressed_findings[0].title)
    assert "[app.py]: The disclosure banner" in dossier.marked_not_applicable[0]


# --- settings must not wipe suppressions ---------------------------------------


def test_saving_settings_keeps_suppressions_and_other_keys(tmp_path: Path) -> None:
    config = tmp_path / ".antifragile-harness.toml"
    config.write_text(
        'team = "growth"\nmode = "deterministic"\n'
        "[scanner]\nmode = \"deterministic\"\nauto_apply = false\n"
        + DISCLOSURE_RULE
        + '\n[[suppress]]\narea = "logging"\nreason = "Logs go to our SIEM."\n',
        encoding="utf-8",
    )
    save_settings(mode="assisted", project_root=tmp_path)
    save_settings(auto_apply=True, project_root=tmp_path)

    text = config.read_text(encoding="utf-8")
    data = tomllib.loads(text)  # still valid TOML
    assert data["team"] == "growth"
    assert data["scanner"] == {"mode": "assisted", "auto_apply": True}
    assert [s["reason"] for s in data["suppress"]] == [
        "The disclosure banner is rendered by our web frontend (separate repo).",
        "Logs go to our SIEM.",
    ]
    assert text.count("# Antifragile Harness settings") == 1
    assert load_settings(tmp_path).mode == "assisted"
    assert len(load_rules(tmp_path)[0]) == 2
