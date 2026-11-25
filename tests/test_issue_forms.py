"""GitHub issue forms and the /ai-act-feedback command must describe the same reports.

The command drafts issues with a title prefix per kind of report; maintainers
triage by those prefixes, so each form's title must start with the prefix the
command uses, and every form must warn reporters not to paste their code.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
FORMS = ROOT / ".github" / "ISSUE_TEMPLATE"
COMMAND = ROOT / "commands" / "ai-act-feedback.md"

EXPECTED = {
    "false-positive.yml": "[false positive] ",
    "missed-gap.yml": "[missed gap] ",
    "confusing-result.yml": "[confusing] ",
    "install-problem.yml": "[install] ",
}


def _form(name: str) -> dict:
    data = yaml.safe_load((FORMS / name).read_text(encoding="utf-8"))
    assert isinstance(data, dict), name
    return data


def test_every_form_is_expected_and_present() -> None:
    present = {p.name for p in FORMS.glob("*.yml")} - {"config.yml"}
    assert present == set(EXPECTED)


@pytest.mark.parametrize(("name", "prefix"), sorted(EXPECTED.items()))
def test_form_title_matches_the_command_prefix(name: str, prefix: str) -> None:
    form = _form(name)
    assert form["title"] == prefix
    assert f"`{prefix.strip()}" in COMMAND.read_text(encoding="utf-8")
    assert form.get("labels"), f"{name} has no label"
    ids = [field["id"] for field in form["body"] if "id" in field]
    assert len(ids) == len(set(ids)), f"{name} repeats a field id"
    assert any(field.get("validations", {}).get("required") for field in form["body"]), name


@pytest.mark.parametrize("name", sorted(set(EXPECTED) - {"install-problem.yml"}))
def test_report_forms_ask_people_not_to_paste_their_code(name: str) -> None:
    intro = next(f for f in _form(name)["body"] if f["type"] == "markdown")["attributes"]["value"]
    assert "don't paste your code" in intro


def test_config_keeps_blank_issues_and_points_at_the_readme() -> None:
    config = yaml.safe_load((FORMS / "config.yml").read_text(encoding="utf-8"))
    assert config["blank_issues_enabled"] is True
    assert any("readme" in link["url"].lower() for link in config["contact_links"])
