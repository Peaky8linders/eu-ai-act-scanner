"""CRA scan (Regulation (EU) 2024/2847): scope step, two checks, report.

Why these tests exist:

* **Scope comes first.** The CRA covers a "product with digital elements". A
  repository that only runs as an internal service must get an empty report:
  telling its team to produce an SBOM for a law that may not reach them, or
  giving it a number, would be a false statement about the law.
* **Every finding can be checked by a reader.** It cites the annex point and
  names either the file that is the evidence or the artefact that is missing.
* **The report never grades.** No score, no percentage, no "compliant".
* **The EU AI Act scan is untouched.** The existing Table 5 trigger keeps
  firing exactly as before.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from scanner.analyzers import AnalyzerContext
from scanner.analyzers.regulatory_perimeter import analyze_regulatory_perimeter
from scanner.cli import main
from scanner.cra import (
    CVD_CHECK_ID,
    SBOM_CHECK_ID,
    CraFinding,
    assess_cra_scope,
    build_cra_report,
    check_cvd_policy,
    check_sbom,
    cra_scan,
    format_cra_report,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

CLI_PYPROJECT = '[project]\nname = "acme-tool"\nversion = "1.0.0"\n\n[project.scripts]\nacme = "acme.cli:main"\n'
PLAIN_PYPROJECT = '[project]\nname = "internal-api"\nversion = "1.0.0"\n'
SERVICE_CODE = "from fastapi import FastAPI\nimport uvicorn\n\napp = FastAPI()\nuvicorn.run(app)\n"
CYCLONEDX = json.dumps({
    "bomFormat": "CycloneDX", "specVersion": "1.6",
    "components": [{"type": "library", "name": "pydantic", "version": "2.9.0"}],
})
SPDX = json.dumps({
    "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
    "packages": [{"name": "pydantic", "SPDXID": "SPDXRef-Package-pydantic"}],
})


def _ctx(files: dict[str, str], extra_paths: tuple[str, ...] = ()) -> AnalyzerContext:
    return AnalyzerContext(files=dict(files), file_list=sorted([*files, *extra_paths]))


def _product(extra: dict[str, str] | None = None, extra_paths: tuple[str, ...] = ()) -> AnalyzerContext:
    return _ctx({"pyproject.toml": CLI_PYPROJECT, "acme/cli.py": "def main():\n    return 0\n", **(extra or {})},
                extra_paths)


# ─── Scope step ─────────────────────────────────────────────────────────


def test_cli_entry_point_looks_like_a_product_and_names_its_evidence() -> None:
    scope = assess_cra_scope(_product())

    assert scope.looks_like_product is True
    assert scope.paths("distributable_artifact") == ["pyproject.toml"]
    assert "pyproject.toml" in scope.reasoning
    assert scope.citations == ["CRA Art. 2(1)", "CRA Art. 3(1)"]


def test_internal_service_with_manifest_and_listener_is_not_a_product() -> None:
    """A manifest and a listener are what every internal API has. Neither shows
    the software is supplied to anyone, so they are recorded but do not decide."""
    scope = assess_cra_scope(_ctx({"pyproject.toml": PLAIN_PYPROJECT, "app/main.py": SERVICE_CODE}))

    assert scope.looks_like_product is False
    assert scope.paths("package_manifest") == ["pyproject.toml"]
    assert scope.paths("network_listener") == ["app/main.py"]
    assert scope.paths("distributable_artifact") == []
    assert "app/main.py" in scope.reasoning and "pyproject.toml" in scope.reasoning
    assert "unknown, not as out of scope in law" in scope.reasoning


@pytest.mark.parametrize(
    ("path", "content", "kind"),
    [
        (".github/workflows/release.yml",
         "jobs:\n  publish:\n    steps:\n      - uses: pypa/gh-action-pypi-publish@release/v1\n",
         "distributable_artifact"),
        ("package.json", json.dumps({"name": "acme", "bin": {"acme": "cli.js"}}), "distributable_artifact"),
        ("package.json", json.dumps({"name": "acme-ext", "engines": {"vscode": "^1.90.0"}}),
         "distributable_artifact"),
        ("src/updater.py", "def check_for_updates(channel):\n    return channel\n", "update_mechanism"),
    ],
)
def test_each_deciding_signal_is_enough_alone(path: str, content: str, kind: str) -> None:
    scope = assess_cra_scope(_ctx({path: content}))

    assert scope.looks_like_product is True
    assert path in scope.paths(kind)  # type: ignore[arg-type]


def test_private_node_app_without_bin_is_not_a_product() -> None:
    scope = assess_cra_scope(_ctx({"package.json": json.dumps({"name": "web", "private": True})}))

    assert scope.looks_like_product is False
    assert scope.paths("package_manifest") == ["package.json"]


def test_signals_inside_test_fixtures_do_not_count() -> None:
    """A fixture describes some other project, not the scanned one."""
    scope = assess_cra_scope(_ctx({"tests/fixtures/sample/pyproject.toml": CLI_PYPROJECT}))

    assert scope.looks_like_product is False
    assert scope.signals == []


def test_scope_assessment_is_deterministic() -> None:
    files = {"pyproject.toml": CLI_PYPROJECT, "app/main.py": SERVICE_CODE, "b/package.json": "{}"}
    assert assess_cra_scope(_ctx(files)) == assess_cra_scope(_ctx(dict(reversed(files.items()))))


def test_existing_perimeter_trigger_is_unchanged_by_the_stricter_scope_step() -> None:
    """The Table 5 trigger still fires on a bare manifest (map the law), while
    the scope step declines to run CRA checks on it."""
    ctx = _ctx({"pyproject.toml": PLAIN_PYPROJECT})
    result = analyze_regulatory_perimeter(ctx)

    assert "rp-cra" in {f.id for f in result.findings}
    assert result.metadata["triggered_instruments"] == ["CRA"]
    assert assess_cra_scope(ctx).looks_like_product is False


# ─── Out of scope: an empty report, never a score ───────────────────────


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in _keys(v)}
    if isinstance(value, list):
        return {k for v in value for k in _keys(v)}
    return set()


def test_out_of_scope_repository_gets_an_empty_report() -> None:
    report = build_cra_report(_ctx({"pyproject.toml": PLAIN_PYPROJECT, "app/main.py": SERVICE_CODE}))

    assert report.scope.looks_like_product is False
    assert report.findings == []
    assert report.live_now == [] and report.applies_later == [] and report.not_checked == []
    text = format_cra_report(report)
    assert "No CRA checks were run" in text
    assert "%" not in text


@pytest.mark.parametrize("in_scope", [True, False])
def test_report_has_no_score_in_any_form(in_scope: bool) -> None:
    ctx = _product() if in_scope else _ctx({"pyproject.toml": PLAIN_PYPROJECT})
    report = build_cra_report(ctx)

    keys = {k.lower() for k in _keys(report.model_dump())}
    assert not {k for k in keys if "score" in k or "pct" in k or "percent" in k}
    text = format_cra_report(report).lower()
    assert "%" not in text and "score" not in text.replace("gives no score", "")


# ─── Check 1: disclosure policy and contact ─────────────────────────────


def test_missing_disclosure_policy_names_the_artefact_to_add() -> None:
    finding = check_cvd_policy(_product())

    assert finding.id == CVD_CHECK_ID == "cra-cvd-policy"
    assert finding.status == "missing"
    assert finding.file_path == ""
    assert finding.missing_artifact == "SECURITY.md or .well-known/security.txt"
    assert finding.citations == ["CRA Annex I Part II(5)", "CRA Annex I Part II(6)"]
    assert finding.applies_from == "2027-12-11"


@pytest.mark.parametrize(
    ("path", "content"),
    [
        ("SECURITY.md", "# Security\nReport vulnerabilities to security@acme.example.\n"),
        (".github/SECURITY.md", "Use https://github.com/acme/tool/security/advisories/new to report.\n"),
        (".well-known/security.txt", "Contact: mailto:psirt@acme.example\nExpires: 2027-12-31T00:00:00Z\n"),
    ],
)
def test_policy_with_a_contact_is_evidence_at_its_path(path: str, content: str) -> None:
    finding = check_cvd_policy(_product({path: content}))

    assert finding.status == "found"
    assert finding.file_path == path
    assert finding.missing_artifact == ""


def test_policy_without_a_contact_is_partial_and_says_what_is_missing() -> None:
    """Annex I Part II(6) asks for a contact address; a policy with none leaves
    a reporter nowhere to send the report."""
    finding = check_cvd_policy(_product({"SECURITY.md": "# Security\nWe take security seriously.\n"}))

    assert finding.status == "partial"
    assert finding.file_path == "SECURITY.md"
    assert "contact address" in finding.missing_artifact


def test_a_security_file_deep_in_the_tree_is_not_the_projects_policy() -> None:
    finding = check_cvd_policy(_product({"vendor/lib/SECURITY.md": "Mail security@other.example\n"}))

    assert finding.status == "missing"


# ─── Check 2: SBOM ──────────────────────────────────────────────────────


def test_missing_sbom_names_the_artefact_to_add() -> None:
    finding = check_sbom(_product())

    assert finding.id == SBOM_CHECK_ID == "cra-sbom"
    assert finding.status == "missing"
    assert "CycloneDX or SPDX" in finding.missing_artifact
    assert finding.citations == ["CRA Annex I Part II(1)"]
    assert finding.applies_from == "2027-12-11"


@pytest.mark.parametrize(
    ("path", "content", "fmt"),
    [("bom.json", CYCLONEDX, "CycloneDX"), ("sbom/acme.cdx.json", CYCLONEDX, "CycloneDX"),
     ("sbom.spdx.json", SPDX, "SPDX")],
)
def test_sbom_in_a_recognised_format_is_evidence(path: str, content: str, fmt: str) -> None:
    finding = check_sbom(_product({path: content}))

    assert finding.status == "found"
    assert finding.file_path == path
    assert fmt in finding.detail


def test_sbom_with_no_components_is_partial() -> None:
    """Annex I Part II(1): "at the very least the top-level dependencies"."""
    empty = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []})
    finding = check_sbom(_product({"bom.json": empty}))

    assert finding.status == "partial"
    assert finding.file_path == "bom.json"
    assert "top-level dependencies" in finding.missing_artifact


def test_a_json_file_merely_called_bom_is_not_an_sbom() -> None:
    finding = check_sbom(_product({"bom.json": json.dumps({"parts": ["bolt", "nut"]})}))

    assert finding.status == "missing"


def test_sbom_in_a_format_the_scanner_cannot_read_is_partial_not_evidence() -> None:
    finding = check_sbom(_product(extra_paths=("release/acme.spdx",)))

    assert finding.status == "partial"
    assert finding.file_path == "release/acme.spdx"
    assert "not verified" in finding.detail


def test_sbom_generated_in_ci_but_absent_from_the_repository_is_partial() -> None:
    workflow = "jobs:\n  sbom:\n    steps:\n      - uses: anchore/sbom-action@v0\n"
    finding = check_sbom(_product({".github/workflows/build.yml": workflow}))

    assert finding.status == "partial"
    assert finding.file_path == ".github/workflows/build.yml"
    assert "SBOM file" in finding.missing_artifact


def test_an_sbom_fixture_under_tests_is_not_the_products_sbom() -> None:
    finding = check_sbom(_product({"tests/fixtures/bom.json": CYCLONEDX}))

    assert finding.status == "missing"


# ─── Every finding: citation + (file or named missing artefact) ─────────


@pytest.mark.parametrize(
    "extra",
    [{}, {"SECURITY.md": "security@acme.example"}, {"SECURITY.md": "tbd"}, {"bom.json": CYCLONEDX},
     {"SECURITY.md": "security@acme.example", "sbom.spdx.json": SPDX}],
)
def test_every_finding_cites_the_regulation_and_points_somewhere(extra: dict[str, str]) -> None:
    report = build_cra_report(_product(extra))

    assert [f.id for f in report.findings] == [CVD_CHECK_ID, SBOM_CHECK_ID]
    for finding in report.findings:
        assert finding.citations and all(c.startswith("CRA Annex I Part II(") for c in finding.citations)
        assert finding.file_path or finding.missing_artifact
        if finding.status != "found":
            assert finding.missing_artifact


def test_a_finding_without_a_citation_or_a_target_cannot_be_built() -> None:
    base = {"id": "cra-x", "title": "x", "detail": "x"}
    with pytest.raises(ValidationError):
        CraFinding(**base, status="found", citations=[], file_path="a.md")
    with pytest.raises(ValidationError):
        CraFinding(**base, status="found", citations=["Annex I"], file_path="a.md")
    with pytest.raises(ValidationError):
        CraFinding(**base, status="found", citations=["CRA Annex I Part II(1)"])
    with pytest.raises(ValidationError):
        CraFinding(**base, status="missing", citations=["CRA Annex I Part II(1)"], file_path="a.md")


# ─── What the report says about dates, and what it never says ───────────


def test_in_scope_report_separates_live_duties_from_december_2027() -> None:
    text = format_cra_report(build_cra_report(_product()))

    assert "## Live now: Art. 14 reporting" in text
    assert "11 September 2026" in text
    assert "## Applies from 11 December 2027" in text
    assert "single reporting platform" in text
    assert "Art. 69(3)" in text
    assert "## Not checked by this scan" in text


@pytest.mark.parametrize(
    "extra", [{}, {"SECURITY.md": "security@acme.example", "bom.json": CYCLONEDX}]
)
def test_report_never_calls_a_product_compliant_or_certified(extra: dict[str, str]) -> None:
    report = build_cra_report(_product(extra))
    text = (format_cra_report(report) + report.model_dump_json()).lower()

    for claim in ("is compliant", "are compliant", "fully compliant", "certified", "ce mark",
                  "conforms", "passes the", "no longer supported"):
        assert claim not in text, claim
    assert "does not say that a product meets" in text


# ─── End to end: directory scan and CLI ─────────────────────────────────


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def test_cra_scan_reads_a_directory_including_dot_folders(tmp_path: Path) -> None:
    _write(tmp_path, {
        "pyproject.toml": CLI_PYPROJECT,
        ".well-known/security.txt": "Contact: mailto:psirt@acme.example\n",
        "bom.json": CYCLONEDX,
    })
    report = cra_scan(tmp_path, project_name="acme")

    assert report.project_name == "acme"
    assert {f.id: f.status for f in report.findings} == {CVD_CHECK_ID: "found", SBOM_CHECK_ID: "found"}
    assert report == cra_scan(tmp_path, project_name="acme")  # deterministic


def test_cli_cra_prints_json_by_default_and_markdown_on_request(tmp_path: Path, capsys) -> None:
    _write(tmp_path, {"pyproject.toml": CLI_PYPROJECT})

    assert main([str(tmp_path), "--cra"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["scope"]["looks_like_product"] is True
    assert [f["id"] for f in payload["findings"]] == [CVD_CHECK_ID, SBOM_CHECK_ID]
    assert "compliance_scores" not in payload and "overall_compliance_pct" not in payload

    assert main([str(tmp_path), "--cra", "--markdown"]) == 0
    assert "# Cyber Resilience Act check" in capsys.readouterr().out


def test_cli_cra_clock_computes_deadlines_without_scanning(capsys) -> None:
    code = main(["--cra-clock", "2026-10-24T12:00:00+02:00", "--cra-event", "severe_incident"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["early_warning_due"] == "2026-10-25T12:00:00+02:00"
    assert payload["notification_citation"] == "CRA Art. 14(4)(b)"
    assert payload["final_report_due"] is None
    assert payload["files_notifications"] is False


@pytest.mark.parametrize(
    "argv",
    [
        ["--cra-clock", "2026-11-03T09:30:00", "--cra-event", "severe_incident"],  # no offset
        ["--cra-clock", "yesterday", "--cra-event", "severe_incident"],
        ["--cra-clock", "2026-11-03T09:30:00+01:00"],  # no event type
        ["--cra-event", "severe_incident"],  # no awareness time
        ["--cra-clock", "2026-11-03T09:30:00+01:00", "--cra-event", "severe_incident",
         "--cra-measure-available-at", "2026-11-05T09:30:00+01:00"],  # wrong anchor
    ],
)
def test_cli_cra_clock_refuses_input_it_cannot_compute_from(argv: list[str], capsys) -> None:
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error:")


# ─── Plugin surface ─────────────────────────────────────────────────────


def test_cra_scan_command_states_what_is_live_and_what_comes_later() -> None:
    text = (REPO_ROOT / "commands" / "cra-scan.md").read_text(encoding="utf-8")

    assert text.startswith("---\nname: cra-scan\n")
    assert "antifragile-scan" in text and "--cra" in text
    assert "11 September 2026" in text and "11 December 2027" in text
    assert "never" in text.lower() and "score" in text.lower()
    assert "cra-scan" in json.loads((REPO_ROOT / "plugin.json").read_text(encoding="utf-8"))["commands"]


def test_readme_documents_the_cra_slice_with_both_dates() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Cyber Resilience Act", 1)[1].split("\n## ", 1)[0]

    assert "/cra-scan" in section
    assert "11 September 2026" in section and "11 December 2027" in section
    assert "Art. 14" in section and "Annex I Part II" in section
