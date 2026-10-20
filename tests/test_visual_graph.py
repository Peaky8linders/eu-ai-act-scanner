"""Tests for interactive context graph visual generator (scanner.visual_graph)."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models import ArchitectureNode, FileFinding, ScanResult
from scanner.visual_graph import build_graph_data, generate_visual_graph

# Absolute URLs that are identifiers, not fetchable resources. The SVG namespace
# string is passed to createElementNS and is never dereferenced.
_ALLOWED_ABSOLUTE_URLS = frozenset({"http://www.w3.org/2000/svg"})

# Classes the page script toggles purely as JavaScript hooks; their styling is
# applied through their own utility classes, so they carry no CSS rule.
_PAGE_SCRIPT_HOOKS = frozenset({"filter-btn", "inspector-tab", "tab-pane"})


def _absolute_urls(markup: str) -> set[str]:
    """Every absolute URL left once comments (which cannot load anything) are gone."""
    text = re.sub(r"<!--.*?-->", "", markup, flags=re.DOTALL)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return {url.rstrip(".,;") for url in re.findall(r"https?://[^\s\"'<>()]+", text)}


def _class_attributes(markup: str) -> set[str]:
    """Class tokens written in markup, including those inside JS template literals."""
    tokens: set[str] = set()
    for value in re.findall(r'class="([^"]*)"', markup):
        tokens.update(value.split())
    return tokens


def _css_classes(css: str) -> set[str]:
    """Class names the stylesheet defines, with CSS escapes removed."""
    names = set()
    for raw in re.findall(r"\.((?:\\.|[^\s,{:.\[\]>+~])+)", css):
        names.add(re.sub(r"\\(.)", r"\1", raw))
    return names


def test_build_graph_data_with_architecture() -> None:
    scan = ScanResult(
        project_name="Demo-AI-System",
        is_ai_system=True,
        overall_compliance_pct=55.0,
        compliance_scores={
            "human_oversight": 20.0,
            "security": 80.0,
            "logging": 40.0,
        },
        inferred_roles=["deployer"],
        architecture=[
            ArchitectureNode(
                id="agent_execution",
                label="Agent Execution Runtime",
                type="agent_runtime",
                compliance_status="gap",
                connected_to=["human_oversight"],
                file_count=2,
            ),
            ArchitectureNode(
                id="human_oversight",
                label="Human Oversight Gate",
                type="guardrail",
                compliance_status="gap",
                connected_to=[],
                file_count=1,
            ),
        ],
        file_findings=[
            FileFinding(
                file_path="agent.py",
                gaps=["Missing autonomous tool invocation bounds"],
                compliance_dimensions=["human_oversight"],
                status="gap",
            )
        ],
    )

    data = build_graph_data(scan)
    assert data["project_name"] == "Demo-AI-System"
    assert data["is_ai_system"] is True
    assert data["total_nodes"] >= 2
    assert data["gap_nodes_count"] >= 1

    # Check node details
    nodes_by_id = {n["id"]: n for n in data["nodes"]}
    assert "human_oversight" in nodes_by_id
    ho = nodes_by_id["human_oversight"]
    assert ho["compliance_status"] == "gap"
    assert "Art. 14" in ho["article"]
    assert "Omnibus" in ho["omnibus_timeline"] or "Regulation (EU) 2026/1744" in ho["omnibus_timeline"]

    # Recommended fix is populated
    assert ho["recommended_fix"] is not None
    assert "human_oversight.py" in ho["recommended_fix"]["target_path"]
    assert "approval_gate" in ho["recommended_fix"]["code_snippet"].lower() or "override" in ho["recommended_fix"]["code_snippet"].lower()


def test_generate_visual_graph_html_output(tmp_path: Path) -> None:
    scan = ScanResult(
        project_name="Visual-Test",
        is_ai_system=True,
        overall_compliance_pct=65.0,
        compliance_scores={"risk_mgmt": 70.0, "transparency": 10.0},
    )

    out_file = tmp_path / "context_graph.html"
    html = generate_visual_graph(scan, output_path=out_file)

    assert "<!DOCTYPE html>" in html
    assert "EU AI Act Context Graph" in html
    assert "Visual-Test" in html
    assert "GRAPH_DATA" in html
    # Utilities are compiled ahead of time and inlined — no CDN JIT at open time.
    assert "--tw-" in html
    assert "<script src" not in html

    assert out_file.is_file()
    saved = out_file.read_text(encoding="utf-8")
    assert saved == html


def test_generated_graph_makes_no_network_request(tmp_path: Path) -> None:
    """The graph is opened on an analyst's machine and must stay offline.

    Guards both halves of the contract: no element that loads a remote asset,
    and no absolute URL anywhere in the document (which also catches a
    ``fetch()`` added to the page script) other than non-fetchable namespace
    identifiers. Comments are ignored — they cannot cause a request.
    """
    scan = ScanResult(
        project_name="Offline-Graph",
        is_ai_system=True,
        overall_compliance_pct=40.0,
        compliance_scores={"human_oversight": 10.0, "transparency": 90.0},
    )
    html = generate_visual_graph(scan, output_path=tmp_path / "offline_graph.html")

    lowered = html.lower()
    assert "<script src" not in lowered
    assert "<link" not in lowered
    assert "@import" not in lowered
    assert "url(http" not in lowered
    assert "url(//" not in lowered
    # Protocol-relative references are remote too and carry no scheme for the
    # absolute-URL audit below to match.
    assert "'//" not in html
    assert '"//' not in html

    unexpected = _absolute_urls(html) - _ALLOWED_ABSOLUTE_URLS
    assert not unexpected, f"generated graph references remote assets: {sorted(unexpected)}"


def test_vendored_css_covers_every_class_the_page_uses(tmp_path: Path) -> None:
    """Removing the CDN means the bundled CSS can silently go stale.

    Adding a utility class to the template without re-running
    ``scripts/build_graph_css.py`` would leave that element unstyled, with no
    error at generation time — so pin the coverage here.
    """
    scan = ScanResult(
        project_name="Css-Coverage",
        is_ai_system=True,
        overall_compliance_pct=45.0,
        compliance_scores={"human_oversight": 20.0, "security": 70.0},
    )
    html = generate_visual_graph(scan, output_path=tmp_path / "coverage_graph.html")
    css = html.split("<style>", 1)[1].split("</style>", 1)[0]

    missing = sorted(_class_attributes(html) - _css_classes(css) - _PAGE_SCRIPT_HOOKS)
    assert not missing, (
        "classes used by the page have no rule in scanner/data/graph.css "
        f"(re-run scripts/build_graph_css.py): {missing}"
    )


def test_repository_derived_label_cannot_break_out_of_the_script(tmp_path: Path) -> None:
    """A file or component named `</script><script>...` must render as text.

    Graph data is embedded in an inline <script>. JSON escaping alone leaves
    ``</script>`` intact, which closes the element and turns the rest of the
    label into markup — arbitrary script in a page the user opens locally.
    """
    payload = "</script><script>window.__pwned = 1</script>"
    scan = ScanResult(
        project_name=payload,
        is_ai_system=True,
        overall_compliance_pct=40.0,
        compliance_scores={"logging": 10.0},
        architecture=[
            ArchitectureNode(
                id="logging",
                label=payload,
                type="service",
                compliance_status="gap",
                connected_to=[],
                file_count=1,
            )
        ],
    )

    html = generate_visual_graph(scan, output_path=tmp_path / "graph.html")

    # The breakout sequence is an unescaped `</script>`; `<script>` alone is
    # inert inside script data, so only the closing tag is pinned.
    assert "</script><script>window.__pwned" not in html
    # Only the single legitimate closing tag remains — the inline graph script
    # (the page no longer loads a CDN bundle).
    assert html.count("</script>") == 1
    # The sequence survives only in its JSON-safe form `\/`.
    assert "<\\/script>" in html
    # The <title> is HTML-escaped, so the payload cannot inject markup there.
    assert "&lt;/script&gt;" in html
