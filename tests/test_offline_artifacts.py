"""Offline audit of every artifact the scanner emits.

The scanner's contract is local-only: it reads a codebase and writes reports,
with no network calls. That contract has two halves, and this module pins both.

* **Artifacts load nothing remotely.** The context graph used to pull Tailwind
  from a CDN, so opening a report made a third-party request. The HTML is now
  covered in ``test_visual_graph.py``; here the human-readable and machine
  readable artifacts — scan markdown, cross-framework report, grounded Q&A,
  incidents, dossier JSON, MCP payloads, the settings file and the patches the
  fix loop proposes — are checked to be inert when opened or rendered.
* **The engine has no outbound client.** An AST walk over ``scanner/`` fails if
  a module imports an HTTP/socket client, or shells out to ``curl``/``wget``.
  The MCP server is the one deliberate network *surface* (a local listener the
  deployer runs); nothing in the package is allowed to call out.

Remote URLs are allowed only where they are evidence: an incident's
``references[].url`` and the corpus ``source_url`` / ``dataset_url`` point at
the primary source for a claim. Anywhere else in an artifact, a URL is a bug —
it means untrusted repo data, or a new feature, is reaching a renderer.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from scanner.cli import _filter_by_article, _format_markdown, _format_qa, _incidents_payload
from scanner.cross_framework import project_scan_to_frameworks
from scanner.dossier import generate_dossier
from scanner.fix_loop import DETERMINISTIC_FIXERS, run_fix_loop
from scanner.mcp_server import tool_incidents_for_article, tool_scan_project
from scanner.orchestrator import scan_project
from scanner.qa import answer_question
from scanner.settings import save_settings

FIXTURE = str(Path(__file__).parent / "fixtures" / "sample_project")

# Markup that makes a viewer or renderer request something when the artifact is
# opened. A plain markdown link is not included: it is inert until clicked.
_REMOTE_LOAD = (
    ("script src", re.compile(r"<script\b[^>]*\bsrc\s*=", re.IGNORECASE)),
    ("link href", re.compile(r"<link\b[^>]*\bhref\s*=", re.IGNORECASE)),
    ("embedding element", re.compile(r"<(?:img|iframe|video|audio|source|embed|object|track|svg)\b", re.IGNORECASE)),
    ("css @import", re.compile(r"@import", re.IGNORECASE)),
    ("css url()", re.compile(r"url\(\s*['\"]?(?:https?:)?//", re.IGNORECASE)),
    ("markdown image", re.compile(r"!\[[^\]]*\]\(\s*<?(?:https?:)?//", re.IGNORECASE)),
)

_ABSOLUTE_URL = re.compile(r"https?://[^\s\"'<>()]+")

# Keys whose value is a citation to the primary source of an incident claim.
# A URL anywhere else is either smuggled repo data or a feature that needs
# review, so the audit fails on it.
_CITATION_KEYS = frozenset(
    {"url", "source_url", "dataset_url", "references", "licence_url", "documentation_url"}
)

# Outbound clients. ``urllib.parse`` and ``urllib.error`` stay allowed; only
# modules that can open a connection are blocked.
_BLOCKED_MODULE_PREFIXES = (
    "urllib.request",
    "urllib3",
    "http.client",
    "socket",
    "requests",
    "httpx",
    "aiohttp",
    "websocket",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc",
)
_BLOCKED_SHELL_COMMANDS = re.compile(r"""["'](?:curl|wget|nc)["']""")


def _network_code_tokens(text: str) -> list[str]:
    """Outbound-client constructs in generated code (used for fixer patches)."""
    tokens = [
        token
        for token in ("requests", "urlopen", "httpx", "aiohttp", "socket.", "fetch(")
        if token in text
    ]
    if re.search(r"^\s*(?:import|from)\s+(?:urllib\.request|http\.client)", text, re.MULTILINE):
        tokens.append("http client import")
    return tokens


def _json_urls(obj: object, path: str = "$") -> list[tuple[str, str]]:
    """Every absolute URL in a JSON-shaped value, with the path it sits under."""
    found: list[tuple[str, str]] = []
    if isinstance(obj, str):
        if _ABSOLUTE_URL.search(obj):
            found.append((path, obj[:80]))
    elif isinstance(obj, dict):
        for key, value in obj.items():
            found.extend(_json_urls(value, f"{path}.{key}"))
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            found.extend(_json_urls(value, f"{path}[{index}]"))
    return found


def _json_key(path: str) -> str:
    return re.sub(r"\[\d+\]$", "", path).rsplit(".", 1)[-1]


def _scan():
    return scan_project(FIXTURE)


# ---------------------------------------------------------------------------
# Human-readable artifacts
# ---------------------------------------------------------------------------


def test_markdown_and_settings_artifacts_load_nothing_remotely(tmp_path: Path) -> None:
    """Scan report, cross-framework report, grounded Q&A and the settings file.

    These are printed to a terminal or rendered as markdown in the host session,
    so an embedded image or raw HTML element would fetch on display.
    """
    scan = _scan()
    qa = answer_question("What does Art. 14 require?")
    settings_path, _ = save_settings(mode="deterministic", project_root=tmp_path)

    artifacts = {
        "scan report": _format_markdown(scan),
        "cross-framework report": project_scan_to_frameworks(scan).format_markdown(),
        "grounded answer": _format_qa(qa),
        "settings file": settings_path.read_text(encoding="utf-8"),
    }

    for name, text in artifacts.items():
        for label, pattern in _REMOTE_LOAD:
            assert not pattern.search(text), f"{name} contains a remote {label}"
        # Comments are inert; a real URL elsewhere is either a citation the
        # author meant to add deliberately or injected repo data.
        urls = {url.rstrip(".,;") for url in _ABSOLUTE_URL.findall(text)}
        assert not urls, f"{name} embeds an absolute URL: {sorted(urls)}"


# ---------------------------------------------------------------------------
# Machine-readable artifacts
# ---------------------------------------------------------------------------


def test_json_artifacts_only_cite_remote_urls(tmp_path: Path) -> None:
    """Dossier, scan, cross-framework, article, incident and MCP payloads.

    JSON is inert, so the risk here is not a fetch — it is a URL reaching a
    field a renderer or a consuming tool treats as content (a banner, a path, a
    title). Only provenance fields may carry one.
    """
    scan = _scan()
    dossier = generate_dossier(scan, FIXTURE)

    artifacts = {
        "dossier": dossier.model_dump(),
        "scan": scan.model_dump(),
        "cross-framework": project_scan_to_frameworks(scan).model_dump(),
        "article filter": _filter_by_article(scan, "art15"),
        "incidents": _incidents_payload("art15"),
        "mcp scan": tool_scan_project(FIXTURE),
        "mcp incidents": tool_incidents_for_article("art15"),
    }

    for name, payload in artifacts.items():
        text = json.dumps(payload, default=str)
        assert "<script" not in text, f"{name} payload contains a script element"
        for path, value in _json_urls(payload):
            assert _json_key(path) in _CITATION_KEYS, (
                f"{name} payload carries a remote URL outside a citation field: {path} -> {value}"
            )


def test_mcp_payload_is_json_serializable_and_uncited_paths_stay_clean() -> None:
    """An MCP host stores the payload verbatim; it must not carry asset markup."""
    payload = tool_scan_project(FIXTURE)
    text = json.dumps(payload)
    for label, pattern in _REMOTE_LOAD:
        assert not pattern.search(text), f"MCP payload contains a remote {label}"


# ---------------------------------------------------------------------------
# Generated code and the engine itself
# ---------------------------------------------------------------------------


def test_fix_proposals_do_not_introduce_network_code(tmp_path: Path) -> None:
    """Patches are written into the user's repo — they must keep it offline.

    A remediation that imported ``requests`` would violate the same guarantee
    the engine holds itself to, and would ship in the user's source tree.
    """
    assert DETERMINISTIC_FIXERS, "no fixers registered"
    for key, fixer in DETERMINISTIC_FIXERS.items():
        proposal = fixer(tmp_path)
        tokens = _network_code_tokens(proposal.content)
        assert not tokens, f"fixer {key!r} writes network code into {proposal.target_path}: {tokens}"

    applied = run_fix_loop(FIXTURE, apply=False)
    for proposal in applied.proposals:
        tokens = _network_code_tokens(proposal.content)
        assert not tokens, f"proposal for {proposal.target_path} adds network code: {tokens}"


def test_no_outbound_network_client_in_the_package() -> None:
    """Static guard: nothing under ``scanner/`` may open an outbound connection.

    The MCP server registers tools with the ``mcp`` SDK (a *server* library the
    deployer binds locally); it does not import an HTTP client of its own. The
    maintainer-only corpus sync lives in ``scripts/`` and is not packaged.
    """
    package_root = Path(__file__).parent.parent / "scanner"
    offenders: list[str] = []

    for source_path in sorted(package_root.rglob("*.py")):
        source = source_path.read_text(encoding="utf-8")
        if _BLOCKED_SHELL_COMMANDS.search(source):
            offenders.append(f"{source_path.relative_to(package_root)}: shells out to curl/wget")
        tree = ast.parse(source, filename=str(source_path))
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            for module in modules:
                if module.startswith(_BLOCKED_MODULE_PREFIXES):
                    offenders.append(f"{source_path.relative_to(package_root)}: imports {module}")

    assert not offenders, "package has outbound network code:\n" + "\n".join(offenders)
