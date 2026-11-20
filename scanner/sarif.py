"""SARIF 2.1.0 export and ingestion for EU AI Act Scanner.

Provides two-way interoperability with cybersecurity tools (Semgrep, Bandit,
Snyk, CodeQL, GitHub Advanced Security, and Claude Code `/ai-act-security-review`):

- :func:`scan_to_sarif` / :func:`write_sarif`: serialize ``ScanResult`` gap
  findings into a valid, strictly offline SARIF 2.1.0 document (no remote
  ``$schema`` or ``informationUri`` URLs by default).
- :func:`ingest_sarif_files`: parse local ``.sarif`` / ``.sarif.json`` files
  into ``scanner.analyzers._base.Finding`` instances mapped to EU AI Act
  Art. 15(4) cybersecurity obligations.

Pure stdlib + Pydantic; zero outbound network calls.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from scanner import __version__
from scanner.analyzers._base import Finding
from scanner.kb import DIMENSIONS
from scanner.models import DiscoveredComponent, ScanResult

_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "eu-ai-act-scanner"

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_URL_RE = re.compile(r"https?://[^\s\"'<>()]+")

_HIGH_SEVERITY_COMPONENTS = frozenset(
    {
        "mcp_toolchain",
        "claude_code_security",
        "lethal_trifecta",
        "article_50_transparency",
        "agent_cascade",
    }
)
_HIGH_SEVERITY_KEYWORDS = (
    "secret",
    "credential",
    "api key",
    "api_key",
    "password",
    "poisoning",
    "ssrf",
    "bypasspermissions",
    "bash(*)",
    "injection",
    "eval",
    "exec",
    "shell=true",
    "pickle",
    "lethal trifecta",
    "unbounded",
    "no auth",
    "no-auth",
    "unauthenticated",
)


def _slugify(value: str, *, max_len: int = 48) -> str:
    slug = _SLUG_RE.sub("-", value.lower()).strip("-")
    if not slug:
        return "finding"
    return slug[:max_len].rstrip("-") or "finding"


def _strip_urls(text: str) -> str:
    """Redact any embedded http(s) URL from free-text SARIF fields to preserve strict offline output."""
    if not text:
        return ""
    return _URL_RE.sub("[redacted-url]", text)


def _component_line_number(comp: DiscoveredComponent) -> int | None:
    """Extract an optional 1-based line number from a component or its details."""
    line = getattr(comp, "line_number", None)
    if line is None and isinstance(comp.details, dict):
        line = comp.details.get("line_number")
        if line is None:
            line = comp.details.get("line")
    if isinstance(line, int) and not isinstance(line, bool) and line >= 1:
        return line
    return None


def _component_articles(comp: DiscoveredComponent) -> list[str]:
    """Resolve EU AI Act article references for a component."""
    articles: list[str] = []
    seen: set[str] = set()

    if isinstance(comp.details, dict):
        raw_articles = comp.details.get("article_paragraphs") or comp.details.get("articles") or []
        if isinstance(raw_articles, str):
            raw_articles = [raw_articles]
        for art in raw_articles:
            if isinstance(art, str) and art.strip() and art.strip() not in seen:
                seen.add(art.strip())
                articles.append(art.strip())

    for dim_id in comp.compliance_dimensions:
        dim = DIMENSIONS.get(dim_id)
        if dim and dim.article and dim.article not in seen:
            seen.add(dim.article)
            articles.append(dim.article)

    return articles


def _component_incidents(comp: DiscoveredComponent, result: ScanResult) -> list[str]:
    """Collect deduplicated corpus incident IDs relevant to a gap component."""
    incidents: list[str] = []
    seen: set[str] = set()

    if isinstance(comp.details, dict):
        raw_incidents = comp.details.get("related_incidents") or []
        if isinstance(raw_incidents, list):
            for inc_id in raw_incidents:
                if isinstance(inc_id, str) and inc_id and inc_id not in seen:
                    seen.add(inc_id)
                    incidents.append(inc_id)

    for dim_id in comp.compliance_dimensions:
        for inc_id in result.incident_grounding.get(dim_id, []):
            if inc_id not in seen:
                seen.add(inc_id)
                incidents.append(inc_id)
            if len(incidents) >= 6:
                return incidents

    return incidents[:6]


def _component_sarif_level(comp: DiscoveredComponent) -> str:
    """Map a gap component to SARIF level: 'error', 'warning', or 'note'."""
    if isinstance(comp.details, dict):
        sev = str(comp.details.get("severity", "")).lower().strip()
        if sev in {"critical", "high", "error"}:
            return "error"
        if sev in {"medium", "warning", "moderate"}:
            return "warning"
        if sev in {"low", "info", "informational", "note"}:
            return "note"

    haystack = f"{comp.component_type} {comp.name}".lower()
    if comp.component_type in _HIGH_SEVERITY_COMPONENTS or any(
        kw in haystack for kw in _HIGH_SEVERITY_KEYWORDS
    ):
        return "error"
    if comp.confidence >= 0.85:
        return "error"
    if comp.confidence >= 0.55:
        return "warning"
    return "note"


def _rule_id_for_component(comp: DiscoveredComponent) -> str:
    if isinstance(comp.details, dict):
        explicit_id = comp.details.get("rule_id") or comp.details.get("id")
        if isinstance(explicit_id, str) and explicit_id.strip():
            return explicit_id.strip()
    comp_slug = _slugify(comp.component_type or "general", max_len=32)
    name_slug = _slugify(comp.name or "gap", max_len=48)
    return f"eu-ai-act/{comp_slug}/{name_slug}"


def scan_to_sarif(
    result: ScanResult,
    *,
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Convert a ``ScanResult`` into a valid offline SARIF 2.1.0 dictionary.

    Omits remote ``$schema`` and ``informationUri`` fields so emitted JSON
    contains zero remote URLs and remains safe for offline security pipelines.
    Only ``gap`` findings are emitted as SARIF results; non-AI repositories
    (``result.is_ai_system is False``) emit an empty result set.
    """
    resolved_version = tool_version or result.scanner_version or __version__

    rules_by_id: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    if result.is_ai_system:
        for comp in result.components:
            if comp.compliance_impact != "gap":
                continue

            rule_id = _rule_id_for_component(comp)
            level = _component_sarif_level(comp)
            articles = _component_articles(comp)
            incidents = _component_incidents(comp, result)
            dimensions = list(comp.compliance_dimensions)
            line_num = _component_line_number(comp)

            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "name": _strip_urls(comp.name),
                    "shortDescription": {"text": _strip_urls(comp.name)},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "eu_ai_act_articles": articles,
                        "dimensions": dimensions,
                        "component_type": comp.component_type,
                    },
                }

            evidence = ""
            if isinstance(comp.details, dict):
                raw_ev = comp.details.get("evidence") or comp.details.get("description") or ""
                if isinstance(raw_ev, str):
                    evidence = _strip_urls(raw_ev.strip())

            msg_parts = [_strip_urls(comp.name)]
            if articles:
                msg_parts.append(f"EU AI Act: {', '.join(articles)}")
            if evidence:
                msg_parts.append(f"Evidence: {evidence}")
            message_text = " | ".join(msg_parts)

            locations: list[dict[str, Any]] = []
            if comp.file_path:
                uri = _strip_urls(comp.file_path.replace("\\", "/"))
                phys: dict[str, Any] = {
                    "artifactLocation": {"uri": uri},
                }
                if line_num is not None:
                    phys["region"] = {"startLine": line_num}
                locations.append({"physicalLocation": phys})

            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": message_text},
                    "locations": locations,
                    "properties": {
                        "eu_ai_act_articles": articles,
                        "dimensions": dimensions,
                        "related_incidents": incidents,
                        "confidence": round(float(comp.confidence), 4),
                        "component_type": comp.component_type,
                    },
                }
            )

    return {
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": resolved_version,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": sarif_results,
                "properties": {
                    "project_name": _strip_urls(result.project_name),
                    "scan_id": result.scan_id,
                    "is_ai_system": result.is_ai_system,
                    "overall_compliance_pct": round(float(result.overall_compliance_pct), 1),
                },
            }
        ],
    }


def write_sarif(
    result: ScanResult,
    output_path: Path | str,
    *,
    tool_version: str | None = None,
) -> Path:
    """Write a ``ScanResult`` to disk as UTF-8 SARIF 2.1.0 JSON."""
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = scan_to_sarif(result, tool_version=tool_version)
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


def _normalize_sarif_uri(uri: str) -> str:
    cleaned = uri.strip()
    if cleaned.lower().startswith("file:///"):
        cleaned = cleaned[8:]
    elif cleaned.lower().startswith("file://"):
        cleaned = cleaned[7:]
    cleaned = cleaned.replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def _extract_rule_map(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rule_map: dict[str, dict[str, Any]] = {}
    tool = run.get("tool")
    if not isinstance(tool, dict):
        return rule_map

    driver = tool.get("driver")
    if isinstance(driver, dict) and isinstance(driver.get("rules"), list):
        for rule in driver["rules"]:
            if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                rule_map[rule["id"]] = rule

    extensions = tool.get("extensions")
    if isinstance(extensions, list):
        for ext in extensions:
            if isinstance(ext, dict) and isinstance(ext.get("rules"), list):
                for rule in ext["rules"]:
                    if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                        rule_map.setdefault(rule["id"], rule)

    return rule_map


def _build_finding(
    *,
    finding_id: str,
    title: str,
    description: str,
    file_path: str,
    confidence: float,
    evidence_snippet: str,
    severity: str,
    line_number: int | None,
) -> Finding:
    """Construct a ``Finding`` compatible with current and extended ``Finding`` schemas."""
    kwargs: dict[str, Any] = {
        "id": finding_id,
        "category": "external_security_sarif",
        "title": title,
        "description": description,
        "file_path": file_path,
        "confidence": confidence,
        "compliance_impact": "gap",
        "compliance_dimensions": ["security", "supply_chain"],
        "evidence_snippet": evidence_snippet[:200],
        "article_paragraphs": ["Art. 15(4)"],
    }
    if "severity" in Finding.model_fields:
        kwargs["severity"] = severity
    if "line_number" in Finding.model_fields and line_number is not None:
        kwargs["line_number"] = line_number
    return Finding(**kwargs)


def ingest_sarif_files(
    paths: Sequence[str | Path],
) -> tuple[list[Finding], list[str]]:
    """Parse one or more local SARIF 2.1.0 files into EU AI Act ``Finding`` objects.

    Supports SARIF output from Semgrep, Bandit, Snyk, CodeQL, GitHub Advanced
    Security, ``/ai-act-security-review``, or :func:`scan_to_sarif`.

    Mapping rules:
    - ``error`` -> ``severity="high"``, ``confidence=0.90``
    - ``warning`` -> ``severity="medium"``, ``confidence=0.75``
    - ``note``, ``none``, suppressed results, and non-fail kinds -> skipped

    Raises:
        ValueError: if a file cannot be read, contains invalid JSON, or does not
            match the top-level SARIF structure (``runs`` list).
    """
    findings: list[Finding] = []
    source_tools: list[str] = []
    seen_tools: set[str] = set()
    counter = 0

    for raw_path in paths:
        path = Path(raw_path)
        if not path.is_file():
            raise ValueError(f"SARIF file not found: {path}")

        try:
            raw_text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"Failed to read SARIF file {path}: {exc}") from exc

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON in SARIF file {path}: {exc.msg}") from exc

        if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
            raise ValueError(f"Invalid SARIF structure in {path}: expected top-level object with 'runs' list")

        for run in data["runs"]:
            if not isinstance(run, dict):
                continue

            tool_obj = run.get("tool")
            driver_obj = tool_obj.get("driver") if isinstance(tool_obj, dict) else None
            tool_name = (
                str(driver_obj.get("name")).strip()
                if isinstance(driver_obj, dict) and driver_obj.get("name")
                else "unknown-sarif-tool"
            )
            if tool_name not in seen_tools:
                seen_tools.add(tool_name)
                source_tools.append(tool_name)

            tool_slug = _slugify(tool_name, max_len=24)
            rule_map = _extract_rule_map(run)

            raw_results = run.get("results")
            if not isinstance(raw_results, list):
                continue

            for entry in raw_results:
                if not isinstance(entry, dict):
                    continue

                # Skip suppressed findings
                suppressions = entry.get("suppressions")
                if isinstance(suppressions, list) and len(suppressions) > 0:
                    continue

                # Skip explicitly non-failing result kinds (e.g. 'pass', 'notApplicable')
                kind = str(entry.get("kind", "fail")).lower().strip()
                if kind not in {"fail", "open", "review", ""}:
                    continue

                rule_id = str(entry.get("ruleId") or "sarif-rule").strip()
                rule_meta = rule_map.get(rule_id, {})

                raw_level = entry.get("level")
                if not raw_level and isinstance(rule_meta, dict):
                    default_cfg = rule_meta.get("defaultConfiguration")
                    if isinstance(default_cfg, dict):
                        raw_level = default_cfg.get("level")
                level = str(raw_level or "warning").lower().strip()

                if level == "error":
                    severity = "high"
                    confidence = 0.90
                elif level == "warning":
                    severity = "medium"
                    confidence = 0.75
                else:
                    # Skip 'note', 'none', or informational results
                    continue

                msg_obj = entry.get("message")
                msg_text = ""
                if isinstance(msg_obj, dict):
                    msg_text = str(msg_obj.get("text") or msg_obj.get("markdown") or "").strip()
                elif isinstance(msg_obj, str):
                    msg_text = msg_obj.strip()
                if not msg_text and isinstance(rule_meta, dict):
                    short_desc = rule_meta.get("shortDescription")
                    if isinstance(short_desc, dict):
                        msg_text = str(short_desc.get("text") or "").strip()
                if not msg_text:
                    msg_text = rule_id

                file_path = ""
                start_line: int | None = None
                snippet_text = ""
                locations = entry.get("locations")
                if isinstance(locations, list) and locations:
                    first_loc = locations[0]
                    if isinstance(first_loc, dict):
                        phys = first_loc.get("physicalLocation")
                        if isinstance(phys, dict):
                            art_loc = phys.get("artifactLocation")
                            if isinstance(art_loc, dict) and isinstance(art_loc.get("uri"), str):
                                file_path = _normalize_sarif_uri(art_loc["uri"])
                            region = phys.get("region")
                            if isinstance(region, dict):
                                raw_line = region.get("startLine")
                                if isinstance(raw_line, int) and not isinstance(raw_line, bool) and raw_line >= 1:
                                    start_line = raw_line
                                snippet_obj = region.get("snippet")
                                if isinstance(snippet_obj, dict) and isinstance(snippet_obj.get("text"), str):
                                    snippet_text = snippet_obj["text"].strip()

                counter += 1
                rule_slug = _slugify(rule_id, max_len=32)
                finding_id = f"sarif-{tool_slug}-{rule_slug}-{counter}"

                short_title_msg = msg_text.splitlines()[0][:90]
                title = f"[{tool_name}] {rule_id}: {short_title_msg}"
                loc_label = f"{file_path}:{start_line}" if (file_path and start_line) else (file_path or "repository")
                description = (
                    f"External SARIF finding from {tool_name} (severity={severity}, "
                    f"rule={rule_id}, location={loc_label}): {msg_text}"
                )
                evidence = (
                    f"severity={severity}; rule={rule_id}; {snippet_text}"
                    if snippet_text
                    else f"severity={severity}; rule={rule_id}; location={loc_label}"
                )

                findings.append(
                    _build_finding(
                        finding_id=finding_id,
                        title=title,
                        description=description,
                        file_path=file_path,
                        confidence=confidence,
                        evidence_snippet=evidence,
                        severity=severity,
                        line_number=start_line,
                    )
                )

    return findings, source_tools


__all__ = [
    "scan_to_sarif",
    "write_sarif",
    "ingest_sarif_files",
]
