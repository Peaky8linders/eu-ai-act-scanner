"""Command-line interface for the EU AI Act scanner.

Usage:
    eu-ai-act-scan [PATH] [--json | --markdown] [--article ARTN]
    eu-ai-act-scan --incidents KEY [--limit N]   # KEY = dimension | artNN | threat
    python -m scanner.cli ./my-project --json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import structlog

# CLI mode: suppress info-level structlog output so stdout stays clean for
# the JSON/markdown payload. Library users can re-enable logs by calling
# structlog.configure() themselves.
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
)

# Ensure UTF-8 output regardless of the host console code page. Windows cmd /
# PowerShell default to cp1252/cp437, which can't encode the em-dashes, smart
# quotes and ellipses in the bundled verbatim statute text — without this a
# `--ask` answer could raise UnicodeEncodeError on those consoles.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):  # pragma: no cover - stream without reconfigure
        pass

from scanner import __version__, scan_project  # noqa: E402
from scanner.data.incident_corpus import get_incident  # noqa: E402
from scanner.incident_grounding import (  # noqa: E402
    incidents_for_article,
    incidents_for_dimension,
    incidents_for_threat,
)
from scanner.kb import DIMENSIONS, dimensions_for_article  # noqa: E402


def _format_markdown(result, top_gaps: int = 10) -> str:
    """Render a human-readable scan summary."""
    if not result.is_ai_system:
        # Out of EU AI Act scope — surface the reason, never a compliance %.
        return "\n".join([
            f"# EU AI Act Scan — {result.project_name}",
            "",
            "**Not an AI system — out of EU AI Act scope.**",
            "",
            result.scope_note or (
                "No AI/ML framework, model, or agent signal was detected; "
                "compliance scoring was skipped."
            ),
            "",
            f"- **Scanner version**: {result.scanner_version}",
            f"- **Files scanned**: {result.total_files:,}",
            f"- **Languages**: {', '.join(f'{k} ({v})' for k, v in list(result.languages.items())[:5]) or 'none detected'}",
        ])

    lines = [
        f"# EU AI Act Scan — {result.project_name}",
        "",
        f"- **Scanner version**: {result.scanner_version}",
        f"- **Files scanned**: {result.total_files:,}",
        f"- **Overall compliance**: **{result.overall_compliance_pct}%**",
        f"- **Languages**: {', '.join(f'{k} ({v})' for k, v in list(result.languages.items())[:5]) or 'none detected'}",
        f"- **Inferred operator role(s)**: {', '.join(result.inferred_roles) or 'none detected'}",
        "",
        "## Compliance by dimension",
        "",
        "| Dimension | Article | Score |",
        "|---|---|---|",
    ]
    for dim_id, score in sorted(result.compliance_scores.items(), key=lambda x: -x[1]):
        dim = DIMENSIONS.get(dim_id)
        label = dim.label if dim else dim_id
        article = dim.article if dim else "—"
        lines.append(f"| {label} | {article} | {score:.1f}% |")

    if result.risk_indicators:
        lines += ["", "## Risk indicators", ""]
        for r in result.risk_indicators[:top_gaps]:
            lines.append(f"- {r}")

    if result.recommendations:
        lines += ["", "## Recommendations", ""]
        for r in result.recommendations[:top_gaps]:
            lines.append(f"- {r}")

    if result.incident_grounding:
        lines += [
            "",
            "## Real-world incident grounding",
            "",
            "_Documented incidents that exploited these gap classes "
            "(source: emmanuelgjr/genai-incidents, CC-BY-4.0)._",
            "",
        ]
        for dim_id, ids in list(result.incident_grounding.items())[:top_gaps]:
            dim = DIMENSIONS.get(dim_id)
            label = dim.label if dim else dim_id
            lines.append(f"- **{label}**")
            for iid in ids:
                inc = get_incident(iid)
                if inc is None:
                    continue
                tag = "/".join(inc.owasp_llm[:2]) or inc.attack_vector or "—"
                lines.append(f"  - `{inc.id}` [{inc.severity}] {inc.title} ({tag})")

    return "\n".join(lines)


def _incidents_payload(key: str, limit: int = 5) -> dict:
    """Resolve a dimension id / article (artNN) / threat id to grounded incidents.

    Backs the `/ai-act-incidents` command. Tries article -> dimension -> threat
    so a single argument form covers all three lookup vocabularies.
    """
    key = key.strip()
    incidents = []
    resolved = None
    if key.lower().startswith("art"):
        incidents = incidents_for_article(key, limit)
        resolved = "article"
    if not incidents and key in DIMENSIONS:
        incidents = incidents_for_dimension(key, limit)
        resolved = "dimension"
    if not incidents:
        threat = incidents_for_threat(key, limit)
        if threat:
            incidents, resolved = threat, "threat"
    if not incidents:
        return {
            "key": key,
            "resolved_as": None,
            "incidents": [],
            "error": (
                f"No incidents found for '{key}'. Try a dimension id (e.g. security), "
                "an article (e.g. art15), or a threat category (e.g. prompt_injection)."
            ),
        }
    return {
        "key": key,
        "resolved_as": resolved,
        "count": len(incidents),
        "incidents": [inc.to_dict() for inc in incidents],
    }


def _filter_by_article(result, article: str) -> dict:
    """Return a dict containing only findings/scores relevant to one article."""
    dims = {d.id for d in dimensions_for_article(article)}
    if not dims:
        return {"error": f"Unknown article '{article}'. Try art9, art15, art50, etc."}

    return {
        "article": article,
        "is_ai_system": result.is_ai_system,
        "dimensions": sorted(dims),
        "compliance_scores": {k: v for k, v in result.compliance_scores.items() if k in dims},
        "components": [
            c.model_dump()
            for c in result.components
            if dims.intersection(c.compliance_dimensions)
        ],
        "evidence_map": {k: v for k, v in result.evidence_map.items() if k in dims},
    }


def _format_qa(result) -> str:
    """Render a grounded Q&A answer for human reading."""
    lines = [f"# {result.question}", "", result.answer, "", f"_Mode: {result.mode}_"]
    if result.citations:
        lines.append(f"_Citations: {', '.join(result.citations)}_")
    if result.dimensions:
        lines.append(f"_Compliance dimensions: {', '.join(result.dimensions)}_")
    if result.sources:
        lines += ["", "## Grounded sources", ""]
        for s in result.sources:
            lines.append(f"- **{s.ref}** ({s.title}): {s.excerpt}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eu-ai-act-scan",
        description="Scan a codebase for EU AI Act (Regulation 2024/1689) compliance evidence and gaps.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Emit full scan result as JSON (default format).",
    )
    parser.add_argument(
        "--markdown", "-m",
        action="store_true",
        help="Emit human-readable markdown summary instead of JSON.",
    )
    parser.add_argument(
        "--article", "-a",
        metavar="ARTN",
        help="Filter output to a single EU AI Act article (e.g. art9, art15, art50).",
    )
    parser.add_argument(
        "--name",
        metavar="NAME",
        help="Project display name (default: directory name).",
    )
    parser.add_argument(
        "--incidents", "-i",
        metavar="KEY",
        help=(
            "Surface real-world incidents for a dimension id (security), an "
            "article (art15), or a threat category (prompt_injection). Does not "
            "scan a codebase. Source: emmanuelgjr/genai-incidents (CC-BY-4.0)."
        ),
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        default=5,
        help="Max incidents to return for --incidents (default: 5).",
    )
    parser.add_argument(
        "--llm-status",
        action="store_true",
        help=(
            "Report the Claude Max LLM-bridge configuration and probe the "
            "wrapper's /health endpoint. Does not scan a codebase."
        ),
    )
    parser.add_argument(
        "--ask", "-q",
        metavar="QUESTION",
        help=(
            "Answer an EU AI Act question, grounded in the bundled knowledge base "
            "(verbatim statute text + obligation paraphrases + risk taxonomy). "
            "Offline + deterministic by default; uses the LLM bridge / assisted "
            "mode when available. Does not scan a codebase."
        ),
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=4,
        help="Max grounded sources to retrieve for --ask (default: 4).",
    )
    parser.add_argument(
        "--settings",
        action="store_true",
        help="Print the resolved scanner settings (mode, auto_apply, LLM bridge).",
    )
    parser.add_argument(
        "--set",
        metavar="KEY=VALUE",
        action="append",
        help=(
            "Persist a setting to .eu-ai-act-scanner.toml, e.g. "
            "--set mode=assisted --set auto-apply=true. Repeatable."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=("deterministic", "assisted"),
        help="Override the mode for this invocation (affects --ask synthesis).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args(argv)

    # Settings persistence — no codebase scan.
    if args.set:
        from scanner.settings import save_settings

        updates: dict[str, str] = {}
        for item in args.set:
            if "=" not in item:
                print(f"error: --set expects KEY=VALUE, got '{item}'", file=sys.stderr)
                return 2
            k, v = item.split("=", 1)
            updates[k.strip().lower().replace("-", "_")] = v.strip()
        unknown = set(updates) - {"mode", "auto_apply"}
        if unknown:
            print(f"error: unknown setting(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        try:
            saved_path, saved = save_settings(
                mode=updates.get("mode"), auto_apply=updates.get("auto_apply")
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({"saved_to": str(saved_path), "settings": saved.to_dict()},
                         indent=2, default=str))
        return 0

    # Settings view — no codebase scan.
    if args.settings:
        from scanner.settings import load_settings

        print(json.dumps(load_settings().to_dict(), indent=2, default=str))
        return 0

    # Grounded Q&A over the bundled knowledge base — no codebase scan.
    if args.ask:
        from scanner.qa import answer_question
        from scanner.settings import load_settings

        mode = args.mode or load_settings().mode
        use_llm = True if mode == "assisted" else None
        qa_result = answer_question(args.ask, top_k=max(1, args.top_k), use_llm=use_llm)
        if args.json:
            print(qa_result.model_dump_json(indent=2))
        else:
            print(_format_qa(qa_result))
        return 0

    # LLM-bridge diagnostics — config + live health probe, no codebase scan.
    if args.llm_status:
        from scanner.llm_bridge import bridge_config, bridge_health

        payload = {"config": bridge_config(), "health": bridge_health()}
        print(json.dumps(payload, indent=2, default=str))
        return 0 if payload["health"]["reachable"] else 1

    # Incident lookup is a corpus query — no codebase scan required.
    if args.incidents:
        payload = _incidents_payload(args.incidents, limit=max(1, args.limit))
        print(json.dumps(payload, indent=2, default=str))
        return 0 if payload.get("incidents") else 2

    path = Path(args.path)
    if not path.exists():
        print(f"error: path does not exist: {path}", file=sys.stderr)
        return 2

    try:
        result = scan_project(path, project_name=args.name)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.article:
        payload = _filter_by_article(result, args.article)
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    if args.markdown:
        print(_format_markdown(result))
        return 0

    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
