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
from scanner.data.role_obligations import CANONICAL_ROLE_IDS  # noqa: E402
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
    ]
    if getattr(result, "active_role", None):
        lines.append(f"- **Active operator role**: **{result.active_role}**")
    scope = getattr(result, "role_scope", None)
    if scope:
        lines.append(
            f"- **Role-scoped obligations ({scope['source']})**: "
            + ", ".join(scope["articles"])
        )
        if scope["out_of_scope_dimensions"]:
            lines.append(
                "- **Dimensions owed only by other roles**: "
                + ", ".join(scope["out_of_scope_dimensions"])
            )
    lines += [
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

    if getattr(result, "cross_framework_summary", None):
        lines += [
            "",
            "## Cross-framework readiness",
            "",
            "| Target Framework | Multi-Framework Coverage |",
            "|---|---|",
        ]
        for fw_name, cov in sorted(result.cross_framework_summary.items(), key=lambda x: -x[1]):
            lines.append(f"| **{fw_name}** | **{cov:.1f}%** |")

    sem = getattr(result, "semantic_audit", None)
    if sem and sem.get("findings"):
        lines += [
            "",
            "## Semantic audit (Claude Code / Codex)",
            "",
            f"_{sem.get('summary', '')}_",
            "",
        ]
        for f in sem.get("findings", [])[:top_gaps]:
            sev = f.get("severity", "high").upper()
            lines.append(f"- **[{sev}] {f.get('title')}** ({f.get('article')}) in `{f.get('file_path')}`")
            if f.get("description"):
                lines.append(f"  {f.get('description')}")
            if f.get("remediation_advice"):
                lines.append(f"  _Remediation:_ {f.get('remediation_advice')}")
        if sem.get("cleared_false_positives"):
            lines += ["", "### Cleared static false positives:"]
            for fp in sem["cleared_false_positives"]:
                lines.append(f"- `{fp}` (semantic analysis verified existing controls)")

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
        "--cross-framework", "-x",
        action="store_true",
        help="Project findings across NIST AI RMF, ISO 42001, GDPR, OWASP LLM/Agentic, SOC 2.",
    )
    parser.add_argument(
        "--role",
        choices=CANONICAL_ROLE_IDS,
        help="Explicitly evaluate codebase under a specific EU AI Act operator role.",
    )
    parser.add_argument(
        "--deep", "--extensive",
        dest="deep",
        action="store_true",
        help="Perform extensive semantic audit via Claude Code or Codex bridge.",
    )
    parser.add_argument(
        "--dossier",
        nargs="?",
        const="compliance-dossier.json",
        metavar="FILE",
        help="Generate a cryptographic, tamper-evident compliance release dossier (default: compliance-dossier.json).",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Run the autonomous scan-fix remediation pipeline.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply remediation patches to disk (dry-run preview by default).",
    )
    parser.add_argument(
        "--graph",
        nargs="?",
        const="context-graph.html",
        metavar="FILE",
        help="Generate an interactive context graph visual with node-by-node gaps and recommended fixes (default: context-graph.html).",
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

    # Remediation pipeline execution
    if args.fix:
        from scanner.fix_loop import run_fix_loop
        fix_res = run_fix_loop(path, apply=args.apply)
        if args.json:
            print(fix_res.model_dump_json(indent=2))
        else:
            lines = [
                f"# EU AI Act Remediation — {fix_res.project_name}",
                "",
                f"- **Iterations**: {fix_res.iterations}",
                f"- **Baseline overall**: {fix_res.baseline_overall:.1f}%",
                f"- **Final overall**: {fix_res.final_overall:.1f}% (+{fix_res.overall_delta:.1f}%)",
                f"- **Fixes applied**: {len(fix_res.applied)}",
                f"- **Regressions avoided**: {len(fix_res.skipped_regressions)}",
                "",
                "## Proposals",
                "",
            ]
            for p in fix_res.proposals:
                lines.append(f"- **[{p.fix_kind.upper()}] {p.title}** (`{p.target_path}` for {p.dimension} / {p.article})")
                lines.append(f"  {p.rationale}")
            print("\n".join(lines))
        return 0

    try:
        result = scan_project(
            path,
            project_name=args.name,
            role=args.role,
            deep=args.deep,
            cross_framework=args.cross_framework,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Cryptographic dossier generation
    if args.dossier:
        from scanner.dossier import generate_dossier
        dossier = generate_dossier(result, path)
        dossier_path = dossier.export_json(args.dossier)
        if not args.json and not args.markdown:
            print(
                f"Sealed cryptographic compliance dossier written to: {dossier_path} "
                f"(Integrity SHA-256: {dossier.dossier_integrity_hash[:16]}...)"
            )
            return 0
        else:
            print(
                f"Sealed cryptographic compliance dossier written to: {dossier_path} "
                f"(Integrity SHA-256: {dossier.dossier_integrity_hash[:16]}...)",
                file=sys.stderr,
            )

    # Interactive context graph visual generation
    if args.graph:
        from scanner.visual_graph import generate_visual_graph
        graph_path = Path(args.graph)
        generate_visual_graph(result, output_path=graph_path, root_path=path)
        if not args.json and not args.markdown:
            print(f"Interactive context graph visual written to: {graph_path}")
            return 0
        else:
            print(f"Interactive context graph visual written to: {graph_path}", file=sys.stderr)

    if args.article:
        payload = _filter_by_article(result, args.article)
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0

    if args.markdown:
        md = _format_markdown(result)
        if args.cross_framework and result.is_ai_system:
            from scanner.cross_framework import project_scan_to_frameworks
            cross_proj = project_scan_to_frameworks(result)
            md += "\n\n" + cross_proj.format_markdown()
        print(md)
        return 0

    if args.cross_framework and result.is_ai_system:
        from scanner.cross_framework import project_scan_to_frameworks
        cross_proj = project_scan_to_frameworks(result)
        out = result.model_dump()
        out["cross_framework_projection"] = cross_proj.model_dump()
        print(json.dumps(out, indent=2, default=str))
        return 0

    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
