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
from typing import Literal

import structlog

# CLI mode: suppress info-level structlog output so stdout stays clean for
# the JSON/markdown payload. Library users can re-enable logs by calling
# structlog.configure() themselves.
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
    # stdout carries the JSON/markdown payload (and is what an agent reads);
    # a warning printed there would corrupt `--json` output.
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
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
    if sem:
        lines += [
            "",
            "## Semantic audit (Claude Code / Codex)",
            "",
            f"_{sem.get('summary', '')}_",
        ]
        if sem.get("error"):
            lines.append(f"- _Note_: {sem.get('error')}")
        if sem.get("findings"):
            lines.append("")
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

    tagged = getattr(result, "agentic_recommendations", None) or []
    if tagged:
        act = [r for r in tagged if r.source == "act_required"]
        paper = [r for r in tagged if r.source == "paper_suggested"]
        lines += [
            "",
            "## Agentic recommendation provenance",
            "",
            "_Compound-risk controls for the agentic risk axes detected in this "
            "scan. **Act-required** items cite the provision they implement; "
            "**paper-suggested** items are governance the working paper "
            "recommends beyond the Act._",
        ]
        if act:
            lines += ["", "### Required by the AI Act", ""]
            for r in act[:top_gaps]:
                lines.append(f"- **{r.risk_label}** — {r.text} _({r.ref})_")
        if paper:
            lines += ["", "### Suggested by the paper (not Act-required)", ""]
            for r in paper[:top_gaps]:
                lines.append(f"- **{r.risk_label}** — {r.text} _({r.ref})_")

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
    from scanner.incident_grounding import incidents_for_key

    key = key.strip()
    resolved, incidents = incidents_for_key(key, limit)
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
    from scanner.data.frameworks import get_crosswalk_for_article
    from scanner.refs import article_key

    # Accept every spelling the CLI is likely to receive: art15, "Art. 15",
    # "Article 15.4", 15 — the KB is keyed on artNN only.
    key = article_key(article)
    dims = {d.id for d in dimensions_for_article(key)} if key else set()
    if not dims:
        return {"error": f"Unknown article '{article}'. Try art9, art15, art50, etc."}

    frameworks = get_crosswalk_for_article(article)

    return {
        "article": article,
        "is_ai_system": result.is_ai_system,
        "dimensions": sorted(dims),
        "frameworks": {k: sorted(v) for k, v in frameworks.items()},
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


def _format_benchmark(report) -> str:
    """Render an offline deterministic benchmark summary as Markdown."""
    lines = [
        "# EU AI Act Scanner — Accuracy Benchmark",
        "",
        f"- **Corpus size**: {report.corpus_size} ({report.positive_samples} positive, {report.negative_samples} negative)",
        f"- **TP / FP / FN / TN**: {report.true_positives} / {report.false_positives} / {report.false_negatives} / {report.true_negatives}",
        f"- **Precision**: {report.precision:.4f}",
        f"- **Recall**: {report.recall:.4f}",
        f"- **F1**: {report.f1:.4f}",
        f"- **Reproducible**: {report.reproducible} (`{report.inputs_digest[:16]}...`)",
        "",
        "## Per-analyzer breakdown",
        "",
        "| Analyzer | TP | FP | FN | TN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report.per_analyzer:
        lines.append(
            f"| `{row.analyzer_id}` | {row.true_positives} | {row.false_positives} | "
            f"{row.false_negatives} | {row.true_negatives} | "
            f"{row.precision:.4f} | {row.recall:.4f} | {row.f1:.4f} |"
        )
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
        "--ask", "-q",
        metavar="QUESTION",
        help=(
            "Answer an EU AI Act question, grounded in the bundled knowledge base "
            "(verbatim statute text + obligation paraphrases + risk taxonomy). "
            "Offline + deterministic. Semantic narration lives in your host "
            "Claude Code session or MCP client. Does not scan a codebase."
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
        help="Print the resolved scanner settings (mode, auto_apply).",
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
        help="Override the mode for this invocation (accepted for compatibility).",
    )
    parser.add_argument(
        "--cross-framework", "-x",
        action="store_true",
        help="Project findings across 12 frameworks (SOC 2, ISO 27002/42001, NIST AI RMF, GDPR, OWASP, ...), each with its legal force.",
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
        help="Include a semantic-review pointer for your host Claude Code / MCP client.",
    )
    parser.add_argument(
        "--founder",
        action="store_true",
        help="Emit the plain-English 3-bucket Founder/Startup Triage brief (or JSON with --json).",
    )
    parser.add_argument(
        "--startup",
        action="store_true",
        help="Use startup priority profile with --fix (live Art. 50 + security blockers ahead of Dec 2027 Annex III docs).",
    )
    parser.add_argument(
        "--sarif",
        nargs="?",
        const="eu-ai-act.sarif.json",
        metavar="FILE",
        help="Export offline SARIF 2.1.0 report (default: eu-ai-act.sarif.json).",
    )
    parser.add_argument(
        "--ingest-sarif",
        action="append",
        metavar="FILE",
        help="Ingest external local SARIF 2.1.0 files (Semgrep, Bandit, Snyk, CodeQL, GHAS). Repeatable.",
    )
    parser.add_argument(
        "--ingest-compliance-api",
        action="append",
        metavar="FILE",
        help="Ingest local Anthropic Claude Compliance API export files (/v1/compliance/*). Repeatable.",
    )
    parser.add_argument(
        "--ingest-claude-security",
        action="append",
        metavar="FILE",
        help="Ingest local /claude-security or /security-review reports (JSONL, JSON, Markdown, or SARIF). Repeatable.",
    )
    parser.add_argument(
        "--save-baseline",
        nargs="?",
        const=".eu-ai-act-baseline.json",
        metavar="FILE",
        help="Save a local per-repo baseline snapshot (default: .eu-ai-act-baseline.json).",
    )
    parser.add_argument(
        "--diff-baseline",
        nargs="?",
        const=".eu-ai-act-baseline.json",
        metavar="FILE",
        help="Compare scan results against a saved local baseline (default: .eu-ai-act-baseline.json).",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run the offline deterministic analyzer precision/recall/F1 benchmark (no codebase scan).",
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
    apply_group = parser.add_mutually_exclusive_group()
    apply_group.add_argument(
        "--apply",
        action="store_true",
        help="Apply remediation patches to disk (dry-run preview by default).",
    )
    apply_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview remediation patches without writing (the default; explicit for scripts).",
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

    # Offline deterministic accuracy benchmark — no codebase scan.
    if args.benchmark:
        from scanner.benchmark import run_scanner_benchmark

        report = run_scanner_benchmark()
        if args.json:
            print(report.model_dump_json(indent=2))
        else:
            print(_format_benchmark(report))
        return 0

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

        qa_result = answer_question(args.ask, top_k=max(1, args.top_k))
        if args.json:
            print(qa_result.model_dump_json(indent=2))
        else:
            print(_format_qa(qa_result))
        return 0

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

        fix_profile: Literal["regulatory", "startup"] = (
            "startup" if args.startup else "regulatory"
        )
        fix_res = run_fix_loop(path, apply=args.apply, profile=fix_profile)
        if args.json:
            print(fix_res.model_dump_json(indent=2))
        else:
            lines = [
                f"# EU AI Act Remediation — {fix_res.project_name}",
                "",
                f"- **Profile**: {fix_profile}",
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

    if args.deep:
        # Kept as an accepted no-op so existing scripts keep working, but a
        # silent flag is worse than a notice: say where semantic review went.
        print(
            "note: --deep is deprecated and ignored — semantic review runs in "
            "your host Claude Code session (assisted mode) or any MCP client; "
            "the scan itself is always the full deterministic pass.",
            file=sys.stderr,
        )

    # Collect optional offline external findings (SARIF, Compliance API, Claude Security)
    external_findings = []
    external_sources: list[str] = []
    seen_sources: set[str] = set()

    def _add_source(label: str) -> None:
        if label and label not in seen_sources:
            seen_sources.add(label)
            external_sources.append(label)

    try:
        if args.ingest_sarif:
            from scanner.sarif import ingest_sarif_files

            sarif_findings, sarif_tools = ingest_sarif_files(args.ingest_sarif)
            external_findings.extend(sarif_findings)
            for tool_name in sarif_tools:
                _add_source(tool_name)

        if args.ingest_compliance_api:
            from scanner.claude_ecosystem import ingest_compliance_api_export

            cca_findings, cca_meta = ingest_compliance_api_export(args.ingest_compliance_api)
            external_findings.extend(cca_findings)
            _add_source(str(cca_meta.get("source") or "anthropic_claude_compliance_api"))

        if args.ingest_claude_security:
            from scanner.claude_ecosystem import ingest_claude_security_report

            cs_findings, cs_meta = ingest_claude_security_report(args.ingest_claude_security)
            external_findings.extend(cs_findings)
            for tool_name in cs_meta.get("source_tools") or ["claude-security"]:
                _add_source(str(tool_name))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        result = scan_project(
            path,
            project_name=args.name,
            role=args.role,
            deep=args.deep,
            cross_framework=args.cross_framework or args.founder,
            external_findings=external_findings or None,
            external_sources=external_sources or None,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Compute baseline diff BEFORE --save-baseline can overwrite the same file.
    baseline_diff = None
    if args.diff_baseline:
        from scanner.baseline import diff_baseline

        try:
            baseline_diff = diff_baseline(result, args.diff_baseline)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    # Artefact writers (dossier, graph, sarif, baseline) are additive: passing
    # several writes all of them. They suppress the default JSON dump only when
    # no other stdout output mode was requested.
    wrote_artefact = False
    has_stdout_mode = bool(
        args.json
        or args.markdown
        or args.article
        or args.cross_framework
        or args.founder
        or args.diff_baseline
    )

    # Cryptographic dossier generation
    if args.dossier:
        from scanner.dossier import generate_dossier
        dossier = generate_dossier(result, path)
        dossier_path = dossier.export_json(args.dossier)
        message = (
            f"Sealed cryptographic compliance dossier written to: {dossier_path} "
            f"(Integrity SHA-256: {dossier.dossier_integrity_hash[:16]}...)"
        )
        if has_stdout_mode:
            print(message, file=sys.stderr)
        else:
            print(message)
        wrote_artefact = True

    # Interactive context graph visual generation
    if args.graph:
        from scanner.visual_graph import generate_visual_graph
        graph_path = Path(args.graph)
        generate_visual_graph(result, output_path=graph_path, root_path=path)
        message = f"Interactive context graph visual written to: {graph_path}"
        if has_stdout_mode:
            print(message, file=sys.stderr)
        else:
            print(message)
        wrote_artefact = True

    # Offline SARIF 2.1.0 report export
    if args.sarif:
        from scanner.sarif import write_sarif
        sarif_path = write_sarif(result, args.sarif)
        message = f"SARIF 2.1.0 report written to: {sarif_path}"
        if has_stdout_mode:
            print(message, file=sys.stderr)
        else:
            print(message)
        wrote_artefact = True

    # Local per-repo baseline snapshot
    if args.save_baseline:
        from scanner.baseline import save_baseline
        baseline_path = save_baseline(result, args.save_baseline)
        message = f"Baseline snapshot saved to: {baseline_path}"
        if has_stdout_mode:
            print(message, file=sys.stderr)
        else:
            print(message)
        wrote_artefact = True

    if wrote_artefact and not has_stdout_mode:
        return 0

    if args.founder:
        from scanner.founder_triage import build_founder_triage, format_founder_brief

        triage = build_founder_triage(result)
        if args.json:
            if baseline_diff is not None:
                founder_payload = triage.model_dump()
                founder_payload["baseline_diff"] = baseline_diff
                print(json.dumps(founder_payload, indent=2, default=str))
            else:
                print(triage.model_dump_json(indent=2))
        else:
            brief = format_founder_brief(triage)
            if baseline_diff is not None:
                from scanner.baseline import format_baseline_diff

                brief += "\n\n" + format_baseline_diff(baseline_diff)
            print(brief)
        return 0

    if baseline_diff is not None:
        from scanner.baseline import format_baseline_diff

        if args.json:
            print(json.dumps(baseline_diff, indent=2, default=str))
        else:
            print(format_baseline_diff(baseline_diff))
        return 0

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
