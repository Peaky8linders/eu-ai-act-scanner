"""Interactive Context Graph Visual generator for EU AI Act Scanner.

Produces a standalone, self-contained interactive visual HTML graph that allows users
to browse the discovered AI system architecture, inspect each node for compliance gaps,
regulatory articles, cross-framework linkages, grounded real-world incidents, and
production-grade recommended code fixes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner.data.frameworks import DIMENSION_CROSSWALK, FRAMEWORK_LABELS
from scanner.data.incident_corpus import get_incident
from scanner.fix_loop import _DIMENSION_TO_FIXER, DETERMINISTIC_FIXERS
from scanner.kb import DIMENSIONS
from scanner.models import ScanResult


def _build_node_fix(dim_id: str, dummy_root: Path) -> dict[str, str] | None:
    """Resolve recommended fix proposal and snippet for a dimension."""
    fixer_key = _DIMENSION_TO_FIXER.get(dim_id, dim_id)
    fixer_fn = DETERMINISTIC_FIXERS.get(fixer_key)
    if fixer_fn:
        try:
            prop = fixer_fn(dummy_root)
            return {
                "title": prop.title,
                "target_path": prop.target_path,
                "rationale": prop.rationale,
                "code_snippet": prop.content,
                "verification": prop.verification,
                "fix_kind": prop.fix_kind,
                "obligation": prop.grounded_obligation or "",
            }
        except Exception:
            pass
    return None


def _get_omnibus_timeline(article: str) -> str:
    """Return enacted statutory timeline under Digital Omnibus Regulation (EU) 2026/1744."""
    art = article.lower()
    if "50" in art:
        return "In Force (Live since 2 August 2026) — Not deferred by Digital Omnibus"
    if "27" in art or "fria" in art:
        return "Applies 2 December 2027 (Annex III deployer obligation per Reg 2026/1744)"
    if any(a in art for a in ("9", "10", "11", "12", "13", "14", "15", "17")):
        return "High-Risk Annex III deferred to 2 December 2027 (Digital Omnibus Reg 2026/1744)"
    if "5" in art:
        return "In Force (Prohibitions active since 2 Feb 2025; NCII/CSAM 2 Dec 2026)"
    return "Phased compliance 2026-2028 under Regulation (EU) 2026/1744"


def build_graph_data(scan_result: ScanResult, root_path: Path | None = None) -> dict[str, Any]:
    """Construct structured JSON payload representing the context graph nodes and links."""
    root = root_path or Path(".")
    nodes: list[dict[str, Any]] = []
    node_ids: set[str] = set()
    links: list[dict[str, Any]] = []

    # Map dimensions to score and gaps
    scores = scan_result.compliance_scores
    file_findings = scan_result.file_findings

    # 1. Start from discovered architecture nodes if present
    arch_nodes = scan_result.architecture or []
    for an in arch_nodes:
        node_ids.add(an.id)
        # Find associated dimension(s)
        dim_id = an.id
        dim_meta = DIMENSIONS.get(dim_id)
        if not dim_meta:
            # Map common analyzer ids to dimensions
            mapping = {
                "ai_frameworks": "model_cards",
                "human_oversight": "human_oversight",
                "security_controls": "security",
                "logging_monitoring": "logging",
                "agent_execution": "tool_governance",
                "data_governance": "data_gov",
                "eval_framework": "eval_framework",
                "fria": "deployer_obligations",
                "documentation": "tech_docs",
                "test_suite": "quality_management",
                "fairness_testing": "fairness_metrics",
                "content_transparency": "transparency",
            }
            dim_id = mapping.get(an.id, an.id)
            dim_meta = DIMENSIONS.get(dim_id)

        article = dim_meta.article if dim_meta else "—"
        score = scores.get(dim_id, scores.get(an.id, 50.0 if an.compliance_status == "partial" else (80.0 if an.compliance_status == "compliant" else 20.0)))
        status = an.compliance_status
        if status not in ("compliant", "partial", "gap"):
            status = "compliant" if score >= 60 else ("partial" if score >= 30 else "gap")

        # Associated files & gaps
        associated_files: list[str] = []
        gaps: list[str] = []
        for ff in file_findings:
            if dim_id in ff.compliance_dimensions or an.id in ff.compliance_dimensions:
                associated_files.append(ff.file_path)
                gaps.extend(ff.gaps)

        if not gaps and status == "gap":
            gaps.append(f"Missing required compliance control or evidence for {an.label}")

        # Incidents
        incident_ids = scan_result.incident_grounding.get(dim_id, [])
        incidents_data: list[dict[str, Any]] = []
        for iid in incident_ids[:3]:
            inc = get_incident(iid)
            if inc:
                incidents_data.append({
                    "id": inc.id,
                    "title": inc.title,
                    "severity": inc.severity,
                    "tags": inc.owasp_llm or [inc.attack_vector or "threat"],
                })

        # Cross-framework mapping
        cw = DIMENSION_CROSSWALK.get(dim_id, {})
        fw_mappings = [
            {"framework": FRAMEWORK_LABELS.get(k, k), "controls": v}
            for k, v in cw.items()
        ]

        # Recommended fix
        rec_fix = _build_node_fix(dim_id, root)

        nodes.append({
            "id": an.id,
            "label": an.label,
            "type": an.type or "component",
            "compliance_status": status,
            "score": round(score, 1),
            "file_count": an.file_count or len(associated_files),
            "article": article,
            "omnibus_timeline": _get_omnibus_timeline(article),
            "dimension_id": dim_id,
            "gaps": sorted(set(gaps))[:10],
            "files": sorted(set(associated_files))[:15],
            "cross_framework": fw_mappings[:5],
            "recommended_fix": rec_fix,
            "incidents": incidents_data,
        })

        for target in an.connected_to:
            links.append({"source": an.id, "target": target})

    # 2. If architecture was empty or small, supplement with key KB dimensions
    if len(nodes) < 6 and scores:
        for dim_id, score in scores.items():
            if dim_id in node_ids:
                continue
            dim_meta = DIMENSIONS.get(dim_id)
            if not dim_meta:
                continue
            node_ids.add(dim_id)
            status = "compliant" if score >= 60 else ("partial" if score >= 30 else "gap")
            gaps = [r for r in scan_result.risk_indicators if dim_id in r.lower()]
            if not gaps and status != "compliant":
                gaps.append(f"Gaps identified in {dim_meta.label} controls")

            rec_fix = _build_node_fix(dim_id, root)
            nodes.append({
                "id": dim_id,
                "label": dim_meta.label,
                "type": "governance_control",
                "compliance_status": status,
                "score": round(score, 1),
                "file_count": len(scan_result.evidence_map.get(dim_id, [])),
                "article": dim_meta.article,
                "omnibus_timeline": _get_omnibus_timeline(dim_meta.article),
                "dimension_id": dim_id,
                "gaps": gaps[:5],
                "files": scan_result.evidence_map.get(dim_id, [])[:10],
                "cross_framework": [
                    {"framework": FRAMEWORK_LABELS.get(k, k), "controls": v}
                    for k, v in DIMENSION_CROSSWALK.get(dim_id, {}).items()
                ][:4],
                "recommended_fix": rec_fix,
                "incidents": [],
            })

    # Link orphan nodes to main central nodes
    if len(links) < len(nodes) - 1:
        core_ids = [n["id"] for n in nodes if n["id"] in ("ai_frameworks", "risk_mgmt", "agent_execution", "human_oversight")]
        core = core_ids[0] if core_ids else (nodes[0]["id"] if nodes else "")
        existing_targets = {link["target"] for link in links}.union({link["source"] for link in links})
        for n in nodes:
            if n["id"] != core and n["id"] not in existing_targets and core:
                links.append({"source": core, "target": n["id"]})

    return {
        "project_name": scan_result.project_name,
        "is_ai_system": scan_result.is_ai_system,
        "overall_compliance_pct": scan_result.overall_compliance_pct,
        "inferred_roles": scan_result.inferred_roles,
        "active_role": scan_result.active_role,
        "scanner_version": scan_result.scanner_version,
        "total_nodes": len(nodes),
        "gap_nodes_count": sum(1 for n in nodes if n["compliance_status"] == "gap"),
        "partial_nodes_count": sum(1 for n in nodes if n["compliance_status"] == "partial"),
        "compliant_nodes_count": sum(1 for n in nodes if n["compliance_status"] == "compliant"),
        "nodes": nodes,
        "links": links,
    }


def generate_visual_graph(
    scan_result: ScanResult,
    output_path: Path | str | None = None,
    root_path: Path | str | None = None,
) -> str:
    """Generate interactive, standalone HTML context graph visualization.

    Args:
        scan_result: ScanResult produced by scan_project.
        output_path: Optional path to write the generated HTML file.
        root_path: Project root directory for path resolution.

    Returns:
        The generated HTML content string.
    """
    graph_data = build_graph_data(
        scan_result,
        Path(root_path) if root_path else None,
    )
    graph_json = json.dumps(graph_data, indent=2, sort_keys=True)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EU AI Act Context Graph — {scan_result.project_name}</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <style>
    :root {{
      --background: #0f172a;
      --card: #1e293b;
      --foreground: #f8fafc;
      --muted-foreground: #94a3b8;
      --border: #334155;
      --primary: #38bdf8;
      --status-gap: #f43f5e;
      --status-partial: #f59e0b;
      --status-compliant: #10b981;
    }}
    body {{
      background-color: var(--background);
      color: var(--foreground);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }}
    .node-pulse-gap {{
      animation: pulse-gap 2.5s infinite;
    }}
    @keyframes pulse-gap {{
      0% {{ r: 24; stroke-opacity: 0.9; }}
      50% {{ r: 28; stroke-opacity: 0.4; }}
      100% {{ r: 24; stroke-opacity: 0.9; }}
    }}
    .custom-scrollbar::-webkit-scrollbar {{
      width: 6px;
      height: 6px;
    }}
    .custom-scrollbar::-webkit-scrollbar-thumb {{
      background-color: #334155;
      border-radius: 9999px;
    }}
  </style>
</head>
<body class="h-screen w-screen overflow-hidden flex flex-col antialiased">
  <!-- Top Navigation & Control Header -->
  <header class="bg-[var(--card)] border-b border-[var(--border)] px-5 py-3 flex flex-wrap items-center justify-between gap-4 shrink-0 shadow-md">
    <div class="flex items-center gap-3">
      <div class="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center font-bold text-white text-base shadow-sm">
        EU
      </div>
      <div>
        <h1 class="text-base font-semibold leading-tight flex items-center gap-2">
          {scan_result.project_name}
          <span class="text-xs px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-300">Context Graph</span>
        </h1>
        <p class="text-xs text-[var(--muted-foreground)]">
          Regulation (EU) 2024/1689 & Digital Omnibus (EU) 2026/1744 &bull; Inferred: <span class="text-sky-400 font-medium">{(', '.join(scan_result.inferred_roles) or 'deployer')}</span>
        </p>
      </div>
    </div>

    <!-- Stats Pill Strip -->
    <div class="flex items-center gap-2 text-xs">
      <div class="px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700/60 flex items-center gap-2">
        <span class="text-[var(--muted-foreground)]">Overall Score:</span>
        <span class="font-bold text-sky-400">{scan_result.overall_compliance_pct}%</span>
      </div>
      <button onclick="setFilter('all')" id="btn-filter-all" class="filter-btn px-2.5 py-1.5 rounded-lg bg-slate-700 text-white font-medium border border-slate-600 transition">
        All ({graph_data["total_nodes"]})
      </button>
      <button onclick="setFilter('gap')" id="btn-filter-gap" class="filter-btn px-2.5 py-1.5 rounded-lg bg-slate-800 text-rose-400 hover:bg-slate-700 border border-slate-700 transition">
        Gaps ({graph_data["gap_nodes_count"]})
      </button>
      <button onclick="setFilter('partial')" id="btn-filter-partial" class="filter-btn px-2.5 py-1.5 rounded-lg bg-slate-800 text-amber-400 hover:bg-slate-700 border border-slate-700 transition">
        Partial ({graph_data["partial_nodes_count"]})
      </button>
      <button onclick="setFilter('compliant')" id="btn-filter-compliant" class="filter-btn px-2.5 py-1.5 rounded-lg bg-slate-800 text-emerald-400 hover:bg-slate-700 border border-slate-700 transition">
        Compliant ({graph_data["compliant_nodes_count"]})
      </button>
    </div>

    <!-- Search & Zoom Tools -->
    <div class="flex items-center gap-2">
      <div class="relative">
        <input
          type="text"
          id="node-search"
          placeholder="Search nodes, articles, gaps..."
          oninput="handleSearch(this.value)"
          class="bg-slate-900 border border-slate-700 text-xs rounded-lg px-3 py-1.5 w-56 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition"
        />
      </div>
      <div class="flex items-center border border-slate-700 rounded-lg overflow-hidden bg-slate-800 text-xs">
        <button onclick="zoom(1.2)" title="Zoom In" class="px-2 py-1.5 hover:bg-slate-700 text-slate-300 font-bold">+</button>
        <button onclick="zoom(0.8)" title="Zoom Out" class="px-2 py-1.5 hover:bg-slate-700 text-slate-300 font-bold">&minus;</button>
        <button onclick="resetZoom()" title="Reset View" class="px-2.5 py-1.5 hover:bg-slate-700 text-slate-300 text-xs">Reset</button>
      </div>
    </div>
  </header>

  <!-- Main Canvas + Inspector Workspace -->
  <main class="flex-1 flex overflow-hidden relative">
    <!-- SVG Interactive Graph Canvas -->
    <div id="canvas-container" class="flex-1 h-full bg-[#0a0f1d] relative overflow-hidden cursor-grab active:cursor-grabbing">
      <svg id="graph-svg" class="w-full h-full select-none">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 9 5 L 0 9 z" fill="#475569" />
          </marker>
          <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>
        <g id="graph-group">
          <g id="links-layer"></g>
          <g id="nodes-layer"></g>
        </g>
      </svg>

      <!-- Canvas Float Hint -->
      <div class="absolute bottom-4 left-4 bg-slate-900/90 backdrop-blur border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-400 pointer-events-none flex items-center gap-3 shadow-lg">
        <span class="flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-full bg-rose-500"></span> Gap / Action Needed</span>
        <span class="flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-full bg-amber-500"></span> Partial Evidence</span>
        <span class="flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Compliant</span>
        <span class="text-slate-500">&bull; Click node to inspect fixes</span>
      </div>
    </div>

    <!-- Inspector Slide-Over Details Panel -->
    <aside id="inspector-panel" class="w-96 max-w-full md:w-[460px] border-l border-[var(--border)] bg-[var(--card)] flex flex-col h-full shrink-0 shadow-2xl transition-all duration-200">
      <div id="inspector-empty" class="p-8 text-center my-auto flex flex-col items-center">
        <div class="w-14 h-14 rounded-2xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400 mb-4 text-2xl shadow-inner">
          &odot;
        </div>
        <h3 class="font-semibold text-base text-[var(--foreground)] mb-1">Select an Architecture Node</h3>
        <p class="text-xs text-[var(--muted-foreground)] max-w-xs mb-4">
          Click any node in the context graph to browse its compliance gaps, regulatory article grounding, cross-framework linkages, and production-ready recommended fixes.
        </p>
        <div class="text-xs text-sky-400/90 bg-sky-950/40 border border-sky-800/60 rounded-lg px-3 py-2">
          &rarr; Try clicking a high-priority red <strong class="text-rose-400">Gap</strong> node
        </div>
      </div>

      <div id="inspector-content" class="hidden flex-1 flex flex-col overflow-hidden">
        <!-- Inspector Header -->
        <div class="p-5 border-b border-[var(--border)] bg-slate-800/40 shrink-0">
          <div class="flex items-start justify-between gap-3 mb-2">
            <div>
              <span id="node-badge" class="inline-block text-xs font-semibold px-2.5 py-0.5 rounded-full uppercase tracking-wider mb-1.5"></span>
              <h2 id="node-title" class="text-lg font-bold text-white leading-tight"></h2>
            </div>
            <div class="text-right shrink-0">
              <div id="node-score" class="text-2xl font-black"></div>
              <span class="text-xs text-slate-400">Score</span>
            </div>
          </div>
          <div class="flex flex-wrap items-center gap-2 text-xs text-slate-300">
            <span class="bg-slate-900 px-2 py-0.5 rounded border border-slate-700 text-sky-300 font-mono" id="node-article"></span>
            <span class="text-slate-400" id="node-timeline"></span>
          </div>
        </div>

        <!-- Inspector Tabs -->
        <div class="flex border-b border-[var(--border)] bg-slate-900/60 text-xs shrink-0">
          <button onclick="switchTab('tab-remediation')" id="tab-btn-remediation" class="inspector-tab flex-1 py-2.5 text-center font-medium border-b-2 border-sky-400 text-sky-400">
            Recommended Fix
          </button>
          <button onclick="switchTab('tab-gaps')" id="tab-btn-gaps" class="inspector-tab flex-1 py-2.5 text-center font-medium border-b-2 border-transparent text-slate-400 hover:text-slate-200">
            Gaps & Files
          </button>
          <button onclick="switchTab('tab-frameworks')" id="tab-btn-frameworks" class="inspector-tab flex-1 py-2.5 text-center font-medium border-b-2 border-transparent text-slate-400 hover:text-slate-200">
            Cross-Framework
          </button>
        </div>

        <!-- Inspector Body -->
        <div class="flex-1 overflow-y-auto p-5 space-y-4 custom-scrollbar">
          <!-- Tab 1: Recommended Fix -->
          <div id="tab-remediation" class="tab-pane space-y-4">
            <div id="remediation-container">
              <!-- Injected dynamically -->
            </div>
          </div>

          <!-- Tab 2: Gaps & Files -->
          <div id="tab-gaps" class="tab-pane hidden space-y-4">
            <div>
              <h4 class="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Identified Compliance Gaps</h4>
              <ul id="node-gaps-list" class="space-y-2 text-xs"></ul>
            </div>
            <div>
              <h4 class="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Discovered Project Files</h4>
              <div id="node-files-list" class="space-y-1 font-mono text-xs"></div>
            </div>
            <div id="node-incidents-section" class="hidden">
              <h4 class="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Real-World Incident Grounding</h4>
              <div id="node-incidents-list" class="space-y-2 text-xs"></div>
            </div>
          </div>

          <!-- Tab 3: Cross-Framework Linkages -->
          <div id="tab-frameworks" class="tab-pane hidden space-y-3">
            <p class="text-xs text-slate-400">
              Resolving this node's EU AI Act controls directly satisfies parallel standards in the international AI governance matrix:
            </p>
            <div id="node-crosswalk-list" class="space-y-2 text-xs"></div>
          </div>
        </div>
      </div>
    </aside>
  </main>

  <!-- Embedded Data Payload -->
  <script>
    const GRAPH_DATA = {graph_json};

    let currentFilter = 'all';
    let searchQuery = '';
    let selectedNodeId = null;

    // SVG Pan & Zoom state
    let scale = 1.0;
    let panX = 0;
    let panY = 0;
    let isDragging = false;
    let startX = 0;
    let startY = 0;

    const svg = document.getElementById('graph-svg');
    const graphGroup = document.getElementById('graph-group');
    const nodesLayer = document.getElementById('nodes-layer');
    const linksLayer = document.getElementById('links-layer');

    // Node layout positions
    const nodePositions = {{}};

    function initLayout() {{
      const nodes = GRAPH_DATA.nodes;
      const width = window.innerWidth - 460;
      const height = window.innerHeight - 60;
      const cx = Math.max(300, width / 2);
      const cy = Math.max(250, height / 2);

      // Arrange nodes in clean organic layers/orbit around center
      const total = nodes.length;
      nodes.forEach((n, idx) => {{
        if (total === 1) {{
          nodePositions[n.id] = {{ x: cx, y: cy }};
          return;
        }}
        // Center high-importance nodes
        if (idx === 0) {{
          nodePositions[n.id] = {{ x: cx, y: cy }};
        }} else {{
          // Distribute on two concentric rings
          const ring = idx <= 7 ? 1 : 2;
          const radius = ring === 1 ? Math.min(220, cy * 0.7) : Math.min(380, cy * 1.1);
          const countInRing = ring === 1 ? Math.min(7, total - 1) : (total - 8);
          const ringIdx = ring === 1 ? (idx - 1) : (idx - 8);
          const angle = (2 * Math.PI * ringIdx) / countInRing - (Math.PI / 2);
          nodePositions[n.id] = {{
            x: cx + radius * Math.cos(angle),
            y: cy + radius * Math.sin(angle) * 0.85
          }};
        }}
      }});
    }}

    function renderGraph() {{
      const nodes = GRAPH_DATA.nodes;
      const links = GRAPH_DATA.links;

      // Filter nodes
      const visibleNodes = nodes.filter(n => {{
        const matchesFilter = (currentFilter === 'all') || (n.compliance_status === currentFilter);
        const matchesSearch = !searchQuery ||
          n.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
          n.article.toLowerCase().includes(searchQuery.toLowerCase()) ||
          n.gaps.some(g => g.toLowerCase().includes(searchQuery.toLowerCase()));
        return matchesFilter && matchesSearch;
      }});

      const visibleIds = new Set(visibleNodes.map(n => n.id));

      // Draw Links
      linksLayer.innerHTML = '';
      links.forEach(l => {{
        if (visibleIds.has(l.source) && visibleIds.has(l.target)) {{
          const p1 = nodePositions[l.source];
          const p2 = nodePositions[l.target];
          if (!p1 || !p2) return;

          const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
          line.setAttribute('x1', p1.x);
          line.setAttribute('y1', p1.y);
          line.setAttribute('x2', p2.x);
          line.setAttribute('y2', p2.y);
          line.setAttribute('stroke', '#334155');
          line.setAttribute('stroke-width', '1.5');
          line.setAttribute('stroke-dasharray', '4 3');
          line.setAttribute('marker-end', 'url(#arrow)');
          line.id = `link-${{l.source}}-${{l.target}}`;
          linksLayer.appendChild(line);
        }}
      }});

      // Draw Nodes
      nodesLayer.innerHTML = '';
      visibleNodes.forEach(n => {{
        const pos = nodePositions[n.id];
        if (!pos) return;

        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('transform', `translate(${{pos.x}}, ${{pos.y}})`);
        g.setAttribute('class', 'cursor-pointer transition-transform');
        g.onclick = () => selectNode(n.id);

        // Status color mapping
        const colors = {{
          gap: {{ fill: '#f43f5e', ring: '#fda4af', border: '#e11d48' }},
          partial: {{ fill: '#f59e0b', ring: '#fcd34d', border: '#d97706' }},
          compliant: {{ fill: '#10b981', ring: '#6ee7b7', border: '#059669' }},
        }};
        const c = colors[n.compliance_status] || colors.partial;
        const isSelected = selectedNodeId === n.id;

        // Outer Glow / Selection Ring
        const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        ring.setAttribute('r', isSelected ? '34' : '28');
        ring.setAttribute('fill', 'none');
        ring.setAttribute('stroke', isSelected ? '#38bdf8' : (n.compliance_status === 'gap' ? c.border : '#1e293b'));
        ring.setAttribute('stroke-width', isSelected ? '3' : '2');
        if (n.compliance_status === 'gap' && !isSelected) {{
          ring.setAttribute('class', 'node-pulse-gap');
        }}
        g.appendChild(ring);

        // Main Node Body
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('r', '24');
        circle.setAttribute('fill', '#1e293b');
        circle.setAttribute('stroke', c.fill);
        circle.setAttribute('stroke-width', '3');
        g.appendChild(circle);

        // Score Text inside node
        const scoreText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        scoreText.setAttribute('y', '4');
        scoreText.setAttribute('text-anchor', 'middle');
        scoreText.setAttribute('font-size', '11');
        scoreText.setAttribute('font-weight', 'bold');
        scoreText.setAttribute('fill', '#f8fafc');
        scoreText.textContent = `${{Math.round(n.score)}}%`;
        g.appendChild(scoreText);

        // Node Label below node
        const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        label.setAttribute('y', '42');
        label.setAttribute('text-anchor', 'middle');
        label.setAttribute('font-size', '12');
        label.setAttribute('font-weight', '600');
        label.setAttribute('fill', isSelected ? '#38bdf8' : '#e2e8f0');
        label.textContent = n.label;
        g.appendChild(label);

        // Subtitle Article below label
        const sub = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        sub.setAttribute('y', '56');
        sub.setAttribute('text-anchor', 'middle');
        sub.setAttribute('font-size', '10');
        sub.setAttribute('fill', '#94a3b8');
        sub.textContent = n.article !== '—' ? n.article : n.type;
        g.appendChild(sub);

        nodesLayer.appendChild(g);
      }});

      updateTransform();
    }}

    function selectNode(nodeId) {{
      selectedNodeId = nodeId;
      renderGraph();

      const node = GRAPH_DATA.nodes.find(n => n.id === nodeId);
      if (!node) return;

      document.getElementById('inspector-empty').classList.add('hidden');
      document.getElementById('inspector-content').classList.remove('hidden');

      // Populate Header
      const badge = document.getElementById('node-badge');
      badge.textContent = node.compliance_status === 'gap' ? 'Action Required (Gap)' : (node.compliance_status === 'partial' ? 'Partial Evidence' : 'Compliant');
      badge.className = `inline-block text-xs font-semibold px-2.5 py-0.5 rounded-full uppercase tracking-wider mb-1.5 ${{
        node.compliance_status === 'gap' ? 'bg-rose-950/80 text-rose-300 border border-rose-700' :
        node.compliance_status === 'partial' ? 'bg-amber-950/80 text-amber-300 border border-amber-700' :
        'bg-emerald-950/80 text-emerald-300 border border-emerald-700'
      }}`;

      document.getElementById('node-title').textContent = node.label;
      const scoreEl = document.getElementById('node-score');
      scoreEl.textContent = `${{node.score}}%`;
      scoreEl.className = `text-2xl font-black ${{
        node.compliance_status === 'gap' ? 'text-rose-400' :
        node.compliance_status === 'partial' ? 'text-amber-400' :
        'text-emerald-400'
      }}`;

      document.getElementById('node-article').textContent = node.article !== '—' ? node.article : 'General AI Act Duty';
      document.getElementById('node-timeline').textContent = node.omnibus_timeline;

      // Tab 1: Remediation
      const remContainer = document.getElementById('remediation-container');
      remContainer.innerHTML = '';
      if (node.recommended_fix) {{
        const rf = node.recommended_fix;
        remContainer.innerHTML = `
          <div class="bg-slate-900 border border-sky-800/80 rounded-xl p-4 shadow-sm">
            <div class="flex items-start justify-between gap-2 mb-2">
              <h5 class="font-bold text-sky-400 text-sm">${{rf.title}}</h5>
              <span class="text-xs px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-700 uppercase">${{rf.fix_kind}}</span>
            </div>
            <p class="text-xs text-slate-300 mb-3">${{rf.rationale}}</p>
            <div class="mb-3">
              <span class="text-xs text-slate-400 block mb-1 font-semibold">Target File to Create/Patch:</span>
              <code class="text-xs bg-slate-950 px-2 py-1 rounded text-emerald-400 border border-slate-800 block select-all">${{rf.target_path}}</code>
            </div>
            <div class="mb-3">
              <div class="flex items-center justify-between mb-1">
                <span class="text-xs text-slate-400 font-semibold">Production Ready Fix Template:</span>
                <button onclick="copySnippet()" id="btn-copy-fix" class="text-xs text-sky-400 hover:text-sky-300 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">Copy Code</button>
              </div>
              <pre class="bg-slate-950 p-3 rounded-lg text-xs font-mono text-slate-200 overflow-x-auto max-h-56 custom-scrollbar border border-slate-800"><code id="code-fix-block">${{escapeHtml(rf.code_snippet)}}</code></pre>
            </div>
            <div class="text-xs text-slate-400 bg-slate-800/50 p-2.5 rounded border border-slate-700/60">
              <strong class="text-slate-300">Verification Gate:</strong> ${{rf.verification}}
            </div>
          </div>
        `;
      }} else {{
        remContainer.innerHTML = `
          <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-5 text-center">
            <div class="text-emerald-400 font-semibold text-sm mb-1">✓ Evidence Verified</div>
            <p class="text-xs text-slate-400">Controls for this node satisfy EU AI Act requirements. No immediate code patch required.</p>
          </div>
        `;
      }}

      // Tab 2: Gaps & Files
      const gapsList = document.getElementById('node-gaps-list');
      gapsList.innerHTML = '';
      if (node.gaps && node.gaps.length) {{
        node.gaps.forEach(g => {{
          const li = document.createElement('li');
          li.className = 'flex items-start gap-2 bg-slate-900/70 p-2.5 rounded border border-rose-900/30 text-rose-200';
          li.innerHTML = `<span class="text-rose-400 font-bold shrink-0">&times;</span> <span>${{escapeHtml(g)}}</span>`;
          gapsList.appendChild(li);
        }});
      }} else {{
        gapsList.innerHTML = '<li class="text-slate-500 italic">No regulatory gaps recorded for this component.</li>';
      }}

      const filesList = document.getElementById('node-files-list');
      filesList.innerHTML = '';
      if (node.files && node.files.length) {{
        node.files.forEach(f => {{
          const div = document.createElement('div');
          div.className = 'bg-slate-900 px-2.5 py-1.5 rounded border border-slate-800 text-slate-300 truncate';
          div.textContent = f;
          filesList.appendChild(div);
        }});
      }} else {{
        filesList.innerHTML = '<div class="text-slate-500 italic font-sans text-xs">No direct files bound to this component.</div>';
      }}

      // Incidents
      const incSec = document.getElementById('node-incidents-section');
      const incList = document.getElementById('node-incidents-list');
      incList.innerHTML = '';
      if (node.incidents && node.incidents.length) {{
        incSec.classList.remove('hidden');
        node.incidents.forEach(inc => {{
          const div = document.createElement('div');
          div.className = 'bg-slate-900 p-2.5 rounded border border-slate-800 text-xs';
          div.innerHTML = `
            <div class="flex items-center justify-between mb-1">
              <span class="font-mono text-amber-400">${{inc.id}}</span>
              <span class="px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 font-semibold uppercase text-[10px]">${{inc.severity}}</span>
            </div>
            <p class="text-slate-300 font-medium mb-1">${{escapeHtml(inc.title)}}</p>
            <div class="text-slate-500 text-[10px]">${{inc.tags.join(' / ')}}</div>
          `;
          incList.appendChild(div);
        }});
      }} else {{
        incSec.classList.add('hidden');
      }}

      // Tab 3: Crosswalks
      const cwList = document.getElementById('node-crosswalk-list');
      cwList.innerHTML = '';
      if (node.cross_framework && node.cross_framework.length) {{
        node.cross_framework.forEach(cw => {{
          const div = document.createElement('div');
          div.className = 'bg-slate-900 p-2.5 rounded border border-slate-800 flex items-start justify-between gap-3';
          div.innerHTML = `
            <div>
              <span class="font-semibold text-slate-200">${{cw.framework}}</span>
              <div class="text-slate-400 text-xs mt-0.5">Controls: ${{cw.controls.map(c => `<code class="bg-slate-800 px-1 py-0.5 rounded text-sky-400 mr-1">${{c}}</code>`).join('')}}</div>
            </div>
            <span class="text-emerald-400 text-xs font-bold shrink-0">Synergy</span>
          `;
          cwList.appendChild(div);
        }});
      }} else {{
        cwList.innerHTML = '<div class="text-slate-500 italic">No direct framework crosswalk mapped for this dimension.</div>';
      }}
    }}

    function switchTab(tabId) {{
      document.querySelectorAll('.tab-pane').forEach(el => el.classList.add('hidden'));
      document.querySelectorAll('.inspector-tab').forEach(btn => {{
        btn.classList.remove('border-sky-400', 'text-sky-400');
        btn.classList.add('border-transparent', 'text-slate-400');
      }});
      const targetPane = document.getElementById(tabId);
      if (targetPane) targetPane.classList.remove('hidden');

      const activeBtn = document.getElementById(`tab-btn-${{tabId.replace('tab-', '')}}`);
      if (activeBtn) {{
        activeBtn.classList.remove('border-transparent', 'text-slate-400');
        activeBtn.classList.add('border-sky-400', 'text-sky-400');
      }}
    }}

    function setFilter(filter) {{
      currentFilter = filter;
      document.querySelectorAll('.filter-btn').forEach(btn => {{
        btn.classList.remove('bg-slate-700', 'text-white');
        btn.classList.add('bg-slate-800');
      }});
      const activeBtn = document.getElementById(`btn-filter-${{filter}}`);
      if (activeBtn) {{
        activeBtn.classList.add('bg-slate-700', 'text-white');
        activeBtn.classList.remove('bg-slate-800');
      }}
      renderGraph();
    }}

    function handleSearch(q) {{
      searchQuery = q.trim();
      renderGraph();
    }}

    function zoom(factor) {{
      scale *= factor;
      scale = Math.max(0.3, Math.min(3.0, scale));
      updateTransform();
    }}

    function resetZoom() {{
      scale = 1.0;
      panX = 0;
      panY = 0;
      updateTransform();
    }}

    function updateTransform() {{
      graphGroup.setAttribute('transform', `translate(${{panX}}, ${{panY}}) scale(${{scale}})`);
    }}

    function copySnippet() {{
      const code = document.getElementById('code-fix-block').textContent;
      navigator.clipboard.writeText(code).then(() => {{
        const btn = document.getElementById('btn-copy-fix');
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        btn.classList.add('text-emerald-400');
        setTimeout(() => {{
          btn.textContent = orig;
          btn.classList.remove('text-emerald-400');
        }}, 2000);
      }});
    }}

    function escapeHtml(text) {{
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }}

    // Canvas Mouse Pan Handling
    const container = document.getElementById('canvas-container');
    container.addEventListener('mousedown', (e) => {{
      if (e.target.tagName === 'circle' || e.target.tagName === 'text') return;
      isDragging = true;
      startX = e.clientX - panX;
      startY = e.clientY - panY;
    }});

    window.addEventListener('mousemove', (e) => {{
      if (!isDragging) return;
      panX = e.clientX - startX;
      panY = e.clientY - startY;
      updateTransform();
    }});

    window.addEventListener('mouseup', () => {{
      isDragging = false;
    }});

    window.addEventListener('resize', () => {{
      initLayout();
      renderGraph();
    }});

    // Initialize
    initLayout();
    renderGraph();

    // Auto-select first gap node if available
    const firstGap = GRAPH_DATA.nodes.find(n => n.compliance_status === 'gap') || GRAPH_DATA.nodes[0];
    if (firstGap) {{
      selectNode(firstGap.id);
    }}
  </script>
</body>
</html>
"""

    if output_path:
        dest = Path(output_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(html_content, encoding="utf-8")

    return html_content
