"""EU AI Act Scanner — static analysis for EU Regulation 2024/1689 compliance.

Scans a codebase for evidence and gaps across 23 compliance dimensions
mapped to EU AI Act articles, including 4 agent-aware dimensions per
Nannini et al. (2026), "AI Agents under EU Law". No network calls, no
telemetry.

Quick start:
    from scanner import scan_project
    result = scan_project("./my-ai-project")
    print(result.overall_compliance_pct)
"""

__version__ = "0.4.0"

from scanner.incident_grounding import (
    incident_corpus_stats,
    incidents_for_article,
    incidents_for_dimension,
    incidents_for_finding,
    incidents_for_threat,
)
from scanner.models import ArchitectureNode, DiscoveredComponent, FileFinding, ScanResult
from scanner.orchestrator import scan_project

__all__ = [
    "__version__",
    "scan_project",
    "ScanResult",
    "DiscoveredComponent",
    "ArchitectureNode",
    "FileFinding",
    # Incident grounding (v0.4)
    "incidents_for_dimension",
    "incidents_for_article",
    "incidents_for_threat",
    "incidents_for_finding",
    "incident_corpus_stats",
]
