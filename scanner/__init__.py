"""EU AI Act Scanner — static analysis for EU Regulation 2024/1689 compliance.

Scans a codebase for evidence and gaps across 19 compliance dimensions
mapped to EU AI Act articles. No network calls, no telemetry.

Quick start:
    from scanner import scan_project
    result = scan_project("./my-ai-project")
    print(result.overall_compliance_pct)
"""

__version__ = "0.1.0"

from scanner.models import ArchitectureNode, DiscoveredComponent, FileFinding, ScanResult
from scanner.orchestrator import scan_project

__all__ = [
    "__version__",
    "scan_project",
    "ScanResult",
    "DiscoveredComponent",
    "ArchitectureNode",
    "FileFinding",
]
