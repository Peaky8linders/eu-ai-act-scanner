"""Top-level scan result models.

Kept separate from `scanner.analyzers._base` so `ScanResult` is importable
by downstream consumers (CLI, optional API) without pulling analyzer internals.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class DiscoveredComponent(BaseModel):
    """A detected component in the scanned project."""
    name: str
    component_type: str  # matches Analyzer ID (ai_frameworks, security_controls, ...)
    file_path: str
    confidence: float = Field(ge=0, le=1)
    compliance_dimensions: list[str] = Field(default_factory=list)
    compliance_impact: str = "neutral"  # positive | neutral | gap
    details: dict = Field(default_factory=dict)


class ArchitectureNode(BaseModel):
    """A node in the discovered architecture graph."""
    id: str
    label: str
    type: str
    compliance_status: str = "unknown"  # compliant | partial | gap | unknown
    connected_to: list[str] = Field(default_factory=list)
    file_count: int = 0
    icon: str = ""


class FileFinding(BaseModel):
    """Per-file compliance findings."""
    file_path: str
    findings: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    compliance_dimensions: list[str] = Field(default_factory=list)
    status: str = "partial"  # compliant | partial | gap


class ScanResult(BaseModel):
    """Complete scan result."""
    project_name: str = "Project"
    scan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    scanner_version: str = ""
    total_files: int = 0
    total_size_bytes: int = 0
    languages: dict[str, int] = Field(default_factory=dict)
    components: list[DiscoveredComponent] = Field(default_factory=list)
    architecture: list[ArchitectureNode] = Field(default_factory=list)
    compliance_scores: dict[str, float] = Field(default_factory=dict)
    overall_compliance_pct: float = 0.0
    risk_indicators: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    evidence_map: dict[str, list[str]] = Field(default_factory=dict)
    file_findings: list[FileFinding] = Field(default_factory=list)
    pre_filled_answers: dict[str, str] = Field(default_factory=dict)
    # dim_id -> incident IDs from the vendored GenAI-incidents corpus that
    # exploited that gap class. Populated for gap/partial dimensions only.
    # Resolve IDs via scanner.incident_grounding / scanner.data.incident_corpus.
    incident_grounding: dict[str, list[str]] = Field(default_factory=dict)
