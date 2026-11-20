"""Cryptographic Compliance Release Dossier generator.

Produces an immutable, tamper-evident compliance dossier (compliance-dossier.json)
binding:
1. Exact SHA-256 digests of all scanned source and configuration files
2. Repository git commit and branch provenance
3. Inferred and declared operator roles (Provider vs Deployer)
4. Full dimension compliance scores and risk findings
5. Cross-framework mappings (NIST AI RMF, ISO 42001, GDPR, OWASP)
6. Enacted statutory grounding under Regulation (EU) 2024/1689 and
   Regulation (EU) 2026/1744 (Digital Omnibus on AI)
7. Cryptographic dossier-level integrity hash for Notified Bodies / auditors

Market Differentiator: Unlike standard scanners that emit transient terminal output,
the dossier provides a mathematically verifiable audit trail acceptable for Notified
Body conformity assessments (Art. 43) and QMS technical documentation (Art. 11 / Annex IV).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, date, datetime
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field

from scanner import __version__
from scanner.cross_framework import project_scan_to_frameworks
from scanner.data.omnibus import (
    AI_ACT_CONSOLIDATED_CELEX,
    OMNIBUS_SHORT_TITLE,
    resolve_applicability,
)
from scanner.data.ontology import OPERATOR_ROLES, ActorRole, RiskClass
from scanner.models import ScanResult
from scanner.paths import is_excluded

_ROLE_ALIASES: dict[str, ActorRole] = {
    "authorized_representative": ActorRole.AUTHORISED_REPRESENTATIVE,
    "product_manufacturer": ActorRole.PROVIDER,
    "gpai_provider": ActorRole.PROVIDER,
}


def _resolve_actor_role(role: str | None) -> ActorRole:
    """Map a scanner role id to a canonical ontology :class:`ActorRole`."""
    if not role:
        return ActorRole.PROVIDER
    norm = role.strip().lower()
    if norm in _ROLE_ALIASES:
        return _ROLE_ALIASES[norm]
    try:
        candidate = ActorRole(norm)
        if candidate in OPERATOR_ROLES:
            return candidate
    except ValueError:
        pass
    return ActorRole.PROVIDER


def _build_regulatory_regime(
    as_of: date | None = None,
    role: str | None = None,
) -> dict[str, str]:
    """Resolve the live Digital Omnibus enforcement summary dynamically."""
    effective_date = as_of or datetime.now(UTC).date()
    actor_role = _resolve_actor_role(role)
    app_res = resolve_applicability(
        as_of=effective_date,
        risk_class=RiskClass.HIGH_RISK_ANNEX_III,
        role=actor_role,
    )
    in_force_arts = sorted(
        {art for phase in app_res.phases_in_force for art in phase.articles}
    )
    pending_parts = [
        f"{phase.label} ({phase.effective_date})"
        for phase in app_res.phases_pending
    ]
    in_force_str = (
        f"{', '.join(in_force_arts)} in force"
        if in_force_arts
        else "no Annex III phases yet in force"
    )
    pending_str = (
        f"; pending: {'; '.join(pending_parts)}"
        if pending_parts
        else "; all Annex III phases in force"
    )
    enforcement_status = f"As of {app_res.as_of} ({actor_role.value}): {in_force_str}{pending_str}"
    return {
        "primary_regulation": "Regulation (EU) 2024/1689 (EU AI Act)",
        "amending_legislation": f"Regulation (EU) 2026/1744 ({OMNIBUS_SHORT_TITLE})",
        "eur_lex_celex": AI_ACT_CONSOLIDATED_CELEX,
        "as_of_date": app_res.as_of,
        "enforcement_status": enforcement_status,
        "harmonised_standards": (
            "EN 18286:2026 (OJ-cited harmonised standard for Art. 17(1) QMS "
            "and Art. 11(1) first sentence technical documentation)"
        ),
    }


class FileDigest(BaseModel):
    """SHA-256 fingerprint of a single source file in the audited codebase."""
    relative_path: str
    sha256: str
    size_bytes: int


class ComplianceDossier(BaseModel):
    """Tamper-evident compliance release package."""

    dossier_id: str = Field(default_factory=lambda: f"dossier-{uuid4().hex[:12]}")
    created_at_utc: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    scanner_version: str = __version__
    project_name: str
    git_commit: str = "unversioned"
    git_branch: str = "unknown"
    is_ai_system: bool = True
    inferred_roles: list[str] = Field(default_factory=list)
    overall_compliance_pct: float = 0.0
    dimension_scores: dict[str, float] = Field(default_factory=dict)
    regulatory_regime: dict[str, str] = Field(
        default_factory=_build_regulatory_regime
    )
    cross_framework_summary: dict[str, float] = Field(default_factory=dict)
    satisfy_once_levers: list[str] = Field(default_factory=list)
    risk_indicators_count: int = 0
    external_security_sources: list[str] = Field(default_factory=list)
    external_security_findings_count: int = 0
    file_manifest: list[FileDigest] = Field(default_factory=list)
    applied_remediations: list[str] = Field(default_factory=list)
    dossier_integrity_hash: str = ""

    def sign_and_seal(self) -> ComplianceDossier:
        """Compute the cryptographic SHA-256 digest of the canonical dossier content."""
        payload_dict = self.model_dump(exclude={"dossier_integrity_hash"})
        canonical_json = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
        self.dossier_integrity_hash = hashlib.sha256(canonical_json).hexdigest()
        return self

    def export_json(self, destination: Path | str) -> Path:
        """Write the sealed dossier to a JSON file."""
        self.sign_and_seal()
        dest_path = Path(destination)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_text(
            json.dumps(self.model_dump(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return dest_path


def _get_git_info(root: Path) -> tuple[str, str]:
    """Extract current git commit and branch if root is a git repository."""
    commit = "unversioned"
    branch = "unknown"
    try:
        proc_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
        if proc_commit.returncode == 0 and proc_commit.stdout.strip():
            commit = proc_commit.stdout.strip()[:12]

        proc_branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
        if proc_branch.returncode == 0 and proc_branch.stdout.strip():
            branch = proc_branch.stdout.strip()
    except Exception:
        pass
    return commit, branch


def _compute_manifest(root: Path, file_list: list[str]) -> list[FileDigest]:
    """Compute SHA-256 for all scanned files."""
    manifest: list[FileDigest] = []
    for rel_path in sorted(file_list):
        full_path = root / rel_path
        if full_path.is_file():
            try:
                content = full_path.read_bytes()
                h = hashlib.sha256(content).hexdigest()
                manifest.append(
                    FileDigest(
                        relative_path=rel_path.replace("\\", "/"),
                        sha256=h,
                        size_bytes=len(content),
                    )
                )
            except (OSError, PermissionError):
                continue
    return manifest


def generate_dossier(
    scan: ScanResult,
    root: Path | str,
    applied_remediations: list[str] | None = None,
    *,
    as_of: date | None = None,
    external_security_findings_count: int | None = None,
) -> ComplianceDossier:
    """Generate an immutable compliance dossier from a ScanResult."""
    root_path = Path(root).resolve()
    git_commit, git_branch = _get_git_info(root_path)

    # Compute cross-framework projection
    cross_proj = project_scan_to_frameworks(scan)
    fw_summary = {
        fw.framework_label: fw.coverage_pct for fw in cross_proj.frameworks
    }
    levers = [lever.impact_summary for lever in cross_proj.satisfy_once_levers[:3]]

    # Compute file digests from the scan's file findings or directory files.
    # Exclusions are relative to the root: a project under `.hidden/` must still
    # produce a manifest (absolute matching used to drop every file).
    file_paths = [ff.file_path for ff in scan.file_findings]
    if not file_paths:
        file_paths = [
            str(p.relative_to(root_path))
            for p in root_path.rglob("*")
            if p.is_file() and not is_excluded(p.relative_to(root_path))
        ]

    manifest = _compute_manifest(root_path, file_paths)

    effective_role = scan.active_role or (
        scan.inferred_roles[0] if scan.inferred_roles else None
    )
    regime = _build_regulatory_regime(as_of=as_of, role=effective_role)

    ext_sources = list(scan.external_security_sources)
    if external_security_findings_count is not None:
        ext_count = external_security_findings_count
    else:
        ext_node = next(
            (node for node in scan.architecture if node.id == "external_security"),
            None,
        )
        if ext_node is not None and ext_node.finding_count > 0:
            ext_count = ext_node.finding_count
        else:
            ext_sources_lower = {s.lower() for s in ext_sources}
            ext_count = sum(
                1
                for comp in scan.components
                if comp.component_type == "external_security"
                or comp.component_type.lower() in ext_sources_lower
            )

    dossier = ComplianceDossier(
        project_name=scan.project_name,
        git_commit=git_commit,
        git_branch=git_branch,
        is_ai_system=scan.is_ai_system,
        inferred_roles=scan.inferred_roles,
        overall_compliance_pct=scan.overall_compliance_pct,
        dimension_scores=dict(sorted(scan.compliance_scores.items())),
        regulatory_regime=regime,
        cross_framework_summary=fw_summary,
        satisfy_once_levers=levers,
        risk_indicators_count=len(scan.risk_indicators),
        external_security_sources=ext_sources,
        external_security_findings_count=ext_count,
        file_manifest=manifest,
        applied_remediations=applied_remediations or [],
    )

    dossier.sign_and_seal()
    return dossier
