"""Legal force of each framework the cross-framework projection maps onto.

Ported from the legit-ai parent project (``app/data/normative_force.py`` and
the matrix rule in ``app/engines/compliance_matrix.py::_derived``), adapted to
the scanner's projection: an EU AI Act code-evidence score is *evidence* for
another framework's control, never an *assessment* of it.

* **Binding law** (GDPR) is reported ``not_assessed``: AI Act evidence can be
  relevant (a human approval step bears on GDPR Art. 22), but whether the law
  is met needs its own legal review. GDPR applies alongside the AI Act in full
  (AI Act Art. 2(7)).
* **Harmonised standards** confer a presumption of conformity only for the AI
  Act requirements they cover, once cited in the Official Journal. EN
  18286:2026 (quality management, Art. 17) is the cited one; ``prEN`` drafts
  are guidance until citation.
* **Voluntary standards and attestation schemes** (ISO/IEC 42001 and 27002,
  SOC 2, NIST AI RMF, NIST SP 800-53, NIST AI 600-1, CSA AICM) are decided by
  an auditor or certification body: code evidence *supports* their controls.
* **Guidance and threat catalogues** (OWASP LLM / Agentic, MITRE ATLAS) have no
  certification; evidence shows diligence.

Stdlib only; deterministic.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class NormativeForce(StrEnum):
    BINDING = "binding_law"
    PRESUMPTION = "harmonised_standard"
    VOLUNTARY = "voluntary_standard"
    GUIDANCE = "guidance"


# Binding instruments first: they are the ones a founder cannot opt out of.
FORCE_RANK: Final[dict[NormativeForce, int]] = {
    NormativeForce.BINDING: 0,
    NormativeForce.PRESUMPTION: 1,
    NormativeForce.VOLUNTARY: 2,
    NormativeForce.GUIDANCE: 3,
}

FRAMEWORK_FORCE: Final[dict[str, NormativeForce]] = {
    "gdpr": NormativeForce.BINDING,
    "cen_cenelec_jtc21": NormativeForce.PRESUMPTION,  # per control: see force_of()
    "iso_42001": NormativeForce.VOLUNTARY,
    "iso_27002": NormativeForce.VOLUNTARY,
    "soc2": NormativeForce.VOLUNTARY,
    "nist_ai_rmf": NormativeForce.VOLUNTARY,
    "nist_sp_800_53": NormativeForce.VOLUNTARY,
    "nist_ai_600_1": NormativeForce.VOLUNTARY,
    "csa_aicm": NormativeForce.VOLUNTARY,
    "owasp_llm": NormativeForce.GUIDANCE,
    "owasp_agentic": NormativeForce.GUIDANCE,
    "mitre_atlas": NormativeForce.GUIDANCE,
}

FORCE_EXPLANATION: Final[dict[NormativeForce, str]] = {
    NormativeForce.BINDING: (
        "Binding law: AI Act code evidence can be relevant, but compliance needs its own legal review."
    ),
    NormativeForce.PRESUMPTION: (
        "Harmonised standard: once cited in the Official Journal it gives a presumption of conformity "
        "for the AI Act articles it covers (EN 18286:2026: Art. 17 quality management); drafts are guidance."
    ),
    NormativeForce.VOLUNTARY: (
        "Voluntary standard or attestation: code evidence supports these controls; an auditor or "
        "certification body decides."
    ),
    NormativeForce.GUIDANCE: "Guidance or threat catalogue: no certification; evidence shows security diligence.",
}

PRESUMPTION_OF_CONFORMITY_NOTE: Final[str] = (
    "Only harmonised standards cited in the Official Journal give a presumption of conformity with the "
    "AI Act. EN 18286:2026 does so for Art. 17 (quality management system). ISO/IEC 42001 certification, "
    "SOC 2 reports and NIST profiles are useful evidence but confer no presumption."
)


def force_of(framework_id: str, control_id: str | None = None) -> NormativeForce:
    """Legal force of a framework, or of one control where force differs per control (CEN drafts)."""
    if framework_id == "cen_cenelec_jtc21" and control_id is not None:
        return NormativeForce.PRESUMPTION if control_id.startswith("EN ") else NormativeForce.GUIDANCE
    return FRAMEWORK_FORCE.get(framework_id, NormativeForce.GUIDANCE)


def is_binding(framework_id: str) -> bool:
    return force_of(framework_id) is NormativeForce.BINDING


__all__ = [
    "FORCE_EXPLANATION",
    "FORCE_RANK",
    "FRAMEWORK_FORCE",
    "NormativeForce",
    "PRESUMPTION_OF_CONFORMITY_NOTE",
    "force_of",
    "is_binding",
]
