"""Cyber Resilience Act support: Regulation (EU) 2024/2847.

A first slice, kept apart from the EU AI Act scan and its scores:

* :func:`cra_scan`: a scope step, then two evidence checks (disclosure policy
  and SBOM). A repository that does not look like a product with digital
  elements gets an empty report, never a score.
* :func:`article_14_clock`: the Art. 14 reporting deadlines, as a pure function.
"""

from scanner.analyzers.regulatory_perimeter import (
    CraScopeAssessment,
    CraScopeSignal,
    assess_cra_scope,
)
from scanner.cra.clock import (
    ARTICLE_14_APPLIES_FROM,
    FULL_APPLICATION_FROM,
    Art14Clock,
    Art14Event,
    article_14_clock,
    format_article_14_clock,
)
from scanner.cra.scan import (
    CVD_CHECK_ID,
    SBOM_CHECK_ID,
    CraFinding,
    CraReport,
    build_cra_report,
    check_cvd_policy,
    check_sbom,
    cra_scan,
    format_cra_report,
)

__all__ = [
    "ARTICLE_14_APPLIES_FROM",
    "CVD_CHECK_ID",
    "FULL_APPLICATION_FROM",
    "SBOM_CHECK_ID",
    "Art14Clock",
    "Art14Event",
    "CraFinding",
    "CraReport",
    "CraScopeAssessment",
    "CraScopeSignal",
    "article_14_clock",
    "assess_cra_scope",
    "build_cra_report",
    "check_cvd_policy",
    "check_sbom",
    "cra_scan",
    "format_article_14_clock",
    "format_cra_report",
]
