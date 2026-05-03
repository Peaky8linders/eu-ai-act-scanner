"""Regulatory Perimeter Analyzer — Table 5 trigger map (paper §7).

Implements the Table 5 trigger scenarios from Nannini et al. (2026)
§7 (paper lines 1303-1366). Each row of Table 5 maps a concrete agent
action to the EU instrument it activates and the obligation that
follows. This analyzer scans the codebase for each trigger and emits
a finding per detected instrument so the audit wizard can map the
correct multi-instrument compliance path.

Conclusion 1 (paper line 2440):

> *"The regulatory perimeter for AI agent providers extends across at
> least eight EU legislative instruments beyond the AI Act itself: the
> GDPR (almost always applicable), the CRA, the DSA, the Data Act, the
> DGA, NIS2, sector-specific legislation, and the revised PLD.
> Parallel compliance across multiple instruments is not a risk
> scenario; it is the baseline."*

What this analyzer detects (per Table 5):

- **GDPR** — agent processes personal data (CRM SDK, email API,
  payment data, customer-service routing).
- **Data Act** — agent interfaces with connected products (IoT/MQTT/
  CoAP/Modbus/OPC-UA/smart-meter SDKs).
- **DSA** — agent operates inside an intermediary/hosting/platform
  service (content moderation flows, social-media publishing, ad
  platforms).
- **CRA** — agent shipped as a product with digital elements (CLI
  entry point, VS Code extension manifest, distributable Python
  package, network-connected standalone software).
- **NIS2** — agent serves an essential entity / OT environment
  (SCADA, energy, healthcare-critical, finance market infra).
- **DGA** — agent platform offers data intermediation (data
  marketplace patterns, multi-tenant data sharing).
- **Sectoral** — MDR (FHIR/DICOM/EHR), MiFID II (order routing,
  trading APIs), PSD2 (SEPA payment endpoints), DORA (financial
  operational resilience).
- **PLD** — flag stale-data caches in financial / clinical agents
  where the harm-from-bad-output vector is concrete (paper Table 5
  PLD row).

Maps to KB dimensions: regulatory_perimeter, risk_mgmt.

References:
- Paper §7 (lines 992-1583), Tables 4 + 5 (lines 1235, 1307)
- Paper §7.5 — CRA M/606 parallel track (lines 1367-1462)
- Paper §7.6 — Digital Omnibus (lines 1463-1547)
"""

from __future__ import annotations

from scanner.analyzers._base import (
    AnalyzerContext,
    AnalyzerResult,
    Finding,
    has_file,
    search_files,
)

# Each entry: (instrument key, label, regex signals, evidence-link
# helper, obligation summary). Instrument is emitted ONCE even if
# multiple signals match — finding description summarises which signals
# fired.

_GDPR_SIGNALS = [
    r"\bsimple_salesforce\b|\bhubspot\b|\bzendesk\b|\bfreshdesk\b",
    r"\bsmtplib\b|\bsendgrid\b|\bmailgun\b",
    r"\bstripe\.PaymentIntent\b|\bplaid\b",
    r"\bGmailService\b|\bgoogleapiclient.*gmail",
]
_DATA_ACT_SIGNALS = [
    r"\bpaho\.mqtt\b|\bmqtt\.client\b",
    r"\baiocoap\b|\bcoapthon\b",
    r"\bopcua\b|\basyncua\b",
    r"\bpymodbus\b|\bminimalmodbus\b",
    r"\bzigbee\b|\bzwave\b|\bsmartthings\b",
    r"\bsmart[-_]?meter\b|\benergy[-_]?reading",
]
_DSA_SIGNALS = [
    # Content moderation / publishing on platforms
    r"\bcontent[-_]?moderation\b|\bflag[-_]?post\b",
    r"\btweepy\b|\bfacebook_business\b|\binstagrapi\b",
    r"\bslack_sdk.*chat_postMessage|\bdiscord\.py\b",
    r"\brecommender\b.*algorithm|algorithm.*recommend",
]
_CRA_SIGNALS_FILES = [
    r"setup\.py$",
    r"pyproject\.toml$",
    r"package\.json$",
    r"vsc(ode)?-?extensions?\.json$|vsce\.config\.",
    # CLI entry-point declarations are inside pyproject.toml/setup.py — checked at content level
]
_CRA_SIGNALS_CONTENT = [
    r'\[project\.scripts\]',  # PEP 621 CLI entry points
    r'console_scripts\s*=',
    r'"bin"\s*:',  # npm CLI
    r'"main"\s*:\s*"[^"]+\.(js|cjs|mjs)"',
    r'#!\s*/usr/bin/env\s+(python|node|sh)',  # shebang in distributable
]
_NIS2_SIGNALS = [
    r"\bopcua\b|\bpymodbus\b",
    r"\bscada\b|\bplc\b|\bdcs\b|\bICS\b",
    r"\benergy[-_]?utility\b|\bsmart[-_]?grid\b",
    r"\bcritical[-_]?infrastructure\b",
]
_DGA_SIGNALS = [
    r"\bdata[-_]?marketplace\b",
    r"\bdata[-_]?intermediation\b",
    # Multi-tenant data sharing primitives
    r"\bcontribute[-_]?dataset\b|\bshare[-_]?training[-_]?data\b",
]
_MDR_SIGNALS = [
    r"\bfhir\b|\bfhirclient\b",
    r"\bpydicom\b|\bdicom\.dataset\b",
    r"\bepic_fhir\b|\bcerner_fhir\b",
    r"\bhl7\b|\bcdaschema\b",
]
_MIFID_SIGNALS = [
    r"\border[_-]routing\b|\bsmart[-_]?order[-_]?routing\b",
    r"\binvest[-_]?advice\b|\bportfolio[-_]?optimization\b",
    r"\bbrokerage[_-]api\b",
]
_PSD2_SIGNALS = [
    r"\bsepa\b.*\b(transfer|credit|debit)\b",
    r"\bxs2a\b|\bopen[-_]banking\b",
    r"\bplaid\b.*\bach\b",
]
_DORA_SIGNALS = [
    r"\bdora\b|\bdigital[-_]operational[-_]resilience\b",
    r"\bfinancial[-_]entity\b.*\b(critical|important)\b",
]
_PLD_SIGNALS = [
    # Stale RAG cache + financial/clinical advice = PLD trigger per Table 5
    r"\brag.*cache.*ttl|cache.*rag.*ttl",
    r"\bcached_until\b.*\b(advice|recommend|diagnosis)\b",
    # @cache / @lru_cache near LLM advice
    r"@(lru_)?cache.*\n[^\n]*(advice|recommend|diagnos|prediction)",
]


def _match_any(ctx: AnalyzerContext, patterns: list[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for pattern in patterns:
        out.extend(search_files(ctx, pattern))
    return out


def _match_files(ctx: AnalyzerContext, patterns: list[str]) -> list[str]:
    out: list[str] = []
    for pattern in patterns:
        out.extend(has_file(ctx, pattern))
    return out


def _emit_finding(
    *, key: str, label: str, evidence_path: str, evidence_line: str,
    rationale: str, obligation: str, kb_q: str,
) -> Finding:
    return Finding(
        id=f"rp-{key}",
        category="regulatory_perimeter",
        title=f"Regulatory trigger: {label}",
        description=f"{rationale} Obligation: {obligation}",
        file_path=evidence_path,
        confidence=0.7,
        compliance_impact="neutral",
        compliance_dimensions=["regulatory_perimeter", "risk_mgmt"],
        evidence_snippet=evidence_line,
        kb_question_ids=[kb_q], suggested_answer="partial",
    )


def analyze_regulatory_perimeter(ctx: AnalyzerContext) -> AnalyzerResult:
    findings: list[Finding] = []
    evidence_files: set[str] = set()
    triggered: list[str] = []

    # ── GDPR ────────────────────────────────────────────────────────────
    gdpr_hits = _match_any(ctx, _GDPR_SIGNALS)
    if gdpr_hits:
        evidence_files.add(gdpr_hits[0][0])
        triggered.append("GDPR")
        findings.append(_emit_finding(
            key="gdpr", label="GDPR (personal data processing)",
            evidence_path=gdpr_hits[0][0], evidence_line=gdpr_hits[0][1],
            rationale="Agent imports CRM/email/payment SDKs that process personal data.",
            obligation="GDPR Art. 6 lawful basis, Art. 5 purpose limitation + minimisation, DPIA if systematic profiling.",
            kb_q="rp-1",
        ))

    # ── Data Act ────────────────────────────────────────────────────────
    da_hits = _match_any(ctx, _DATA_ACT_SIGNALS)
    if da_hits:
        evidence_files.add(da_hits[0][0])
        triggered.append("Data Act")
        findings.append(_emit_finding(
            key="data-act", label="Data Act (connected products)",
            evidence_path=da_hits[0][0], evidence_line=da_hits[0][1],
            rationale="Agent interfaces with connected products via IoT/OT protocols (MQTT, CoAP, OPC-UA, Modbus, smart meters).",
            obligation="Data access rights for the user, portability to third parties on request.",
            kb_q="rp-2",
        ))

    # ── DSA ─────────────────────────────────────────────────────────────
    dsa_hits = _match_any(ctx, _DSA_SIGNALS)
    if dsa_hits:
        evidence_files.add(dsa_hits[0][0])
        triggered.append("DSA")
        findings.append(_emit_finding(
            key="dsa", label="DSA (intermediary / hosting / platform service)",
            evidence_path=dsa_hits[0][0], evidence_line=dsa_hits[0][1],
            rationale="Agent operates inside a content-moderation, social-publishing, or recommender flow.",
            obligation="DSA Art. 17 statement of reasons, recommender transparency, systemic risk assessment if VLOP.",
            kb_q="rp-3",
        ))

    # ── CRA ─────────────────────────────────────────────────────────────
    cra_files = _match_files(ctx, _CRA_SIGNALS_FILES)
    cra_content_hits = _match_any(ctx, _CRA_SIGNALS_CONTENT)
    if cra_files or cra_content_hits:
        path = cra_files[0] if cra_files else cra_content_hits[0][0]
        line = "" if cra_files else cra_content_hits[0][1]
        evidence_files.add(path)
        triggered.append("CRA")
        findings.append(_emit_finding(
            key="cra", label="CRA (product with digital elements)",
            evidence_path=path, evidence_line=line,
            rationale="Distributable artefact (CLI entry point, npm bin, packaged extension) — agent ships as a network-connected software product.",
            obligation="CRA secure-by-design, vulnerability reporting from 11 Sep 2026, SBOM, full conformity by 11 Dec 2027. Note CRA Art. 12 conformity-presumption bridge with AI Act Art. 15.",
            kb_q="rp-4",
        ))

    # ── NIS2 ────────────────────────────────────────────────────────────
    nis2_hits = _match_any(ctx, _NIS2_SIGNALS)
    if nis2_hits:
        evidence_files.add(nis2_hits[0][0])
        triggered.append("NIS2")
        findings.append(_emit_finding(
            key="nis2", label="NIS2 (essential / important entity)",
            evidence_path=nis2_hits[0][0], evidence_line=nis2_hits[0][1],
            rationale="OT/SCADA/critical-infrastructure signals — agent likely serves a NIS2 essential entity.",
            obligation="24h incident reporting, supply-chain security, cybersecurity risk management.",
            kb_q="rp-5",
        ))

    # ── DGA ─────────────────────────────────────────────────────────────
    dga_hits = _match_any(ctx, _DGA_SIGNALS)
    if dga_hits:
        evidence_files.add(dga_hits[0][0])
        triggered.append("DGA")
        findings.append(_emit_finding(
            key="dga", label="DGA (data intermediation service)",
            evidence_path=dga_hits[0][0], evidence_line=dga_hits[0][1],
            rationale="Data-marketplace / multi-tenant training-data-sharing primitives detected.",
            obligation="DGA notification, structural separation, neutrality.",
            kb_q="rp-6",
        ))

    # ── Sectoral: MDR ───────────────────────────────────────────────────
    mdr_hits = _match_any(ctx, _MDR_SIGNALS)
    if mdr_hits:
        evidence_files.add(mdr_hits[0][0])
        triggered.append("MDR")
        findings.append(_emit_finding(
            key="mdr", label="MDR/IVDR (medical device)",
            evidence_path=mdr_hits[0][0], evidence_line=mdr_hits[0][1],
            rationale="FHIR/DICOM/HL7/Epic/Cerner SDK present — clinical-decision-support pattern.",
            obligation="Full MDR conformity assessment, ISO 13485 QMS, ISO 14971 risk management, GDPR Art. 9, AI Act Annex I(A) HIGH-RISK.",
            kb_q="rp-7",
        ))

    # ── Sectoral: MiFID II ──────────────────────────────────────────────
    mifid_hits = _match_any(ctx, _MIFID_SIGNALS)
    if mifid_hits:
        evidence_files.add(mifid_hits[0][0])
        triggered.append("MiFID II")
        findings.append(_emit_finding(
            key="mifid", label="MiFID II (investment services)",
            evidence_path=mifid_hits[0][0], evidence_line=mifid_hits[0][1],
            rationale="Order-routing / investment-advice signals.",
            obligation="MiFID II Art. 24 investor protection, best-execution, suitability assessment.",
            kb_q="rp-7",
        ))

    # ── Sectoral: PSD2 ──────────────────────────────────────────────────
    psd2_hits = _match_any(ctx, _PSD2_SIGNALS)
    if psd2_hits:
        evidence_files.add(psd2_hits[0][0])
        triggered.append("PSD2")
        findings.append(_emit_finding(
            key="psd2", label="PSD2 (payment services)",
            evidence_path=psd2_hits[0][0], evidence_line=psd2_hits[0][1],
            rationale="SEPA / open-banking / XS2A signals — payment-initiation pattern.",
            obligation="PSD2 strong customer authentication (SCA), XS2A access, payment-initiation/account-information licensing.",
            kb_q="rp-7",
        ))

    # ── Sectoral: DORA ──────────────────────────────────────────────────
    dora_hits = _match_any(ctx, _DORA_SIGNALS)
    if dora_hits:
        evidence_files.add(dora_hits[0][0])
        triggered.append("DORA")
        findings.append(_emit_finding(
            key="dora", label="DORA (financial operational resilience)",
            evidence_path=dora_hits[0][0], evidence_line=dora_hits[0][1],
            rationale="Explicit DORA / financial-entity-critical signal.",
            obligation="DORA ICT risk management, third-party risk, incident reporting.",
            kb_q="rp-7",
        ))

    # ── PLD ─────────────────────────────────────────────────────────────
    pld_hits = _match_any(ctx, _PLD_SIGNALS)
    if pld_hits:
        evidence_files.add(pld_hits[0][0])
        triggered.append("PLD")
        findings.append(_emit_finding(
            key="pld", label="PLD (Product Liability Directive — stale-data risk)",
            evidence_path=pld_hits[0][0], evidence_line=pld_hits[0][1],
            rationale="Cached LLM advice/diagnosis/recommendation pattern. Per Table 5 (paper line 1330), stale RAG cache producing financial advice that triggers loss = PLD strict liability.",
            obligation="Strict liability for harm caused by defective AI output. Art. 15 non-compliance = strong evidence of defect.",
            kb_q="rp-8",
        ))

    # ── Step 9 readiness: did the operator produce the inventory? ───────
    # If any perimeter trigger fired, demand an `adjacent-legislation.md`
    # or equivalent — paper Step 9 (line 1727).
    if triggered:
        adjacent_doc = (
            has_file(ctx, r"adjacent[-_]?legislation\.md$")
            or has_file(ctx, r"regulatory[-_]?perimeter\.md$")
            or has_file(ctx, r"compliance[-_]?map\.md$")
        )
        if adjacent_doc:
            findings.append(Finding(
                id="rp-step9-doc", category="regulatory_perimeter",
                title="Step 9 'Map adjacent legislation' artefact detected",
                description=(
                    "An adjacent-legislation / regulatory-perimeter / compliance-map artefact "
                    "is present. This satisfies Step 9 of the paper's twelve-step compliance "
                    "sequence structurally."
                ),
                file_path=adjacent_doc[0], confidence=0.75,
                compliance_impact="positive",
                compliance_dimensions=["regulatory_perimeter", "tech_docs"],
                evidence_snippet="",
                kb_question_ids=["rp-9"], suggested_answer="yes",
            ))
        else:
            findings.append(Finding(
                id="rp-step9-missing", category="regulatory_perimeter",
                title="Step 9 inventory missing despite triggered instruments",
                description=(
                    f"Perimeter triggers detected ({', '.join(sorted(triggered))}) but no "
                    "`adjacent-legislation.md` / `regulatory-perimeter.md` / `compliance-map.md` "
                    "artefact in the repo. Per paper Step 9 (line 1727) — the four-question "
                    "tool trace through GDPR / Data Act / DSA / sectoral must be documented."
                ),
                file_path="(no file)",
                confidence=0.7,
                compliance_impact="gap",
                compliance_dimensions=["regulatory_perimeter", "tech_docs"],
                evidence_snippet="",
                kb_question_ids=["rp-9"], suggested_answer="no",
            ))

    # ── Score ───────────────────────────────────────────────────────────
    if not findings:
        score = 80.0  # not applicable — no perimeter triggers
    else:
        positives = sum(1 for f in findings if f.compliance_impact == "positive")
        gaps = sum(1 for f in findings if f.compliance_impact == "gap")
        # Neutral findings (perimeter triggers) are informational — they don't
        # reduce the score directly, but they expand the obligation surface.
        # We score on the positive/gap balance for the Step 9 artefact.
        if not gaps and positives:
            score = 85.0
        elif gaps and positives:
            score = 60.0
        elif gaps:
            score = 40.0
        else:
            score = 65.0  # triggers but no Step 9 evidence either way

    return AnalyzerResult(
        analyzer_id="regulatory_perimeter",
        label="Regulatory Perimeter (Table 5)",
        findings=findings,
        score=round(score, 1),
        file_count=len(evidence_files),
        graph_node_type="regulation",
        graph_icon="⚖",
        connected_categories=["agent_inventory", "tool_governance", "agent_cascade"],
        metadata={
            "triggered_instruments": sorted(triggered),
            "instrument_count": len(triggered),
        },
    )
