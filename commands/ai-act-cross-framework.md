---
name: ai-act-cross-framework
description: Project EU AI Act scan findings across NIST AI RMF, ISO 42001, GDPR, OWASP LLM 2025, OWASP Agentic Top 10, and SOC 2. Identifies 'Satisfy Once, Comply Everywhere' levers.
---

# /ai-act-cross-framework

Evaluate your codebase against international AI governance, security, and data privacy frameworks simultaneously from a single EU AI Act scan.

## Usage

```bash
/ai-act-cross-framework [PATH]
```

Or via CLI:
```bash
python -m scanner.cli [PATH] --cross-framework --markdown
```

## Supported Frameworks

- **NIST AI Risk Management Framework (NIST AI RMF 1.0 / AI 100-1)**
- **ISO/IEC 42001:2023** (Artificial Intelligence Management System)
- **OWASP Top 10 for LLM Applications (2025 Edition)**
- **OWASP Top 10 for Agentic Applications (ASI01-ASI10)**
- **GDPR (Regulation EU 2016/679)**
- **MITRE ATLAS** (Adversarial Threat Landscape for AI Systems)
- **NIST AI 600-1** (Generative AI Profile)
- **SOC 2 Type II** (Trust Services Criteria)
- **CSA AI Controls Matrix (AICM v1.0)**
- **ISO/IEC 27002:2022 & NIST SP 800-53 Rev. 5**

## Output Sections

1. **Framework Readiness Summary**: Table showing multi-framework readiness score (%), compliant count, partial count, and top priority remediation gaps.
2. **Satisfy Once, Comply Everywhere Levers**: Ranks single EU AI Act dimensions whose remediation simultaneously closes gaps across multiple global standards.
3. **Evidence Harmonization & Reuse Opportunities**: Practical guidance on reusing AI Act technical documentation (Art. 11/Annex IV) and FRIA (Art. 27) for GDPR DPIA (Art. 35) and NIST MP profiles.
