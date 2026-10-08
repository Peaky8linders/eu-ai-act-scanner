---
name: ai-act-dossier
description: Generate and cryptographically seal an immutable compliance release dossier (compliance-dossier.json) for Notified Bodies, auditors, and release gates.
---

# /ai-act-dossier

Produce a mathematically verifiable, tamper-evident compliance dossier binding the exact code state, git provenance, compliance scores, and statutory grounding.

## Usage

```bash
/ai-act-dossier [PATH] [--out compliance-dossier.json]
```

Or via CLI:
```bash
python -m scanner.cli [PATH] --dossier compliance-dossier.json
```

## What it binds

1. **SHA-256 File Manifest**: Exact cryptographic digests of all scanned source files and configuration manifests.
2. **Git Provenance**: Repository commit hash and active branch.
3. **Operator Roles**: Inferred and declared operator roles (Provider vs Deployer).
4. **Compliance Scores**: Dimension-by-dimension compliance scores and identified gaps.
5. **Statutory Grounding**:
   - Primary regulation: Regulation (EU) 2024/1689
   - Amending enactment: Regulation (EU) 2026/1744 (Digital Omnibus on AI)
   - Official CELEX reference: `02024R1689-20260727`
6. **Cross-Framework Mappings**: Readiness ratings across NIST AI RMF, ISO 42001, and GDPR.
7. **Applied Remediations**: Tracked fixes applied via the remediation loop.
8. **Dossier Integrity Hash**: A single cryptographic SHA-256 seal covering canonical dossier contents. Any modification to the dossier or underlying code breaks the signature.

## Auditor / CI Gate Integration

Use the sealed dossier in CI/CD release pipelines to enforce conformity gates:
```bash
eu-ai-act-scan . --dossier release-dossier.json
```
If compliance scores fall below threshold or critical gaps are unresolved, the pipeline fails before code is deployed.
