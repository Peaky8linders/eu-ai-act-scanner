---
name: founder-startup-triage
description: "Plain-English EU AI Act priorities for founders, covering what to fix before launch, what unblocks enterprise deals, and what can wait until Dec 2027. Use for startup, launch-readiness or security-questionnaire questions."
user_invocable: true
---

# Founder & Startup EU AI Act Triage

Cut through legal jargon so a lean AI team knows what blocks shipping **today**, what unblocks **enterprise deals** this quarter, and what can safely wait until **2 Dec 2027**.

## When to invoke

- "Do we need to worry about the EU AI Act before launch?"
- "What actually applies to an AI startup today?"
- "Are we a deployer or a provider?"
- "A customer sent us an AI security questionnaire — what do we put?"
- "What should we check in our OpenAI / Anthropic / AI SaaS vendor contract?"
- After running `/ai-act-quickstart`

## Applies to

- Seed-to-Series-B AI startups building LLM apps, RAG pipelines, AI agents, or MCP tools.
- **In scope**: plain-English role triage, Digital Omnibus timelines, 3-bucket engineering prioritization, Customer/Investor Security Briefs, and handoff to Anthropic's official Legal Plugin (`/review-contract`).
- **Out of scope**: formal legal opinions or Notified Body conformity verdicts (Art. 43).

## Step 1 — Check scope & operator role in plain English

1. **Are you even in scope (Art. 3(1))?** If the repo has no AI/ML framework, model call, or agent runtime (`is_ai_system: false`), EU AI Act obligations do not apply. Stop here.
2. **Deployer vs. Provider (Art. 3(3)–(4) & Art. 25(1))**:
   - **Deployer (most startups calling OpenAI / Anthropic / Bedrock / Gemini APIs)**: You integrate third-party models under your authority -> you owe **Art. 50 transparency today** and **Art. 26/27 deployer duties** (from 2 Dec 2027 if high-risk).
   - **Provider**: You train a model/system or place an AI system on the market under your own name/trademark -> you owe **Art. 50 today** and **Art. 9–15 / 17 / 43** if high-risk (from 2 Dec 2027).
   - **Watch out for the Art. 25(1) silent flip**: Putting your own brand on a high-risk AI system, changing its intended purpose to a high-risk use case, or substantially modifying it (Art. 3(23)) flips a deployer into full provider duties.

## Step 2 — Digital Omnibus Timeline (What Is Live Today vs. 2027/2028)

Enacted under **EU Regulation 2024/1689** as amended by the **Digital Omnibus Regulation (EU) 2026/1744**:

| Date | What applies | Startup impact |
|---|---|---|
| **2 Feb 2025** | Art. 5 prohibited AI practices & Art. 4 AI literacy | **IN FORCE.** Never build social scoring, manipulative subliminal systems, or workplace/school emotion recognition. |
| **2 Aug 2025** | Chapter V GPAI model provider duties (Art. 53–55) | **IN FORCE** for foundation model creators (pre-existing models have until 2 Aug 2027 under Art. 111(3)). |
| **2 Aug 2026** | **Art. 50 Transparency** (chatbot disclosure, synthetic media C2PA/watermarking, deepfake labels) | **IN FORCE TODAY.** Add visible AI notices & synthetic-content marking before shipping. |
| **Oct 2026** | **EN 18286:2026** cited in the Official Journal | The only harmonised standard so far: following it gives a presumption of conformity for Art. 17 (quality management system), which only providers of high-risk AI owe. ISO/IEC 42001 certification and SOC 2 reports are useful evidence but give no presumption. |
| **2 Dec 2026** | New Art. 5(1)(ba)–(bb) NCII & CSAM generation bans | **Reg. 2026/1744.** Ensure safety filters block non-consensual intimate & CSAM generation. |
| **2 Dec 2027** | **Annex III High-Risk Obligations** (Art. 9–15, 17, 26, 27 FRIA) | **Deferred by Digital Omnibus.** Only critical earlier if selling into hiring/HR, credit/lending, healthcare, biometrics, education, or law enforcement. |
| **2 Aug 2028** | **Annex I Safety-Component Products** (medical devices, machinery, toys) | **Deferred by Digital Omnibus.** |

## Step 3 — The 3-Bucket Founder Priority Model

1. **Bucket 1 — Fix Before Shipping (Live Today)**
   - Missing Art. 50 user-facing AI disclosure or synthetic-media marking.
   - Active exploit risks: MCP tool poisoning, unauthenticated/SSRF MCP servers, hardcoded `.mcp.json` or repo secrets, `.claude/settings.json` `Bash(*)` or `bypassPermissions`, lethal trifecta (private data + untrusted input + external side effects), `eval`/`exec`/`shell=True`, unbounded agent loops.
2. **Bucket 2 — Unblocks Enterprise Deals (SOC 2 / GDPR / OWASP)**
   - Automated PR security review workflow (`/ai-act-security-review` or `anthropics/claude-code-security-review`).
   - Pinning MCP servers, Docker base images, dependencies, and GitHub Actions.
   - Structured audit logging with correlation IDs (satisfies Art. 12 + SOC 2 CC7.2 + ISO 27002 8.15 in one PR).
   - Prompt-injection, robustness, and fairness regression tests + RBAC/access controls.
   - Highlight the top 3 **"Satisfy Once, Comply Everywhere"** levers from `founder_triage` / `cross_framework`.
3. **Bucket 3 — Track on Roadmap (2 Dec 2027)**
   - Annex III Art. 9–11, 14, 17, 27 governance docs (`MODEL_CARD.md`, `DATA_CARD.md`, risk register, FRIA).
   - Keep lightweight living markdown docs now; schedule formal conformity prep only if targeting an Annex III vertical.

## Customer / Investor Security Brief Template (<50 lines)

Generate automatically via `/ai-act-quickstart` (`brief_markdown`), or adapt this copy-pasteable template for customer security questionnaires and investor memos:

```markdown
# AI Security & EU AI Act Readiness Brief — <Product Name>

- **EU AI Act Role:** <Deployer (Art. 3(4)) / Provider (Art. 3(3))> — <one-line plain-English explanation>
- **Risk Classification:** <Minimal / Transparency-scoped (Art. 50) / Annex III High-Risk>
- **Live Controls Verified (Local Static Scan):**
  - **Art. 50 Transparency (live 2 Aug 2026):** <AI interaction disclosure & synthetic output marking status>
  - **Art. 15(4) Security & Agent Hardening:** <MCP pinning, secrets guard, least-privilege permissions / managed settings, THREAT_MODEL.md & Claude Code Security review>
  - **Art. 12 / Art. 26(6) / SOC 2 CC7.2 Auditability:** <Structured logging / OpenTelemetry / Claude Compliance API >=180-day audit trail>
  - **Art. 14 / OWASP Agentic Oversight:** <Human approval gates for high-impact tool actions & clean user instructions>
- **Cross-Framework Alignment:** Mapped locally to 12 frameworks (SOC 2, ISO/IEC 27002 and 42001, NIST AI RMF, OWASP, GDPR and more), each with its legal force: code evidence supports voluntary controls, while binding law such as GDPR is reported as not assessed.
- **2027 Roadmap (Digital Omnibus Reg. 2026/1744):** Tracking Annex III obligations ahead of 2 Dec 2027 (Annex I: 2 Aug 2028).
- **Evidence Artifact:** Reproducible local scan baseline + optional signed release dossier (`uvx --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan --dossier`).
```

## Claude Ecosystem Fast-Track (Security + Org Compliance)

If your team already builds with Claude Code or Claude Enterprise/Team, two 5-minute workflows close the biggest enterprise questionnaire gaps:

1. **Claude Code Security (`https://code.claude.com/docs/en/claude-security`) — Art. 15(4) & Art. 9(2)**:
   - Install `claude-security@claude-plugins-official` and `security-guidance@claude-plugins-official`.
   - Run `/threat-model` to produce `THREAT_MODEL.md`, then run `/claude-security` or `/security-review`.
   - Feed the local report into `uvx --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan . --ingest-claude-security <report>` — Claude Security's **adversarial verification panel** verdicts are honored automatically (mitigated/false-positive items are filtered out).
   - Lock team-wide `permissions.allow` / `permissions.deny` with **managed settings** and stream session audit metrics via **OpenTelemetry**.
2. **Anthropic Claude Compliance API — Art. 12(1), Art. 14, Art. 26(2)/(6), Art. 50(1)**:
   - Generate a read-only **Compliance Access Key** in `claude.ai` (*Organization settings > Data and privacy*, scopes `read:compliance_activities`, `read:compliance_org_data`, `read:compliance_user_data`) and set `ANTHROPIC_COMPLIANCE_ACCESS_KEY`.
   - Run the opt-in local fetcher (strictly `GET https://api.anthropic.com/v1/compliance/*` with `anthropic-version: 2026-10-21`; never uploads repo code) and ingest offline:
     ```bash
     uv run --no-project "${CLAUDE_PLUGIN_ROOT}/scripts/fetch_claude_compliance.py" --dry-run
     uv run --no-project "${CLAUDE_PLUGIN_ROOT}/scripts/fetch_claude_compliance.py" --output compliance-api-export.json --org-uuid "$ORG_UUID"
     uvx --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan . --ingest-compliance-api compliance-api-export.json --dossier release-dossier.json
     ```
     (The fetcher ships with the plugin and only reads from the Claude Compliance API.)
   - Automatically verifies >=180-day audit retention, RBAC group governance, clean *Instructions for Claude* / *Cowork Global instructions*, and reviewed remote-session tool executions.

## Vendor Contract Review Handoff (Anthropic Official Legal Plugin)

When a startup operates as a **deployer**, half of your EU AI Act exposure lives in your **vendor contracts** (LLM API terms, SaaS MSAs, DPAs), not your code.

Hand off vendor MSAs/DPAs to **Anthropic's official Legal Plugin** using the bundled playbook in this repo:

1. Point `/review-contract` at **`playbooks/ai-act-contract-positions.yaml`** (8 pre-built EU AI Act negotiation positions updated for Digital Omnibus dates).
2. Focus first on the top 3 startup deal-breakers:
   - **`aiact-01` (Art. 25(1))**: Reject "as-is compliance" clauses that silently flip provider obligations onto you.
   - **`aiact-02` & `aiact-03` (Art. 26(1), 26(6))**: Require written instructions for use and >=6-month log retention (or log locally).
   - **`aiact-04` & `aiact-06` (Art. 10(5), Art. 73)**: Ensure the DPA covers AI data handling/zero-training and timely security/serious incident notice.

## Cross-references

- [interpreting-findings](../interpreting-findings/SKILL.md) — detailed scoring model and audit caveats
- [claude-code-security-hardening](../claude-code-security-hardening/SKILL.md) — hardening `.claude/settings.json`, `.mcp.json`, and PR reviews
- [eu-ai-act-timeline](../eu-ai-act-timeline/SKILL.md) — full Art. 113 & Digital Omnibus schedule
- [eu-ai-act-operator-roles](../eu-ai-act-operator-roles/SKILL.md) — deep dive into NLF operator roles

## Source of truth

EU Regulation 2024/1689 (EU AI Act) & Regulation (EU) 2026/1744 (Digital Omnibus). Install from this repo with `/plugin marketplace add Peaky8linders/antifragile-harness`, then `/plugin install antifragile-harness@antifragile-harness`, and have [uv](https://docs.astral.sh/uv/) on your PATH: the plugin starts its bundled engine with it.
