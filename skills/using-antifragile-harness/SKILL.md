---
name: using-antifragile-harness
description: "Runs the EU AI Act scanner on a codebase and explains the results. Use when asked to scan, audit or check a repo for EU AI Act compliance."
user_invocable: true
---

# Using the Antifragile Harness

Route the request to the right command, then keep the answer short and in plain language.

| The user says | Run |
|---|---|
| "do we need to care?", "what blocks launch?", founder or startup questions | `/ai-act-quickstart` |
| "scan", "audit", "check compliance", "where are our gaps" | `/ai-act-scan` |
| "fix the gaps", "make us compliant" | `/ai-act-scan-fix` (add `--startup` for startups) |
| "review this branch for security", has a claude-security / SARIF report | `/ai-act-security-review` |
| "what about SOC 2 / ISO / NIST / GDPR?" | `/ai-act-cross-framework` |
| names an article | `/ai-act-article <art>` or the [eu-ai-act-reference](../eu-ai-act-reference/SKILL.md) skill |
| "what does this result mean?", "are we compliant?" | [interpreting-findings](../interpreting-findings/SKILL.md) |
| "are we high-risk?", "is this banned?", "do we need a FRIA?" | [article-6](../eu-ai-act-article-6-classification/SKILL.md), [article-5](../eu-ai-act-article-5-prohibited/SKILL.md), [FRIA](../eu-ai-act-fria-guide/SKILL.md) skills |

Before scanning, confirm the path if it is ambiguous; never guess one.

After scanning, lead with what to do, not with the full output. The scan covers 23 areas visible in code and configuration; it is evidence for people to review, not a compliance verdict.

**Escalate** when the overall score is below 30% and the user describes a high-risk (Annex III) use: say plainly that static analysis cannot establish compliance, and that a high-risk system needs a documented risk management system, technical documentation, human oversight and a conformity assessment before it can be placed on the EU market.

Common misreadings to correct:

- "The scan passed, so we're compliant." Compliance is a legal determination (Art. 43); the scan shows technical evidence only.
- "80% is great, ship it." A score says nothing about areas the scan cannot see (policies, contracts, training, real-world use).
- "We just call OpenAI's API, so the AI Act doesn't apply." That usually makes you a deployer (Art. 26 and Art. 50 duties), not exempt.
