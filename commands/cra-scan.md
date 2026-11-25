---
name: cra-scan
description: "Checks a repository for Cyber Resilience Act evidence (disclosure policy, SBOM) and explains the Art. 14 reporting deadlines. No score."
argument-hint: "[path]"
---

# /cra-scan

Check a codebase against the Cyber Resilience Act, Regulation (EU) 2024/2847. This is separate from the EU AI Act scan and does not change its results.

1. Run `uvx --native-tls --python ">=3.14" --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan "$1" --cra --markdown` (default path: the current folder).
2. Read the **Scope** section first. If it says the repository does not look like a product with digital elements, report the reasoning and the evidence paths, say that no CRA checks were run, and stop. Never give a score, a percentage or a pass/fail for it. Add that this is a repository heuristic: if the team does supply the software to others, they should treat the result as unknown.
3. Otherwise report, in this order:
   - why it looks like a product, with the evidence paths, and the caveat that scope in law also depends on facts a repository cannot show (commercial supply, the exclusions in Art. 2);
   - **what is live now:** Art. 14 reporting applies since 11 September 2026. An actively exploited vulnerability or a severe incident needs an early warning within 24 hours of becoming aware, a notification within 72 hours and a final report, sent to the coordinator CSIRT and ENISA through the single reporting platform;
   - **what applies from 11 December 2027:** the rest of the Regulation, including the two checks below;
   - each check with its id, result, citation and either the file found or the artefact that is missing: `cra-cvd-policy` (Annex I Part II(5) and (6)) and `cra-sbom` (Annex I Part II(1));
   - the "Not checked by this scan" list, so nobody reads silence as coverage.
4. If the user says they have an exploited vulnerability or a severe incident, ask when they became aware (with time zone) and which of the two it is, then run `uvx --native-tls --python ">=3.14" --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan --cra-clock "<ISO time with offset>" --cra-event actively_exploited_vulnerability --markdown` (or `--cra-event severe_incident`). For the final report add `--cra-measure-available-at "<time>"` (vulnerability) or `--cra-notification-submitted-at "<time>"` (incident). Show the dates as computed. The clock only calculates: never say that a notification was filed, is on time or is not needed.

Report only what the scanner found. Never say the product is compliant, conformant or certified, and never turn the findings into a score. Whether an event is reportable, who the coordinator CSIRT is and how periods are counted are questions for counsel. The scan runs locally and never uploads code.
