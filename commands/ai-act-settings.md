---
name: ai-act-settings
description: "Shows or changes scanner settings (mode and auto-apply)."
argument-hint: "[mode=deterministic|assisted] [auto-apply=true|false]"
# Only the user changes settings; keep it out of the model's skill listing.
disable-model-invocation: true
---

# /ai-act-settings

1. Show the current settings with `antifragile-scan --settings`.
2. To change one, run `antifragile-scan --set mode=assisted` or `antifragile-scan --set auto-apply=true` (repeatable). Values are saved to `.antifragile-harness.toml` in the project.

- `mode`: `deterministic` (default) presents the scanner's findings as they are. `assisted` lets the commands use this Claude Code session for extra review and fix design; the scanner's scores stay the baseline.
- `auto_apply` (default `false`): in assisted mode, lets `/ai-act-scan-fix` apply an approved plan without asking per fix.
