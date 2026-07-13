---
name: ai-act-settings
description: View or change the scanner's settings — mode (deterministic vs assisted) and auto_apply. Assisted mode lets the plugin use your own Claude Code for semantic scanning, grounded Q&A, and applying fixes.
---

# /ai-act-settings

View or change how much the scanner leans on your own Claude Code.

## Behaviour

1. To show the current settings:
   ```bash
   python -m scanner.cli --settings
   ```
   Reports `mode`, `auto_apply`, where the values came from (`source`), and the
   optional headless LLM-bridge config.
2. To change a setting, persist it to `.eu-ai-act-scanner.toml` in the project
   root:
   ```bash
   python -m scanner.cli --set mode=assisted
   python -m scanner.cli --set auto-apply=true
   ```
   `--set` is repeatable; invalid values are rejected.

## Settings

- **`mode`**
  - `deterministic` (default) — pure static analysis. No LLM, no network, no
    telemetry.
  - `assisted` — **use your own Claude Code power.** The slash commands drive
    this Claude Code session to run a semantic pass over the deterministic
    findings (`/ai-act-scan`), answer grounded questions (`/ai-act-ask`), and
    apply fixes (`/ai-act-scan-fix`). No API key and no wrapper are needed — the
    plugin already runs inside your Claude Code.
- **`auto_apply`** (default `false`) — in `assisted` mode, let `/ai-act-scan-fix`
  apply approved edits directly with your own edit tools instead of only
  proposing them. A scan is never destructive unless you opt in.

## Notes

- The deterministic scanner output is always the objective baseline; assisted
  mode augments it, never overwrites the scores.
- The headless wrapper bridge (`EU_AI_ACT_SCANNER_LLM=…`, `--llm-status`) is a
  separate path for running the CLI outside Claude Code; it is **not** required
  for assisted mode.
