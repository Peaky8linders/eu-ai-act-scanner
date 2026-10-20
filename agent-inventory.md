# Agent inventory — eu-ai-act-scanner

This is the external-action inventory for **this repository**, written to the
four facets the `agent_inventory` analyzer checks (Nannini et al. 2026,
Conclusion 3; EU AI Act Art. 11 / Annex IV; Art. 14 authority decisions;
Art. 12 record-keeping).

Reviewed: 2026-10-19 · Owner: maintainer ([@Peaky8linders](https://github.com/Peaky8linders)) · Re-review: on any new tool, writer or network path.

## 1. Autonomy

| Property | Value |
|---|---|
| Runtime posture | **Looped** — an MCP client or Claude Code session may call the 11 tools repeatedly; the engine itself is stateless per call |
| Multi-agent chaining | None inside the engine (no agent framework dependency; `agent_cascade` reports no chained agents) |
| Writes without a human decision | **None** — every writer is behind an explicit argument (`--dossier`, `--graph`, `--set`) or defaults to dry-run (`remediation_loop(apply=False)`, `eu-ai-act-fix`) |
| Stops on its own | Yes — each call returns; no background process, daemon, scheduler or listener socket |

## 2. External actions (what can touch the world)

| Action class | Where | Gate |
|---|---|---|
| `write_file` | `scanner/dossier.py` (sealed JSON dossier), `scanner/visual_graph.py` (HTML graph), `scanner/settings.py` (`--set` writes `.eu-ai-act-scanner.toml`), `scanner/fix_loop.py` (`--apply` remediations) | Explicit path/flag; fix loop is dry-run by default and reverts any fix that regresses another dimension |
| `execute_code` | `scanner/dossier.py` — `subprocess.run(["git", ...])` to bind the scanned commit into the dossier | Read-only git plumbing; no shell, no `shell=True`, argv list only |
| `read_file` | Whole scan path: walks the target tree (default 2 MB/file cap, standard exclusions) | Read-only; refuses non-directories |
| `send_email`, `authorize_payment`, `post_content`, `infra_mutation`, `modify_db` | **Not present** — no cloud/billing/social/database clients anywhere in the package | n/a |

## 3. Data flows

```
scanned repo (local)  ──►  engine (in-process)  ──►  stdout / JSON / MCP response
                                             └──►  dossier.json, context-graph.html   (explicit flags only)
```

- **No network calls, no telemetry, no phone-home** in the engine or any analyzer. CI has no step that ships source anywhere.
- **Emitted artifacts are inert.** The context graph inlines compiled CSS (no CDN) and no report embeds a remote image, script or stylesheet, so opening a scan report, dossier or graph makes no request. `tests/test_offline_artifacts.py` fails if one does, and an AST guard forbids outbound HTTP clients under `scanner/`.
- The engine never transmits scanned code. **Host client caveat:** in `assisted` mode (Claude Code) or through an MCP client, the *client* may send the files it chooses to read to its own model provider — that flow is governed by the client's policy, not by this engine. The engine's guarantee is only that *it* sends nothing.
- Credentials: none required. No API keys, no `.env` secrets read (`.env.example` only), no tokens stored.
- Maintainer-only scripts (`scripts/sync_incident_corpus.py`, `scripts/update_readme_countdown.py`) run in CI/hand and touch the vendored corpus and README — never at scan time.

## 4. Connected systems

| System | Direction | Purpose |
|---|---|---|
| Local filesystem | read + explicit writes | the scan target and the exported artefacts |
| `git` binary | read-only invocation | commit hash binding for the dossier (`AML`/provenance) |
| MCP client (stdio) | in-process pipe | `eu-ai-act-scan-mcp` — no TCP port, no listening socket |
| Claude Code | host session | slash commands, skills, assisted-mode narrative |
| HuggingFace dataset | **not at runtime** | only when a maintainer regenerates the vendored incident corpus |

## 5. Affected persons

- **Direct users:** developers, security and compliance engineers running the scan (adults, professional context).
- **Data subjects in scanned code:** the engine reads whatever the target repository contains; if that includes personal data, it stays on the operator's machine (see §3). Operators scanning personal data remain the controller for it (GDPR Art. 24 — see [adjacent-legislation.md](adjacent-legislation.md)).
- **No automated decisions about people.** The scanner produces compliance findings about *code*, never scores, profiles or decisions about individuals.
- **No minors, no biometrics, no health data, no employment decisions** are processed by this repository's own runtime.

## When this inventory must be updated

A new MCP tool, a new file writer, any network call, a new dependency that can
reach the network, or a change in the default of an existing write path. The
`agent_inventory` and `privilege_minimization` analyzers run on this repo in CI
and in the maintainer's scan, so a new action class is expected to show up as a
new finding first.
