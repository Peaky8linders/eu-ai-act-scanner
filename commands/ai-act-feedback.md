---
name: ai-act-feedback
description: "Reports a wrong, missing or confusing result to the maintainers, or marks a finding as not applicable to this project. Shows everything before anything is sent."
argument-hint: "[what was wrong]"
---

# /ai-act-feedback

Help the user give feedback on a scan result. Nothing leaves the machine unless the user approves the exact text first; the scanner itself never sends anything.

1. Work out what the user is reporting from `$ARGUMENTS` and this conversation (usually the latest brief or scan). Ask one short question if it is unclear. The kinds are:
   - **False positive**: a finding that is not a problem in their code.
   - **Missed gap**: a problem the scan did not report.
   - **Confusing result**: correct, but hard to understand or act on.
   - **Install or connection problem**: for example `/mcp` shows the server as failed.

   Note the finding's title as shown, its file (path only), its area or article, and, if a detailed result is at hand, the analyzer (`component_type`).
2. **For a false positive, first offer to mark it not applicable in this project.** Add an entry to `.antifragile-harness.toml` at the project root:

   ```toml
   [[suppress]]
   title = "<text from the finding title>"
   path = "<the file, if the finding names one>"
   reason = "<the user's reason, in their words>"
   ```

   A reason is required. Show the exact lines and append them only on a yes; never rewrite or reorder the rest of the file. Then re-run the founder triage (`founder_triage(path=".")`, or `uvx --native-tls --from "${CLAUDE_PLUGIN_ROOT}" antifragile-scan . --founder`) and confirm the brief lists it as marked not applicable. Suggest committing the file, so teammates and reviewers see every exception and its reason; the release dossier records them too.
3. **Offer to tell the maintainers**, so the rule can be fixed for everyone. Draft a GitHub issue for `Peaky8linders/antifragile-harness`:
   - Title: `[false positive] <finding title>`, `[missed gap] <short summary>`, `[confusing] <short summary>` or `[install] <short summary>`.
   - Body: the kind, the finding title, the area or article, the analyzer if known, what the user expected instead and why, the plugin version (the `version` in `${CLAUDE_PLUGIN_ROOT}/.claude-plugin/plugin.json`) and the operating system.
   - A minimal, made-up example that reproduces it is the most useful part, because maintainers turn it into a benchmark case. Write it fresh; never copy the user's code.
   - Include the file path, and the reason from step 2, only if the user agrees.
   - Never include code from the project, file contents, secrets, customer or company names, internal URLs, or anything else from the conversation the user has not approved.
4. Show the complete draft and ask whether to send it. Only on a clear yes:
   - if `gh auth status` shows a signed-in account, run `gh issue create --repo Peaky8linders/antifragile-harness --title "<title>" --body-file -` with the body on stdin, and give the user the issue link;
   - otherwise give them https://github.com/Peaky8linders/antifragile-harness/issues/new/choose and the draft to paste into the matching form.
5. Say exactly what happened: what was added to `.antifragile-harness.toml`, which issue was filed, or that nothing was sent.
