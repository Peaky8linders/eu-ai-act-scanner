# AI Startup Security Scan Instructions

Reusable diff-aware security review rules for AI codebases, consumable by both:
- **`/ai-act-security-review`** (built into the `antifragile-harness` plugin)
- **`anthropics/claude-code-security-review`** (copy or reference as `.claude/security-scan-instructions.md`)

Report every confirmed finding with:
- **File + line number**
- **Category** (from the 10 classes below)
- **Severity**: Critical / High / Medium / Low
- **EU AI Act article & dimension** where applicable

Pair with `templates/false-positive-filter.md` to eliminate test/fixture/build-artifact noise.

---

## 1. EU AI Act Art. 15(4)-(5) — AI robustness & runtime resilience gaps

Inspect AI/LLM inference routes and agent entrypoints for:
- Untrusted user or third-party inputs passed directly to model or tool calls without validation or length/schema bounds
- Model outputs executed, queried, or rendered directly without schema validation, escaping, or error handling
- LLM/embedding API calls missing explicit timeouts, retry bounds, or circuit breakers

## 2. Prompt injection & indirect prompt injection vectors

Inspect prompt builders, RAG pipelines, and tool outputs for:
- Untrusted user input or retrieved external documents interpolated directly into `system` prompts (`f"..."`, `.format()`, `%`, template literals)
- External web/email/ticket/document content fed into an agent context alongside privileged write tools without boundary separation or output validation
- Missing structural separation between trusted system instructions and untrusted data

## 3. MCP & Claude Code configuration security

Inspect `.mcp.json`, MCP server implementations, and `.claude/settings*.json` for:
- **Hardcoded secrets** inside `.mcp.json` `env` blocks instead of runtime environment references
- **Unpinned MCP server launches** (`npx -y`, unpinned `uvx`, floating `@latest` tags)
- **Unauthenticated or SSRF-exposed MCP endpoints** (binding `0.0.0.0` without auth, or fetching user-controlled URLs without blocking `169.254.169.254` / RFC1918 private IPs)
- **Tool description poisoning** (hidden directives in MCP tool descriptions instructing the model to exfiltrate files or ignore constraints)
- **Over-privileged Claude Code settings** (`"defaultMode": "bypassPermissions"`, `"allow": ["Bash(*)"]`, or unreviewed shell hooks)

## 4. Hardcoded credentials & secrets

Flag live source or config files containing:
- Provider/cloud token prefixes: `sk-`, `sk-ant-`, `AKIA`, `ghp_`, `gho_`, `glpat-`, `xoxb-`, `xoxp-`, `AIza`
- Private key headers (`-----BEGIN ... PRIVATE KEY-----`)
- Literal secret assignments (`api_key = "..."`, `password = "..."`, `secret = "..."`, `token = "..."`) that do not read from environment variables or a secrets manager

## 5. Command injection & unsafe subprocess calls

Flag:
- `subprocess.run(..., shell=True)`, `subprocess.Popen(..., shell=True)`, `os.system(...)`, `os.popen(...)`, Node `child_process.exec(...)` where any argument can be influenced by user or LLM output
- Unvalidated command execution spawned from agent tool calls without an explicit command allowlist and resolved executable path (`shutil.which`)

## 6. Insecure deserialization & dynamic code execution

Flag:
- `eval(...)`, `exec(...)`, or `Function(...)` called on model-generated or user-supplied strings
- `pickle.loads(...)` / `joblib.load(...)` on untrusted or externally fetched bytes
- `torch.load(...)` without `weights_only=True`
- `yaml.load(...)` without `Loader=yaml.SafeLoader` (use `yaml.safe_load`)

## 7. Lethal trifecta & unbounded agent loops

Flag agent architectures that combine all three without an explicit human approval gate or isolation boundary:
1. Access to private data / credentials / internal APIs
2. Exposure to untrusted external content (web, email, user uploads, third-party APIs)
3. Ability to trigger external side effects (sending messages, webhooks, writes, shell execution)

Also flag recursive or multi-step agent/subagent loops lacking a hard `max_iterations` / `max_steps` ceiling or token/cost budget cap.

## 8. AI supply-chain risks

Flag:
- Unpinned ML/AI dependencies (`>=` without lockfile, floating git branches) or unpinned Docker base images (`:latest`)
- Unpinned GitHub Actions (`uses: org/action@main` instead of commit SHA or pinned release)
- Downloading remote model weights or hub artifacts (`trust_remote_code=True`) without commit-SHA pinning

## 9. Auth, SSRF & tenant isolation on AI endpoints

Flag:
- AI-serving HTTP/RPC endpoints missing authentication or authorization middleware
- RAG vector queries or memory stores missing tenant/user scoping filters (cross-tenant data leakage)
- Server-side URL fetching (e.g., web-reader or MCP fetch tools) that does not block link-local/metadata (`169.254.169.254`) and internal network addresses

## 10. Silenced errors & missing audit trails in AI paths

Flag:
- Bare `except: pass` or `except Exception: pass` swallowing failures in auth, safety-filter, or AI-guardrail paths without logging
- Production AI decision/tool-execution paths that emit no structured audit record (timestamp, correlation/session ID, model/tool invoked) — needed for EU AI Act Art. 12 and SOC 2 CC7.2
