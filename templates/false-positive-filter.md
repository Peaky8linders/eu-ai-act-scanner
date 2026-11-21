# AI Startup False-Positive Filter

Universal suppression rules for security reviews, consumable by both:
- **`/ai-act-security-review`** (built into `eu-ai-act-scanner`)
- **`anthropics/claude-code-security-review`** (copy or reference as `.claude/false-positive-filter.md`)

When reviewing candidate findings, **suppress** (do not report as confirmed vulnerabilities) the categories below unless the finding demonstrates a concrete production exploit path outside the suppressed scope.

---

## 1. Test, fixture, and spec files

**Suppress findings in:**
- `tests/`, `test/`, `__tests__/`, `specs/`, `fixtures/`, `testdata/`, `test_data/` (any depth)
- `test_*.py`, `*_test.py`, `conftest.py`
- `*.test.js`, `*.test.ts`, `*.test.tsx`, `*.spec.js`, `*.spec.ts`

**Reason:** Test suites intentionally contain mock API keys, synthetic prompt-injection payloads, intentional error paths, and `pickle`/`eval` fixtures to verify security controls.

---

## 2. Example, demo, and evaluation harness files

**Suppress findings in:**
- `examples/`, `example/`, `demo/`, `demos/`, `evals/`, `benchmarks/` (any depth)
- Files ending in `_example.py`, `_demo.py`, `.example.ts`, `.demo.ts`

**Reason:** Developer examples and offline evaluation harnesses are not deployed to production runtime surfaces. Flag only if an example is explicitly imported by production code.

---

## 3. Environment templates and documentation

**Suppress findings in:**
- `.env.example`, `.env.template`, `.env.sample`
- `docs/`, `README.md`, `CHANGELOG.md`, `*.md` prose examples (unless a real production credential with a valid provider prefix and high entropy is pasted in)

**Reason:** Placeholder keys (`sk-your-key-here`, `CHANGE_ME`, `${OPENAI_API_KEY}`) and prose examples are intentional developer documentation, not leaked credentials.

---

## 4. Static-analysis rule tables and detector definitions

**Suppress findings in:**
- Regex tables, YARA/Semgrep rules, security scanner pattern definitions, or allowlist/denylist strings that *describe* dangerous APIs (`"eval("`, `"shell=True"`, `"pickle.loads"`, `"sk-"`) without executing them.

**Reason:** Security tools and guardrails necessarily reference exploit signatures as data literals.

---

## 5. Database migration scripts

**Suppress findings in:**
- `migrations/`, `alembic/versions/`, `prisma/migrations/`, `db/migrate/` (any depth)

**Reason:** Schema migrations run under operator supervision during deployments and legitimately contain raw SQL statements and DDL strings.

---

## 6. Generated build and vendor artifacts

**Suppress findings in:**
- `dist/`, `build/`, `node_modules/`, `.next/`, `.nuxt/`, `.vite/`, `.venv/`, `venv/`, `__pycache__/`, `coverage/`, `*.min.js`, `*.bundle.js`

**Reason:** Generated bundles and third-party vendor trees produce minified false positives; fix vulnerabilities at the source file or dependency lockfile instead.

---

## 7. Already-mitigated global middleware controls

**Suppress findings for:**
- Missing per-route rate limiting or request-size caps **only when** you have verified by reading the application entrypoint that global rate-limiting / body-size middleware is actively registered and not bypassed on the flagged route.
- Missing per-route authentication on explicitly public endpoints (e.g., `/health`, `/healthz`, `/ready`, `/metrics` on internal-only ports, or public OAuth callback/login routes).

**Reason:** Avoid noisy duplicate findings when verified application-level middleware already enforces the control.
