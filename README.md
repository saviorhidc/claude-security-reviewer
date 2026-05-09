# claude-security-reviewer

An opinionated security review checklist for web projects — sharing in case it's useful.

> Built by [saviorhidc](https://github.com/saviorhidc). Companion to [saviorhidc/claude-web-design-skills](https://github.com/saviorhidc/claude-web-design-skills) — for frontend-specific (Next.js, Supabase, Vercel, React) security review, use that pack instead.

---

## Why This Exists

AI code generators have predictable failure modes. The same mistakes appear across tools and languages: hardcoded API keys and database URLs, authentication middleware that's present on 90% of routes and missing on the one that matters, SQL queries built with template literals or f-strings, record fetches that check `id` but not `user_id`. These aren't edge cases — they're the defaults when a language model fills in a route handler without a specific prompt to do otherwise.

The design pack's `security-reviewer` agent was built to catch these patterns in Next.js + Supabase projects. It works well there, but it's too narrowly scoped for anything else — it references Supabase RLS, Next.js middleware, `NEXT_PUBLIC_` prefixes, and Vercel-specific deploy headers. Running it against a Flask API or a Go service produces guidance that doesn't apply.

This standalone is the stack-agnostic version of that agent. It reads any web codebase — Node, Python, Go, Rust, Java, or framework-agnostic config files — and runs the same checklist-driven review. The 15-point checklist covers the vulnerabilities that AI tools introduce most often. The agent runs in two modes: Diff Review for PRs and incremental changes, Deployment Review before pushing to production.

If you only build Next.js + Supabase apps, the design pack's `frontend-security-reviewer` is a better fit. If you build anything else — backend services, APIs, infra scripts — this is the one.

---

## What's in the Box

| Component | What it does |
|-----------|-------------|
| `security-reviewer` (agent) | Reviews any web codebase against the 15-point checklist. Diff Review for PRs, Deployment Review before pushing prod. Outputs Critical/High/Medium/Low findings with file:line. Pinned to `claude-sonnet-4-6`. |
| `security-checklist` (skill) | The 15-point baseline as a reference skill. Auto-triggers on prompts about API routes, auth flows, DB queries, deploy prep. |

### The 15 checklist sections

| Section | Topic |
|---------|-------|
| §1 | Secrets Exposure |
| §2 | Authentication |
| §3 | Authorization (IDOR / BOLA) |
| §4 | Input Validation |
| §5 | SQL Injection |
| §6 | XSS Prevention |
| §7 | CSRF Protection |
| §8 | Security Headers |
| §9 | Rate Limiting |
| §10 | CORS |
| §11 | Cookies |
| §12 | Dependencies |
| §13 | File Uploads |
| §14 | SSRF |
| §15 | Logging and Error Handling |

The checklist is language-neutral. Code examples in the skill lean toward Node, Python, and Go — those are where most AI codegen lands — but the same principles apply across stacks.

---

## What it Does NOT Cover

- **Frontend-specific concerns** — Next.js middleware, Supabase RLS (`USING` vs `WITH CHECK`, `auth.jwt()`, `service_role`), React `dangerouslySetInnerHTML`, Vercel deploy headers, RSC server boundary, `NEXT_PUBLIC_` prefix leaks. Use [`saviorhidc/claude-web-design-skills`](https://github.com/saviorhidc/claude-web-design-skills) for those.
- **Mobile app security** — Android, iOS, React Native. Out of scope.
- **Containers and Kubernetes** — Dockerfile hardening beyond a single non-root user check, K8s RBAC, pod security policies. Out of scope.
- **Cloud provider IAM** — AWS, GCP, Azure-specific permission models. Too provider-specific for a stack-agnostic baseline.
- **Compliance frameworks** — SOC2, PCI-DSS, HIPAA. The checklist is technical, not compliance-mapped.
- **Auto-fixing** — The agent reports findings. Humans fix them.
- **Full SAST replacement** — This is a checklist-driven Claude agent, not Snyk or Semgrep. The agent invokes `semgrep` and `gitleaks` when useful but does not reimplement static analysis.

---

## Installation

> **Security note:** Skills are markdown that materially influence Claude's behavior — they are system-prompt-equivalent. Read `agents/security-reviewer.md` and `skills/security-checklist/SKILL.md` before copying anything into your Claude config. Pin to the latest tag (`git checkout $(git describe --tags --abbrev=0)`) rather than tracking `main` so a future repo change can't silently rewrite your installed content on the next `git pull`.

### Option A: Plugin install (recommended)

Plugin install enables updates via `claude plugin update .` and avoids name collisions with global skills.

```bash
git clone https://github.com/saviorhidc/claude-security-reviewer.git
cd claude-security-reviewer
claude plugin install .
```

### Option B: Manual copy (fallback)

```bash
git clone https://github.com/saviorhidc/claude-security-reviewer.git
cd claude-security-reviewer

# Copy skill to global Claude skills directory
cp -r skills/security-checklist ~/.claude/skills/

# Copy agent to your project's agents directory
cp agents/security-reviewer.md .claude/agents/
```

### Option C: Symlink (keeps content auto-updating when you `git pull`)

```bash
# macOS / Linux — per-skill symlink
git submodule add https://github.com/saviorhidc/claude-security-reviewer.git .security-reviewer
cd .security-reviewer
ln -sf "$(pwd)/skills/security-checklist" ~/.claude/skills/security-checklist
```

### Windows (PowerShell) — Option B equivalent

```powershell
git clone https://github.com/saviorhidc/claude-security-reviewer.git
cd claude-security-reviewer

# Copy skill to global Claude skills directory
Copy-Item -Recurse -Path skills\security-checklist -Destination "$HOME\.claude\skills\security-checklist" -Force

# Copy agent to your project's .claude/agents directory (create it first if needed)
New-Item -ItemType Directory -Force -Path .claude\agents
Copy-Item agents\security-reviewer.md -Destination .claude\agents\ -Force
```

### Verify installation

**Confirm the plugin is registered:**

```bash
claude plugin list
# Expected: claude-security-reviewer listed
```

**Smoke test:** Open a new Claude Code session and ask:

> "Review this Express route for security issues."

If `security-checklist` is active, Claude will work through the checklist sections rather than giving a freeform answer.

> **User vs project scope:** Skills install to `~/.claude/skills/` (global — available across all Claude Code sessions). The `security-reviewer` agent installs to `.claude/agents/` (per-project — intentional: different projects may want different review depth, output format, or tool permissions). Copy the agent to each project where you want it.

---

## Stack Compatibility

| Stack | Status |
|-------|--------|
| Node.js (Express, Fastify, Hono, raw `http`) | Tested in eval corpus and minimal example |
| Python (Flask, FastAPI, Django) | Tested in eval corpus and minimal example |
| Go (`net/http`, gorilla/mux, chi) | Partial coverage in eval corpus |
| Rust (axum, actix-web) | Patterns apply; no targeted corpus yet |
| Java (Spring Boot) | Patterns apply; no targeted corpus yet |
| Generic / framework-agnostic | Config files, SQL, shell scripts, CI workflows covered |

The 15-point checklist is language-neutral. The eval corpus and skill code examples lean toward Node + Python + Go — those stacks cover most of the AI-codegen volume. The same checklist items apply to Rust and Java; they just haven't been validated against a targeted snippet corpus yet.

See [`evals/README.md`](./evals/README.md) for coverage detail per section and per stack.

---

## Eval Suite

The `evals/` directory contains 15 labelled skill-trigger prompts (10 should activate `security-checklist`, 5 should not) and 50 vulnerable code snippets across four stacks (Node, Python, Go, generic). Each snippet is annotated with expected findings and severity.

Evals are manual — paste a snippet or prompt into a Claude Code session with the plugin installed and compare output to expectations.

Coverage at v1.0.0: Node.js and Python are fully covered (all 15 checklist sections represented). Go has 10 snippets covering 10 sections; four sections (XSS, CSRF, file uploads, dependency lockfile) are not yet covered with Go-idiomatic examples. See the coverage matrix in [`evals/README.md`](./evals/README.md).

---

## Examples

Two minimal projects in `examples/` — each is a deliberately vulnerable API with a `before/` directory containing broken code.

- [`examples/minimal-express-api/`](./examples/minimal-express-api/) — Node 20 + Express 4. 11 expected findings across 7 checklist sections.
- [`examples/minimal-flask-api/`](./examples/minimal-flask-api/) — Python 3.12 + Flask 3. 11 expected findings across 7 checklist sections.

Each has a README with an expected-findings table (file, line, severity, category, checklist section). Use them as smoke tests: run `security-reviewer` in Deployment Review mode against the `before/` directory and check that it surfaces at least 80% of the expected findings.

There is no `after/` directory. The agent's fix recommendations are the after — see the report output.

---

## Credits

- Checklist grounded in [OWASP Top 10](https://owasp.org/www-project-top-ten/) and [OWASP API Security Top 10](https://owasp.org/API-Security/).
- Structure inspired by [forrestchang/andrej-karpathy-skills](https://github.com/forrestchang/andrej-karpathy-skills).
- Companion to [saviorhidc/claude-web-design-skills](https://github.com/saviorhidc/claude-web-design-skills).

---

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). For security disclosures, see [`SECURITY.md`](./SECURITY.md).

### Formatting

```bash
npx prettier --write "**/*.md"
npx markdownlint "**/*.md" --ignore node_modules
```

---

## License

MIT — see [`LICENSE`](./LICENSE).
