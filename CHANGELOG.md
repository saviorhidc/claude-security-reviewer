# Changelog

All notable changes to this project are documented here.

## [1.0.0] — 2026-05-09

### Agent

- **`security-reviewer`** — General-purpose security reviewer for web projects (Node, Python, Go, Rust, Java). Pinned to `claude-sonnet-4-6`. Scoped Bash tools: `git diff:*`, `git status:*`, `git log:*`, `git ls-files:*`, `npm audit:*`, `pip-audit:*`, `cargo audit:*`, `gitleaks:*`, `semgrep:*`. Diff Review mode for PRs and incremental changes; Deployment Review mode for pre-production pushes. `SECURITY_REVIEW_FAILED` sentinel for CI and deployment gates. Prompt-injection defense section.

### Skill

- **`security-checklist`** — 15-point stack-agnostic security baseline: secrets, auth, authorization (IDOR/BOLA), input validation, SQL injection, XSS, CSRF, security headers, rate limiting, CORS, cookies, dependencies, file uploads, SSRF, logging and error handling. Code examples for Node + Express, Python + Flask, Go `net/http`.

### Eval suite

- `evals/skill-trigger/trigger-prompts.md` — 15 labelled prompts (10 should-trigger, 5 should-not-trigger).
- `evals/security/nodejs-vulnerable.md` — 15 vulnerable Node 20 + Express 4 snippets.
- `evals/security/python-vulnerable.md` — 15 vulnerable Python 3.12 + Flask / FastAPI snippets.
- `evals/security/go-vulnerable.md` — 10 vulnerable Go 1.22 + `net/http` snippets.
- `evals/security/generic-vulnerable.md` — 10 framework-agnostic config, SQL, shell, and CI snippets.
- `evals/README.md` — manual run instructions, results table, coverage matrix.

### Examples

- `examples/minimal-express-api/` — Node 20 + Express 4 vulnerable API. 11 expected findings across 7 checklist sections. README with expected-findings table.
- `examples/minimal-flask-api/` — Python 3.12 + Flask 3 vulnerable API. 11 expected findings across 7 checklist sections. README with expected-findings table.

### Plugin manifest and CI

- `.claude-plugin/plugin.json` — plugin manifest (name, version, description, author, license, homepage, repository, keywords).
- `.github/workflows/ci.yml` — frontmatter validation for skills and agents; `plugin.json` schema check.

### Documentation

- `README.md` — plugin install (primary), manual copy and symlink (fallbacks), Windows PowerShell path, stack compatibility table, eval coverage summary.
- `SECURITY.md` — vulnerability disclosure policy.
- `CONTRIBUTING.md` — PR checklist for skills, agents, and evals.
- `CHANGELOG.md` — this file.
- `LICENSE` — MIT.
