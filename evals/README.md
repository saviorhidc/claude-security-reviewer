# Evals

This directory contains evaluation corpora for testing skill activation and security-reviewer detection accuracy.

## Structure

```
evals/
├── README.md                         (this file)
├── skill-trigger/
│   └── trigger-prompts.md            15 labelled prompts — 10 should fire security-checklist, 5 should not
└── security/
    ├── nodejs-vulnerable.md          15 vulnerable Node 20 + Express 4 snippets
    ├── python-vulnerable.md          15 vulnerable Python 3.12 + Flask / FastAPI snippets
    ├── go-vulnerable.md              10 vulnerable Go 1.22 + net/http snippets
    └── generic-vulnerable.md         10 framework-agnostic config / SQL / shell / CI snippets
```

## Running Evals

Evals are manual — there is no automated harness. Run each prompt or snippet by hand and record the outcome.

### Skill-trigger eval

1. Open a fresh Claude Code session with this plugin installed.
2. Paste the `Input` from each prompt in `skill-trigger/trigger-prompts.md`.
3. Note which skill (if any) auto-activates.
4. Compare against `Expected skill`.
5. Record the result in the tracking table at the bottom of the trigger-prompts file.

A regression means: wrong skill activated, no skill activated when one was expected, or a skill activated when none was expected.

### Security corpus eval

1. Run the `security-reviewer` agent in Deployment Review mode against one of the `security/*.md` files, or paste individual snippets into a review session.
2. For each snippet, the agent should produce at minimum the finding annotated in the `// EXPECTED:` (or `# EXPECTED:` / `-- EXPECTED:`) comment.
3. Record findings in the results table below.

### Results Table

Record results after each eval run:

| Date | File | Snippet # | Expected severity | Expected category | Agent reported? | Pass/Fail | Notes |
|------|------|-----------|-------------------|-------------------|-----------------|-----------|-------|
| YYYY-MM-DD | nodejs-vulnerable.md | 1 | Critical | SecretsExposure | Yes | PASS | |
| YYYY-MM-DD | python-vulnerable.md | 5 | Critical | InputValidation | Yes | PASS | |
| YYYY-MM-DD | go-vulnerable.md | 3 | Critical | SQLInjection | Yes | PASS | |
| YYYY-MM-DD | generic-vulnerable.md | 4 | Critical | SecretsExposure | Yes | PASS | |

Track two metrics over time:
- **Recall** — percentage of EXPECTED findings the agent surfaces
- **Precision** — percentage of agent findings that match the corpus (versus noise)

## Coverage at v1.0.0

### Skill-trigger coverage

`security-checklist` skill trigger: 15 prompts (10 should-trigger / 5 should-not-trigger). All 15 directly address the skill's described scope or are clean misses.

### Security corpus coverage

The 15-section checklist is the reference:

| Section | Node.js | Python | Go | Generic |
|---------|---------|--------|----|---------|
| §1 SecretsExposure | snippet 1 | snippet 1 | snippet 1 | snippets 1, 4 |
| §2 MissingAuthentication | snippet 2 | snippet 2 | snippet 2 | — |
| §3 BrokenAuthorization | snippet 3 | snippet 3 | snippet 4 | snippets 6, 10 |
| §4 InputValidation | snippet 6 | snippets 5, 6 | — | — |
| §5 SQLInjection | snippets 4, 5 | snippet 4 | snippet 3 | — |
| §6 XSS | snippet 7 | snippet 7 | — | — |
| §7 CSRF | snippet 8 | snippet 8 | — | — |
| §8 MissingSecurityHeaders | snippet 15 | snippet 11* | snippet 6 | snippets 3, 8 |
| §9 WeakRateLimiting | snippet 10 | snippet 10 | snippet 10 | — |
| §10 CORSMisconfiguration | snippet 9 | snippet 9 | snippet 5 | snippet 5 |
| §11 InsecureCookie | snippet 11 | snippet 11 | snippet 8 | — |
| §12 DependencyVulnerability | — | — | — | snippets 2, 7 |
| §13 InsecureFileUpload | snippet 13 | snippet 13 | — | — |
| §14 SSRF | snippet 12 | snippet 12 | snippet 7 | — |
| §15 ErrorLeakage / LoggingPII | snippet 14 | snippet 15 | snippet 9 | snippet 9 |

\* Python snippet 11 covers InsecureCookie (SESSION_COOKIE_SECURE=False); §8 MissingSecurityHeaders for Python is covered by the generic corpus.

**Stacks fully covered at v1.0.0:** Node.js (all 15 sections represented across 15 snippets), Python (all 15 sections represented across 15 snippets), Generic config/infra (10 snippets covering 9 sections).

**Stacks partially covered at v1.0.0:** Go — 10 snippets covering 10 sections. The following checklist sections do not yet have Go-idiomatic snippets: §6 XSS (Go `html/template` is safe-by-default so the failure mode is `text/template` — to be added), §7 CSRF (gorilla/csrf is the standard fix — missing snippet), §12 DependencyVulnerability (`go.sum` missing from git), §13 InsecureFileUpload. These will be added in a future release.

## Adding New Snippets

1. Add the snippet to the appropriate file under `security/`.
2. Follow the `### N. <short title>` format with a one-line description.
3. Include an EXPECTED comment (`// EXPECTED:`, `# EXPECTED:`, or `-- EXPECTED:`) at the top of the code block.
4. Use a severity from: `Critical`, `High`, `Medium`, `Low`.
5. Use a category from the controlled vocabulary: `SecretsExposure`, `MissingAuthentication`, `BrokenAuthorization`, `InputValidation`, `SQLInjection`, `XSS`, `CSRF`, `MissingSecurityHeaders`, `WeakRateLimiting`, `CORSMisconfiguration`, `InsecureCookie`, `DependencyVulnerability`, `InsecureFileUpload`, `SSRF`, `ErrorLeakage`, `LoggingPII`.
6. Run the snippet through the agent and record the initial result in the results table above.
