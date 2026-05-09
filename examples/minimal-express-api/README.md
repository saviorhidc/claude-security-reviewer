# minimal-express-api

A deliberately vulnerable Express API used as a regression target for `security-reviewer`. Don't deploy it. Don't copy patterns from it. It exists so the reviewer has something concrete to run against.

Stack: Node 20, Express 4, `pg` (node-postgres). No authentication middleware, no helmet, no rate limiter, no parameterized queries where it counts.

---

## Run it (optional)

Running the app is not required — the reviewer reads source files, not a live server. If you want to spin it up anyway:

```sh
cd before
npm install
node server.js
```

You'll need a local Postgres instance. Copy `.env.example` to `.env` and adjust. The app listens on port 3000 by default.

---

## Expected findings

Run `security-reviewer` against the `before/` directory. It should surface at least 8 of the 10 findings below (≥80% recall = passing).

| File | Finding | Severity | Category | Checklist section |
|------|---------|----------|----------|-------------------|
| `before/db.js:7` | Hardcoded DB password in source | Critical | SecretsExposure | §1 Secrets Exposure |
| `before/routes/admin.js:9` | No auth check on `GET /admin/users` | Critical | MissingAuthentication | §2 Authentication |
| `before/routes/orders.js:17` | Template-literal SQL injection via `req.params.id` | Critical | SQLInjection | §5 SQL Injection |
| `before/routes/orders.js:26` | Order returned without ownership check (IDOR) | Critical | BrokenAuthorization | §3 Authorization |
| `before/routes/auth.js:28` | Plaintext password comparison — credentials stored/compared in cleartext | Critical | SecretsExposure | §1 Secrets Exposure |
| `before/server.js:13` | CORS wildcard origin + `credentials: true` | High | CORSMisconfiguration | §10 CORS |
| `before/routes/auth.js:37` | Session cookie missing `httpOnly`, `secure`, `sameSite` | High | InsecureCookie | §11 Cookies |
| `before/routes/auth.js:10` | No rate limiting on login endpoint | High | WeakRateLimiting | §9 Rate Limiting |
| `before/server.js:1` | No security headers middleware (no helmet, no CSP, no HSTS) | Medium | MissingSecurityHeaders | §8 Security Headers |
| `before/server.js:20` | Body parser limit set to 50 MB | Medium | InputValidation | §4 Input Validation |
| `before/server.js:32` | Error handler returns `err.message` and `err.stack` | Medium | ErrorLeakage | §15 Logging & Error Handling |

Category values are from the controlled vocabulary in `evals/security/nodejs-vulnerable.md`.

---

## How to use this

Point the reviewer at the `before/` directory in Deployment Review mode:

```
Run security-reviewer against examples/minimal-express-api/before/ in Deployment Review mode.
```

Compare the report it produces to the table above. Count how many expected findings appear in the output. A result of 9 or more out of 11 is a pass. Anything below 7 is a regression worth investigating.

If a finding is present but described differently (different severity, different file line), that counts as a hit for recall purposes — you're testing whether the reviewer detects the class of vulnerability, not whether it produces word-for-word identical output.

---

## No `after/`?

There is no `after/` directory. The security-reviewer's report is the after. The point of this example is to give the reviewer a target with known vulnerabilities, run it, and see how many it catches. Producing a fixed version of the code is useful for learning but it's not what this project is for — the fixes are in the report itself (see the Fix recommendation for each finding).

If you want to see what the fixed code looks like, the `security-reviewer` agent gives a specific fix recommendation for each finding. Apply them and re-run the review.
