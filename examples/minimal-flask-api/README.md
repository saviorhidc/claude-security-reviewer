# minimal-flask-api

A deliberately vulnerable Flask API used as a regression target for `security-reviewer`. Don't deploy it. Don't copy patterns from it. It exists so the reviewer has something concrete to run against.

Stack: Python 3.12, Flask 3, `psycopg2-binary`, `flask-cors`. No `@login_required`, no `flask-limiter`, no `flask-talisman`, no parameterized queries where it counts.

---

## Run it (optional)

Running the app is not required — the reviewer reads source files, not a live server. If you want to spin it up anyway:

```sh
cd before
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
python app.py
```

You'll need a local Postgres instance. Copy `.env.example` to `.env` and adjust. The app listens on port 3000 by default.

---

## Expected findings

Run `security-reviewer` against the `before/` directory. It should surface at least 8 of the 10 findings below (≥80% recall = passing).

| File | Finding | Severity | Category | Checklist section |
|------|---------|----------|----------|-------------------|
| `before/db.py:6` | Hardcoded DB password in source | Critical | SecretsExposure | §1 Secrets Exposure |
| `before/routes/admin.py:10` | No auth check on `GET /admin/users` | Critical | MissingAuthentication | §2 Authentication |
| `before/routes/orders.py:20` | f-string SQL injection via `order_id` | Critical | SQLInjection | §5 SQL Injection |
| `before/routes/orders.py:29` | Order returned without ownership check (IDOR) | Critical | BrokenAuthorization | §3 Authorization |
| `before/routes/auth.py:29` | Plaintext password comparison — credentials stored/compared in cleartext | Critical | SecretsExposure | §1 Secrets Exposure |
| `before/app.py:16` | CORS wildcard origin + `supports_credentials=True` | High | CORSMisconfiguration | §10 CORS |
| `before/app.py:26` | Session cookie missing `Secure` and `SameSite` flags | High | InsecureCookie | §11 Cookies |
| `before/routes/auth.py:12` | No rate limiting on login endpoint | High | WeakRateLimiting | §9 Rate Limiting |
| `before/app.py:31` | `MAX_CONTENT_LENGTH` not set — unbounded request body | Medium | InputValidation | §4 Input Validation |
| `before/app.py:46` | Error handler returns `str(e)` and full traceback | Medium | ErrorLeakage | §15 Logging & Error Handling |

Category values are from the controlled vocabulary in `evals/security/python-vulnerable.md`.

---

## How to use this

Point the reviewer at the `before/` directory in Deployment Review mode:

```
Run security-reviewer against examples/minimal-flask-api/before/ in Deployment Review mode.
```

Compare the report it produces to the table above. Count how many expected findings appear in the output. A result of 8 or more out of 10 is a pass. Anything below 6 is a regression worth investigating.

If a finding is present but described differently (different severity, different file line), that counts as a hit for recall purposes — you're testing whether the reviewer detects the class of vulnerability, not whether it produces word-for-word identical output.

---

## No `after/`?

There is no `after/` directory. The security-reviewer's report is the after. The point of this example is to give the reviewer a target with known vulnerabilities, run it, and see how many it catches. Producing a fixed version of the code is useful for learning but it's not what this project is for — the fixes are in the report itself (see the Fix recommendation for each finding).

If you want to see what the fixed code looks like, the `security-reviewer` agent gives a specific fix recommendation for each finding. Apply them and re-run the review.
