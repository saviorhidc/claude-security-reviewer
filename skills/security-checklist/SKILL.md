---
name: security-checklist
description: Stack-agnostic security baseline for web projects — secrets, auth, authorization, input validation, SQL injection, XSS, CSRF, headers, rate limiting, CORS, cookies, dependencies, file uploads, logging hygiene, error handling, SSRF, pre-deploy gates. Use when reviewing or writing API routes, auth flows, database queries, or preparing any web project for deploy.
---

# Security Checklist

An opinionated security baseline I built for my own web work — sharing in case it's useful. It covers the patterns that AI code generators get wrong most often, across any stack. It doesn't replace a dedicated SAST tool or a penetration test, but it catches the repeatable failures before they ship.

---

## Quick Reference

| Section | Topic | Key rule |
|---------|-------|----------|
| §1 | Secrets Exposure | No credentials in source; use env vars; gitleaks before push |
| §2 | Authentication | Verify session server-side; PKCE for OAuth; validate JWT signature |
| §3 | Authorization (IDOR/BOLA) | Every record query must include an ownership constraint |
| §4 | Input Validation | Schema validation with size limits on every server endpoint |
| §5 | SQL Injection | Parameterized queries — no string concatenation in SQL |
| §6 | XSS Prevention | Auto-escaping templates; no raw HTML from user input |
| §7 | CSRF Protection | Double-submit token or SameSite + Origin check |
| §8 | Security Headers | CSP nonce-based; HSTS; frame-ancestors; nosniff |
| §9 | Rate Limiting | Auth: 5/15min; API: 100/15min; use distributed store |
| §10 | CORS | Explicit allowlist; Vary: Origin; no wildcard on credentialed endpoints |
| §11 | Cookies | Secure + HttpOnly + SameSite; `__Host-` prefix; timeouts |
| §12 | Dependencies | Lockfile committed; audit clean; no wildcards on security-critical libs |
| §13 | File Uploads | Magic-byte validation; server-generated filenames; size limits |
| §14 | SSRF | URL allowlist; block IMDS and private ranges |
| §15 | Logging & Error Handling | No PII/secrets in logs; generic errors to clients; correlation IDs |

---

## Quick-Reference Checklist

Run through these before shipping any API route, auth flow, or data-mutation endpoint:

- [ ] **Secrets**: No API keys, tokens, or credentials in source code or committed config files
- [ ] **Auth**: Every sensitive handler verifies session server-side before acting
- [ ] **Authorization**: Every record fetch/mutate includes an ownership or role constraint
- [ ] **Input**: All user input validated with a schema library (Zod, Pydantic, Go struct validation) on the server
- [ ] **SQL**: All queries use parameterized placeholders — no string concatenation or f-strings in SQL
- [ ] **XSS**: No raw HTML rendering with user-controlled content; CSP header present
- [ ] **CSRF**: State-changing endpoints use CSRF token or `SameSite=Strict` + `Origin` check
- [ ] **Headers**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy present
- [ ] **Rate limiting**: Auth endpoints rate-limited; limiter backed by a distributed store, not in-process memory
- [ ] **CORS**: Explicit origin allowlist; `Vary: Origin` set; no `*` on credentialed endpoints
- [ ] **Cookies**: `Secure`, `HttpOnly`, `SameSite`, absolute timeout on all session cookies
- [ ] **Dependencies**: Lockfile committed; audit passes; no unexpected lifecycle scripts
- [ ] **Uploads**: Type validated by magic bytes; server-generated filenames; size limit enforced
- [ ] **SSRF**: User-supplied URLs validated against allowlist; private/IMDS ranges blocked
- [ ] **Errors**: Generic messages to clients; stack traces and DB errors logged server-side only

---

## §1. Secrets Exposure

### The Problem

AI code generators frequently embed API keys, database URLs, and tokens directly in source files. Once committed, a secret is compromised even if later deleted — it lives in git history.

### Rules

- Store secrets in environment variables, not source files
- Add `.env`, `.env.local`, `.env.*` to `.gitignore` before the first commit
- Run `gitleaks` on staged files before every push
- If a secret is committed and pushed, rotate it immediately — removal from history doesn't undo exposure

### Implementation

**Node + Express**
```javascript
// ❌ Never — hardcoded secret
const stripeKey = "sk_live_abc123xyz";

// ✅ Correct — from environment
const stripeKey = process.env.STRIPE_SECRET_KEY;
if (!stripeKey) throw new Error("STRIPE_SECRET_KEY is not set");
```

**Python + Flask**
```python
import os

# ❌ Never — hardcoded database URL
DATABASE_URL = "postgresql://user:hunter2@db.example.com/prod"

# ✅ Correct — from environment
DATABASE_URL = os.environ["DATABASE_URL"]  # raises KeyError if missing — surfaces config errors early
```

**Pre-commit scan (shell)**
```bash
# Scan staged files only
git diff --cached | gitleaks detect --pipe --exit-code 1

# Full-history scan (run before first push to a new remote)
gitleaks detect --source . --no-git --exit-code 1
```

**What to look for:** Credential-like strings in `config/`, `*.yml`, `*.sh`, `Dockerfile`, and CI workflow files. Also check for secrets committed to `settings.py`, `application.properties`, and similar framework config files.

---

## §2. Authentication

### The Problem

Missing auth checks and identity sourced from request data (headers, body) instead of verified sessions are among the most common AI-codegen failures. Cookie presence is not authentication — the session must be verified against the auth store.

### Rules

- Every handler touching user data must verify the session before acting
- User identity comes from the verified session/JWT — never from `X-User-Id` headers or body fields
- Use PKCE (`code_challenge_method=S256`) for any OAuth/OIDC flow
- Verify JWT signatures using the provider's SDK — never decode without verification
- Enable refresh token rotation; handle `401` by refreshing, not silently failing
- Implement account lockout or exponential backoff after repeated failed logins

### Implementation

**Node + Express — session verification**
```javascript
const { getSession } = require('./lib/auth');

async function requireAuth(req, res, next) {
  const session = await getSession(req);
  if (!session?.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.userId = session.userId;  // sourced from verified session, not req.body
  next();
}

// Apply to all protected routes
app.use('/api/user', requireAuth);
app.use('/api/admin', requireAuth);
```

**Python + Flask — JWT verification**
```python
import jwt
from functools import wraps
from flask import request, jsonify, g

SECRET_KEY = os.environ["JWT_SECRET_KEY"]

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            # Verify signature — never use jwt.decode without the key
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.PyJWTError:
            return jsonify({"error": "Unauthorized"}), 401
        g.user_id = payload["sub"]
        return f(*args, **kwargs)
    return decorated
```

**Go + net/http — middleware**
```go
func requireAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
        if token == "" {
            http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
            return
        }
        claims, err := verifyJWT(token) // signature verified inside verifyJWT
        if err != nil {
            http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
            return
        }
        ctx := context.WithValue(r.Context(), userIDKey, claims.Subject)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

**What to look for:** Handlers in `routes/`, `api/`, `controllers/` that access `req.body.userId`, `request.headers['x-user-id']`, or similar client-supplied identity without server-side session verification. Also flag `jwt.decode()` / `base64.b64decode()` calls that don't verify the signature.

---

## §3. Authorization (IDOR / BOLA)

### The Problem

OWASP API Security Top 10 #1. AI tools generate queries that fetch records by primary key without verifying the requesting user owns that record. An attacker who knows any valid ID can read or mutate any record.

### Rules

- Every query that fetches or mutates a record by ID must also constrain by the authenticated user's ID, role, or tenant ID
- Admin endpoints must check role explicitly — any valid session is not sufficient
- Mass assignment: never pass an unvalidated request body directly to a database update call; use an explicit field allowlist
- Open redirects: validate `?next=` / `?redirect_to=` against an allowlist or restrict to path-relative values (starts with `/`, not `//`)

### Implementation

**Node + Express — ownership constraint**
```javascript
// ❌ Never — IDOR vulnerability
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await db.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
  res.json(order.rows[0]);
});

// ✅ Correct — ownership verified
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await db.query(
    'SELECT id, total, status FROM orders WHERE id = $1 AND user_id = $2',
    [req.params.id, req.userId]  // req.userId from verified session
  );
  if (!order.rows[0]) return res.status(404).json({ error: 'Not found' });
  res.json(order.rows[0]);
});
```

**Python + Flask — mass assignment defense**
```python
from pydantic import BaseModel

class UpdatePostRequest(BaseModel):
    title: str
    content: str
    # Note: is_admin, user_id, role are NOT in this model — they cannot be mass-assigned

@app.route("/posts/<int:post_id>", methods=["PATCH"])
@require_auth
def update_post(post_id):
    body = UpdatePostRequest.model_validate(request.get_json())
    # body.model_dump() only contains title and content — safe to use
    db.execute(
        "UPDATE posts SET title = %s, content = %s WHERE id = %s AND user_id = %s",
        (body.title, body.content, post_id, g.user_id)
    )
    return jsonify({"ok": True})
```

**What to look for:** `WHERE id = $1` with no `AND user_id =` or role check. `db.update(table, req.body)` with no schema stripping. Redirect endpoints that use `req.query.next` without validation.

---

## §4. Input Validation

### The Problem

Unvalidated input reaches databases, file systems, and downstream services. Size limits are especially important — missing them enables denial-of-service via oversized payloads.

### Rules

- Validate all server-side input with a schema library: Zod (Node/TS), Pydantic (Python), Go struct tags + a validator, Bean Validation (Java)
- Client-side validation is UX only — never rely on it for security
- Include size limits on strings, arrays, and file sizes
- Allowlist expected characters for search and filter inputs

### Implementation

**Node + Express — Zod with size limits**
```javascript
const { z } = require('zod');

const createCommentSchema = z.object({
  postId: z.string().uuid(),
  content: z.string().min(1).max(2000),
  tags: z.array(z.string().max(50)).max(5).default([]),
});

app.post('/api/comments', requireAuth, async (req, res) => {
  // Check payload size before parsing
  const contentLength = parseInt(req.headers['content-length'] ?? '0');
  if (contentLength > 100_000) {
    return res.status(413).json({ error: 'Payload too large' });
  }

  const result = createCommentSchema.safeParse(req.body);
  if (!result.success) {
    // Do NOT return result.error.issues — leaks schema internals
    return res.status(400).json({ error: 'Invalid input' });
  }
  const { postId, content, tags } = result.data;
  // proceed with validated data only
});
```

**Python + Flask — Pydantic with size constraints**
```python
from pydantic import BaseModel, Field

class CreateCommentRequest(BaseModel):
    post_id: str  # validated as UUID by downstream logic
    content: str = Field(min_length=1, max_length=2000)
    tags: list[str] = Field(default=[], max_length=5)

@app.route("/comments", methods=["POST"])
@require_auth
def create_comment():
    try:
        body = CreateCommentRequest.model_validate(request.get_json())
    except ValidationError:
        return jsonify({"error": "Invalid input"}), 400
    # proceed with body.content, body.post_id, body.tags
```

**What to look for:** Route handlers that access `req.body.*` or `request.json[...]` without a preceding schema parse. String fields with no `.max()` constraint. Integer fields with no range validation.

---

## §5. SQL Injection

### The Problem

String concatenation or f-strings in SQL queries allow attackers to inject arbitrary SQL. AI tools generate this pattern frequently, often using template literals.

### Rules

- Every SQL query must use parameterized placeholders — never concatenate user input
- Know the placeholder syntax for your driver: `$1` (Postgres/node-postgres/asyncpg), `%s` or `?` (MySQL/PyMySQL/mysql2), `@p1` (MSSQL), `?` (SQLite/better-sqlite3/Go database/sql with MySQL), `$1` (Go pgx)
- ORM raw-query methods are not automatically safe — check them for string building
- Validate input types before querying (UUID, integer range, allowlisted string values)

### Implementation

**Node + Express — node-postgres**
```javascript
// ❌ Never — SQL injection via concatenation
const results = await db.query(
  `SELECT * FROM users WHERE name LIKE '%${req.query.search}%'`
);

// ✅ Correct — parameterized
const results = await db.query(
  'SELECT id, name, email FROM users WHERE name ILIKE $1 LIMIT 20',
  [`%${req.query.search}%`]  // the value is parameterized, not the LIKE itself
);
```

**Python + Flask — psycopg2 / PyMySQL**
```python
# ❌ Never — f-string in SQL
cursor.execute(f"SELECT * FROM orders WHERE status = '{status}'")

# ✅ Correct — parameterized (psycopg2 uses %s regardless of type)
cursor.execute(
    "SELECT id, total FROM orders WHERE status = %s AND user_id = %s",
    (status, g.user_id)
)
```

**Go — database/sql**
```go
// ❌ Never
query := fmt.Sprintf("SELECT * FROM products WHERE name = '%s'", name)
rows, err := db.Query(query)

// ✅ Correct — placeholder (? for MySQL/SQLite, $1 for pgx)
rows, err := db.QueryContext(ctx,
    "SELECT id, name, price FROM products WHERE name = ? AND tenant_id = ?",
    name, tenantID,
)
```

**What to look for:** `grep -rE "(query|execute|sql)\s*[+]=.*req\." .` and `grep -rE "f\"(SELECT|INSERT|UPDATE|DELETE)" .` (Python f-strings in SQL). Any template literal containing SQL keywords.

---

## §6. XSS Prevention

### The Problem

User-controlled content rendered as raw HTML allows attackers to inject scripts. This affects both server-rendered templates and client-side SPAs that handle user-generated content.

### Rules

- Use auto-escaping template engines (Jinja2 with `autoescape=True`, Go `html/template`) — never disable escaping for user content
- Sanitize content before any raw HTML render using a server-side library (Python: `bleach`; Go: `bluemonday`)
- Set a Content Security Policy header with nonces to limit the impact of any bypass
- `eval()`, `setTimeout(string)`, or `Function(string)` with user input are always Critical

### Implementation

**Python + Flask — Jinja2 autoescape (correct default)**
```python
# Jinja2 autoescape is on by default for .html templates — never call Markup() with user input
# ❌ Never
from markupsafe import Markup
return render_template('page.html', bio=Markup(user.bio))  # disables escaping

# ✅ Correct — autoescape handles it
return render_template('page.html', bio=user.bio)

# If you need to render limited HTML (e.g., user-written rich text), sanitize first:
import bleach
ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'a']
ALLOWED_ATTRS = {'a': ['href', 'title']}
safe_bio = bleach.clean(user.bio, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
return render_template('page.html', bio=Markup(safe_bio))
```

**Go — html/template vs text/template**
```go
import "html/template"  // ✅ auto-escapes all interpolated values

// ❌ Never use text/template for HTML — it does NOT escape
import "text/template"

// If you must render user-supplied HTML, sanitize with bluemonday first:
import "github.com/microcosm-cc/bluemonday"
p := bluemonday.UGCPolicy()
safeHTML := p.Sanitize(userInput)
// then pass safeHTML as template.HTML to bypass escaping (only after sanitization)
```

**What to look for:** `| safe`, `Markup(user_input)`, `template.HTML(userInput)` without prior sanitization. `innerHTML` assignments in JavaScript. `eval()` called with user-controlled strings.

---

## §7. CSRF Protection

### The Problem

Browsers automatically attach cookies to cross-origin requests. Without CSRF protection, an attacker's page can trigger state-changing actions on behalf of a logged-in user.

### Rules

- State-changing endpoints (POST, PUT, PATCH, DELETE) require one of: double-submit CSRF token, or `SameSite=Strict` cookies with `Origin`/`Referer` validation
- No state changes via GET — GET must be idempotent
- Double-submit: CSRF token in a cookie (readable by JS) and in a request header — server verifies they match using constant-time comparison
- `SameSite=Strict` blocks CSRF but breaks OAuth redirect flows; `SameSite=Lax` is acceptable if paired with `Origin` header validation

### Implementation

**Node + Express — double-submit pattern**
```javascript
const crypto = require('crypto');

// Issue CSRF token on session creation
app.get('/api/csrf-token', requireAuth, (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  res.cookie('csrf_token', token, { sameSite: 'lax', secure: true });
  res.json({ csrfToken: token });
});

// Verify on state-changing endpoints
function verifyCsrf(req, res, next) {
  const headerToken = req.headers['x-csrf-token'];
  const cookieToken = req.cookies['csrf_token'];
  if (!headerToken || !cookieToken) return res.status(403).json({ error: 'CSRF check failed' });
  // Constant-time comparison prevents timing attacks
  const valid = crypto.timingSafeEqual(Buffer.from(headerToken), Buffer.from(cookieToken));
  if (!valid) return res.status(403).json({ error: 'CSRF check failed' });
  next();
}

app.post('/api/posts', requireAuth, verifyCsrf, createPost);
```

**Python + Flask — flask-wtf / Origin check**
```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)  # protects all POST/PUT/PATCH/DELETE routes automatically
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1-hour token expiry
```

**Go — gorilla/csrf**
```go
import "github.com/gorilla/csrf"

csrfMiddleware := csrf.Protect(
    []byte(os.Getenv("CSRF_KEY")),
    csrf.SameSite(csrf.SameSiteLaxMode),
    csrf.Secure(true),
)

mux.Handle("/api/", csrfMiddleware(apiRouter))
// In handlers: use csrf.Token(r) to embed the token in forms/responses
```

**What to look for:** GET handlers that write data. POST/PUT/DELETE handlers with no CSRF token check and no `Origin` validation. `SameSite=None` cookies without accompanying CSRF token verification.

---

## §8. Security Headers

### The Problem

Missing security headers leave applications open to clickjacking, MIME-type sniffing, cross-site information leakage, and script injection. They are free mitigations that AI tools routinely omit.

### Rules

- Apply headers globally via middleware — not per-route
- CSP: use nonce-based `script-src` (`'nonce-{nonce}'`); avoid `'unsafe-inline'` in `script-src` — it nullifies CSP
- HSTS: set at least `max-age=63072000; includeSubDomains`; add `preload` only after deliberate submission to https://hstspreload.org
- Include both `X-Frame-Options: DENY` (legacy support) and `frame-ancestors 'none'` in CSP

### Implementation

**Node + Express — helmet**
```javascript
const helmet = require('helmet');
const crypto = require('crypto');

app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

app.use((req, res, next) => {
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
        styleSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
        imgSrc: ["'self'", "data:", "https:"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: { maxAge: 63072000, includeSubDomains: true },
    frameguard: { action: 'deny' },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  })(req, res, next);
});
```

**Python + Flask — flask-talisman**
```python
from flask_talisman import Talisman

csp = {
    'default-src': "'self'",
    'script-src': ["'self'", "'nonce-{nonce}'"],  # Talisman substitutes {nonce}
    'object-src': "'none'",
    'frame-ancestors': "'none'",
}

Talisman(
    app,
    content_security_policy=csp,
    strict_transport_security=True,
    strict_transport_security_max_age=63072000,
    strict_transport_security_include_subdomains=True,
    frame_options='DENY',
    referrer_policy='strict-origin-when-cross-origin',
)
```

**What to look for:** `grep -rE "X-Frame-Options|Content-Security-Policy|X-Content-Type-Options|Strict-Transport-Security" .` — if there are no matches, security headers are missing entirely. `'unsafe-inline'` in `script-src` is a High finding.

---

## §9. Rate Limiting

### The Problem

Without rate limiting, auth endpoints are open to credential stuffing and brute force. Expensive API endpoints are vulnerable to abuse and accidental DoS. In-memory rate limiters do not work in serverless or multi-process deployments — they reset on cold start and don't share state across instances.

### Rules

- Auth endpoints (login, password reset, OTP verification): 5 attempts / 15 minutes per IP + per username
- General API: 100 requests / 15 minutes per IP
- Expensive operations (report generation, bulk export, email): 10 per hour
- Use a distributed backing store (Redis, Upstash, Memcached) — never a module-level `Map` or `dict` in serverless contexts
- Return `429 Too Many Requests` with a `Retry-After` header

### Implementation

**Node + Express — express-rate-limit with Redis store**
```javascript
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const { createClient } = require('redis');

const redisClient = createClient({ url: process.env.REDIS_URL });
await redisClient.connect();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  store: new RedisStore({ sendCommand: (...args) => redisClient.sendCommand(args) }),
  handler: (req, res) => {
    res.status(429).json({ error: 'Too many attempts. Try again later.' });
  },
});

app.post('/auth/login', authLimiter, loginHandler);
```

**Python + Flask — flask-limiter with Redis**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.environ["REDIS_URL"],  # Redis — not in-memory
    default_limits=["100 per 15 minutes"],
)

@app.route("/auth/login", methods=["POST"])
@limiter.limit("5 per 15 minutes")
def login():
    ...
```

**Go — golang.org/x/time/rate (suitable for single-instance; use Redis for multi-instance)**
```go
import "golang.org/x/time/rate"

// Token bucket: 5 requests burst, refills at 1/3 min (≈ 5 per 15 min)
var authLimiter = rate.NewLimiter(rate.Every(3*time.Minute), 5)

func loginHandler(w http.ResponseWriter, r *http.Request) {
    if !authLimiter.Allow() {
        w.Header().Set("Retry-After", "60")
        http.Error(w, `{"error":"Too many attempts"}`, http.StatusTooManyRequests)
        return
    }
    // proceed
}
```

**What to look for:** Module-level `Map` or `dict` used as a rate-limit store in any serverless or container-orchestrated context. Auth endpoints with no rate limiter at all. `429` responses without `Retry-After`.

---

## §10. CORS

### The Problem

`Access-Control-Allow-Origin: *` on endpoints that use cookie-based auth or return sensitive data allows any origin to read the response. Without `Vary: Origin`, CDNs cache the wrong CORS headers for multi-origin apps.

### Rules

- Never use `*` as the allowed origin for credentialed endpoints
- Use an explicit allowlist — not a regex, which can be subverted by origin strings like `evil.myapp.com`
- Always set `Vary: Origin` so CDNs cache per origin, not globally
- Set `Access-Control-Max-Age` (e.g., 86400) to reduce preflight overhead
- Handle `OPTIONS` preflight requests explicitly

### Implementation

**Node + Express — CORS allowlist**
```javascript
const cors = require('cors');

const ALLOWED_ORIGINS = new Set([
  'https://app.example.com',
  'https://admin.example.com',
]);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.has(origin)) {
      callback(null, origin || '*');  // origin=undefined means same-origin request
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  maxAge: 86400,
}));

// Ensure Vary: Origin is set on all responses
app.use((req, res, next) => {
  res.vary('Origin');
  next();
});
```

**Python + Flask — flask-cors with allowlist**
```python
from flask_cors import CORS

ALLOWED_ORIGINS = ["https://app.example.com", "https://admin.example.com"]

CORS(
    app,
    origins=ALLOWED_ORIGINS,  # explicit list — not "*"
    supports_credentials=True,
    max_age=86400,
    vary_header=True,          # sets Vary: Origin automatically
)
```

**What to look for:** `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` — this is a Critical finding (browsers block it, but some libraries mis-handle it). Dynamic origin echo without allowlist check. Missing `Vary: Origin`.

---

## §11. Cookies

### The Problem

Session cookies without `HttpOnly`, `Secure`, or `SameSite` flags are vulnerable to XSS-based theft, interception over HTTP, and CSRF attacks. No timeout means sessions that never expire.

### Rules

- All session cookies: `Secure`, `HttpOnly`, `SameSite=Lax` minimum
- `__Host-` prefix: enforces `Secure`, no `Domain` attribute, `Path=/` at the browser level — use for auth session cookies
- Set both an absolute timeout (`maxAge`) and track last-activity server-side for idle timeout
- `SameSite=Strict` breaks OAuth redirect flows; `Lax` is the correct production default for most apps
- `None` requires `Secure` and is only appropriate for embedded cross-origin widgets

### Implementation

**Node + Express — cookie hardening**
```javascript
const session = require('express-session');

app.use(session({
  name: '__Host-session',  // __Host- prefix: browser enforces Secure + no Domain + path=/
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,         // no JS access
    secure: true,           // HTTPS only
    sameSite: 'lax',        // lax: allows OAuth redirect; strict: blocks it
    maxAge: 8 * 60 * 60 * 1000,  // 8-hour absolute timeout (ms)
    path: '/',              // required with __Host- prefix
    // no domain: required with __Host- prefix (browser binds to exact host)
  },
}));
```

**Python + Flask — response cookie**
```python
from flask import make_response

response = make_response(jsonify({"ok": True}))
response.set_cookie(
    "__Host-session",
    value=session_token,
    max_age=8 * 3600,       # 8-hour absolute timeout (seconds)
    secure=True,
    httponly=True,
    samesite="Lax",
    path="/",
    # domain= NOT set — required for __Host- prefix
)
```

**What to look for:** `set_cookie` or `res.cookie` calls without `httpOnly: true`. Any `SameSite: 'none'` without accompanying CSRF protection. Cookies with no `maxAge` or `expires`.

---

## §12. Dependencies

### The Problem

Supply-chain attacks, known CVEs in direct and transitive dependencies, and lockfile poisoning are real vectors. A committed lockfile with integrity hashes prevents silent dependency substitution.

### Rules

- Always commit lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `go.sum`, `Cargo.lock`)
- Run the ecosystem audit tool before any deploy: `npm audit`, `pip-audit`, `cargo audit`
- Avoid `^` or `~` version ranges on packages that handle auth, crypto, parsing, or HTTP
- Review `postinstall` / `preinstall` scripts in `package.json` — unexpected lifecycle scripts are a supply-chain risk

### Implementation

**Node — npm audit and lockfile install**
```bash
# Install from lockfile only (fails if lockfile is out of date — surfaces supply-chain drift)
npm ci

# Audit production dependencies only
npm audit --omit=dev --audit-level=high

# Scan with osv-scanner (broader vulnerability database, no network calls to npm)
npx osv-scanner scan --lockfile package-lock.json
```

**Python — pip-audit**
```bash
# Audit installed packages against OSV database
pip-audit

# For CI: fail the build on any vulnerability
pip-audit --strict
```

**Rust — cargo audit**
```bash
cargo audit
```

**What to look for:** Missing lockfiles (`git ls-files | grep -E "lock$|\.lock$|go\.sum"`). Wildcards on security-critical packages (`^1.0.0` on `jsonwebtoken`, `cryptography`, etc.). Unexpected `postinstall` scripts in `node_modules/.package-lock.json`.

---

## §13. File Uploads

### The Problem

Trusting client-supplied `Content-Type` or file extensions allows attackers to upload malicious files (SVG with embedded scripts, polyglots, oversized payloads). Stored filenames from user input enable path traversal.

### Rules

- Validate file type by reading magic bytes — never trust `Content-Type` or file extension from the client
- Enforce size limits server-side (not just via client validation or upload middleware config)
- Replace client-supplied filenames with server-generated UUIDs + allowed extension
- Serve uploaded files from a separate origin or with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`
- Add virus-scanning hooks for user-facing file sharing

### Implementation

**Node + Express — magic-byte validation with file-type**
```javascript
const { fileTypeFromBuffer } = require('file-type');  // ESM: import { fileTypeFromBuffer }
const crypto = require('crypto');
const multer = require('multer');

const ALLOWED_MIME = new Set(['image/jpeg', 'image/png', 'image/webp', 'application/pdf']);
const MAX_SIZE = 5 * 1024 * 1024;  // 5MB

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_SIZE } });

app.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });

  // Detect by magic bytes — ignore req.file.mimetype (client-controlled)
  const detected = await fileTypeFromBuffer(req.file.buffer.subarray(0, 4100));
  if (!detected || !ALLOWED_MIME.has(detected.mime)) {
    return res.status(400).json({ error: 'Unsupported file type' });
  }

  // Server-generated filename — never use req.file.originalname
  const safeFilename = `${crypto.randomUUID()}.${detected.ext}`;
  // ... store safeFilename in object storage
  res.json({ filename: safeFilename });
});
```

**Python + Flask — python-magic**
```python
import magic
import uuid
import os

ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "application/pdf"}
MAX_SIZE = 5 * 1024 * 1024  # 5MB

@app.route("/upload", methods=["POST"])
@require_auth
def upload_file():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file"}), 400

    data = f.read(MAX_SIZE + 1)
    if len(data) > MAX_SIZE:
        return jsonify({"error": "File too large"}), 413

    # Detect by magic bytes — do not trust f.content_type or f.filename extension
    mime = magic.from_buffer(data[:4096], mime=True)
    if mime not in ALLOWED_MIME:
        return jsonify({"error": "Unsupported file type"}), 400

    ext = mime.split("/")[1]  # crude; use a mime→ext map for production
    safe_filename = f"{uuid.uuid4()}.{ext}"
    # ... store safe_filename
    return jsonify({"filename": safe_filename})
```

**What to look for:** Any use of `req.file.originalname`, `f.filename`, or `os.path.basename(filename)` as the stored filename. File type checks that read only `Content-Type` or the file extension. No size limit on upload endpoints.

---

## §14. SSRF

### The Problem

Server-side request forgery lets attackers use your application as a proxy to reach internal services, cloud metadata endpoints (AWS IMDS, GCP metadata server), and private network resources.

### Rules

- Validate user-supplied URLs against an explicit allowlist of trusted domains and schemes before making outbound requests
- Block requests to: `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`, `169.254.169.254` (IMDS), `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and any link-local / multicast range
- Where possible, resolve the hostname to an IP and validate the IP — not just the hostname string (DNS rebinding mitigation)
- Prefer fetching only from allowlisted origins — don't allow arbitrary user URLs unless the use case specifically requires it

### Implementation

**Node + Express — URL allowlist + IMDS block**
```javascript
const { URL } = require('url');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);

async function safeFetch(userUrl) {
  let parsed;
  try {
    parsed = new URL(userUrl);
  } catch {
    throw new Error('Invalid URL');
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Disallowed protocol');
  }
  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new Error('Host not in allowlist');
  }

  // Resolve hostname and verify the resulting IP is not internal
  const addresses = await dns.resolve4(parsed.hostname).catch(() => []);
  for (const addr of addresses) {
    const ip = ipaddr.parse(addr);
    if (ip.range() !== 'unicast') throw new Error('SSRF: internal address');
  }

  return fetch(userUrl, { signal: AbortSignal.timeout(5000) });
}
```

**Python + Flask — simple allowlist check**
```python
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def safe_fetch(user_url: str) -> requests.Response:
    parsed = urlparse(user_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Disallowed protocol")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not in allowlist")
    # For extra safety, resolve and check IP before requesting
    return requests.get(user_url, timeout=5, allow_redirects=False)
```

**What to look for:** `fetch(req.body.url)`, `requests.get(request.json['url'])`, `http.Get(userURL)` with no validation. Any endpoint that accepts a URL parameter and makes a server-side HTTP call.

---

## §15. Logging & Error Handling

### The Problem

Logging PII or secrets creates compliance and security risk. Returning stack traces or database error messages in API responses exposes internal structure to attackers and is an information disclosure vulnerability.

### Rules

- Log events and IDs — not payloads containing PII (email, name, address, phone) or credentials
- Use structured logging (JSON lines) with a request ID on every log entry for traceability
- Return generic error messages to clients: `"Internal server error"` with a correlation ID
- Log the full error server-side, including stack trace and error code, keyed to the same correlation ID
- Never propagate `error.message`, `error.stack`, SQL error text (`SQLSTATE`, table names), or file paths in API responses

### Implementation

**Node + Express — structured error handler**
```javascript
const crypto = require('crypto');

// Structured logger (use pino or winston in production; console.error for illustration)
function logError(requestId, context, error) {
  // Server-side only — never send this to the client
  console.error(JSON.stringify({
    requestId,
    ...context,
    error: error.message,
    stack: error.stack,
    code: error.code,         // e.g. pg error code "23503"
    timestamp: new Date().toISOString(),
  }));
}

// Global error handler
app.use((error, req, res, next) => {
  const requestId = req.requestId ?? crypto.randomUUID();
  logError(requestId, { endpoint: req.path, method: req.method }, error);
  // Generic message + requestId to client — requestId lets support trace without leaking details
  res.status(500).json({ error: 'Internal server error', requestId });
});

// Assign requestId early in the middleware chain
app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  next();
});
```

**Python + Flask — error handler**
```python
import logging
import uuid

logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(e):
    request_id = getattr(g, 'request_id', str(uuid.uuid4()))
    # Log full details server-side
    logger.error(
        "Unhandled exception",
        extra={"request_id": request_id, "path": request.path},
        exc_info=True,  # includes stack trace in server logs
    )
    # Return generic message to client
    return jsonify({"error": "Internal server error", "requestId": request_id}), 500

@app.before_request
def assign_request_id():
    g.request_id = str(uuid.uuid4())
```

**What to look for:** `res.json({ error: error.message })` or `jsonify({"error": str(e)})` — both send raw exception messages to clients. `console.log(user.email)`, `logger.info(password)` — PII in logs. Any response that includes SQL error text or a file path.

---

## Common AI-codegen Mistakes

| Mistake | How to Spot | Fix |
|---------|-------------|-----|
| Hardcoded API keys or DB URLs | `grep -rE "(sk_\|password\s*=\|api_key\s*=)" src/` | Move to environment variables; rotate if exposed |
| Auth check missing on a route | Handler accesses user data with no session check | Add auth middleware; verify session before touching data |
| IDOR — no ownership constraint | `WHERE id = $1` with no `AND user_id = $2` | Add ownership constraint to every record query |
| SQL via string concatenation | Template literal or f-string containing SQL keywords | Use parameterized placeholders for the driver |
| Raw HTML from user input | `innerHTML = userInput`, `Markup(user_bio)`, `| safe` | Use auto-escaping; sanitize with bleach/bluemonday if HTML is needed |
| In-memory rate limiter in serverless | `new Map()` or module-level dict used as rate-limit store | Switch to Redis / Upstash |
| CORS wildcard on credentialed endpoint | `Access-Control-Allow-Origin: *` with `Credentials: true` | Use an explicit origin allowlist |
| Cookie without HttpOnly | Session cookie readable by JavaScript | Add `HttpOnly`, `Secure`, `SameSite` flags |
| Mass assignment via unvalidated body | `db.update(table, req.body)` with no schema | Use schema validation to strip unknown fields before update |
| Stack trace or DB error in response | `res.json({ error: error.message })` | Log error server-side; return generic message + correlation ID |
| No lockfile committed | `package-lock.json` / `poetry.lock` absent from git | Commit the lockfile; use `npm ci` / `pip install --no-deps` in CI |
| SSRF via user-supplied URL | `fetch(req.body.url)` with no validation | Validate against allowlist; block IMDS and private ranges |

---

## Security Review Workflow

1. **Scan for secrets**: `gitleaks detect --source . --no-git` — flag any hits before anything else
2. **Check auth guards**: Every route in `routes/`, `handlers/`, `controllers/` that returns or mutates user data should have a session verification call near the top
3. **Audit SQL queries**: `grep -rE "(query|execute)\(.*\+" .` — any string concatenation in a query is Critical
4. **Check authorization**: For every route that queries by ID, verify there's also an ownership or role constraint in the WHERE clause
5. **Review schema validation**: Every POST/PUT/PATCH handler should have a schema parse (Zod, Pydantic, Go struct) before touching the data
6. **Check security headers**: `grep -rE "Content-Security-Policy|X-Frame-Options|Strict-Transport-Security" .` — if no results, headers are missing
7. **Verify error handling**: Search for `error.message` or `str(e)` in response payloads — should never reach the client
8. **Run dependency audit**: `npm audit --audit-level=high`, `pip-audit`, or `cargo audit` as appropriate; fix Critical/High before deploy
9. **Check CORS configuration**: `grep -rE "Access-Control-Allow-Origin" .` — flag any `*`; verify `Vary: Origin` is set
10. **Review cookie flags**: `grep -rE "set_cookie|res\.cookie|Set-Cookie" .` — verify `HttpOnly`, `Secure`, `SameSite` are present on session cookies
