# Security eval corpus — Node.js / Express vulnerable snippets

These are deliberately insecure Node 20 + Express 4 snippets used as a regression corpus for the `security-reviewer` agent. Each snippet is annotated with the expected finding so results can be diffed against what the agent reports.

Stack: Node 20, Express 4, `pg` (node-postgres), `mysql2`, `mongoose`, `jsonwebtoken`, `multer`, `express-session`, `cors`.

Format:

````
### N. <short title>

<one-line description>

```js
// EXPECTED: <Severity> <Category> — <brief description>
<vulnerable code>
```
````

Severities: `Critical`, `High`, `Medium`, `Low`.
Categories: `SecretsExposure`, `MissingAuthentication`, `BrokenAuthorization`, `InputValidation`, `SQLInjection`, `XSS`, `CSRF`, `MissingSecurityHeaders`, `WeakRateLimiting`, `CORSMisconfiguration`, `InsecureCookie`, `DependencyVulnerability`, `InsecureFileUpload`, `SSRF`, `ErrorLeakage`, `LoggingPII`.

---

### 1. Hardcoded API key in source

Secret committed to source — trivially exposed in git history even if deleted later.

```js
// EXPECTED: Critical SecretsExposure — hardcoded Stripe API key committed to source
const stripe = require('stripe');
const client = stripe('sk_live_PLACEHOLDER_REPLACE_ME_xxxxxxxxxxxxxxxx');

app.post('/api/checkout', async (req, res) => {
  const session = await client.checkout.sessions.create({ /* ... */ });
  res.json({ url: session.url });
});
```

---

### 2. Missing auth on admin route

Handler serves sensitive admin data with no session verification.

```js
// EXPECTED: Critical MissingAuthentication — /api/admin route returns user data without auth check
const { Pool } = require('pg');
const db = new Pool({ connectionString: process.env.DATABASE_URL });

app.get('/api/admin/users', async (req, res) => {
  const result = await db.query('SELECT id, email, role, created_at FROM users');
  res.json(result.rows);
});
```

---

### 3. IDOR — record fetched by ID with no ownership constraint

Authenticated user can read any order by guessing an integer ID.

```js
// EXPECTED: Critical BrokenAuthorization — order fetched by id with no user_id ownership check
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const result = await db.query(
    'SELECT * FROM orders WHERE id = $1',
    [req.params.id]
  );
  if (!result.rows[0]) return res.status(404).json({ error: 'Not found' });
  res.json(result.rows[0]);
});
```

---

### 4. SQL injection via template literal

User input concatenated directly into a SQL string — allows arbitrary query execution.

```js
// EXPECTED: Critical SQLInjection — user-controlled search term concatenated into SQL string
app.get('/api/products', async (req, res) => {
  const { search } = req.query;
  const result = await db.query(
    `SELECT id, name, price FROM products WHERE name LIKE '%${search}%'`
  );
  res.json(result.rows);
});
```

---

### 5. NoSQL injection via direct req.body to find()

Mongoose `find()` receives an unsanitised object — attacker can inject `$ne`, `$gt`, or `$where` operators.

```js
// EXPECTED: High SQLInjection — req.body passed directly to mongoose find(), enabling operator injection
const User = require('./models/User');

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  // Attacker sends: { "username": { "$ne": null }, "password": { "$ne": null } }
  const user = await User.findOne({ username, password });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: generateToken(user) });
});
```

---

### 6. Missing input validation — req.body passed directly to DB

No schema validation; attacker can set arbitrary fields including `is_admin`, `role`, or `balance`.

```js
// EXPECTED: High InputValidation — req.body inserted into DB with no schema validation or field allowlist
app.post('/api/users', requireAuth, async (req, res) => {
  const result = await db.query(
    'INSERT INTO users (email, name, role, is_admin) VALUES ($1, $2, $3, $4) RETURNING id',
    [req.body.email, req.body.name, req.body.role, req.body.is_admin]
  );
  res.json({ id: result.rows[0].id });
});
```

---

### 7. XSS via unescaped res.send of user input

User-controlled content reflected directly into an HTML response without escaping.

```js
// EXPECTED: High XSS — user-supplied search query reflected into HTML response without escaping
app.get('/search', (req, res) => {
  const { q } = req.query;
  res.send(`
    <html>
      <body>
        <h1>Results for: ${q}</h1>
      </body>
    </html>
  `);
});
```

---

### 8. CSRF — state-changing GET endpoint

DELETE operation exposed via GET; any page with an `<img>` tag can trigger it cross-origin.

```js
// EXPECTED: Medium CSRF — state-changing delete served via GET, callable from any cross-origin page
app.get('/api/posts/delete', requireAuth, async (req, res) => {
  const { id } = req.query;
  await db.query('DELETE FROM posts WHERE id = $1 AND user_id = $2', [id, req.userId]);
  res.json({ ok: true });
});
```

---

### 9. CORS wildcard with credentials

`*` origin is paired with `credentials: true` — browsers block it but some library combinations mis-handle it; the intent is a High misconfiguration.

```js
// EXPECTED: High CORSMisconfiguration — wildcard CORS origin on credentialed endpoint allows any origin to read responses
const cors = require('cors');

app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));
```

---

### 10. In-memory rate limiter on serverless-style deployment

Module-level `Map` resets on every cold start; rate limit is never enforced across instances.

```js
// EXPECTED: High WeakRateLimiting — module-level Map used as rate-limit store, resets on cold start, state not shared across instances
const loginAttempts = new Map();

app.post('/auth/login', async (req, res) => {
  const ip = req.ip;
  const attempts = (loginAttempts.get(ip) ?? 0) + 1;
  loginAttempts.set(ip, attempts);
  if (attempts > 5) {
    return res.status(429).json({ error: 'Too many attempts' });
  }
  // ... verify credentials
});
```

---

### 11. Cookie missing HttpOnly, Secure, and SameSite flags

Session cookie readable by JavaScript and transmitted over HTTP; no CSRF protection from SameSite.

```js
// EXPECTED: High InsecureCookie — session cookie set without HttpOnly, Secure, or SameSite flags
app.post('/auth/login', async (req, res) => {
  const sessionToken = generateSessionToken();
  res.cookie('session', sessionToken, {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  });
  res.json({ ok: true });
});
```

---

### 12. SSRF — server fetches req.query.url with no allowlist

Attacker can read cloud metadata (AWS IMDS at 169.254.169.254), internal services, or private network resources.

```js
// EXPECTED: Critical SSRF — server fetches user-supplied URL with no allowlist; exposes IMDS and internal network
app.get('/api/preview', async (req, res) => {
  const { url } = req.query;
  const response = await fetch(url);
  const text = await response.text();
  res.send(text);
});
```

---

### 13. File upload trusts req.file.mimetype instead of magic bytes

`req.file.mimetype` is set from the `Content-Type` header the client sends — trivially spoofed.

```js
// EXPECTED: High InsecureFileUpload — file type validated by client-controlled mimetype, not magic bytes
const multer = require('multer');
const upload = multer({ dest: 'uploads/', limits: { fileSize: 10 * 1024 * 1024 } });

app.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (req.file.mimetype !== 'image/jpeg' && req.file.mimetype !== 'image/png') {
    return res.status(400).json({ error: 'Images only' });
  }
  // Store req.file.originalname as-is — path traversal risk too
  await saveFile(req.file.path, req.file.originalname);
  res.json({ ok: true });
});
```

---

### 14. Error response includes err.message and err.stack

Raw exception details — including file paths, library versions, and SQL error text — sent to the client.

```js
// EXPECTED: Medium ErrorLeakage — err.message and err.stack returned in API response, leaking internal details
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    code: err.code,
  });
});
```

---

### 15. Missing security headers — no helmet, no CSP or HSTS

No security headers middleware applied; responses lack CSP, HSTS, X-Frame-Options, and X-Content-Type-Options.

```js
// EXPECTED: Medium MissingSecurityHeaders — no security headers middleware; CSP, HSTS, X-Frame-Options absent
const express = require('express');
const { Pool } = require('pg');

const app = express();
const db = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(express.json());

app.get('/api/status', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000);
```

---

## How to use this corpus

1. Run the `security-reviewer` agent in Deployment Review mode against a file containing these snippets, or paste individual snippets into a review session.
2. For each snippet, the agent should produce at minimum the finding annotated in the `// EXPECTED:` comment.
3. Track recall (how many EXPECTED findings the agent surfaces) and precision (how many agent findings are not in the corpus) across runs.
4. When adding new snippets, follow the same format and include an `// EXPECTED:` comment with a category from the controlled vocabulary.
