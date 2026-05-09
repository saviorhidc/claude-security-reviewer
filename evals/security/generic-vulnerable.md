# Security eval corpus — framework-agnostic vulnerable patterns

These are deliberately insecure config, SQL, shell, Dockerfile, and CI patterns that are not tied to a single application framework. Each snippet is annotated with the expected finding.

Stacks covered: `.env` / git, `package.json`, Dockerfile, GitHub Actions workflows, nginx, SQL migrations, shell scripts, PostgreSQL role configuration.

Format:

````
### N. <short title>

<one-line description>

```<lang>
# EXPECTED: <Severity> <Category> — <brief description>
<vulnerable snippet>
```
````

Severities: `Critical`, `High`, `Medium`, `Low`.
Categories: `SecretsExposure`, `MissingAuthentication`, `BrokenAuthorization`, `InputValidation`, `SQLInjection`, `XSS`, `CSRF`, `MissingSecurityHeaders`, `WeakRateLimiting`, `CORSMisconfiguration`, `InsecureCookie`, `DependencyVulnerability`, `InsecureFileUpload`, `SSRF`, `ErrorLeakage`, `LoggingPII`.

---

### 1. .env committed to git

Secrets file tracked by git — any checkout, clone, or `git log -p` exposes all credentials.

```bash
# EXPECTED: Critical SecretsExposure — .env file tracked by git, credentials visible in checkout and full history
# Output of: git ls-files | grep env
.env
.env.local
config/.env.production
```

---

### 2. Dependency version wildcard in package.json

`"*"` allows npm to install any version including future breaking or malicious releases.

```json
// EXPECTED: Medium DependencyVulnerability — wildcard version on axios allows any version, including malicious future releases
{
  "dependencies": {
    "axios": "*",
    "express": "^4.18.0",
    "jsonwebtoken": "*"
  }
}
```

---

### 3. Dockerfile running as root with no USER directive

Container process runs as UID 0; any container escape gives immediate root on the host.

```dockerfile
# EXPECTED: Medium MissingSecurityHeaders — Dockerfile has no USER directive; container runs as root
FROM node:20-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

EXPOSE 3000
CMD ["node", "src/index.js"]
```

---

### 4. GitHub Actions workflow echoes AWS secret to logs

`echo` of a secret writes the value in plaintext to the workflow run log, which is readable by anyone with repo access.

```yaml
# EXPECTED: Critical SecretsExposure — AWS secret key echoed into workflow log output
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Debug credentials
        run: |
          echo "Key is: ${{ secrets.AWS_SECRET_ACCESS_KEY }}"
          aws s3 sync ./dist s3://my-bucket
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

---

### 5. nginx CORS — wildcard origin on credentialed endpoint

`add_header Access-Control-Allow-Origin *` combined with `add_header Access-Control-Allow-Credentials true`; any origin can read credentialed responses.

```nginx
# EXPECTED: High CORSMisconfiguration — nginx sets wildcard CORS origin with allow-credentials on API location
server {
    listen 443 ssl;
    server_name api.example.com;

    location /api/ {
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Credentials true;
        add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS";
        proxy_pass http://app:3000;
    }
}
```

---

### 6. SQL migration grants ALL PRIVILEGES to app role

Application role gets superuser-equivalent access to the database — a compromised app account has full write/drop access.

```sql
-- EXPECTED: High BrokenAuthorization — app role granted ALL PRIVILEGES instead of least-privilege SELECT/INSERT/UPDATE/DELETE
-- Migration: 003_create_app_role.sql

CREATE ROLE app_user WITH LOGIN PASSWORD 'apppassword';
GRANT ALL PRIVILEGES ON DATABASE appdb TO app_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO app_user;
```

---

### 7. CI pipeline uses npm install instead of npm ci

`npm install` may update the lockfile and pull different (potentially vulnerable) dependency versions than what was tested.

```yaml
# EXPECTED: Medium DependencyVulnerability — npm install in CI mutates lockfile and may pull untested versions; use npm ci --ignore-scripts
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Install dependencies
        run: npm install
      - name: Run tests
        run: npm test
```

---

### 8. chmod 777 in deploy script

World-writable permissions on application files allow any process or user on the host to modify executables or read secrets.

```bash
# EXPECTED: Medium MissingSecurityHeaders — chmod 777 grants world-writable permissions, allows any process to modify app files
#!/bin/bash
set -e

git pull origin main
npm ci --omit=dev
chmod -R 777 /var/app
systemctl restart app
echo "Deploy complete"
```

---

### 9. Logging full HTTP request including Authorization header

Structured logger records the entire request headers object, writing bearer tokens and session cookies to the log store.

```javascript
// EXPECTED: Critical LoggingPII — full request headers logged including Authorization, exposing bearer tokens and cookies
const logger = require('pino')();

app.use((req, res, next) => {
  logger.info({
    method: req.method,
    path: req.path,
    headers: req.headers,   // includes Authorization, Cookie, X-API-Key
    body: req.body,         // may include password, SSN, card number
    ip: req.ip,
  }, 'incoming request');
  next();
});
```

---

### 10. PostgreSQL app account created as SUPERUSER

`SUPERUSER` grants the account the ability to bypass RLS, drop tables, read all databases, and modify server configuration.

```sql
-- EXPECTED: High BrokenAuthorization — app database account created with SUPERUSER, bypasses all RLS and grants full cluster access
-- Migration: 001_create_users.sql

CREATE ROLE api_service
  WITH LOGIN
       SUPERUSER
       PASSWORD 'service-password-here';
```

---

## How to use this corpus

1. Run the `security-reviewer` agent in Deployment Review mode over a repository that contains files matching these patterns, or paste individual snippets into a review session.
2. For each snippet, the agent should produce at minimum the finding annotated in the `# EXPECTED:` / `-- EXPECTED:` / `// EXPECTED:` comment.
3. Track recall (how many EXPECTED findings the agent surfaces) and precision (how many agent findings are not in the corpus) across runs.
4. When adding new snippets, follow the same format and include an EXPECTED comment in the appropriate comment syntax for the language.
