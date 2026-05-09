# Security eval corpus — Go / net/http vulnerable snippets

These are deliberately insecure Go 1.22 + `net/http` snippets used as a regression corpus for the `security-reviewer` agent. Each snippet is annotated with the expected finding.

Stack: Go 1.22, `net/http`, `database/sql` + `lib/pq` (Postgres driver).

**Coverage note (v1.0.0):** This file covers 10 of the 15 checklist sections. The remaining sections (CSRF, XSS, InsecureFileUpload, DependencyVulnerability, LoggingPII) are not yet represented with Go-idiomatic examples. They will be added in a future release. See `evals/README.md` for the full coverage matrix.

Format:

````
### N. <short title>

<one-line description>

```go
// EXPECTED: <Severity> <Category> — <brief description>
<vulnerable code>
```
````

Severities: `Critical`, `High`, `Medium`, `Low`.
Categories: `SecretsExposure`, `MissingAuthentication`, `BrokenAuthorization`, `InputValidation`, `SQLInjection`, `XSS`, `CSRF`, `MissingSecurityHeaders`, `WeakRateLimiting`, `CORSMisconfiguration`, `InsecureCookie`, `DependencyVulnerability`, `InsecureFileUpload`, `SSRF`, `ErrorLeakage`, `LoggingPII`.

---

### 1. Hardcoded API key as const

Secret committed in source — exposed in any checkout and in git history even after deletion.

```go
// EXPECTED: Critical SecretsExposure — Stripe API key hardcoded as const in source file
package main

import "github.com/stripe/stripe-go/v76"

const stripeKey = "sk_live_PLACEHOLDER_REPLACE_ME_xxxxxxxxxxxxxxxx"

func init() {
	stripe.Key = stripeKey
}
```

---

### 2. Missing auth on handler

Handler queries user data with no session or token verification before acting.

```go
// EXPECTED: Critical MissingAuthentication — /api/admin/users handler queries DB with no auth check
package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

func listUsersHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query("SELECT id, email, role FROM users")
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var users []map[string]any
		for rows.Next() {
			var id int
			var email, role string
			rows.Scan(&id, &email, &role)
			users = append(users, map[string]any{"id": id, "email": email, "role": role})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	}
}
```

---

### 3. SQL injection — fmt.Sprintf into query

User input from the URL query string interpolated directly into a SQL string via `fmt.Sprintf`.

```go
// EXPECTED: Critical SQLInjection — user-supplied name interpolated into SQL via fmt.Sprintf
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func searchProductsHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		query := fmt.Sprintf("SELECT id, name, price FROM products WHERE name LIKE '%%%s%%'", name)
		rows, err := db.Query(query)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		// ... encode rows
	}
}
```

---

### 4. IDOR — record queried by ID with no user scoping

Authenticated request fetches an order using only its primary key — any user can read any order.

```go
// EXPECTED: Critical BrokenAuthorization — order fetched by id only, no user_id ownership constraint in WHERE clause
package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
)

func getOrderHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.URL.Query().Get("id")
		id, _ := strconv.Atoi(idStr)

		var total float64
		var status string
		err := db.QueryRow("SELECT total, status FROM orders WHERE id = $1", id).Scan(&total, &status)
		if err == sql.ErrNoRows {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"total": total, "status": status})
	}
}
```

---

### 5. CORS — wildcard Access-Control-Allow-Origin with credentials

`Access-Control-Allow-Origin: *` set on a handler that also sets `Access-Control-Allow-Credentials: true`.

```go
// EXPECTED: High CORSMisconfiguration — wildcard CORS origin combined with credentials header on credentialed endpoint
package main

import "net/http"

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

---

### 6. Missing security headers

Handler sets no security headers — no HSTS, no X-Frame-Options, no X-Content-Type-Options.

```go
// EXPECTED: Medium MissingSecurityHeaders — handler sets no security headers; HSTS, X-Frame-Options, nosniff absent
package main

import (
	"encoding/json"
	"net/http"
)

func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func main() {
	http.HandleFunc("/api/status", statusHandler)
	http.ListenAndServe(":8080", nil)
}
```

---

### 7. SSRF — http.Get on URL from query param

`http.Get` called with a user-controlled URL from the request; internal metadata endpoints and private networks are reachable.

```go
// EXPECTED: Critical SSRF — http.Get called with user-supplied URL, no allowlist or IMDS range block
package main

import (
	"io"
	"net/http"
)

func fetchPreviewHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, "Fetch error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	w.Write(body)
}
```

---

### 8. Cookie set without Secure, HttpOnly, or SameSite

Session cookie issued over HTTP without any hardening flags.

```go
// EXPECTED: High InsecureCookie — session cookie set without Secure, HttpOnly, or SameSite attributes
package main

import (
	"net/http"
	"time"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// ... verify credentials
	sessionToken := generateSessionToken()
	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   sessionToken,
		Path:    "/",
		Expires: time.Now().Add(7 * 24 * time.Hour),
		// Secure, HttpOnly, SameSite not set
	})
	w.WriteHeader(http.StatusOK)
}
```

---

### 9. Error leakage — http.Error exposes DB error to client

`err.Error()` (which may contain SQL error text, table names, or file paths) sent directly to the HTTP response.

```go
// EXPECTED: Medium ErrorLeakage — err.Error() returned in HTTP response, leaks DB error text to client
package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

func getUserHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		var email string
		err := db.QueryRow("SELECT email FROM users WHERE id = $1", id).Scan(&email)
		if err != nil {
			// Sends e.g. "pq: relation \"users\" does not exist" to the client
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"email": email})
	}
}
```

---

### 10. In-memory rate limiter with sync.Map across handlers

`sync.Map` is process-local; rate limit is invisible to horizontally-scaled instances or after a restart.

```go
// EXPECTED: High WeakRateLimiting — sync.Map used as rate-limit store; not shared across instances or restarts
package main

import (
	"net/http"
	"sync"
	"time"
)

var attempts sync.Map

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		val, _ := attempts.LoadOrStore(ip, []int64{})
		timestamps := val.([]int64)
		now := time.Now().Unix()
		var recent []int64
		for _, t := range timestamps {
			if now-t < 900 {
				recent = append(recent, t)
			}
		}
		if len(recent) >= 5 {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		attempts.Store(ip, append(recent, now))
		next.ServeHTTP(w, r)
	})
}
```

---

## How to use this corpus

1. Run the `security-reviewer` agent in Deployment Review mode against a file containing these snippets, or paste individual snippets into a review session.
2. For each snippet, the agent should produce at minimum the finding annotated in the `// EXPECTED:` comment.
3. Track recall (how many EXPECTED findings the agent surfaces) and precision (how many agent findings are not in the corpus) across runs.
4. When adding new snippets, follow the same format and include a `// EXPECTED:` comment with a category from the controlled vocabulary.
