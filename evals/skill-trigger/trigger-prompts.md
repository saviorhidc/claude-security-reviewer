# Skill-trigger eval corpus — 15 labelled prompts

These prompts test the auto-activation logic for the `security-checklist` skill. The `description` field in `skills/security-checklist/SKILL.md` is what the orchestrator matches against — a prompt should fire the skill if and only if it falls within that skill's stated scope.

**Skill tested:** `security-checklist`
**Count:** 15 prompts (10 should trigger, 5 should not)
**Discrimination logic:** "Should trigger" prompts involve reviewing, writing, or auditing web-facing code (API routes, auth flows, database queries, headers, deploy readiness). "Should not trigger" prompts are conceptual questions, unrelated work, or operational tasks with no security review component.

Eval is manual — paste each input into a fresh Claude Code session with this plugin installed, observe which skill (if any) activates, and compare against the Expected column.

---

## SHOULD TRIGGER (10)

### Prompt 1
**Input:** "Review my login endpoint for security issues — it handles username/password auth and issues a session cookie."
**Expected skill:** `security-checklist`
**Reason:** Direct security review of an auth endpoint — the skill description leads with "Use when reviewing or writing API routes, auth flows."

---

### Prompt 2
**Input:** "Audit this database query — I want to make sure it's safe before I deploy."
**Expected skill:** `security-checklist`
**Reason:** "Audit" + "database query" + "before I deploy" hits three trigger phrases from the skill description (SQL injection, input validation, pre-deploy gates).

---

### Prompt 3
**Input:** "What security headers should my Express app be sending? I'm about to go live."
**Expected skill:** `security-checklist`
**Reason:** Security headers is §8 of the checklist; "about to go live" implies pre-deploy review. No overlap with other skills.

---

### Prompt 4
**Input:** "Help me implement secrets management for this project — API keys, DB passwords, and a JWT signing key."
**Expected skill:** `security-checklist`
**Reason:** Secrets management is §1; JWT key storage is §2. Direct match to the skill's described scope.

---

### Prompt 5
**Input:** "Add rate limiting to my /auth/login route — I don't want it brute-forceable."
**Expected skill:** `security-checklist`
**Reason:** Rate limiting an auth endpoint is §9 with the specific concern (brute force) spelled out in the checklist. Unambiguous — no overlap with infra or design.

---

### Prompt 6
**Input:** "Validate this file upload endpoint — users can upload profile pictures and I want to make sure I'm checking file types correctly."
**Expected skill:** `security-checklist`
**Reason:** File upload validation is §13; the question asks specifically about type checking, which maps to the magic-byte vs Content-Type distinction in the checklist.

---

### Prompt 7
**Input:** "I'm verifying a JWT on my API — can you check this code to make sure I'm not trusting an unverified token?"
**Expected skill:** `security-checklist`
**Reason:** JWT signature verification is explicitly in §2. The phrasing "make sure I'm not trusting an unverified token" is a direct statement of the risk the checklist covers.

---

### Prompt 8
**Input:** "Review my OAuth callback handler — I want to make sure there's no open redirect or state parameter bypass."
**Expected skill:** `security-checklist`
**Reason:** OAuth callback security (open redirect, state validation) spans §2 (PKCE, state) and §3 (open redirect allowlist). Both are in the skill's scope.

---

### Prompt 9
**Input:** "I'm building a new POST /api/payments route — what security concerns should I address before I write this?"
**Expected skill:** `security-checklist`
**Reason:** Writing a new API route from scratch where security is the explicit question. The skill description says "Use when reviewing or writing API routes." Payment routes touch auth, input validation, CSRF, and logging hygiene.

---

### Prompt 10
**Input:** "We're about to push to production — run a security check on this project before I deploy."
**Expected skill:** `security-checklist`
**Reason:** "Before deploy" + "security check" directly maps to the skill description's "preparing any web project for deploy." This is the Deployment Review mode trigger.

---

## SHOULD NOT TRIGGER (5)

### Prompt 11
**Input:** "Explain how OAuth 2.0 authorization code flow works, step by step."
**Expected skill:** (none — should not trigger)
**Reason:** Conceptual explanation of a standard — no code, no review, no project to audit. The skill is for doing security work, not explaining security concepts.

---

### Prompt 12
**Input:** "Center this div horizontally and vertically using Flexbox."
**Expected skill:** (none — should not trigger)
**Reason:** Pure CSS layout task. No auth, API routes, database queries, or security headers involved.

---

### Prompt 13
**Input:** "Build me an n8n workflow that watches a Google Sheet and sends a Slack message when a new row is added."
**Expected skill:** (none — should not trigger)
**Reason:** Visual workflow automation with no web app security component. The n8n workflow has no API routes, cookies, or authentication flows to review.

---

### Prompt 14
**Input:** "Set up a GitHub Actions CI matrix that runs tests on Ubuntu, macOS, and Windows for Node 18, 20, and 22."
**Expected skill:** (none — should not trigger)
**Reason:** CI infrastructure configuration — no secrets exposure, web security headers, or API routes. Cross-platform build matrix is a pure DevOps task.

---

### Prompt 15
**Input:** "What does gitleaks do and how does it work conceptually? I want to understand it before deciding whether to add it to my workflow."
**Expected skill:** (none — should not trigger)
**Reason:** Conceptual question about a tool — the user is asking what gitleaks is, not asking to run it or add it to a project. The skill covers applying security practices, not explaining what tools do in the abstract.

---

## Tracking results

When running this corpus, record results in this table:

| # | Input (abbreviated) | Expected | Actual | Pass/Fail | Notes |
|---|---------------------|----------|--------|-----------|-------|
| 1 | "Review my login endpoint..." | security-checklist | | | |
| 2 | "Audit this database query..." | security-checklist | | | |
| 3 | "What security headers should..." | security-checklist | | | |
| 4 | "Help me implement secrets management..." | security-checklist | | | |
| 5 | "Add rate limiting to /auth/login..." | security-checklist | | | |
| 6 | "Validate this file upload endpoint..." | security-checklist | | | |
| 7 | "I'm verifying a JWT on my API..." | security-checklist | | | |
| 8 | "Review my OAuth callback handler..." | security-checklist | | | |
| 9 | "I'm building a new POST /api/payments..." | security-checklist | | | |
| 10 | "We're about to push to production..." | security-checklist | | | |
| 11 | "Explain how OAuth 2.0 works..." | (none) | | | |
| 12 | "Center this div horizontally..." | (none) | | | |
| 13 | "Build me an n8n workflow..." | (none) | | | |
| 14 | "Set up a GitHub Actions CI matrix..." | (none) | | | |
| 15 | "What does gitleaks do conceptually..." | (none) | | | |

A regression in this corpus typically points at an over-broad `description:` field in `SKILL.md` — tighten the wording so the skill's trigger surface doesn't fire on conceptual questions or unrelated infra work.
