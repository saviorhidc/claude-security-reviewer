---
name: LinkedIn Post Ideas - claude-security-reviewer
description: Emerging LinkedIn post topics as we walk through the security reviewer explanation
type: reference
---

# LinkedIn Post Ideas

## Post 1: The Big Picture (Ready for Draft)

**Status:** Captured from Step 1 explanation  
**Audience:** Developers using Claude Code/AI tools  
**Angle:** The predictable security gaps AI code generators make

**Core idea:**
- AI code is fast (10x speed) but makes the same security mistakes every time
- These aren't random bugs—they're predictable patterns (hardcoded secrets, missing auth checks, SQL concatenation, CORS wildcards)
- Developers need a way to catch these gaps *before* production, not months after
- The security reviewer solves this: checklist-driven, any stack, two modes (Diff for PRs, Deployment for production)

**Key hooks:**
- "Three weeks in, security finds hardcoded credentials in your source code"
- "Auth checks on 90% of routes, mysteriously missing on the one that matters"
- "These aren't random bugs. They're predictable."

**Amendments needed:**
- (To be filled in after user feedback on this version)

---

## Post 2: Clarification — Web Apps vs. APIs (Important Context)

**Status:** Important clarification from Step 4 discussion  
**Audience:** Developers using Claude Code/AI tools to build web projects  
**Angle:** The reviewer covers the ENTIRE backend of web apps, not just APIs

**Core idea:**
- The security reviewer covers ANY web project (websites, apps, APIs)
- Scope: the backend/API/business logic layer of web applications
- What's NOT covered: frontend-specific patterns (React, Next.js middleware), which use the companion skill pack
- But it DOES cover the principles that apply everywhere (auth, CORS, SQL injection, etc.)

**Real example:**
- Lovable-generated marketplace: frontend uses companion skill, backend uses security reviewer
- Both checklist and frontend-security work together for complete web app coverage

**Why it matters for positioning:**
- Clarifies that this isn't "API-only" — it's for anyone deploying a web project with a backend
- Positions the tool as essential for full-stack developers, not just API builders

---

## Post 3: How to Update the Security Reviewer (Emerging Idea)

**Status:** Captured from Step 4 discussion  
**Audience:** Developers using Claude Code/AI tools  
**Angle:** Maintenance and evolution—how to know when security threats shift and where to look

**Core idea:**
- A security checklist doesn't stay static; threats evolve
- Real signals tell you when to update: repeated patterns in audits, OWASP shifts, CVEs, framework advisories
- Authoritative sources: OWASP Top 10, CVE database, framework security blogs, your own audit findings
- Your own code reviews are the most valuable research—notice patterns and ask "Is this a checklist item?"

**Key hooks:**
- "I used to think security research meant reading papers. Then I started reviewing code."
- "The signal isn't random incidents—it's patterns that repeat across multiple codebases"
- "OWASP updates every 3-4 years. Your checklist should update when you see the pattern, not when the standard does."

**Why it matters:**
- Builds credibility (shows the checklist evolves, not static)
- Teaches developers how to stay current themselves
- Positions user as practitioner, not theorist

---

## Post Ideas TBD

(Will fill in as we progress through Steps 5–7)
