# Security Policy

## Scope

This plugin ships markdown that influences Claude's behavior — the agent and skill files are system-prompt-equivalent. Security vulnerabilities include:

- Agent prompts that could be exploited via prompt injection (e.g., a pattern in the agent body that an attacker could trigger by embedding instructions in reviewed code)
- Skill checklist content that teaches incorrect security patterns or misses real-world vulnerabilities
- Install instructions that could expose users to a supply-chain attack (e.g., a compromised clone URL, an unexpected postinstall script)

## Reporting a Vulnerability

Please **do not open a public GitHub issue** for security vulnerabilities.

Report privately via:

- Email: security@saviorhidc.dev (response within 48 hours)
- GitHub Security Advisories: https://github.com/saviorhidc/claude-security-reviewer/security/advisories

Include:

- Which file is affected (`agents/security-reviewer.md`, `skills/security-checklist/SKILL.md`, install instructions, etc.)
- The vulnerable pattern — quote the specific line or section
- What impact a user following that pattern would see in their codebase or Claude session
- A suggested fix (optional but appreciated)

## Response

We aim to triage within 48 hours and publish a fix within 7 days for Critical issues.

## Supply Chain Security

This repository has no runtime dependencies — it is pure markdown. The only build tooling is the CI validation workflow (`.github/workflows/ci.yml`), which runs frontmatter validation and `plugin.json` schema checks on every push. There is no `npm install` or equivalent in CI; there are no lifecycle scripts.

To verify you have the intended content, pin to a signed tag:

```bash
git checkout $(git describe --tags --abbrev=0)
git verify-tag <tag>   # requires the tag to be GPG-signed
```
