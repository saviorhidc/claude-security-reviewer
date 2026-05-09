# Contributing

## Adding a new skill

1. Create a directory: `skills/<skill-name>/`
2. Create `skills/<skill-name>/SKILL.md` with frontmatter:
   ```yaml
   ---
   name: <skill-name>   # MUST match directory name exactly
   description: ...     # Single sentence; mutually exclusive with other skills' triggers
   ---
   ```
3. Only `name` and `description` are valid frontmatter keys — any others fail CI.
4. The CI validator is inline in [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) (no standalone script). Open a draft PR to let CI run, or copy the node heredoc out of the workflow for local validation.

## Adding a new agent

1. Create `agents/<agent-name>.md`
2. Valid frontmatter keys: `name`, `description`, `tools`, `model` only.
3. Include a prompt-injection defense section if the agent reads user-controlled content (source files, PR diffs, dependency manifests). The existing `agents/security-reviewer.md` is the reference implementation.
4. Include an IDOR/authorization check if the agent reviews API code — it should flag missing ownership constraints on record queries.
5. Scope `tools` to the minimum needed. Prefer `Bash(git diff:*)` over `Bash(*:*)`.

## Adding a new eval

1. Add snippets to the appropriate file under `evals/security/`, or add prompts to `evals/skill-trigger/trigger-prompts.md`.
2. Follow the existing format: `### N. <short title>` with a one-line description and an `EXPECTED` comment in the code block.
3. Use a severity from the controlled vocabulary: `Critical`, `High`, `Medium`, `Low`.
4. Use a category from the controlled vocabulary: `SecretsExposure`, `MissingAuthentication`, `BrokenAuthorization`, `InputValidation`, `SQLInjection`, `XSS`, `CSRF`, `MissingSecurityHeaders`, `WeakRateLimiting`, `CORSMisconfiguration`, `InsecureCookie`, `DependencyVulnerability`, `InsecureFileUpload`, `SSRF`, `ErrorLeakage`, `LoggingPII`.
5. Run the snippet through the agent and record the result in the results table in `evals/README.md`.
6. See [`evals/README.md`](./evals/README.md) for the full format guide.

## Reporting security issues

See [`SECURITY.md`](./SECURITY.md) for the vulnerability disclosure policy. Do not open a public issue for security vulnerabilities.

## Formatting

All Markdown files are formatted with Prettier and checked with markdownlint. Run before committing:

```bash
npx prettier --write "**/*.md"
npx markdownlint "**/*.md" --ignore node_modules
```
