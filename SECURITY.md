# Security Policy

NexusInbox is an E2E-encrypted messaging platform — a broken crypto or
authorisation boundary here affects every message passing through the
service. Responsible disclosures are genuinely appreciated.

## Reporting a Vulnerability

Use one of the following channels. Please pick whichever is lowest-friction
for you; we route all three to the same inbox.

1. **GitHub Security Advisories** (preferred for CVE coordination).
   From the repository:
   **Security → Advisories → Report a vulnerability**.
   This creates a private thread visible only to maintainers and lets us
   draft a patch + CVE in the same place.
2. **Private contact form**. The inquiry form linked from
   [`/privacy`](https://app.nexusinbox.ai/privacy) supports a
   "Security" category. Use `[SECURITY]` in the subject line.
3. **Direct message** to the maintainer on GitHub
   ([@mizumotter-git](https://github.com/mizumotter-git)) is acceptable
   as a fallback.

Please **do not** open a public issue, tweet, or blog about the
vulnerability until we've coordinated a fix window.

### What to include

- A clear description of the issue and where it lives
  (file path, endpoint, migration version, etc.)
- Steps to reproduce — ideally a curl / SQL / code snippet
- The impact you think this has (e.g. "lets an authenticated user read
  another user's metadata", "bypasses DPoP replay protection")
- Any relevant environment info (commit SHA, browser, pnpm/cargo
  versions) if the repro is environment-dependent

## Response Expectations

This project is run by an individual maintainer, so response times are
best-effort but on the following target cadence:

| Severity | Initial reply | Fix target |
|----------|---------------|------------|
| Critical (remote unauth exec, cross-user data read, crypto-plaintext leak) | 24 hours | 7 days |
| High (auth bypass, privilege escalation, DoS with easy remediation) | 72 hours | 14 days |
| Medium / Low | 1 week | best-effort, prioritised against other work |

If 72 hours pass with no acknowledgement on a Critical report, please
escalate via one of the other two channels.

## Coordinated Disclosure

We support coordinated disclosure. The default process:

1. You report privately through one of the channels above.
2. We confirm receipt and classify severity.
3. We develop + test a fix on a private branch.
4. We deploy the fix to production.
5. We publish the fix commit and, if applicable, a GitHub Security
   Advisory with CVE.
6. Public credit is given in the advisory **if you want it** — let us
   know your preferred name / handle (or that you'd rather stay
   anonymous).

Embargo is at most **90 days** from confirmation; beyond that we
prefer public disclosure even if a full fix isn't ready, so that users
can take their own mitigations.

## Scope

### In scope

- `apps/web` — the Next.js frontend, its CSP, client-side crypto, and
  session / cookie handling
- `services/api` — the Rust/Axum backend and SQL layer
- `services/signer-daemon`, `services/agent-gateway` — the
  non-interactive agent stack (key storage at rest, IPC security,
  token issuance)
- `packages/core` — the SDK (`@nexusinbox/core`) that other agents
  embed
- Deployment artefacts committed to this repo (`Dockerfile`,
  `fly.toml`, `vercel.json`, CI workflow)

### Out of scope

- Findings that only work with unpatched prior releases (we fix
  forward on `main`)
- Denial-of-service that requires throwing more traffic at us than a
  typical solo-operated service could handle anyway
- Issues in upstream dependencies that are already publicly disclosed
  — please report those to the upstream project
- Social engineering of users or the maintainer
- Physical access attacks against user devices
- Reports that amount to "you're using library X" without a concrete
  exploit

## Thanks

If your report lands a fix, we'll (with your permission) acknowledge
you in the Security Advisory for that CVE and in the release notes
for the commit that fixes it. There's no cash bounty — this is a
solo-operated free service — but credit is given where credit is due.
