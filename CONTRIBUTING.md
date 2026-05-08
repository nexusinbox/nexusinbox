# Contributing

Thanks for wanting to help. NexusInbox is a solo-operated project, but
pull requests are genuinely welcome — the ones that are easy to review
and land fast tend to follow the patterns below.

## Before you start

For anything beyond a typo fix, please **open an issue first** describing
the problem and the direction you'd like to take. That avoids sinking a
weekend into an implementation that conflicts with something already in
flight, and gives us a paper trail the commit message can refer back to.

Good first issues to look at:
- Missing test coverage against a specific handler
- Small DX improvements in `templates/agent-runtime-node/`
- Doc clarifications or fixes where something no longer matches the code

Large refactors of `services/api/src/lib.rs` (the 10k-line monolith) —
please chat with maintainers first. The modularisation plan is coming
but it needs to sequence with other work.

## Local setup

See [`README.md`](./README.md#quick-start-local-dev) for the canonical
setup. Short version:

```bash
cp .env.example .env
docker compose up -d
pnpm install
```

## Running checks locally

CI runs all of the below. Running them before pushing keeps the
review cycle short and keeps you out of "green main, red PR" loops.

```bash
# Rust (services/api, services/signer-daemon, services/agent-gateway)
cd services/<svc>
cargo fmt && cargo clippy -- -D warnings
cargo test

# DB integration tests (require the compose Postgres running)
docker-compose up -d postgres
DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
  AGENT_INBOX_DB_TESTS=1 \
  cargo test --test blocks_db_integration_test \
             --test attachments_db_integration_test \
             --test token_revocation_test \
             -- --test-threads=1

# Live storage integration tests (optional)
docker-compose up -d minio
AGENT_INBOX_S3_LIVE_TESTS=1 \
  AGENT_INBOX_S3_ENDPOINT=http://127.0.0.1:9000 \
  AGENT_INBOX_S3_REGION=us-east-1 \
  AGENT_INBOX_S3_BUCKET=nexusinbox-test \
  AGENT_INBOX_S3_ACCESS_KEY_ID=agent_inbox \
  AGENT_INBOX_S3_SECRET_ACCESS_KEY=agent_inbox \
  AGENT_INBOX_S3_PATH_STYLE=true \
  cargo test --manifest-path services/api/Cargo.toml --test s3_live_integration_test -- --nocapture

docker-compose up -d ipfs
AGENT_INBOX_IPFS_LIVE_TESTS=1 \
  AGENT_INBOX_IPFS_API_URL=http://127.0.0.1:5001 \
  cargo test --manifest-path services/api/Cargo.toml --test ipfs_live_integration_test -- --nocapture

# TypeScript side
pnpm exec tsc --noEmit
pnpm lint
pnpm test
pnpm contract:check           # OpenAPI ↔ code shape
```

Rust is strict: `cargo clippy -- -D warnings` is the CI gate, so a
single unused field will block the merge. Running `cargo fmt` before
every commit is the easiest way to never get caught by formatter-only
diffs — rustfmt will silently reshape a one-line if-else into a
multi-line form and CI's `cargo fmt --check` will then reject the
identical-behaviour commit.

If the DB integration tests fail with `failed to lookup address information`,
check that you did not literally use `DATABASE_URL=postgres://...`. Use the
full local URL shown above. More troubleshooting notes live in
[`docs/16_p8_security_verification.md`](./docs/16_p8_security_verification.md#53-よくあるつまずき).

## Testing expectations

- Follow TDD where practical: write the failing test first, make it
  pass with the minimal change, then refactor with the test staying
  green.
- **Every behavioural change needs a test.** Bug fixes need a
  regression test that fails on `main` and passes on your branch.
- Tests that need a real Postgres / S3 / R2 go under the
  `*_db_integration_test.rs` convention and are gated with
  `AGENT_INBOX_DB_TESTS=1` so default `cargo test` stays hermetic.
- Pure-logic in-memory tests go in the existing `internal_tests`
  module inside `src/lib.rs`.

## Branch and PR conventions

- Branch off `main`. Keep the branch focused on one concern.
- Rebase (don't merge) before opening a PR, so CI runs on the
  integrated state.
- PR title: use the same scope as your commit message (see below).
- PR description: what / why / how, a test-plan checklist, and
  screenshots if you touched UI. The existing PR template fills in
  this skeleton.
- **Heads up — `main` is live to production.** Any merged PR that
  touches `services/api/**` auto-deploys to
  `https://api.nexusinbox.ai` via
  [`.github/workflows/deploy-api.yml`](./.github/workflows/deploy-api.yml),
  so call out schema migrations / breaking changes in the PR
  description and double-check the gate job (fmt / clippy / cargo
  test) stayed green on your branch before requesting review. See
  [README → Auto-deploy (API → Fly)](./README.md#auto-deploy-api--fly)
  for the rollback handle when something does slip through.

## Commit messages

We follow Conventional Commits — every commit to `main` starts with
one of:

- `feat(scope):`  new user-visible capability
- `fix(scope):`  bug fix
- `refactor(scope):`  no external change but code reshaped
- `docs(scope):`  documentation only
- `chore(scope):`  build/CI/tooling only
- `test(scope):`  test-only
- `perf(scope):`  performance optimisation

Scope is typically the directory (`api`, `web`, `sdk`, `daemon`,
`gateway`, `ci`) or the feature (`non-interactive`, `attachments`,
`csp`).

The body should explain **why**, not **what** — the diff is the what.
Short paragraphs are preferred over bulleted lists when the reasoning
has narrative structure.

## House style

- **Japanese UI, English code comments.** User-facing strings in
  `apps/web` are bilingual via `lib/i18n`; code comments are English
  so any contributor can read them without a locale switch.
- Prefer **narrow functions over god objects**. The monolithic
  `services/api/src/lib.rs` is acknowledged tech debt; new code
  should be decomposable from day one even while the rest of the
  file isn't.
- **Errors are data**. In the API, `(StatusCode, Json<ErrorResponse>)`
  is the error type throughout; don't invent ad-hoc error shapes.
- **Never log plaintext**. Logs / audit rows never contain decrypted
  subject, body, filename, or key material. The audit log stores
  ciphertext references and metadata only.

## Security-sensitive changes — keep docs and UI in sync

NexusInbox's trust story is *what the user sees* as much as what the
code does. A change that quietly alters who can read plaintext, who
holds a key, or how a token is scoped is a security change even if no
algorithm moved. When you touch one of these surfaces, update the
other three in the **same PR** so the repo never ships a state where
the implementation and the user-visible story disagree.

The surfaces that must move together:

1. **Implementation** — the Rust / TS / SDK change itself.
2. **Design docs** — `docs/20_mcp_skill_strategy.md`,
   `docs/21_message_visibility_ux_for_mcp_modes.md`,
   `docs/22_bridged_restore_design.md` (whichever is closest).
3. **Help / onboarding copy** — `apps/web/app/help/**` and any
   onboarding / empty-state copy that describes what the feature
   does.
4. **Settings page wording** — `apps/web/app/settings/**`,
   particularly the agents, credentials, and audit pages where the
   security posture is surfaced to end users.
5. **Protocol / payload docs** — when you add a new `content_type`
   value, an A2A protocol type, or change the shape of an A2A
   payload, update [`docs/24_a2a_protocol_design.md`](docs/24_a2a_protocol_design.md)
   and the content_type table in [`docs/04_messaging_protocol.md`](docs/04_messaging_protocol.md)
   **in the same PR**. These files are the normative reference for
   the encrypted-content contract; a diff that moves code without
   moving them produces protocol drift that's invisible to the
   server and very painful to debug after the fact.

Triggers that require this synchronised update:

- Anything that changes **who sees plaintext** (Isolated mode / Standard mode, MCP
  visibility, bridged-restore ciphertext handling).
- Anything that changes **who holds the private key** (`web_keystore`
  vs `signer_daemon` vs `unknown`, pairing / restore flow).
- Anything that changes **what a token can do** (scope names, DPoP
  binding, rate caps, policy tiers L1/L2/L3).
- Anything that changes **what is logged** (new audit event types,
  new `detail` fields that humans read, new bridge event shapes).
- Anything that changes **what a token can do automatically** —
  auto-reply policies, scheduled executions, anything that lets an
  agent send a message without a human tap. See [docs/25](docs/25_auto_reply_engine_design.md)
  for the policy DSL and phase split; Phase 4.4b-e each need their
  own security review before landing.

Reviewer checklist — a PR that trips any trigger above should show
diffs in at least `implementation + docs + (help or settings copy)`.
A PR that only changes the code is usually one of:

- a bug fix that preserves the existing security story (OK — note
  this explicitly in the PR description), or
- a silent drift (not OK — block and ask for the docs / UI update).

### IDKit / `'unsafe-eval'` isolation (route-level, not origin-level)

`@worldcoin/idkit` transitively depends on WalletConnect, which calls
`new Function()` at initialisation. Any page that imports IDKit must
therefore serve a CSP with `script-src 'unsafe-eval'`, which defeats
most of the nonce + `'strict-dynamic'` XSS protection on that page.

To keep the eval blast radius minimal we **only load IDKit from
`apps/web/app/login/idkit/**`** and embed that route as a same-origin
iframe from the parent `/login`. The parent carries no IDKit code and
runs under the strict CSP.

**What this buys us, and what it does not.** This is
*main-document CSP isolation* + *route-level isolation*: the top
frame of `/login` does not load IDKit, so its CSP stays eval-free,
and the eval allowance is confined to one path. It is **not** origin
isolation — parent and child are both on `app.nexusinbox.ai`. The
security boundary against spoofed post-auth messages is the
postMessage handler in `/login/page.tsx`, which checks
`event.origin`, `event.source`, and the `idkit/` type prefix. Do
not assume the iframe walls off same-origin DOM access in general.

Rules:

- New calls into IDKit must live inside `apps/web/app/login/idkit/**`.
  If you need to re-auth in a new flow, embed the isolation sub-route
  via iframe rather than adding a second `@worldcoin/idkit` import
  site — the ESLint `no-restricted-imports` rule enforces this.
- Do not broaden `UNSAFE_EVAL_PATHS` / `SAME_ORIGIN_FRAME_PATHS` in
  [apps/web/middleware.ts](apps/web/middleware.ts) without explicit
  security review.
- The only other allow-listed import site is
  [apps/web/lib/world/idkit.ts](apps/web/lib/world/idkit.ts) — it
  imports *types only* and is audited for runtime purity.
- Child → parent communication lives entirely in postMessage. Do
  not reach into `window.parent` for DOM or storage; do not rely on
  `window.location.ancestorOrigins` for parent-origin checks (it's
  Firefox-blind).

## Code of conduct

Be kind, be constructive, and assume good faith. There's no formal
CoC document yet, but the baseline is the GitHub Community Guidelines
plus "don't be a jerk." Harassment, disrespect, and spam will get
you banned from the issue tracker without warning.

## Reporting security issues

**Do not open a public issue** for security vulnerabilities. See
[`SECURITY.md`](./SECURITY.md) for the private disclosure process.

## Licensing

By submitting a contribution, you agree to license it under the
[Apache License 2.0](./LICENSE) — the same license as the rest of
the project. Apache 2.0's patent grant applies to your contribution
automatically; no separate CLA is required.
