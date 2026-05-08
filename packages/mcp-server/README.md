# @nexusinbox/mcp-server

MCP server that exposes NexusInbox to any MCP-compatible LLM runtime —
Claude Desktop, Cursor, Claude Code. Implements the strategy described
in [docs/20_mcp_skill_strategy.md](../../docs/20_mcp_skill_strategy.md).

## Status

**Phase 1B complete — send / reply behind explicit human confirmation, structured audit to stderr.**
**Phase 2.5 complete — Interactive mode (Gateway + Signer Daemon) now serves the full 6-tool surface. The daemon's new `unwrap_content_key` RPC lets the Gateway decrypt inbound content keys via X25519 ECDH without ever lifting the recipient's private key out of the daemon process.**

## Deployment modes

NexusInbox MCP runs in one of two modes:

- **Interactive** *(recommended)* — keys live in a Signer Daemon
  process, reachable from both the Web UI (via Bridged restore) and
  any AI runtime (via the Agent Gateway). This is the everyday
  "human + AI on the same inbox" setup the help page leads with.
- **Autonomous** *(lighter setup)* — keys live in a single client's
  keystore. Bot-style agents driven from one runtime; no daemon to
  keep running.

| Mode | Env value | Key material | Best for |
|---|---|---|---|
| **Interactive** | `mode_a_gateway_daemon` | Signer Daemon encrypted key files (Ed25519 + X25519) + Agent Gateway UDS RPC | Web UI and AI runtime sharing one inbox |
| **Autonomous** *(default)* | `mode_b_saas_keystore` | Local keystore (`~/.nexusinbox/<credential_id>.json`) + in-memory tokens | Single-client bot agents, simplest setup |

Pick the mode by setting `AGENT_INBOX_MCP_MODE` (defaults to
`mode_b_saas_keystore` when unset).

### Note on the env-var values

These modes appeared in the original design docs under the names
**Standard** and **Isolated**, and the env-var values still encode
those legacy labels:

```
mode_a_gateway_daemon  ↔ Interactive  (was "Isolated")
mode_b_saas_keystore   ↔ Autonomous   (was "Standard")
```

The values are kept stable so existing deployments aren't broken by
the rename. **Interactive** and **Autonomous** are the public-facing
labels used everywhere else (help page, settings UI, this README).

### How Interactive mode decrypts without holding the X25519 key

The MCP server in Interactive mode never holds the recipient's X25519
private key. Decryption flows like this:

1. `read_message` — Gateway fetches the encrypted envelope from the API.
2. The MCP runtime calls `unwrap_content_key` on the Gateway, which
   proxies to the Signer Daemon. The daemon does the X25519 ECDH +
   HKDF-SHA256 + AES-GCM unwrap and returns only the resulting
   short-lived `content_key`.
3. The MCP runtime decrypts subject + body locally with that
   `content_key` (AES-GCM via `@nexusinbox/crypto`) and returns
   plaintext to the LLM.

The daemon must be launched with both key files for the unwrap path
to be active:

```bash
nexusinbox-signer \
  --key-file ~/.nexusinbox/daemon/signing.key.enc \
  --encryption-key-file ~/.nexusinbox/daemon/encryption.key.enc \
  --aid aid:ai:YOUR_AGENT \
  --credential-id <uuid>
```

Both files share the same passphrase (single prompt at boot). When
`--encryption-key-file` is absent the daemon stays signing-only and
`unwrap_content_key` returns an explicit error — Interactive mode read tools
will propagate that error rather than silently returning ciphertext.

## Tool surface

| Tool | Risk | What it does |
|------|------|--------------|
| `list_my_agents` | low | Return the caller's own agent as `aid` + current `did` |
| `list_inbox` | low | Paginated message index for an `aid` |
| `read_message` | medium | Decrypts subject + body with the recipient's X25519 private key (plaintext returned to the LLM) |
| `resolve_recipient` | low | `aid` or `did` → current active `did` + `encryption_public_key` |
| `send_text_message` | high | Draft by default. `mode: "send"` actually posts the envelope but requires `confirmed_by_user: true`. |
| `reply_to_message` | high | Same draft / send / confirmation contract. Subject auto-prefills as `Re: <decrypted subject>`. |

## Phase 1B confirmation ritual

Every write tool accepts three policy fields in addition to the domain args:

| Field | Type | Role |
|-------|------|------|
| `mode` | `"draft"` (default) \| `"send"` | `draft` returns the composed envelope + `draft_body_hash` without sending. `send` actually posts. |
| `confirmed_by_user` | `boolean` | **Required when `mode === "send"`.** Missing / `false` throws a readable error. The LLM host is expected to surface a confirmation UI and echo `true` only once the human says yes. |
| `provider_hint` | `string` (≤128 chars) | Free-form label (e.g. `claude-sonnet-4.5`, `cursor-inline`) logged verbatim to the audit stream. Never used for authz. |

Every call returns `draft_body_hash` — SHA-256 hex of the exact body
string — so a draft → send transition can be matched in the audit log
without ever writing plaintext anywhere.

## Audit log

One JSON line per write-tool invocation is emitted on **stderr** so the
MCP transport on stdout stays clean. Operators can redirect / aggregate:

```bash
node dist/cli.js --stdio 2>> /var/log/nexusinbox-mcp.log
```

Schema (mirrors `docs/20_mcp_skill_strategy.md` §11.3):

```jsonc
{
  "timestamp": "2026-04-21T00:00:00.000Z",
  "source": "mcp-server",
  "tool_name": "send_text_message",
  "aid": "aid:ai:YOUR_AGENT",
  "did": "did:key:z6Mk...",
  "credential_id": "<uuid>",
  "mode": "send",
  "confirmed_by_user": true,
  "provider_hint": "claude-sonnet-4.5",
  "draft_body_hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  "message_id": "m-123",
  "recipient_aid": "aid:ai:RECIPIENT",
  "recipient_did": "did:key:z6Mk...",
  "thread_id": "thread-7"
}
```

`draft_body_hash` is the same value the caller received from the prior
draft response, so auditing "did the user confirm exactly this text?"
becomes a simple hash match. The server-side `agent_audit_log` table
(see `services/api/migrations/0008_agent_audit_log.sql`) captures the
authoritative `agent_message_sent` event; this stream captures the
*intent* layer (what the LLM proposed, what the human confirmed, which
provider drove the call). The two combined give full draft → send
traceability without storing any plaintext.

## Install (local dev)

```bash
pnpm -w install
pnpm --filter @nexusinbox/mcp-server build
pnpm --filter @nexusinbox/mcp-server test

# Preview the tool catalog without any network / keystore
node packages/mcp-server/dist/cli.js --print-manifest | jq
```

## First-run activation (Autonomous mode)

One-shot: materialise the local keystore from a freshly issued
`credential_id` + `ens_...`. After this the enrollment secret is
consumed; subsequent boots never need it.

```bash
AGENT_INBOX_BASE_URL="https://api.nexusinbox.ai" \
AGENT_AID="aid:ai:YOUR_AGENT" \
AGENT_CREDENTIAL_ID="<credential uuid>" \
AGENT_ENROLLMENT_SECRET="ens_..." \
AGENT_KEYSTORE_PASSPHRASE="a strong passphrase" \
  node packages/mcp-server/dist/cli.js --init
```

Response (example):

```json
{
  "ok": true,
  "source": "activated",
  "keystore": "/Users/you/.nexusinbox/<credential_id>.json",
  "aid": "aid:ai:YOUR_AGENT",
  "did": "did:key:z6Mk...",
  "activated_at": "2026-04-21T00:00:00.000Z"
}
```

- `0600` file mode, atomic rename, AES-GCM-256 + PBKDF2-SHA256 at rest
  when `AGENT_KEYSTORE_PASSPHRASE` is set.
- `enrollment_secret` is **never** written to disk — only private keys.

## Claude Desktop setup

### Autonomous mode (default — full read + send)

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```jsonc
{
  "mcpServers": {
    "nexusinbox": {
      "command": "node",
      "args": [
        "/ABSOLUTE/PATH/TO/nexusinbox/packages/mcp-server/dist/cli.js",
        "--stdio"
      ],
      "env": {
        "AGENT_INBOX_BASE_URL": "https://api.nexusinbox.ai",
        "AGENT_AID": "aid:ai:YOUR_AGENT",
        "AGENT_CREDENTIAL_ID": "<credential uuid>",
        "AGENT_KEYSTORE_PASSPHRASE": "same passphrase you used during --init"
      }
    }
  }
}
```

Restart Claude Desktop, then in any chat ask:

> Show me my NexusInbox inbox and summarise the unread ones.

Claude will call `list_inbox` → `read_message` automatically via MCP.
`AGENT_ENROLLMENT_SECRET` is intentionally **omitted** after `--init` —
the keystore has the keypair on disk, and leaving the one-shot secret in
Claude Desktop's config would be a pointless disk-resident liability.

### Interactive mode (self-hosted, full read + send)

Requires a local Agent Gateway + Signer Daemon already running per
`docs/19_non_interactive_agent_runbook_2026-04-18.md`. The daemon must
be started with `--encryption-key-file` so it can fulfil
`unwrap_content_key`. Gateway socket defaults to
`/tmp/nexusinbox-gateway.sock`.

```jsonc
{
  "mcpServers": {
    "nexusinbox": {
      "command": "node",
      "args": [
        "/ABSOLUTE/PATH/TO/nexusinbox/packages/mcp-server/dist/cli.js",
        "--stdio"
      ],
      "env": {
        "AGENT_INBOX_MCP_MODE": "mode_a_gateway_daemon",
        "AGENT_INBOX_GATEWAY_SOCKET": "/tmp/nexusinbox-gateway.sock"
      }
    }
  }
}
```

In this configuration the LLM can read inbound bodies, reply, and
send outbound messages — the same surface as Autonomous mode. The X25519
private key lives only inside the Signer Daemon process; the MCP
server never sees it.

## Security contract

| Never on disk | On disk |
|---------------|---------|
| access token, refresh token, DPoP proof | Ed25519 signing private key (keystore) |
| enrollment secret (`ens_...`) after use | X25519 encryption private key (keystore) |
| decrypted subject / body | `activated_at` timestamp + public keys |

The MCP server does not and cannot decrypt someone else's traffic — the
keystore is bound to a single `credential_id` per file, and the keypair
only round-trips the owning recipient's X25519 key. See
`docs/20_mcp_skill_strategy.md` §11 for the full threat model.

## Completion criteria

Tracked here (copied from the strategy doc §13) so the bar lives with
the code.

### Phase 1A
- [x] Claude Desktop から inbox 一覧取得ができる
- [x] `read_message` で復号済み本文が取れる
- [x] `resolve_recipient` で `aid` → 現在 `did` / 暗号化公開鍵が返る
- [x] access_token / refresh_token / 秘密鍵のどれも LLM 側には渡らない

### Phase 1B
- [x] `send_text_message` / `reply_to_message` が実 send を実行できる
- [x] `mode: "send"` は `confirmed_by_user: true` なしでは fail-closed
- [x] 監査ログに `draft_body_hash` / `confirmed_by_user` / `provider_hint` が残る
- [x] draft → send で `draft_body_hash` が一致するので遷移を照合できる

## Roadmap

| Phase | Status | Target |
|-------|--------|--------|
| 1A | ✅ shipped | read-family tools + draft-only write stubs (Autonomous mode) |
| 1B | ✅ shipped | `mode: "send"` + confirmation ritual + structured audit |
| 2 | ✅ shipped | Interactive mode Gateway adapter (send path) |
| 2.5 | ✅ shipped | Daemon `unwrap_content_key` RPC → Interactive mode `read_message` / `reply_to_message` unblocked |
| 3 | planned | attachment read/download, scope presets in Web UI |
| 4 | **non-goal (SaaS variant)** | see below |

### Phase 4 — why "SaaS-hosted Remote MCP" is off the table

An earlier draft of this roadmap listed "Remote (hosted) MCP with
OAuth-like connection UX" as a future phase. We've since decided
that variant is **architecturally incompatible** with NexusInbox's
core value proposition — the server never sees plaintext — and
dropped it from the roadmap.

Rationale: `read_message` requires the recipient's X25519 private
key to unwrap the content key before AES-GCM decrypting the body.
If we host an MCP server on our infrastructure that Claude / ChatGPT
/ Cursor reach over HTTP, the private key has to live either
(a) on our server (breaks "server never sees plaintext") or
(b) on the user's device with the remote server acting as a pure
proxy, in which case Remote MCP gives us nothing over local stdio
MCP — mobile / web clients still need the user's device online
to decrypt. See docs/20 §MCP deployment choice for the full
enumeration.

**User-hosted Remote MCP** (the user runs `@nexusinbox/mcp-server`
themselves on their own Fly / Cloudflare Worker / home server) is
a separate, future-compatible path — the private key stays with
the user, the server operator just becomes "the user" in a
different location. Parked as
[issue #2](https://github.com/nexusinbox/nexusinbox/issues/2)
for when concrete mobile / web-Claude requirements materialise,
rather than pre-implementing it. The local-stdio deployment
remains the primary and recommended setup.

## Local smoke test

The package ships three test suites:

```bash
pnpm --filter @nexusinbox/mcp-server test
```

| Suite | What it locks in |
|-------|------------------|
| `mcp-server.test.ts` | Phase 1A / 1B tool shape + confirmation invariants |
| `runtime-saas.test.ts` | Autonomous mode glue: draft-only policy, aid resolution, reply flow |
| `cli.test.ts` | CLI smoke: `--print-manifest`, `--help`, missing-env, unknown-flag |
