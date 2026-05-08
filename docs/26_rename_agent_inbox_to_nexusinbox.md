# 26. Rename: Agent Inbox → NexusInbox (2026-04-24)

## 1. 背景

ブランドネーミングを **NexusInbox** に確定。GitHub org / X handle / `nexusinbox.ai` ドメイン / J-PlatPat・USPTO の商標サーチが clean だったため、コード・docs・各種設定に散らばる "Agent Inbox" を一斉に NexusInbox へ寄せ替えた。

タグライン: **"Inbox for verified AI agents."**

## 2. リネーム対象 (clean-cut)

| カテゴリ | 旧 | 新 |
|---|---|---|
| ブランド文字列 (UI / docs / README) | `Agent Inbox` | `NexusInbox` |
| TypeScript 公開クラス | `AgentInboxApiClient`, `AgentInboxGatewayClient` | `NexusInboxApiClient`, `NexusInboxGatewayClient` |
| TypeScript packages | `@agent-inbox/{core,crypto,storage-adapters,mcp-server,ui,web}` | `@nexusinbox/*` |
| Rust crates | `agent-inbox-{api,signer,gateway}` | `nexusinbox-*` |
| MCP server bin | `agent-inbox-mcp` | `nexusinbox-mcp` |
| Cookie 名 | `agent_inbox_session` | `nexusinbox_session` |
| JWT issuer / audience 既定値 | `agent-inbox-api` / `agent-inbox-web` | `nexusinbox-api` / `nexusinbox-web` |
| IndexedDB 名 | `agent-inbox-keystore`, `agent-inbox-llm`, `agent-inbox-gcal` | `nexusinbox-keystore`, `nexusinbox-llm`, `nexusinbox-gcal` |
| localStorage key | `agent-inbox-locale`, `agent_inbox.<key>` | `nexusinbox-locale`, `nexusinbox.<key>` |
| Daemon socket path 既定値 | `/tmp/agent-inbox-signer.sock`, `/tmp/agent-inbox-gateway.sock` | `/tmp/nexusinbox-signer.sock`, `/tmp/nexusinbox-gateway.sock` |
| Bridge HTTP header | `X-Agent-Inbox-Bridge`, `X-Agent-Inbox-Bridge-Nonce` | `X-NexusInbox-Bridge`, `X-NexusInbox-Bridge-Nonce` |
| HKDF info constant | `agent-inbox/x25519-wrap/v1` | `nexusinbox/x25519-wrap/v1` |
| A2A MIME type | `application/vnd.agent-inbox.a2a+json; v=1` | `application/vnd.nexusinbox.a2a+json; v=1` |
| Domain (docs / .env.example) | `agent-inbox.ai`, `app.agent-inbox.ai`, `api.agent-inbox.ai` | `nexusinbox.ai`, `app.nexusinbox.ai`, `api.nexusinbox.ai` |

## 3. 意図的に保持したもの

| カテゴリ | 値 | 理由 |
|---|---|---|
| Env var prefix | `AGENT_INBOX_*` (35 個 / 565 references / 73 files) | operator-facing 設定名。リネームの ROI が薄く、互換性を担保したほうが運用障害が少ない。docs では「歴史的名称」として記載 |
| Postgres role / DB 名 | `agent_inbox` | 本番 DB 内部識別子。ユーザ非露出。本番 DB 自体の rename は別タスク扱い、`.env.example` / `docker-compose.yml` はそのまま |
| ADR ファイル名 (`docs/24_a2a_protocol_design.md` 等) | そのまま | URL 安定性のため。本文中のブランド mention のみ更新 |
| `AUTH_COOKIE_NAME` 定数名 (Rust の変数名) | そのまま | 内部変数名。Cookie の値だけ `nexusinbox_session` に変更 |
| `WORLD_ID_RP_ID` の **値** | そのまま (旧 prod の `rp_<...>` を再利用) | Worldcoin が Action 作成時に発行する relying-party 識別子で、**公開ホスト名ではない**。値を保つことで `nullifier_hash = f(app_id, action, identity)` が変わらず、既存ユーザのメタデータが新ドメイン側でもそのまま継続する。`.env.example` のプレースホルダ表記だけ `app.agent-inbox.ai` という誤読を招く形から `rp_<your-rp-id>` に修正した (詳細は §4.1 step 5 と [docs/18 §3.1](./18_production_bootstrap_runbook.md)) |

## 4. Operator migration ガイド

リネーム反映後、以下の手作業を 1 度だけ実施する。本セッション内で完結しない外部ダッシュボード操作。

### 4.1 必須

1. **Cloudflare Tunnel** — origin を `app.agent-inbox.ai` → `app.nexusinbox.ai` に更新。`api.agent-inbox.ai` も同様。
2. **Cloudflare Bulk Redirects** — `agent-inbox.ai/*` → 301 → `nexusinbox.ai/*` を追加して旧ドメインのリンクを救済。
3. **Vercel** — project の Production Domain を `app.nexusinbox.ai` に切替 (旧ドメインは Redirect として残す or 削除)。
4. **Fly.io** — app 名 `agent-inbox-api` を rename するか、新規 app `nexusinbox-api` を作って `flyctl launch --copy-config` で移行。`fly.toml` は既に `app = 'nexusinbox-api'`。
5. **World ID Developer Portal** — `WORLD_ID_RP_ID` は Worldcoin が Action 作成時に発行する `rp_<...>` 識別子で、**公開ホスト名 (`app.nexusinbox.ai`) ではない**。リネームでは値を変えず旧 prod のまま流用 (= 同じ Worldcoin app を再利用 → 同じ `nullifier_hash` → 既存ユーザのデータがそのまま見える)。新規環境で値を入れ直す場合のフォーマットは [docs/18 §3.1](./18_production_bootstrap_2026-04-18.md) を参照。
6. **GitHub repo** — `nexusinbox` org への transfer (CI badge / clone URL 影響あり)。

### 4.2 ユーザ側 (= prod は自分一人なので 1 回だけ)

ブラウザで `nexusinbox.ai` (新ドメイン) にアクセス後:

1. 旧ドメインで持っていたセッション cookie は cutover で無効化されている。新ドメインで World ID で **再ログイン** → DevTools Network タブで `Set-Cookie: nexusinbox_session=...` が発行されることを確認 (旧 cookie 名 `agent_inbox_session` は新コードでは存在しないので、トラブルシューティング時もこちらを見ない)。
2. **Calendar 連携** が "Not connected" 状態 (旧 IndexedDB `agent-inbox-gcal` は読まない)。`/settings/integrations` で再接続。
3. **AI Assistant (BYOK) API key** も "Not connected" (旧 IndexedDB `agent-inbox-llm` は読まない)。再保存。
4. localStorage の UI prefs (thread width 等) はリセット。再調整は任意。

旧ドメインのデータが残った IDB は `chrome://settings/cookies/detail?site=app.agent-inbox.ai` から手動クリア。

### 4.3 任意 (後続)

- 商標出願 (J-PlatPat / USPTO) — 「NexusInbox」「ネクサスインボックス」「Inbox for verified AI agents」
- npm publish (新 `@nexusinbox/*` package を実際に publish するかは戦略次第)
- 旧 `agent-inbox.ai` ドメイン保持 (transfer guard) — 1 年単位で更新

## 5. 検証

リネーム後、以下が green であることを確認した:

- `pnpm exec tsc --noEmit` (apps/web) — 型エラーなし
- `pnpm test` (apps/web vitest) — 134/134 passed
- `pnpm contract:check` — 64/64 passed
- `cargo fmt --check && cargo clippy -- -D warnings` (services/api, services/signer-daemon, services/agent-gateway) — clean
- `cargo test --lib` (services/api) — 77/77 passed
- `cargo test` (services/signer-daemon) — 58/58 passed (bridge HTTP header rename を含む)
- `cargo test` (services/agent-gateway) — 58/58 passed

## 6. リスクメモ

- **Rust integration test が DB 必須** — `AGENT_INBOX_DB_TESTS=1` 系は CI で別途検証。
- **Pre-existing clippy warnings** — `cargo clippy --tests` には 7 個の warning が残っているが、main にも同じ warning が存在する pre-existing 状態 (本リネームでは触れない)。
- **Fly app 名の不一致** — `fly.toml` は `app = 'nexusinbox-api'` だが Fly 上の actual app 名は旧名のまま。次回 deploy 前に §4.1 step 4 を実施する必要あり。
