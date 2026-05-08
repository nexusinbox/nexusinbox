# 27. Local Dev → Production 反映フロー (2026-05-01)

## 1. 目的

公開後は「ローカルで挙動確認 → main に merge → 本番反映」が日常運用になる。
このドキュメントは **その手順を 1 箇所に固定**して、毎回考え直さなくて済むようにする。

## 2. 1 度だけやるセットアップ

```bash
git clone git@github.com:nexusinbox/nexusinbox.git
cd nexusinbox
cp .env.example .env

# 必須: JWT_SECRET を 32 文字以上の乱数に置き換える
# (空のままだと API が起動拒否)
sed -i '' "s/replace-with-32chars-or-more-random-secret/$(openssl rand -hex 32)/" .env

# 必須ツール
brew install pnpm rustup-init flyctl
rustup-init -y                     # Rust toolchain
pnpm install                       # workspaces 全部解決
```

`pnpm --filter @nexusinbox/mcp-server build` を 1 度走らせると MCP の `dist/` ができる
(`pnpm dev` 経由で turbo が呼ぶので普段は意識不要)。

## 3. 毎日の起動: ターミナル 3 つ

```bash
# ── Terminal 1: 依存サービス (Postgres / Redis / MinIO / IPFS)
docker compose up -d
# → postgres on :5432, redis on :6379, minio on :9000+:9001
# 落とす時は `docker compose down`、データ全削除なら `docker compose down -v`

# ── Terminal 2: API (Rust/Axum)
cargo run --manifest-path services/api/Cargo.toml
# → http://localhost:8080
# 起動時に sqlx::migrate! が migrations/ を順に流す (services/api/src/lib.rs:1017)
# → migration 追加した時はここで自動適用される
# 確認: curl -s http://localhost:8080/health  →  ok
# 注意: 既に動いてる prod DB に向けると本番 schema を破壊しうるので、
#        DATABASE_URL がローカルの postgres を指していること

# ── Terminal 3: Web (Next.js)
pnpm --filter @nexusinbox/web dev --port 3100
# → http://localhost:3100
# CSP 用の nonce を毎リクエストで生成するため必ず dynamic 描画
```

ブラウザで <http://localhost:3100> を開く → /login にリダイレクト → World ID。

### Dev での World ID

`.env` で:

```
AGENT_INBOX_WORLD_VERIFY_ENABLED=false
AGENT_INBOX_ALLOW_WORLD_VERIFY_MOCK=true
```

の状態だと、IDKit から実際の Worldcoin 検証を呼ばずに **mock proof** で通る。
本番 token は発行されず、ローカルで完結。詳しくは
[`docs/14_login_session_runbook_2026-04-11.md`](./14_login_session_runbook_2026-04-11.md)。

### MCP / Signer Daemon は通常不要

Web + API だけ動かせば inbox / compose / settings は全部触れる。
**MCP の動作確認をする時** だけ追加で:

```bash
# MCP server (Claude Desktop から繋ぐ前にセットアップ)
pnpm --filter @nexusinbox/mcp-server build
AGENT_AID=aid:ai:test \
AGENT_CREDENTIAL_ID=<uuid from /settings/agents> \
AGENT_ENROLLMENT_SECRET=<ens_...> \
AGENT_INBOX_BASE_URL=http://localhost:8080 \
AGENT_KEYSTORE_PASSPHRASE=devpass \
node packages/mcp-server/dist/cli.js --init
```

## 4. 変更してから commit までの確認シーケンス

「コードをいじった → push する前に必ずこれだけ通す」リスト。
CI が走るのと同じコマンドなのでローカルで通ればほぼ赤化しない。

### TS / Web 側を触ったら

```bash
cd apps/web
pnpm exec tsc --noEmit            # 型エラー
pnpm test                         # vitest (134 tests)
pnpm test:e2e                     # Playwright (DB は不要、middleware モック完結)
                                  # CI ではまだ走らないが、auth gate に依存する変更は手元で 1 度回す
cd ../..
pnpm contract:check               # OpenAPI lint + contract test
```

### Rust 側を触ったら (CLAUDE.md と一致)

```bash
cd services/<api|signer-daemon|agent-gateway>
cargo fmt && cargo clippy -- -D warnings
cargo test --lib                  # api: 77 tests、signer-daemon/gateway は --bins
```

> CI は `cargo fmt --check && cargo clippy -- -D warnings` を走らせる。
> 1 行 if-else をフォーマッタが書き直したいだけの差分で赤になるので、
> 必ずローカルで `fmt` を先に通してから commit する。

### MCP server を触ったら

```bash
cd packages/mcp-server
pnpm test                         # 33 tests (build → vitest)
```

### 全部触った場合

repo ルートで:

```bash
pnpm test                         # turbo で全 workspace のテスト
pnpm contract:check
```

## 5. ローカル → 本番までの flow

```
   feature branch
        │
        │ git push
        ▼
   ┌──────────────────────────────────┐
   │ GitHub PR (gh pr create)         │
   ├──────────────────────────────────┤
   │ CI workflow (ci.yml)             │
   │  ├─ node (tsc + vitest +         │
   │  │  contract)                    │
   │  ├─ rust-api (fmt + clippy +     │
   │  │  test --lib, with cache)      │
   │  ├─ rust-signer-daemon           │
   │  └─ rust-agent-gateway           │
   │ → 全部 green になるまで merge 禁止 │
   └──────────────────────────────────┘
        │ gh pr merge <N> --rebase --delete-branch
        ▼
   ┌──────────────────────────────────┐
   │ main branch                      │
   └──────────────────────────────────┘
        │
        │ workflow_run (deploy-api.yml が CI 完了を待つ)
        │
        ├──── apps/web/** が変わった?
        │       │
        │       ▼
        │   ┌─────────────────────────────┐
        │   │ Vercel auto deploy           │
        │   │ → app.nexusinbox.ai (≈ 5 分) │
        │   └─────────────────────────────┘
        │
        └──── services/api/** が変わった?
                │
                ▼
            ┌──────────────────────────────┐
            │ deploy-api.yml が flyctl     │
            │ deploy + /health smoke       │
            │ → api.nexusinbox.ai (≈ 8 分) │
            └──────────────────────────────┘
```

判別ロジック:

| 変更パス | 自動 deploy 先 | 触った時の確認 |
|---|---|---|
| `apps/web/**` | Vercel | `https://app.nexusinbox.ai/` ブラウザ目視 + DevTools |
| `services/api/**` | Fly | `curl -sI https://api.nexusinbox.ai/health` |
| `services/signer-daemon/**` `services/agent-gateway/**` | **手動** (本番では現状未配備) | ローカルで `cargo test --bins` |
| `packages/mcp-server/**` | **publish していない**ので影響範囲はローカル + `--init` 済端末のみ | `pnpm test` |
| `docs/**` `README.md` | 自動 deploy なし | GitHub 上で render 確認 |
| `apps/web/middleware.ts` の `isPublicPath` | Vercel | **新しい file-conv route を追加した時は必ずここに allow-list する** (commit `327cb0a` の教訓、PR #6) |

## 6. 本番反映後の確認

merge → deploy 完了したら必ず:

```bash
# Web
curl -sI https://app.nexusinbox.ai/login | head -3
# → HTTP/2 200

curl -sI https://app.nexusinbox.ai/opengraph-image | head -3
# → HTTP/2 200, content-type: image/png

# API
curl -s https://api.nexusinbox.ai/health
# → ok (warm なら < 1s、auto_stop=stop の machine が起きる時は ~7s)

# OG card プレビュー (link unfurl)
open "https://www.opengraph.xyz/url/https%3A%2F%2Fapp.nexusinbox.ai"
```

ブラウザで `app.nexusinbox.ai` にアクセス → 自分のセッションで本番動作を 1 件 (例: 受信箱表示 / compose 起動) 触る。

### Mobile login (Android Chrome / iOS Safari)

スマホは独自の落とし穴があるので、**desktop でログインできた = 完了** ではない。
最低 1 回はスマホ実機で `/login` → World ID 認証まで通すこと。

設計メモ:

- `/login` は mobile UA 検知時に **`/login/idkit` へ top-level navigation** する。
- desktop は引き続き iframe 内に embed (eval-isolation 維持、docs/18 §10.3)。
- 理由: Android Chrome は **iframe 内からの `https://world.org/...` App Link を World App にルーティングしない** — iframe 内では普通の HTTP navigation 扱いになる。iOS Safari の universal link も iframe 経由だと不安定。

「**World ID アプリが起動しない / コンテンツがブロックされました**」と報告されたら、上から順に確認:

1. **World App 自体がインストールされているか** (Play Store / App Store)。未インストールなら link は web fallback に落ちる。
2. **アプリ内ブラウザではないか** — LINE / X / Instagram / Facebook の中で URL を踏むと universal link が壊れる。「ブラウザで開く」 / 「Safari で開く」を案内。
3. **mobile UA 検知が動いているか** — `/login` で「Connect World ID」を押した瞬間に URL が `/login/idkit?next=...` に変わるはず。変わらなければ UA detection が落ちている (例: Brave で UA spoofing on)。
4. **CSP に `world-id-assets.com` が残っているか** — `apps/web/middleware.ts` の `font-src` / `img-src`。IDKit が TWK Lausanne フォントをここから fetch するので、外すと iOS Safari で violation interstitial が出ることがある (PR #9 の教訓)。
5. **コンテンツブロッカ拡張** — 1Blocker / AdGuard / Brave Shields が `worldcoin.org` を弾いている可能性。一時的に無効化して検証。

DevTools を mobile mode (Chrome → Toggle device toolbar → Pixel 等) にして UA を Android に切り替えると、`/login` の挙動が iframe → top-level redirect に変わるのを手元で再現できる。

## 7. 困った時の rollback

### Vercel (Web)

Dashboard → Deployments → 1 つ前の successful deploy → `…` → **Promote to Production**。1 分以内に旧版に戻る。

### Fly (API)

```bash
flyctl releases -a nexusinbox-api          # 履歴
flyctl deploy --image-label v123 -a nexusinbox-api   # 戻したい version で再 deploy
```

または GitHub Actions の `Deploy API` ワークフローを `workflow_dispatch` で
known-good commit ref に向けて走らせる ([`docs/18_production_bootstrap_runbook.md`](./18_production_bootstrap_runbook.md) §7)。

### DB マイグレーション

`sqlx::migrate!` は **追記のみ** で動く設計なので、追加した migration が壊れた場合は
**新しい migration ファイルを書いて打ち消す** のが正攻法。手で `\_sqlx_migrations`
を編集するのは最後の手段 (commit `ece7ed4` の教訓)。

## 8. 関連 docs

- [`README.md`](../README.md) §"Quick start (local dev)"
- [`CLAUDE.md`](../CLAUDE.md) §"コミット前チェック"
- [`docs/14_login_session_runbook_2026-04-11.md`](./14_login_session_runbook_2026-04-11.md) — World ID dev フロー
- [`docs/18_production_bootstrap_runbook.md`](./18_production_bootstrap_runbook.md) — 本番 bootstrap、§10 footguns、§7 rollback
- [`docs/19_non_interactive_agent_runbook_2026-04-18.md`](./19_non_interactive_agent_runbook_2026-04-18.md) — Signer Daemon / Gateway 運用
- [`packages/mcp-server/README.md`](../packages/mcp-server/README.md) — MCP setup
