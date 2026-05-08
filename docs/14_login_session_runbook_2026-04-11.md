# ログイン/セッション運用Runbook (2026-04-11)

## 目的

- World ID 認証後にダッシュボード遷移しない問題を再発させない
- ローカル開発と `app.nexusinbox.ai` 経由の確認手順を統一する

## 現在の実装ポイント

- Web ミドルウェアで未認証アクセスを `/login?next=...` へリダイレクト
- ログイン画面は `Connect World ID` ボタンのみを主導線にした最小構成
- `POST /api/auth/verify` (Next Route) で API の `Set-Cookie` を Web オリジンへ転送
- `GET /api/auth/session` で `HttpOnly` セッションcookie定着を判定
- ログイン成功時はセッション確立を短時間ポーリング確認後に `next` へ遷移
- エージェント設定画面では以下を分けて表示する
  - `aid:ai:...` = 人間や外部システムに共有する安定 ID
  - `did:key:...` = 現在アクティブな鍵に対応する技術 DID
  - `credential_id` + `enrollment_secret` = Signer Daemon 初回登録に必要

## 使用エンドポイント

- `GET /api/world/request-config`
- `POST /api/auth/verify`
- `GET /api/auth/session` — 認証状態 + プロフィール取得 (Web の認証ガードが利用)
- `PATCH /api/auth/session` — `display_name` 更新
- `POST /api/auth/logout` — セッション失効 + Cookie クリア
- `GET /api/status` — バックエンド機能の公開ステータス (認証不要)

## ローカル実行手順（固定URL確認）

1. API 起動

```bash
# from repo root
cargo run --manifest-path services/api/Cargo.toml
```

2. Web 起動

```bash
# from repo root
pnpm --filter @nexusinbox/web dev --port 3100
```

3. Cloudflare Named Tunnel 起動

```bash
cloudflared tunnel run nexusinbox
```

4. 確認URL

- `https://app.nexusinbox.ai/login`

## 必須環境変数

### Web (`apps/web/.env.local`)

- `WORLD_ID_APP_ID`
- `WORLD_ID_ACTION=login`
- `WORLD_ID_RP_ID`
- `WORLD_ID_SIGNER_PRIVATE_KEY`
- `NEXT_PUBLIC_API_BASE_URL=/api`

### API (`services/api/.env.local`)

- `JWT_SECRET` (32文字以上のランダム値)
- `JWT_ISSUER` (任意, default: `nexusinbox-api`)
- `JWT_AUDIENCE` (任意, default: `nexusinbox-web`)
- `AGENT_INBOX_COOKIE_SECURE=true` (本番推奨。`NODE_ENV=production` では強制Secure。Cloudflare Tunnel 経由で HTTPS 終端する構成では明示的に有効化する)
- `AGENT_INBOX_CORS_ORIGINS=https://app.nexusinbox.ai,http://localhost:3000,http://localhost:3100` (CSRF Origin 許可リスト。未設定時は `NODE_ENV` から自動決定するが、Tunnel 経由で `NODE_ENV` を開発のままにする場合は必須)
- `DATABASE_URL` (本番では必須。未設定時の in-memory フォールバックは `database_required()` で無効化される)
- `WORLD_ID_APP_ID`
- `WORLD_ID_ACTION=login`
- `AGENT_INBOX_WORLD_VERIFY_ENABLED=true`
- `AGENT_INBOX_ALLOW_WORLD_VERIFY_MOCK=false` (本番では常に無効扱い)
- `WORLD_ID_VERIFY_BASE_URL=https://developer.world.org`

## 非対話型エージェント接続の運用手順

1. 人間が World ID でログインする
2. `/settings/agents` でエージェントを作成する
3. 同画面で API クレデンシャルを作成する
4. 作成直後に表示される以下 3 つを安全な経路で Signer Daemon に渡す

- `aid` — 共有用の安定した Agent ID
- `credential_id` — クレデンシャル識別子
- `enrollment_secret` — 一度だけ表示される有効化シークレット

5. Signer Daemon が鍵ペアを生成し、`POST /agent-credentials/:id/activate` を実行する
6. Signer Daemon が JWS Assertion を使って `POST /agent-auth/token` でトークンを取得する
7. 宛先が `aid:ai:...` で共有されている場合は `GET /recipients/resolve?identifier=<aid>` で現在 DID と公開鍵を解決する
8. 以後の送信 API では `sender_did` に Signer Daemon が登録した現在 DID を使う

補足:

- `agent_id` UUID は UI 内部での選択に使う内部 ID であり、通常は人間が控える必要はない
- `recipient_did` という入力名は残っているが、現在は `aid:ai:...` も受理し、サーバー側で current DID に解決する

## トラブルシューティング

### 1) `Unexpected token '<'` が出る

原因:
- API Route が JSON ではなく Next のエラーページ(HTML)を返している

対処:

```bash
# from repo root
rm -rf apps/web/.next
pnpm --filter @nexusinbox/web dev --port 3100
```

### 2) 認証成功表示は出るが遷移しない

確認:
- `https://app.nexusinbox.ai/api/auth/session` を開く

期待:
- `{"authenticated":true}` ならセッションは定着済み
- `{"authenticated":false,...}` なら cookie 未定着

### 3) `DNS_PROBE_FINISHED_NXDOMAIN`

原因:
- Quick Tunnel URL 失効

対処:
- Named Tunnel (`app.nexusinbox.ai`) を使う
- `cloudflared tunnel run nexusinbox` を再起動

### 4) API起動直後に `invalid API runtime configuration: JWT_SECRET is required`

原因:
- APIは起動時にJWT設定を検証し、`JWT_SECRET` 未設定/短すぎる値を拒否する

対処:
- `services/api/.env.local` に32文字以上の `JWT_SECRET` を設定
- 必要に応じて `JWT_ISSUER` / `JWT_AUDIENCE` を明示指定

### 5-A) `/api/auth/verify` が **403 Forbidden** で `"request origin is not allowed"` を返す

原因:
- CSRF Origin ミドルウェアが Origin ヘッダを許可リストと照合し、不一致で 403
- Cloudflare Tunnel 経由でアクセスすると Origin は `https://app.nexusinbox.ai` だが、`NODE_ENV` 未設定(= 開発モード)の許可リストは `localhost:3000/3100` のみ

対処:
- `AGENT_INBOX_CORS_ORIGINS` 環境変数に Tunnel の公開ホストを含める:
  ```bash
  export AGENT_INBOX_CORS_ORIGINS="https://app.nexusinbox.ai,http://localhost:3000,http://localhost:3100"
  ```
- API を再起動して反映

### 5-B) `/api/auth/session` が **404 Not Found** を返す

原因:
- 古い Rust API バイナリが 8080 に残っていて、新しく追加された `/auth/session` ルートがまだ存在しない

対処:
```bash
lsof -i :8080          # 古いプロセスの PID を確認
kill <PID>
cd ~/dev/NexusInbox/services/api
cargo run              # 最新ソースからリビルド
```
疎通確認:
```bash
curl -i http://localhost:8080/auth/session
# → 401 unauthorized が返れば OK (404 ならまだ古いバイナリが動いている)
```

### 5-C) 認証直後に `/` に遷移するが即座に `/login` に戻される

原因 (過去発生):
- `AppShell` / `AuthSessionStatus` / `RealtimeSubscriber` が同一 queryKey `["auth","session"]` を **別々の queryFn** で登録していたため、TanStack Query 内部で衝突し、片方がエラー → `data: undefined` → 認証ガードが未認証扱いして redirect するループ

対処 (適用済み):
- `apps/web/lib/api/hooks.ts` に `useAuthSessionQuery` を追加し、3コンポーネントを同一フックで統一
- `lib/api/client.ts#getAuthSession` が 401/403 で throw せず `{ authenticated: false }` を返すよう変更
- `AuthSessionStatus` の redirect 判定を「`data !== undefined && !authenticated`」に厳格化 (ネットワーク一過性エラーで勝手にログアウトされない)

再発した場合は `["auth","session"]` queryKey を `useQuery` で独自登録している箇所がないか `grep -rn '"auth", "session"'` で確認する。

### 6) `world_verify_required` が返る

原因:
- `NODE_ENV=production` では mock認証が禁止され、World verify有効化が必須

対処:
- `AGENT_INBOX_WORLD_VERIFY_ENABLED=true` を設定
- `WORLD_ID_RP_ID` と World verify設定を有効化

## 既知の制約

- まだ World proof は legacy 受け取りベースで運用
- Web ミドルウェアは cookie の存在判定であり、署名検証は API 側が担当

## 次の改善候補

1. Web 側アクセス制御の厳密化（署名付きセッション検証）
2. World proof v4 ネイティブ対応
