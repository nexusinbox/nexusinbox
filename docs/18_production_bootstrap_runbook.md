# 18a. 本番初期セットアップ実行 Runbook

`docs/18_production_bootstrap_2026-04-18.md` の手順を「実際に進めるときにやること」に落とし込んだチェックリスト。

本ドキュメントは、デプロイ成果物（Dockerfile / fly.toml / vercel.json）が揃った前提で、各サービスに登録する値と順番を明示する。

---

## 0. 事前に用意されているもの

以下は既にリポジトリにコミット済み。手作業は不要。

| 成果物 | 場所 | 用途 |
|---|---|---|
| Rust API Dockerfile | `services/api/Dockerfile` | Fly.io ビルド |
| Docker ignore | `services/api/.dockerignore` | ビルド context を小さく |
| Fly.io 設定 | `services/api/fly.toml` | `fly launch` / `fly deploy` が読む |
| Vercel 設定 | `apps/web/vercel.json` | monorepo でのビルドコマンド固定 |
| DB マイグレーション | `services/api/migrations/0001–0010` | API 起動時に適用 |

---

## 1. World ID 本番 App の登録

**場所**: https://developer.worldcoin.org

| 設定項目 | 値 |
|---|---|
| App URL | `https://app.nexusinbox.ai` |
| Action | `login` |
| 検証レベル | `orb` のみ |

**取得するもの**:
- `WORLD_ID_APP_ID` (例: `app_xxxxxxxxxxxxx`)
- `WORLD_ID_SIGNER_PRIVATE_KEY` (Secret)

---

## 2. Supabase プロジェクト作成

**場所**: https://supabase.com/dashboard

1. Organization を作成（Free plan のまま）
2. Project 作成 — リージョンは Tokyo (ap-northeast-1) を推奨
3. Project Settings → Database → Connection string → **Transaction** or **Session** mode の URI をコピー
   - `sslmode=require` が含まれていることを確認

**取得するもの**:
- `DATABASE_URL=postgres://postgres.<ref>:<password>@<host>:5432/postgres?sslmode=require`

**補足**: マイグレーションは API の起動時に自動適用される（`initialize_database_if_configured` が `sqlx::migrate!()` を呼ぶ）。SQL Editor から手動で当てる必要はない。

---

## 3. Cloudflare R2 バケット + API Token

**場所**: https://dash.cloudflare.com → R2

1. Create bucket → 名前 `nexusinbox-prod`、リージョン `APAC`
2. bucket 詳細 → Settings → **CORS Policy** を以下の JSON で設定:

```json
[
  {
    "AllowedOrigins": ["https://app.nexusinbox.ai"],
    "AllowedMethods": ["PUT", "GET", "HEAD"],
    "AllowedHeaders": [
      "Content-Type",
      "x-amz-meta-attachment-id",
      "x-amz-meta-owner-user-id",
      "x-amz-meta-issued-at"
    ],
    "ExposeHeaders": ["ETag", "Content-Length"],
    "MaxAgeSeconds": 600
  }
]
```

3. R2 → **Manage R2 API Tokens** → Create API token
   - Permissions: Object Read & Write
   - Specify bucket(s): `nexusinbox-prod` のみに限定
   - TTL: 1年
4. 発行される Access Key ID / Secret Access Key / Endpoint URL を保存

**取得するもの**:
- `AGENT_INBOX_S3_ENDPOINT` = `https://<account-id>.r2.cloudflarestorage.com`
- `AGENT_INBOX_S3_ACCESS_KEY_ID`
- `AGENT_INBOX_S3_SECRET_ACCESS_KEY`

---

## 4. Fly.io アプリ作成 & デプロイ

**前提**: `flyctl` CLI ([install guide](https://fly.io/docs/hands-on/install-flyctl/))、Fly.io アカウント + カード登録済。

### 4.1 アプリ作成

```bash
cd services/api
fly launch --no-deploy --copy-config --name nexusinbox-api --region nrt
```

- `--copy-config` で既存の `fly.toml` が使われる
- `--no-deploy` で deploy は後回し

### 4.2 Secret 登録

まず強い `JWT_SECRET` を生成:

```bash
openssl rand -hex 32
```

32バイト hex を控えたら、Fly に一括登録:

```bash
fly secrets set \
  JWT_SECRET='<openssl で生成した値>' \
  DATABASE_URL='<Supabase の connection string>' \
  WORLD_ID_APP_ID='app_xxxxxxxxxxxxx' \
  WORLD_ID_ACTION=login \
  WORLD_ID_RP_ID=rp_<your-rp-id> \
  AGENT_INBOX_CORS_ORIGINS=https://app.nexusinbox.ai \
  AGENT_INBOX_S3_ENDPOINT='https://<account-id>.r2.cloudflarestorage.com' \
  AGENT_INBOX_S3_REGION=auto \
  AGENT_INBOX_S3_BUCKET=nexusinbox-prod \
  AGENT_INBOX_S3_ACCESS_KEY_ID='<r2_key>' \
  AGENT_INBOX_S3_SECRET_ACCESS_KEY='<r2_secret>' \
  AGENT_INBOX_S3_PATH_STYLE=false \
  AGENT_INBOX_S3_PREFIX=prod
```

**重要**: `PORT`, `LOG_FORMAT`, `NODE_ENV`, `AGENT_INBOX_DATABASE_REQUIRED`, `AGENT_INBOX_WORLD_VERIFY_ENABLED`, `AGENT_INBOX_COOKIE_SECURE` は `fly.toml` の `[env]` で設定済なので secrets に追加しない。

### 4.3 デプロイ

```bash
fly deploy
```

初回は 5〜8 分かかる。完了後の確認:

```bash
# マシンが起動しているか
fly status

# ヘルスチェック（fly が割り当てた仮ドメインで）
curl -i https://nexusinbox-api.fly.dev/health
```

### 4.4 カスタムドメイン

```bash
fly certs add api.nexusinbox.ai
```

Fly が DNS 設定を提示する。Cloudflare 側で `api` レコードを作る（§5 参照）。

---

## 5. Cloudflare DNS 設定

**場所**: Cloudflare Dashboard → nexusinbox.ai → DNS → Records

**重要**: 既存の `app` レコード（Cloudflare Tunnel）は一旦**バックアップを取ってから削除** or 無効化。

| Type | Name | Target | Proxy |
|---|---|---|---|
| CNAME | `app` | `cname.vercel-dns.com` | DNS only |
| CNAME | `api` | `<fly-app>.fly.dev` (fly certs add で表示される) | DNS only |

**補足**:
- proxy (orange cloud) は WebSocket 等で挙動が変わるため、最初は DNS only で始めて後で調整
- Vercel 側の CNAME 値は `Settings → Domains → Add` 後に表示される

---

## 6. Vercel プロジェクト作成 & デプロイ

**場所**: https://vercel.com/new

### 6.1 Import

1. GitHub → `nexusinbox` repository を import
2. **Framework Preset**: Next.js（自動判定）
3. **Root Directory**: `apps/web`
4. **Build / Install Command**: 自動判定されるはず（`vercel.json` がある）
5. そのまま deploy（失敗しても環境変数後に Redeploy する）

### 6.2 Environment Variables

**場所**: Project → Settings → Environment Variables
**Environment**: Production / Preview / Development の 3 つすべてにチェック

| Key | Value |
|---|---|
| `NODE_ENV` | `production` |
| `API_ORIGIN` | `https://api.nexusinbox.ai` |
| `NEXT_PUBLIC_API_BASE_URL` | `/api` |
| `NEXT_PUBLIC_SITE_URL` | `https://app.nexusinbox.ai` |
| `NEXT_PUBLIC_WS_URL` | `wss://api.nexusinbox.ai/ws` |
| `WORLD_ID_APP_ID` | (Secret) |
| `WORLD_ID_ACTION` | `login` |
| `WORLD_ID_RP_ID` | `rp_<your-rp-id>` (Worldcoin 発行の rp id; ドメインではない) |
| `WORLD_ID_SIGNER_PRIVATE_KEY` | (Secret) |

### 6.3 Domain 割当

1. Settings → Domains → Add → `app.nexusinbox.ai`
2. Vercel が DNS 検証方法を案内 → §5 で設定済みなら自動で Valid になる

### 6.4 Redeploy

Environment variables 追加後は既存 deploy に反映されないため、**Deployments タブから Redeploy**。

---

## 7. 疎通確認

```bash
# API のヘルスチェック
curl -i https://api.nexusinbox.ai/health
# → HTTP 200 + {"status":"ok","version":"0.1.0","service":"nexusinbox-api"}

# Web → API proxy が動いているか
curl -i https://app.nexusinbox.ai/api/health
# → HTTP 200 + 同じ JSON

# WebSocket
wscat -c wss://api.nexusinbox.ai/ws
# → 接続 OK（認証がなければ 401 だが TLS handshake は成立する）
```

ブラウザで `https://app.nexusinbox.ai` にアクセス → `/login` → World ID 認証 → 受信トレイが表示される、まで通ったら疎通完了。

---

## 8. CI の追従（任意）

本番 deploy 後、CI にも本番相当の検証を足すと安心:

- GitHub Actions の matrix に `cargo fmt --check && cargo clippy -- -D warnings` を追加（既に lint 内で実施中）
- main branch への push でのみ `fly deploy` を呼ぶ workflow（Fly.io token を Secrets に登録）

現状は手動 deploy で十分。自動化は運用が安定してから。

---

## 9. 問題が起きたときの切り戻し

| 症状 | 対処 |
|---|---|
| Fly の API が起動しない | `fly logs` → env 不足 / Supabase 接続失敗が定番 |
| Vercel build fail | `vercel.json` の buildCommand がモノレポ root から走るか確認 |
| `/health` は OK だが `/auth/verify` が 500 | `WORLD_ID_*` の値が Web/API で一致しているか確認 |
| 添付 upload が CORS で弾かれる | R2 bucket の CORS Policy を再確認（`x-amz-meta-issued-at` が含まれているか） |
| CSP violation | `middleware.ts` の nonce 生成が Edge runtime で走っているか（Vercel の Function logs で確認） |

Cloudflare Tunnel (ローカル運用) はいつでも復活できる: `~/.cloudflared/config.yml` を再度有効にして、DNS の `app` を tunnel 側に戻すだけ。

---

## 10. 初期セットアップで踏んだ地雷（2026-04-18 実録）

次回以降の自分/他メンバーが同じところで詰まらないように、実際に 2026-04-18 のデプロイでハマったポイントを残す。

### 10.1 Dockerfile の pre-warm キャッシュが stub バイナリを残していた

**症状**:
- `fly deploy` は成功
- マシン起動後 **約 2 秒で exit code 0**（SIGTERM ではない、panic でもない）
- アプリ側ログは一切出ない（`LOG_FORMAT=json` でも何も出ない）
- `file` コマンドで確認するとバイナリが **442 KB**（本来 10〜30 MB）

**原因**:
`Dockerfile` の依存関係キャッシュを温めるための pre-warm ステップ：

```dockerfile
# ❌ BAD
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo "fn main() {}" > src/main.rs \
    && touch src/lib.rs \
    && cargo build --release --locked 2>/dev/null || true \
    && rm -rf src

COPY src/ src/
RUN cargo build --release --locked --bin nexusinbox-api
```

この `touch src/lib.rs`（空の lib.rs を作ってコンパイル）のあとに本物の `src/lib.rs` をコピーしても、cargo のフィンガープリントキャッシュの状態によっては **再ビルドが効かず stub の `fn main() {}` バイナリが残ったまま**になる。結果、起動しても即 return する（main が空なので）。

**対処**:
pre-warm ステップを削除して素直にフルビルドする：

```dockerfile
# ✅ GOOD
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY migrations/ migrations/
RUN cargo build --release --locked --bin nexusinbox-api
```

初回ビルドは遅くなるが、確実。どうしても pre-warm したい場合は Docker の BuildKit cache mount (`--mount=type=cache,target=/build/target`) を使うほうが安全。

**診断手順（再発時に役立つ）**:
`ENTRYPOINT` を一時的にシェルラッパーに変えるとバイナリの状態が見える：

```dockerfile
ENTRYPOINT ["/bin/sh", "-c", "file /usr/local/bin/nexusinbox-api && ls -la /usr/local/bin/nexusinbox-api && /usr/local/bin/nexusinbox-api"]
```

`file` は `apt-get install file` で追加。バイナリサイズが 1 MB 未満なら何か間違っている。

### 10.2 Vercel で `turbo.json` に env を宣言していないとビルドに渡らない

**症状**:
Vercel の Environment Variables には `API_ORIGIN` 等を全部登録済みにもかかわらず、ビルドが：

```
Error: API_ORIGIN environment variable is required in production
```

で失敗。さらに Turbo の警告が出る：

```
[warn] @nexusinbox/web#build
[warn]   - API_ORIGIN
[warn]   - WORLD_ID_APP_ID
...
```

**原因**:
Turborepo は **ビルドタスクが参照する env を明示宣言しないと子プロセスに渡さない**（キャッシュキーの決定性を保つため）。Vercel の Project Settings で登録しても、Turbo が「これはビルドに必要ない変数」と判断して剥がしてしまう。

**対処**:
`turbo.json` の該当タスクに `env` 配列を追加：

```json
{
  "tasks": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": ["dist/**", ".next/**"],
      "env": [
        "NODE_ENV",
        "API_ORIGIN",
        "NEXT_PUBLIC_API_BASE_URL",
        "NEXT_PUBLIC_SITE_URL",
        "NEXT_PUBLIC_WS_URL",
        "WORLD_ID_APP_ID",
        "WORLD_ID_ACTION",
        "WORLD_ID_RP_ID",
        "WORLD_ID_SIGNER_PRIVATE_KEY"
      ]
    }
  }
}
```

`NEXT_PUBLIC_*` も、ビルド時にインライン化されるため明示宣言が必要（ランタイムで evaluate されるわけではない）。

**ついでの罠**: Next.js の `next.config.ts` で `process.env.API_ORIGIN` を参照しているコードは **ビルドタイムに実行される**ので、Vercel 側で env が見えていないとここで失敗する。ランタイム参照に逃がしたくなるが、`rewrites()` は静的に解決されるので無理。turbo.json での宣言が正道。

### 10.3 IDKit と CSP `'unsafe-eval'` — `/login` strict / `/login/idkit` 隔離の route 分離

**症状 (現象としては今も同じ)**:
- World ID ボタンを押しても **`IDKit error: generic_error`** が出て QR モーダルが開かない
- Network タブに `bridge.worldcoin.org` へのリクエストが**一切**出ない（初期化以前に死ぬ）
- DevTools Issues タブに「Directive: script-src / Status: blocked」が出る

**原因**:
`@worldcoin/idkit` v4 の transitive な依存（WalletConnect 系）が内部で `Function()` / `eval()` を呼ぶため、CSP の `script-src` に `'unsafe-eval'` が無いと初期化時点で例外。

**現在の design (shipped)**:
全域に `'unsafe-eval'` を付けると XSS の blast radius が広がるので、**route で隔離**してある:

| Route | `'unsafe-eval'` | `frame-ancestors` | 役割 |
|---|---|---|---|
| `/login` | ❌ なし (strict) | `'none'` | 親ページ。`<iframe>` で `/login/idkit` を埋め込むだけ |
| `/login/idkit` | ✅ あり | `'self'` (同一 origin の iframe 許可) | IDKit を実際に動かす隔離 sub-route |
| その他全 route | ❌ なし | `'none'` | strict のまま |

XSS が `/inbox` 等で起きても `eval()` は使えない。IDKit のため広げた eval 権限は `/login/idkit` という単一 route に閉じ込められている。

**実装の所在**:
- `apps/web/middleware.ts`
  - `UNSAFE_EVAL_PATHS = new Set(["/login/idkit"])` — eval 許可ルート 1 個
  - `SAME_ORIGIN_FRAME_PATHS = new Set(["/login/idkit"])` — 親 `/login` から iframe される
  - `buildCsp(nonce, pathname)` が pathname に応じて分岐

**operator が production でやること (= 何もしない)**:
- middleware.ts の上記 set はリポに入っているので、deploy するだけで route 分離が効く
- `'unsafe-eval'` を「production 全域に追加」してはいけない — 上の隔離が崩れて XSS 緩和が無効化される
- `script-src 'unsafe-eval'` を Next.js config / `vercel.json` / 上流 proxy で**追加するなら絶対に / 全域には付けない**

**新しく IDKit を別画面で使いたくなったら**:
- 新ルートを `UNSAFE_EVAL_PATHS` に直接追加するのは原則 NG (= eval を許可するルートが増える)
- 代わりに `<iframe src="/login/idkit?...">` を埋めて使う pattern を踏襲する
- 「eval を許可する route はちょうど 1 つ」という invariant を維持するのが XSS 表面積を小さく保つ唯一の方法

**将来 IDKit が `eval()` を排除したら**:
- `UNSAFE_EVAL_PATHS` から `/login/idkit` を削除 → 全 route が strict-dynamic only に統一できる
- IDKit / WalletConnect 系の changelog を半年に 1 度ぐらい見る価値あり

### 10.4 補足: CSP nonce を静的ページで効かせるには `headers()` で dynamic 化が必要

**症状**（10.3 と混ざりやすいので分けて記載）:
- Next.js のビルドで `/login` が `○` (Static) と出ている
- 本番で全 `_next/static/chunks/*.js` が `blocked` になる

**原因**:
Next.js 15 はランタイムに `Content-Security-Policy` ヘッダに含まれる nonce を検出して自動で `<script>` タグに stamp する。が、**静的生成されたページは HTML が build 時に焼かれる**ため、ランタイム nonce を埋め込む術がない。`'strict-dynamic'` 下では nonce なしスクリプトは全て拒否され、login ページが真っ白になる。

**対処**:
`app/layout.tsx` で `headers()` を呼んで全ページを dynamic render に落とす：

```tsx
import { headers } from "next/headers";

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Force dynamic rendering so Next.js can stamp the per-request nonce
  // into every auto-generated <script> tag.
  await headers();
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
```

ビルドログで `/login` が `ƒ (Dynamic)` に変われば OK。パフォーマンスへの影響は実質なし（Vercel の edge で毎回 render されるだけ、HTML は小さい）。

---

## 11. 残課題 — 運用上の未実装機能 (2026-04-18)

プライバシーポリシー / 利用規約でユーザーに提示した権利のうち、**セルフサービス機能として未実装**のもの。現状はお問い合わせフォーム経由で運営者が手動対応する運用で法的要件は満たしている。将来、請求件数が増えるなど運用負荷が上がってきたら自動化を検討する。

### 11.1 アカウント全体削除 (セルフサービス)

**現状**:
- ユーザー側 UI / API にアカウント削除エンドポイントなし
- 個別の message / agent / credential 削除はセルフサービス可能 (実装済み)
- アカウント全体の削除請求はお問い合わせフォーム (`/privacy` と `/terms` 記載) 経由

**手動対応手順 (請求が来たとき運営者が行うこと)**:
1. フォーム記入の `aid` / `did` で該当 `user_id` を特定 (`users` テーブル)
2. 本人確認 (同一 aid の credential で署名されたメッセージを送信してもらう等)
3. 関連テーブルの削除順序:
   - `agent_audit_log` (user_id FK)
   - `agent_tokens`
   - `agent_credentials`
   - `agent_identity_keys`
   - `agent_identities`
   - `agents`
   - `contacts`
   - `blocks`
   - `message_index`
   - `sessions`
   - `users`
4. BYOS object の掃除 (storage_ref を拾って R2 から削除)
5. World ID nullifier hash は deny list に退避しておくか検討 (再登録の扱い)
6. 請求者にメールで完了通知

**自動化するとしたら**:
- `DELETE /auth/account` エンドポイント (Cookie 認証必須、パスフレーズや IDKit 再認証で二段階確認)
- 上記 SQL を 1 トランザクションで実行
- BYOS 掃除は既存 `delete_storage_object_by_ref` を流用
- 推定工数: 0.5〜1 日

**優先度**: 中。請求件数が月数件を超えたら着手。

### 11.2 データエクスポート (ポータビリティ)

**現状**:
- E2E 暗号化の性質上、運営者側から出せるのは ciphertext のみ (復号鍵は持っていない)
- 意図的にセルフサービス機能を提供しない方針
- GDPR Art. 20 対応はお問い合わせフォームで個別対応

**自動化するとしたら**:
- スキーマが安定するまで本格実装は見送る
- 実装するなら JSON Lines 形式で `message_index` 全件 + `agents` + `contacts` + `blocks` + 暗号化本文の storage_ref 一覧を出す想定

**優先度**: 低。実装予定なし (請求件数と GDPR 対応負荷を見て判断)。
