# 18. 本番初期セットアップガイド (Vercel + Supabase + Fly.io)

## 1. 目的

このドキュメントは、NexusInbox を以下の最小構成で本番相当公開するための初期セットアップ手順をまとめる。

- Web: Vercel
- DB: Supabase (Postgres)
- API: Fly.io
- DNS: Cloudflare
- 添付: Cloudflare R2

方針:

- 最初は「数名で確認できる」ことを優先する
- セキュアでシンプルな構成を崩さない
- 使い始めは無料または最小課金で始める
- 後から有料プランへ昇格できる前提で設計する

2026-04-18 時点の公式情報ベースでは:

- Vercel Hobby は無料
- Supabase Free は 2 free projects まで
- Fly.io は新規 org では実質的に usage-based 課金前提で考える

参考:

- Vercel Hobby: https://vercel.com/docs/plans/hobby
- Supabase billing: https://supabase.com/docs/guides/platform/billing-on-supabase
- Fly.io billing: https://fly.io/docs/about/billing/

---

## 2. 推奨初期構成

### 2.1 ドメイン

- `app.nexusinbox.ai` -> Vercel
- `api.nexusinbox.ai` -> Fly.io

補足:

- Web から API へは `API_ORIGIN=https://api.nexusinbox.ai` で接続する
- WebSocket も API 側から配信するため、`NEXT_PUBLIC_WS_URL=wss://api.nexusinbox.ai/ws` を使う

### 2.2 プラットフォームごとの役割

| 役割 | サービス | 初期プラン |
|---|---|---|
| Next.js 配信 | Vercel | Hobby |
| PostgreSQL | Supabase | Free |
| Rust API 常駐 | Fly.io | 最小構成の従量課金 |
| DNS / Proxy | Cloudflare | Free |
| Object Storage | Cloudflare R2 | 従量課金 |

### 2.3 なぜこの分割か

- Vercel は Next.js 15 の配信に最も相性がよい
- Supabase は Postgres の初期運用が軽い
- Fly.io は Rust API 常駐プロセス運用に向く
- Cloudflare は DNS / TLS / R2 をまとめやすい

---

## 3. 初期セットアップ手順

## 3.1 先に決めるもの

最初に以下を確定する。

- 本番 Web URL: `https://app.nexusinbox.ai`
- 本番 API URL: `https://api.nexusinbox.ai`
- World ID Action 名: `login`
- Supabase organization 名
- Fly.io organization 名
- R2 bucket 名

## 3.2 Supabase

1. Supabase で新規 organization を作る
2. Free plan のまま新規 project を作る
3. Project Settings から connection string を取得する
4. SQL Editor または migration 経由で API 起動時に schema を適用する
5. 接続情報を API 用 Secret として保存する

初期確認ポイント:

- `DATABASE_URL` が取得できる
- `sslmode=require` 付きの接続文字列を使う
- Free plan の project pause 挙動を理解しておく

## 3.3 Fly.io

1. Fly.io organization を作成する
2. クレジットカードを登録する
3. `services/api/Dockerfile` を使って API アプリを作る
4. 最初は 1 app / 1 machine / 最小メモリ構成で始める
5. `api.nexusinbox.ai` を Fly app に向ける
6. Secret を登録して deploy する

初期確認ポイント:

- API は `PORT=8080` で起動する
- `DATABASE_URL` で Supabase に接続できる
- `AGENT_INBOX_DATABASE_REQUIRED=true` を有効にする
- `NODE_ENV=production` で起動する

## 3.4 Vercel

1. GitHub repository を Vercel に import する
2. root は monorepo のままで、Web app を `apps/web` として設定する
3. `app.nexusinbox.ai` を Vercel project に紐付ける
4. Environment Variables を登録する
5. Production Deployment を作る

初期確認ポイント:

- `API_ORIGIN` が `https://api.nexusinbox.ai`
- `NEXT_PUBLIC_WS_URL` が `wss://api.nexusinbox.ai/ws`
- `/login` から World ID 連携が始まる

## 3.5 Cloudflare DNS / R2

1. `nexusinbox.ai` を Cloudflare 管理下に置く
2. `app` を Vercel 向け CNAME にする
3. `api` を Fly.io 側に向ける
4. R2 bucket を 1 つ作成する
5. R2 API Token を発行する
6. API 側へ S3 互換変数として登録する

初期確認ポイント:

- bucket は public にしない
- presigned URL のみで upload / download する
- CORS は必要最小限にする

## 3.6 World ID

1. Developer Portal で app URL を `https://app.nexusinbox.ai` に設定する
2. `Action = login` を作成する
3. `App ID` と signer private key を取得する
4. Web / API 双方で action 名を一致させる

初期確認ポイント:

- Web と API で `WORLD_ID_ACTION=login` が一致する
- `WORLD_ID_APP_ID` が本番値
- orb のみ許可する運用で固定する

---

## 4. 本番向け環境変数整理表

## 4.1 Web (`apps/web`)

| 変数 | 必須度 | 例 | 用途 |
|---|---|---|---|
| `NODE_ENV` | 必須 | `production` | 本番モード |
| `API_ORIGIN` | 必須 | `https://api.nexusinbox.ai` | Next.js から API へ rewrite / proxy |
| `NEXT_PUBLIC_API_BASE_URL` | 推奨 | `/api` | ブラウザ側 API base |
| `NEXT_PUBLIC_SITE_URL` | 必須 | `https://app.nexusinbox.ai` | metadata / canonical base |
| `NEXT_PUBLIC_WS_URL` | 必須 | `wss://api.nexusinbox.ai/ws` | Realtime 接続先 |
| `WORLD_ID_APP_ID` | 必須 | `app_...` | IDKit 設定 |
| `WORLD_ID_ACTION` | 必須 | `login` | World ID Action |
| `WORLD_ID_RP_ID` | 必須 | `rp_<your-rp-id>` | Worldcoin が Action 作成時に発行する relying party id。**ドメインではない** |
| `WORLD_ID_SIGNER_PRIVATE_KEY` | 必須 | `<secret>` | IDKit request config 生成 |

補足:

- `NEXT_PUBLIC_API_BASE_URL` は現状 `/api` のままでもよい
- `API_ORIGIN` は本番では必須

## 4.2 API (`services/api`)

| 変数 | 必須度 | 例 | 用途 |
|---|---|---|---|
| `NODE_ENV` | 必須 | `production` | 本番モード |
| `PORT` | 必須 | `8080` | API listen port |
| `JWT_SECRET` | 必須 | 32文字以上 | セッション署名 |
| `DATABASE_URL` | 必須 | `postgres://...` | Postgres 接続 |
| `AGENT_INBOX_DATABASE_REQUIRED` | 必須 | `true` | in-memory fallback 禁止 |
| `AGENT_INBOX_WORLD_VERIFY_ENABLED` | 必須 | `true` | World verify 本番有効化 |
| `WORLD_ID_APP_ID` | 必須 | `app_...` | World ID verify |
| `WORLD_ID_ACTION` | 必須 | `login` | verify action 一致 |
| `WORLD_ID_RP_ID` | 必須 | `rp_<your-rp-id>` | World verify URL のパスに埋め込む rp id。**ドメインではない** |
| `WORLD_ID_VERIFY_BASE_URL` | 任意 | `https://developer.worldcoin.org/api/v2` など | verify API base override |
| `AGENT_INBOX_COOKIE_SECURE` | 必須 | `true` | Secure cookie |
| `AGENT_INBOX_CORS_ORIGINS` | 必須 | `https://app.nexusinbox.ai` | 許可 origin |
| `LOG_FORMAT` | 推奨 | `json` | 構造化ログ |

## 4.3 添付ファイル/R2 (API 側)

| 変数 | 必須度 | 例 | 用途 |
|---|---|---|---|
| `AGENT_INBOX_S3_ENDPOINT` | 必須 | `https://<account>.r2.cloudflarestorage.com` | R2 endpoint |
| `AGENT_INBOX_S3_REGION` | 必須 | `auto` | R2 region |
| `AGENT_INBOX_S3_BUCKET` | 必須 | `nexusinbox-prod` | bucket 名 |
| `AGENT_INBOX_S3_ACCESS_KEY_ID` | 必須 | `<secret>` | R2 access key |
| `AGENT_INBOX_S3_SECRET_ACCESS_KEY` | 必須 | `<secret>` | R2 secret key |
| `AGENT_INBOX_S3_PATH_STYLE` | 推奨 | `true` または `false` | endpoint 方式に合わせる |
| `AGENT_INBOX_S3_PREFIX` | 任意 | `prod` | object prefix |

## 4.4 初期フェーズでは不要または後回し

| 変数 | 状態 |
|---|---|
| `AGENT_INBOX_GDRIVE_*` | Google Drive adapter 着手時に設定 |
| `AGENT_INBOX_IPFS_*` | IPFS backend 利用時のみ |
| `AGENT_INBOX_FILTER_SERVICE_URL` | 外部 spam filter 導入時 |
| `AGENT_INBOX_ADMIN_TOKEN` | 管理系 endpoint を外部運用するなら設定 |
| `JWT_ISSUER`, `JWT_AUDIENCE` | 将来の厳格運用で整理 |

---

## 5. Secret の置き場所

| 変数群 | 保存先 |
|---|---|
| Web 用公開設定 (`NEXT_PUBLIC_*`) | Vercel Environment Variables |
| Web 用秘密 (`WORLD_ID_SIGNER_PRIVATE_KEY`) | Vercel Environment Variables |
| API 秘密 (`JWT_SECRET`, `DATABASE_URL`, `AGENT_INBOX_S3_*`) | Fly.io Secrets |
| GitHub Actions 用必要値 | GitHub Actions Secrets |
| ローカル開発用 | `.env.local` / `.env` (未コミット) |

ルール:

- `.env`, `.env.local`, 秘密鍵はコミットしない
- Web と API で同じ値を持つ変数は、表を見ながら二重登録漏れがないようにする

---

## 6. まず無料/最小課金で始める具体プラン

## 6.1 推奨

### Vercel

- Plan: Hobby
- 用途: `apps/web` の production / preview 配信
- 理由:
  - 数名規模の確認なら十分
  - 先に UI / login / API 接続確認へ進める

注意:

- Hobby は無料だが、超過時は自動課金より制限待ちになる機能がある
- 商用公開を本格化する段階では Pro を検討する

### Supabase

- Plan: Free
- 用途: production-like DB を 1 project 用意
- 理由:
  - 数名規模確認には十分
  - schema / migration / session / message_index の本番相当確認ができる

注意:

- Free は 2 free projects まで
- pause や各種制限があるので、継続運用段階では Pro へ上げる

### Fly.io

- Plan: usage-based の最小構成
- 用途: Rust API 常駐
- 理由:
  - 無料枠前提より「小額課金前提」で考えたほうが現実的
  - 常駐プロセスの本番確認ができる

注意:

- 新規 org はクレジットカードが必要
- 最初から「無料枠で乗り切る」前提にはしない

### Cloudflare R2

- Plan: 従量課金
- 用途: 添付 upload/download
- 理由:
  - 数名・5MB制限であれば初期コストは小さい
  - 早い段階から本番構成で試せる

## 6.2 最初の実行順

1. Supabase Free で DB を作る
2. Fly.io に API を 1台だけ立てる
3. Vercel Hobby で Web を出す
4. Cloudflare DNS で `app` / `api` を固定化する
5. World ID の本番 app URL を `https://app.nexusinbox.ai` で確定する
6. R2 を繋いで添付 upload を有効化する

---

## 7. 昇格の目安

## 7.1 Vercel Pro に上げるタイミング

- チームメンバーを増やす
- Preview / Runtime logs / spend management が必要
- Hobby 制限が運用の足を引っ張る

## 7.2 Supabase Pro に上げるタイミング

- Free の pause / 制限が厳しい
- PITR や custom domain を使いたい
- 数名確認を超えて継続運用へ入る

## 7.3 Fly.io でコストを上げるタイミング

- API の CPU / RAM が足りない
- 監視・安定性のため machine を増やす
- HA や multi-region を考え始める

---

## 8. 初期 Go / No-Go

初期公開前に最低限満たすべき条件:

1. `app.nexusinbox.ai` と `api.nexusinbox.ai` が固定化されている
2. `NODE_ENV=production` で Web/API が起動する
3. `DATABASE_URL` 必須化が有効
4. `AGENT_INBOX_WORLD_VERIFY_ENABLED=true`
5. `WORLD_ID_ACTION=login` が Web/API で一致
6. `AGENT_INBOX_COOKIE_SECURE=true`
7. `AGENT_INBOX_CORS_ORIGINS=https://app.nexusinbox.ai`
8. 添付を使うなら `AGENT_INBOX_S3_*` が揃っている
9. CI が green

---

## 9. 次にやること

1. Vercel / Supabase / Fly.io / Cloudflare / World ID / R2 のアカウントと project を作る
2. 環境変数を Secret Manager に登録する
3. API を Fly.io へ deploy する
4. Web を Vercel へ deploy する
5. World ID login と message read path を production URL で確認する

---

## 10. 登録先別の実値テンプレート

以下は 2026-04-18 時点の NexusInbox 本番想定値テンプレートである。

## 10.1 Vercel に登録する値

対象:

- `Vercel > Project Settings > Environment Variables`

登録するキー:

```env
NODE_ENV=production
API_ORIGIN=https://api.nexusinbox.ai
NEXT_PUBLIC_API_BASE_URL=/api
NEXT_PUBLIC_SITE_URL=https://app.nexusinbox.ai
NEXT_PUBLIC_WS_URL=wss://api.nexusinbox.ai/ws
WORLD_ID_APP_ID=app_xxxxxxxxxxxxx
WORLD_ID_ACTION=login
WORLD_ID_RP_ID=rp_<your-rp-id>
WORLD_ID_SIGNER_PRIVATE_KEY=<world_id_signer_private_key>
```

補足:

- `WORLD_ID_ACTION` は必ず `login`
- `WORLD_ID_RP_ID` は Worldcoin 発行の `rp_...` 識別子（例: `rp_<your-rp-id>`）
- `WORLD_ID_SIGNER_PRIVATE_KEY` は Secret 扱い

## 10.2 Supabase で取得する値

Supabase 自体に NexusInbox 用の環境変数を登録するというより、以下を取得して Fly.io に渡す。

取得する値:

```env
DATABASE_URL=postgres://postgres.<project-ref>:<password>@<host>:5432/postgres?sslmode=require
```

取得場所の目安:

- `Supabase > Project Settings > Database`

補足:

- まずは Supabase が提示する標準の接続文字列を使う
- API 常駐接続なので、まずはシンプルに `DATABASE_URL` 1本で始める

## 10.3 Fly.io に登録する値

対象:

- `fly secrets set ...`
- または Fly dashboard の Secrets / Variables

登録するキー:

```env
NODE_ENV=production
PORT=8080
JWT_SECRET=<32chars_or_more_random_secret>
DATABASE_URL=<supabase_database_url>
AGENT_INBOX_DATABASE_REQUIRED=true
AGENT_INBOX_WORLD_VERIFY_ENABLED=true
WORLD_ID_APP_ID=app_xxxxxxxxxxxxx
WORLD_ID_ACTION=login
WORLD_ID_RP_ID=rp_<your-rp-id>
AGENT_INBOX_COOKIE_SECURE=true
AGENT_INBOX_CORS_ORIGINS=https://app.nexusinbox.ai
LOG_FORMAT=json
AGENT_INBOX_S3_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
AGENT_INBOX_S3_REGION=auto
AGENT_INBOX_S3_BUCKET=nexusinbox-prod
AGENT_INBOX_S3_ACCESS_KEY_ID=<r2_access_key_id>
AGENT_INBOX_S3_SECRET_ACCESS_KEY=<r2_secret_access_key>
AGENT_INBOX_S3_PATH_STYLE=true
AGENT_INBOX_S3_PREFIX=prod
```

補足:

- `JWT_SECRET` は 32文字以上必須
- `AGENT_INBOX_DATABASE_REQUIRED=true` で in-memory fallback を禁止する
- `AGENT_INBOX_CORS_ORIGINS` はまず `https://app.nexusinbox.ai` のみ
- `AGENT_INBOX_S3_PREFIX=prod` は任意だが付けておくと運用しやすい

## 10.4 Cloudflare R2 で作成・取得する値

R2 では bucket と API token を作り、Fly.io の `AGENT_INBOX_S3_*` に流し込む。

作成/取得するもの:

```env
AGENT_INBOX_S3_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
AGENT_INBOX_S3_REGION=auto
AGENT_INBOX_S3_BUCKET=nexusinbox-prod
AGENT_INBOX_S3_ACCESS_KEY_ID=<generated_access_key_id>
AGENT_INBOX_S3_SECRET_ACCESS_KEY=<generated_secret_access_key>
AGENT_INBOX_S3_PATH_STYLE=true
AGENT_INBOX_S3_PREFIX=prod
```

初期方針:

- bucket 名は `nexusinbox-prod`
- path prefix は `prod`
- bucket は public 化しない
- ブラウザは presigned URL のみ利用する

## 10.5 すぐ使える最小セット

最初の本番相当確認で最低限必要な値だけに絞ると以下。

### Vercel 最小セット

```env
API_ORIGIN=https://api.nexusinbox.ai
NEXT_PUBLIC_SITE_URL=https://app.nexusinbox.ai
NEXT_PUBLIC_WS_URL=wss://api.nexusinbox.ai/ws
WORLD_ID_APP_ID=app_xxxxxxxxxxxxx
WORLD_ID_ACTION=login
WORLD_ID_RP_ID=rp_<your-rp-id>
WORLD_ID_SIGNER_PRIVATE_KEY=<world_id_signer_private_key>
```

### Fly.io 最小セット

```env
JWT_SECRET=<32chars_or_more_random_secret>
DATABASE_URL=<supabase_database_url>
AGENT_INBOX_DATABASE_REQUIRED=true
AGENT_INBOX_WORLD_VERIFY_ENABLED=true
WORLD_ID_APP_ID=app_xxxxxxxxxxxxx
WORLD_ID_ACTION=login
WORLD_ID_RP_ID=rp_<your-rp-id>
AGENT_INBOX_COOKIE_SECURE=true
AGENT_INBOX_CORS_ORIGINS=https://app.nexusinbox.ai
```

### 添付を有効化する場合のみ追加

```env
AGENT_INBOX_S3_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
AGENT_INBOX_S3_REGION=auto
AGENT_INBOX_S3_BUCKET=nexusinbox-prod
AGENT_INBOX_S3_ACCESS_KEY_ID=<r2_access_key_id>
AGENT_INBOX_S3_SECRET_ACCESS_KEY=<r2_secret_access_key>
AGENT_INBOX_S3_PATH_STYLE=true
AGENT_INBOX_S3_PREFIX=prod
```

---

## 11. 管理画面での登録手順

この節では、Vercel / Fly.io / Cloudflare の管理画面で「どこに何を入れるか」を画面単位で整理する。

参考:

- Vercel Environment Variables: https://vercel.com/docs/environment-variables
- Vercel Domains: https://vercel.com/docs/domains/working-with-domains/add-a-domain
- Fly Secrets: https://fly.io/docs/apps/secrets/
- Fly Deploy: https://fly.io/docs/launch/deploy/
- Cloudflare DNS Records: https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/
- Cloudflare R2 API tokens: https://developers.cloudflare.com/r2/api/tokens/

## 11.1 Vercel

### A. Project を作る

画面:

- `Vercel Dashboard > Add New... > Project`

手順:

1. GitHub repository `nexusinbox` を選ぶ
2. Framework Preset が `Next.js` になっていることを確認する
3. Root Directory を `apps/web` にする
4. Build / Install は自動判定のままでよい
5. いったん deploy する

### B. Environment Variables を入れる

画面:

- `Vercel Dashboard > Project > Settings > Environment Variables`

ここに登録する値:

| Key | Value |
|---|---|
| `NODE_ENV` | `production` |
| `API_ORIGIN` | `https://api.nexusinbox.ai` |
| `NEXT_PUBLIC_API_BASE_URL` | `/api` |
| `NEXT_PUBLIC_SITE_URL` | `https://app.nexusinbox.ai` |
| `NEXT_PUBLIC_WS_URL` | `wss://api.nexusinbox.ai/ws` |
| `WORLD_ID_APP_ID` | `app_xxxxxxxxxxxxx` |
| `WORLD_ID_ACTION` | `login` |
| `WORLD_ID_RP_ID` | `rp_<your-rp-id>` (Action 作成時に Worldcoin が発行) |
| `WORLD_ID_SIGNER_PRIVATE_KEY` | `<world_id_signer_private_key>` |

入れ方:

1. `Add New`
2. `Key` に変数名
3. `Value` に値
4. Environment は最初は `Production`, `Preview`, `Development` の3つを選んでよい
5. `Save`

補足:

- `WORLD_ID_SIGNER_PRIVATE_KEY` は secret 値なので取り扱い注意
- 追加後は既存 deploy には反映されないため、再デプロイが必要

### C. Domain を入れる

画面:

- `Vercel Dashboard > Project > Settings > Domains`

手順:

1. `Add Domain`
2. `app.nexusinbox.ai` を入力
3. `Add`
4. Vercel が DNS 設定を案内するので、Cloudflare 側の DNS レコードを合わせる

確認:

- Vercel 側で `Valid Configuration` 相当の表示になる
- 最終的に `https://app.nexusinbox.ai` で Web が開く

---

## 11.2 Fly.io

### A. App を作る

画面:

- 基本は `flyctl` での作成が安定
- 管理画面では作成後の確認・Secrets 管理を行う

推奨コマンド:

```bash
cd services/api
fly launch --no-deploy
```

初期設定の考え方:

- App name: `nexusinbox-api` など
- Region: 日本から近いリージョン
- 初回は 1 machine でよい

### B. Secrets を入れる

画面:

- `Fly Dashboard > Apps > <app-name> > Secrets`

登録する値:

| Key | Value |
|---|---|
| `NODE_ENV` | `production` |
| `PORT` | `8080` |
| `JWT_SECRET` | `<32chars_or_more_random_secret>` |
| `DATABASE_URL` | `<supabase_database_url>` |
| `AGENT_INBOX_DATABASE_REQUIRED` | `true` |
| `AGENT_INBOX_WORLD_VERIFY_ENABLED` | `true` |
| `WORLD_ID_APP_ID` | `app_xxxxxxxxxxxxx` |
| `WORLD_ID_ACTION` | `login` |
| `WORLD_ID_RP_ID` | `rp_<your-rp-id>` (Action 作成時に Worldcoin が発行) |
| `AGENT_INBOX_COOKIE_SECURE` | `true` |
| `AGENT_INBOX_CORS_ORIGINS` | `https://app.nexusinbox.ai` |
| `LOG_FORMAT` | `json` |
| `AGENT_INBOX_S3_ENDPOINT` | `https://<account-id>.r2.cloudflarestorage.com` |
| `AGENT_INBOX_S3_REGION` | `auto` |
| `AGENT_INBOX_S3_BUCKET` | `nexusinbox-prod` |
| `AGENT_INBOX_S3_ACCESS_KEY_ID` | `<r2_access_key_id>` |
| `AGENT_INBOX_S3_SECRET_ACCESS_KEY` | `<r2_secret_access_key>` |
| `AGENT_INBOX_S3_PATH_STYLE` | `true` |
| `AGENT_INBOX_S3_PREFIX` | `prod` |

CLI でまとめて入れる例:

```bash
fly secrets set \
  NODE_ENV=production \
  PORT=8080 \
  JWT_SECRET='<secret>' \
  DATABASE_URL='<database_url>' \
  AGENT_INBOX_DATABASE_REQUIRED=true \
  AGENT_INBOX_WORLD_VERIFY_ENABLED=true \
  WORLD_ID_APP_ID='app_xxxxxxxxxxxxx' \
  WORLD_ID_ACTION=login \
  WORLD_ID_RP_ID=rp_<your-rp-id> \
  AGENT_INBOX_COOKIE_SECURE=true \
  AGENT_INBOX_CORS_ORIGINS=https://app.nexusinbox.ai \
  LOG_FORMAT=json
```

添付を有効にする場合は追加で:

```bash
fly secrets set \
  AGENT_INBOX_S3_ENDPOINT='https://<account-id>.r2.cloudflarestorage.com' \
  AGENT_INBOX_S3_REGION=auto \
  AGENT_INBOX_S3_BUCKET=nexusinbox-prod \
  AGENT_INBOX_S3_ACCESS_KEY_ID='<r2_access_key_id>' \
  AGENT_INBOX_S3_SECRET_ACCESS_KEY='<r2_secret_access_key>' \
  AGENT_INBOX_S3_PATH_STYLE=true \
  AGENT_INBOX_S3_PREFIX=prod
```

### C. Deploy する

画面/操作:

- ローカルから deploy

```bash
cd services/api
fly deploy
```

確認:

- `Fly Dashboard > Apps > <app-name> > Machines`
- `Fly Dashboard > Apps > <app-name> > Metrics`
- `Fly Dashboard > Apps > <app-name> > Logs`

### D. カスタムドメイン

Fly 側ではアプリを公開しつつ、Cloudflare DNS から `api.nexusinbox.ai` を向ける。

手順:

1. Fly app の公開 hostname か割当 IP を確認する
2. Cloudflare 側で `api` レコードを作る
3. `https://api.nexusinbox.ai/health` などで疎通確認する

---

## 11.3 Cloudflare

### A. DNS で `app` を Vercel に向ける

画面:

- `Cloudflare Dashboard > <zone> > DNS > Records`

手順:

1. `Add record`
2. Type: `CNAME`
3. Name: `app`
4. Target: Vercel が案内した値
5. Proxy status: まずは `DNS only` でもよいが、最終的には要件に応じて調整
6. `Save`

補足:

- Vercel 側の Domains 画面に表示される推奨値を優先する

### B. DNS で `api` を Fly.io に向ける

画面:

- `Cloudflare Dashboard > <zone> > DNS > Records`

手順:

1. `Add record`
2. Type: `A` または `CNAME`（Fly の案内に合わせる）
3. Name: `api`
4. Content/Target: Fly.io 側の公開先
5. Proxy status: API/WebSocket の挙動確認を見ながら設定する
6. `Save`

確認:

- `https://api.nexusinbox.ai/health`
- `wss://api.nexusinbox.ai/ws`

### C. R2 bucket を作る

画面:

- `Cloudflare Dashboard > R2 Object Storage`

手順:

1. `Create bucket`
2. Bucket name: `nexusinbox-prod`
3. Jurisdiction は要件に合わせて選ぶ
4. bucket 作成後、public 化しない

### D. R2 API Token を作る

画面:

- `Cloudflare Dashboard > R2 Object Storage > Overview`
- `Account Details > Manage API Tokens`

手順:

1. `Manage API Tokens`
2. 必要な bucket に対する token を作る
3. Access Key ID / Secret Access Key を保存する
4. その値を Fly.io の `AGENT_INBOX_S3_ACCESS_KEY_ID` と `AGENT_INBOX_S3_SECRET_ACCESS_KEY` に登録する

必要になる値:

| Cloudflare 側 | Fly.io に入れる値 |
|---|---|
| Account endpoint | `AGENT_INBOX_S3_ENDPOINT` |
| Bucket name | `AGENT_INBOX_S3_BUCKET` |
| Access Key ID | `AGENT_INBOX_S3_ACCESS_KEY_ID` |
| Secret Access Key | `AGENT_INBOX_S3_SECRET_ACCESS_KEY` |

### E. Cloudflare で今やらなくてよいもの

初期の数名確認段階では、以下は後回しでよい。

- WAF の細かなチューニング
- Rate limiting ルールの詳細調整
- Zero Trust との本格統合
- R2 lifecycle rules の最適化

---

## 7. Deploy 自動化 (GitHub Actions → Fly)

Issue #1 の対応として `main` への push から Fly API への自動 deploy を GitHub Actions に委譲している。対象 workflow: `.github/workflows/deploy-api.yml`。

### 7.1 トリガー

| 条件 | 挙動 |
|---|---|
| `push` to `main` かつ `services/api/**` or `.github/workflows/deploy-api.yml` に変更あり | 自動で gate (fmt/clippy/test) → `flyctl deploy` → `/health` smoke check |
| `push` to `main` で他 path のみ (`apps/web/**` / `docs/**` 等) | **発火しない** (Fly machine を無用に churn しない) |
| Actions タブから手動 `workflow_dispatch` | 同上。`skip_gate` チェックで lint/test をバイパス (緊急 rollback 専用) |

### 7.2 初回セットアップ (1 回だけ)

1. `FLY_API_TOKEN` を発行 (app スコープに限定):
   ```bash
   flyctl tokens create deploy -x 8760h -a nexusinbox-api
   ```
2. GitHub repo の `Settings > Secrets and variables > Actions` で `FLY_API_TOKEN` として登録。
3. `Settings > Environments > production` を作成し、必要に応じて required reviewers を追加する (workflow は既に `environment: production` を参照している)。

### 7.3 トークンローテ手順

1. `flyctl tokens create deploy -x 8760h -a nexusinbox-api` で新しいトークンを発行。
2. GitHub の `FLY_API_TOKEN` secret を新しい値に上書き。
3. `flyctl tokens list` で古いトークンを確認し、`flyctl tokens revoke <id>` で無効化。
4. 次の deploy が green で通ることを確認。
5. 推奨ローテ頻度: 年 1 回、または漏洩疑いが出た時。

### 7.4 Rollback 手順 (v1)

1. Actions タブで `Deploy API` ワークフローを開き、`Run workflow` を選択。
2. ブランチのドロップダウンで rollback 先のコミット ref を指定 (e.g. `release/rollback-2026-04-24`)。
3. 緊急時で lint/test を通していられないなら `skip_gate = true` にチェック (通常は off 推奨)。
4. 実行 → gate (任意) → flyctl deploy → `/health` smoke check で成功を確認。
5. 事後: incident 原因を調査し、必要に応じて forward-fix の PR を切る。将来 Fly native release rollback (`flyctl releases rollback`) を採用するなら本節を更新。

### 7.5 手動 deploy (自動化を迂回する場合)

自動化に問題がある / GitHub Actions が落ちている時用:

```bash
cd services/api
flyctl deploy --remote-only -c fly.toml
```

workflow と同じ `--remote-only` + `-c` を使い、Fly 側で何が起きても workflow との差分が出ないようにする。

### 7.6 注意事項

- **Migration race**: `concurrency: group: deploy-api` で同時 deploy はキューイングされる。連続 push が 2 分以内に続いたときは GitHub Actions 画面で queue 状況を確認。
- **Schema 変更を含む PR**: description に明記して reviewer に 0015 のような migration を目立たせる。deploy 失敗時は Fly の health check が 60 s grace 後にマシンを unhealthy 扱いにして自動で rollback する。
- **Web deploy は別系統**: Cloudflare Tunnel / Pages / Vercel どれを採用するか決定したら別ワークフローで対応予定 (issue #1 の out-of-scope)。
