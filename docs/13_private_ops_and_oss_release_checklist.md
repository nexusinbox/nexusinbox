# NexusInbox Private運用とOSS公開準備ガイド

## 目的

- 開発中は `Private` リポジトリで安全に運用する
- 将来の OSS 公開時に、機密漏えいなしで公開できるようにする

## 1. いま実施すること（Private運用）

### 1.1 GitHub Actions Secrets に登録する値

対象画面:

- `GitHub Repository > Settings > Secrets and variables > Actions > Secrets > New repository secret`

登録する名前と内容:

| Name | 例 | 取り扱い |
|---|---|---|
| `DATABASE_URL` | `postgres://<user>:<password>@<host>:5432/<db>` | 機密。必ず Secret |
| `REDIS_URL` | `redis://:<password>@<host>:6379` | 機密。必ず Secret |
| `JWT_SECRET` | 32文字以上ランダム値 | 機密。必ず Secret |
| `WORLD_ID_APP_ID` | `app_...` | 非公開運用なら Secret |
| `WORLD_ID_SIGNER_PRIVATE_KEY` | `<hex private key>` | 機密。必ず Secret |
| `AGENT_INBOX_WORLD_VERIFY_ENABLED` | `true` | 本番は Secret か Environment Secret |

`JWT_SECRET` 生成例:

```bash
openssl rand -base64 48
```

### 1.2 GitHub Actions Variables に登録する値

対象画面:

- `GitHub Repository > Settings > Secrets and variables > Actions > Variables > New repository variable`

登録する名前と内容:

| Name | 例 | 取り扱い |
|---|---|---|
| `NODE_ENV` | `production` | Variable |
| `API_PORT` | `8080` | Variable |
| `WORLD_ID_ACTION` | `login` | Variable |
| `WORLD_ID_RP_ID` | `rp_...` | Variable |
| `WORLD_ID_VERIFY_BASE_URL` | `https://developer.world.org` | Variable |
| `NEXT_PUBLIC_API_BASE_URL` | `https://api.example.com` | Variable |
| `NEXT_PUBLIC_WS_URL` | `wss://api.example.com/ws` | Variable |

### 1.3 運用ルール（必須）

- `.env` / `.env.*` はコミットしない（`.env.example` のみコミット）
- 実鍵はローカル `.env` と GitHub Secrets のみに置く
- キーを誤コミットした疑いが出たら、対象キーを即ローテーションする

## 2. Actions での参照例

`.github/workflows/ci.yml` で使うときの形式:

- Secret: `${{ secrets.DATABASE_URL }}`
- Variable: `${{ vars.NEXT_PUBLIC_API_BASE_URL }}`

## 3. 将来の OSS 公開前チェックリスト

### 3.1 公開前に必須でやること

1. 履歴を含めたシークレットスキャンを実施
2. 漏えい疑いのあるキーを全ローテーション
3. 公開ブランチに機密が残っていないことを再検証

### 3.2 公開前に揃えるべきファイル

- `LICENSE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `.env.example`（ダミー値のみ）

### 3.3 公開前の確認コマンド例

```bash
git grep -n "password\\|secret\\|token\\|api[_-]*key\\|private[_-]*key"
git ls-files | rg -n "\\.env$|\\.env\\.|\\.pem$|\\.key$"
```

`0件` であることを確認してから公開する。

## 4. 公開時の方針

- リポジトリ Visibility を `Public` に変更する前に、上記チェックを完了する
- 公開直後に issue テンプレ・security policy を確認する
- 本番環境の機密は引き続き GitHub Secrets / Environment Secrets で管理する
