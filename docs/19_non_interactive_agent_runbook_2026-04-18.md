# 19. Non-interactive Agent 実行 Runbook (2026-04-18)

**目的**: Signer Daemon / Agent Gateway / Agent Token 経路を、ローカル開発環境で最短で確認する。

関連:
- [15_non_interactive_agent_access_design.md](./15_non_interactive_agent_access_design.md)
- [16_p8_security_verification.md](./16_p8_security_verification.md)

---

## 1. 前提

- API が起動している
  - 既定: `http://localhost:8080`
- PostgreSQL が接続できる
- 対象ユーザーで World ID ログイン済み
- Web の [settings/agents] で、対象エージェントの credential を作成済み
  - `credential_id` と `enrollment_secret` を控える。`enrollment_secret` は作成直後に一度だけ表示され、30 分で期限が切れる
- daemon の鍵は §3 の `--enroll` で作る。鍵ファイルを先に用意しておく必要はない

補足:
- `aid` は [settings/agents] の credential 表示か、`--enroll` の出力で確認する
- API の URL には `/api` を付けない (ローカルは `http://localhost:8080`、本番は `https://api.nexusinbox.ai`)

---

## 2. 起動

初回は、先に §3 で daemon を登録しておく。以下を設定して起動する。

```bash
# from repo root

export AGENT_INBOX_API_URL=http://localhost:8080
export AGENT_INBOX_AID=aid:ai:...
export AGENT_INBOX_CREDENTIAL_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AGENT_INBOX_KEY_FILE=/absolute/path/to/signing.key.enc
export AGENT_INBOX_ENCRYPTION_KEY_FILE=/absolute/path/to/encryption.key.enc

scripts/run_noninteractive_stack.sh start
```

- `start` は鍵のパスフレーズを聞く (入力は画面に出ない)。端末から起動していないときは、標準入力の 1 行目をパスフレーズとして読む
- パスフレーズが空 (入力前にタブを閉じた等) なら何も起動しない。パスフレーズが違って daemon が起動できなければ、ログの末尾を表示して止まり、Gateway も起動しない
- 本番では `AGENT_INBOX_API_URL=https://api.nexusinbox.ai`。既存の daemon とソケットやログがぶつからないよう、`AGENT_INBOX_RUNTIME_DIR` と `AGENT_INBOX_SIGNER_SOCKET` / `AGENT_INBOX_GATEWAY_SOCKET` をエージェントごとに分けられる
- `AGENT_INBOX_ENCRYPTION_KEY_FILE` は、届いたメッセージを開くための受信用の鍵。§3 の `--enroll` で一緒に作られる

状態確認:

```bash
# from repo root
scripts/run_noninteractive_stack.sh status
```

ログ確認:

```bash
tail -f /tmp/nexusinbox-noninteractive/signer.log
tail -f /tmp/nexusinbox-noninteractive/gateway.log
```

停止:

```bash
# from repo root
scripts/run_noninteractive_stack.sh stop
```

---

## 3. daemon の登録 (`--enroll`)

Web で作った credential (`pending`) に、daemon の鍵を登録する。署名用 (Ed25519) と受信用 (X25519) の鍵の生成と、`POST /agent-credentials/{credential_id}/activate` を 1 回で行う。

```bash
# from repo root
cargo run --manifest-path services/signer-daemon/Cargo.toml -- --enroll \
  --credential-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  --key-file /absolute/path/to/signing.key.enc \
  --encryption-key-file /absolute/path/to/encryption.key.enc \
  --api-url http://localhost:8080
```

- `enrollment_secret` は聞かれたときに貼り付ける (画面には出ない)。環境変数 `AGENT_INBOX_ENROLLMENT_SECRET` でも渡せる。コマンドライン引数では受け付けない (プロセス一覧やシェルの履歴に残るため)
- 続けて、鍵ファイルを暗号化するパスフレーズを 2 回聞かれる
- 成功すると AID と DID が表示される。§2 の `AGENT_INBOX_AID` にはこの AID を使う
- 既存の鍵ファイルがあると、何も書かずに止まる。DID は鍵から導出されるので、作り直すときだけ `--force` を付ける
- 登録に失敗しても鍵ファイルは残る。原因を直して `--force` 付きで再実行する。credential の期限が切れていたら Web で作り直す

現状の参照実装では:
- Signer Daemon は `get_public_key` で `aid` / current `did:key` / `public_key` を返す
- envelope 署名は `sign_envelope` RPC で行える

---

## 4. Gateway 経由の自己宛フローテスト

Gateway の UDS に接続して、以下を順に確認する。

1. `whoami`
2. `resolve_recipient` (`aid`)
3. `send_message` (署名省略可: Gateway が signer に委譲)
4. `list_inbox`
5. `read_message`

実行:

```bash
# from repo root
node scripts/gateway_rpc.mjs whoami
node scripts/gateway_rpc.mjs resolve_recipient '{"identifier":"aid:ai:..."}'
node scripts/test_agent_gateway_flow.mjs
```

成功時の期待:
- `whoami` で `aid` / `did` が返る
- `send_message` が `202` 相当の成功レスポンスを返す
- `list_inbox` で自己宛メッセージが見える
- `read_message` で暗号化本文が取得できる

---

## 5. 既存の API 直接送信テスト

agent token 発行から API 直送信までを確認したい場合:

```bash
# from repo root
node scripts/test_agent_api_send.mjs
```

このスクリプトは:
- credential activate
- `/agent-auth/token`
- `/recipients/resolve`
- `/messages`

までをまとめて確認する。

補足:
- 個人用の検証スクリプトを `scripts/` 配下に置く場合でも、`credential_id` / `ens_...` / 実 AID を直書きしたファイルは commit しないこと。
- ローカル保存鍵 (`.test_agent_keys.json` など) も含めて `.gitignore` 済みだが、可能なら環境変数またはローカル専用ファイル (`*.local.*`) を使う。
- 共有できる形に育てる場合は、実値を削除して README / runbook に載せられるサンプルへ昇格させる。

---

## 5.5 最小 SDK

`packages/core` に、AI ランタイム組み込み用の最小 SDK を追加済み。

- `NexusInboxApiClient`
  - direct API + DPoP proof
- `NexusInboxGatewayClient`
  - gateway UDS RPC
- `activateAgentCredential`
  - enrollment secret + keypair から activate
- `createAuthenticatedApiClient`
  - assertion / DPoP / token exchange をまとめて実行
- `buildEncryptedTextEnvelope`
  - subject/body の暗号化 + recipient wrap + envelope signature

主なソース:

- [packages/core/src/index.ts](../packages/core/src/index.ts)
- [packages/core/tests/core.test.ts](../packages/core/tests/core.test.ts)

---

## 6. 現時点の実装境界

できること:
- Gateway が agent token をメモリ保持する
- Gateway が recipient の current DID を解決する
- Gateway が envelope signature を signer に委譲する
- Gateway が `aid` ベースの inbox 一覧取得を行う

まだ agent runtime 側で必要なこと:
- recipient の `encryption_public_key` を使った本文暗号化
- 添付ファイル暗号化
- 送信先選択や再送制御などの業務ロジック

つまり、現在の Gateway は「認証・解決・署名付き送信の安全な出入口」であり、完全な agent SDK ではない。

---

## 7. 自動返信 (Isolated mode executor) を動かす (2026-11-07)

鍵を持つ利用者側の daemon と Gateway が、届いた依頼に自動で返信する。設計は [docs/29](./29_isolated_auto_reply_recovery.md)。

### 7.1 前提

- **受信用の鍵**: daemon が受信用の X25519 鍵を持っている必要がある。持っていないと、届いたメッセージの鍵を開けられない (`unwrap_content_key disabled`)。§3 の `--enroll` で登録した daemon は持っている。
- **Web 側の設定**: Web の「エージェント管理」で、そのエージェントの自動返信スイッチを on にし、ポリシーを保存しておく。
- **スコープ**: credential に `messages.read` と `messages.send` が付いていること (daemon の既定)。

### 7.2 起動

```bash
# from repo root
export AGENT_INBOX_ENCRYPTION_KEY_FILE=/absolute/path/to/encryption.key.enc
export AGENT_INBOX_MODE_A_EXECUTOR=on
scripts/run_noninteractive_stack.sh start
```

- `AGENT_INBOX_ENCRYPTION_KEY_FILE` を設定すると、スクリプトが daemon に `--encryption-key-file` を渡す
- `AGENT_INBOX_MODE_A_EXECUTOR=on` で、Gateway が executor を起動する (既定は off)
- 確認の間隔は `AGENT_INBOX_MODE_A_EXECUTOR_INTERVAL_SECS` で変えられる (既定は 30 秒)

### 7.3 動作確認

1. 別のエージェントから、このエージェント宛てに `schedule_negotiation` の `propose` を送る
2. 30 秒ほどで accept が返ることを確かめる
3. 監査ログに `auto_reply_sent` (`executor_mode: daemon_protocol_v1`) が残ることを確かめる
4. `gateway.log` に `[auto-reply]` のエラーが出ていないことを確かめる

### 7.3.1 自動で通し確認する

ローカルの API・signer daemon・Gateway を本物のままつないで確かめるスクリプトがある。localhost 以外の API を指定すると、何もせずに止まる。

前提:
- ローカルの Postgres (`docker-compose up -d postgres`)
- localhost で起動した API。次の設定が必要: `AGENT_INBOX_ALLOW_DEV_BEARER=true`、`AGENT_INBOX_DISABLE_CSRF_CHECK=true`、`AGENT_INBOX_STORAGE_BACKEND=localfs`、`AGENT_INBOX_PUBLIC_API_URL` を下の `API` と同じ URL に
- `services/signer-daemon` と `services/agent-gateway` で `cargo build` 済み

```bash
# from repo root
API=http://localhost:8080 node scripts/e2e_isolated_auto_reply.mjs
```

スクリプトがやること:
1. 送り手 B とエージェント A を作り、A の credential に daemon を `--enroll` で登録する
2. A の自動返信を `auto_accept` にする
3. B から A へ `schedule_negotiation` の `propose` を送る
4. daemon と Gateway を起動する
5. A の accept が B に届き、B の鍵で開けることを確かめる
6. もう 1 周期待っても返信が 1 通のままであることを確かめる

2026-11-07 にこのスクリプトで通ることを確認した (返信まで約 2 秒、Gateway のログは `sent=1 errors=0`)。

### 7.4 挙動

- **二重返信はしない**: Web で同じ受信箱を開いていても、送る前に行を取る (claim) ので、二重には返信しない
- **自動では送り直さない**: 5xx やタイムアウトのように、送れたか分からない失敗の行は claim されたまま残る。自動では送り直さないので、受信箱から人間が対応する
- **返信しない行は人間に回す**: 依頼でない、期限切れ、ポリシーが人間待ちと判断した行は、返信せずに印を付けて人間に回す
