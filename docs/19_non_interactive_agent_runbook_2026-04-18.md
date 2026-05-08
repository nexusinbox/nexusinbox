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
- UI もしくは API で、対象エージェントの `aid` と `credential_id` を払い出し済み
- Signer 用の鍵ファイルを持っている

補足:
- `aid` と `credential_id` は [settings/agents] の credential 表示から確認する
- `enrollment_secret` は発行直後の一度だけ表示される

---

## 2. 起動

以下を設定して起動する。

```bash
# from repo root

export AGENT_INBOX_API_URL=http://localhost:8080
export AGENT_INBOX_AID=aid:ai:...
export AGENT_INBOX_CREDENTIAL_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AGENT_INBOX_KEY_FILE=/absolute/path/to/signing.key.enc

scripts/run_noninteractive_stack.sh start
```

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

## 3. Credential activate

credential が `pending` の場合は activate が必要。

1. signer から公開鍵を取得する
2. `POST /agent-credentials/{credential_id}/activate` を呼ぶ
3. `status=active` になったことを確認する

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
