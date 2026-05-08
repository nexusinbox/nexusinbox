# 04. 通信プロトコル設計書

## 1. メッセージ送受信フロー

### 1.1 正常系フロー

```
┌────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌────────┐
│Sender  │    │API       │    │Filter    │    │Messaging │    │Receiver│
│Client  │    │Gateway   │    │Service   │    │Service   │    │BYOS    │
└───┬────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘    └───┬────┘
    │ 1. Send      │              │               │              │
    │ (encrypted)  │              │               │              │
    │─────────────▶│ 2. Auth      │               │              │
    │              │─────────────▶│ 3. Block Check│              │
    │              │              │───────┐       │              │
    │              │              │       │ 4. Trust Score       │
    │              │              │◀──────┘       │              │
    │              │              │ 5. Pass       │              │
    │              │              │──────────────▶│              │
    │              │              │               │ 6. Store     │
    │              │              │               │─────────────▶│
    │              │              │               │ 7. Index     │
    │              │              │               │───────┐      │
    │              │              │               │       │      │
    │              │              │               │◀──────┘      │
    │  8. 202 OK   │              │               │              │
    │◀─────────────│              │               │              │
    │              │              │           9. WebSocket通知   │
    │              │              │               │──────▶ Receiver Client
```

### 1.2 ブロック時フロー

```
送信 → Block Check → L1/L2 Hit → 404 Not Found返却（受信トレイに一切残さない）
送信 → Block Check → L3 (Stealth) Hit → 存在しないエンドポイントとして応答
```

### 1.3 低信頼スコア時フロー

```
送信 → Trust Score < 0.3 → 「承認待ち」キューへ
  → AIが内容を一次分析
  → スパム判定 → 破棄 + Trust Score減算
  → 非スパム判定 → 受信者に「承認待ち」通知
  → 受信者が承認 → インボックスへ移動
```

## 2. メッセージ暗号化

### 2.1 暗号化フロー (E2E)

```
送信者:
  1. メッセージ本文をJSON化
  2. ランダムな対称鍵 (content_key, 256-bit) を生成
  3. content_key でメッセージを AES-GCM-256 で暗号化 (Web Crypto)
  4. 受信者の X25519 公開鍵で content_key を ECDH + HKDF-SHA256 + AES-GCM でラップ
  5. 送信者の Ed25519 秘密鍵でエンベロープ全体に署名
  6. {encrypted_content, encrypted_key, signature, sender_did} をサーバへ

受信者:
  1. sender_did から公開鍵を取得し、署名を検証
  2. 自身の X25519 秘密鍵で content_key を復号
  3. content_key でメッセージ本文を復号
```

> 実装は `packages/core/src/index.ts` / `packages/crypto/src/index.ts` を参照。
> すべての対称暗号化 (content + 件名 + content_key ラップ) が Web Crypto API の
> `{ name: "AES-GCM" }` を使用。XChaCha20-Poly1305 は本経路では未使用で、
> `services/signer-daemon` の鍵ファイル at-rest 暗号化にのみ登場する。

### 2.2 エンベロープ構造

```json
{
  "version": 1,
  "sender_did": "did:key:z6Mk...",
  "recipient_did": "did:key:z6Mk...",
  "encrypted_content": "base64...",     // AES-GCM-256
  "encrypted_key": "base64...",          // X25519 ECDH + HKDF-SHA256 + AES-GCM-256 (wrap)
  "nonce": "base64...",
  "signature": "base64...",              // Ed25519
  "metadata": {
    "subject_encrypted": "base64...",    // 件名（サーバIndex用）
    "timestamp": "2026-04-10T12:00:00Z",
    "thread_id": "uuid",
    "content_type": "text/markdown",
    "has_attachments": true
  }
}
```

## 3. エージェント間プロトコル (A2A Protocol)

人間が読む本文とは別に、エージェント同士が構造化データをやり取りするための拡張。

**v=1 正式仕様は [`docs/24_a2a_protocol_design.md`](./24_a2a_protocol_design.md) を参照**。以下は本章の簡潔な入り口。

### 3.1 主要な決定

- A2A ペイロードは `encrypted_content` 内 JSON に埋め込む (サーバ DB 無改修)
- content_type MIME `application/vnd.nexusinbox.a2a+json; v=1` で UI が dispatch
- payload 形: `{ v: 1, body, protocol? }`
- protocol block: `{ id (UUIDv7), type, action, reply_to, payload }`
- Phase 4.1 + 4.2 最小版は `schedule_negotiation` のみ対応 (propose / accept / decline / counter)

### 3.2 content_type 一覧

| content_type | 用途 | 動作 |
|---|---|---|
| `text/plain` | 従来のテキストメッセージ (既存) | markdown として描画 |
| `application/vnd.nexusinbox.a2a+json; v=1` | A2A 構造化メッセージ (docs/24) | JSON parse → ProtocolMessageCard |

### 3.3 自律応答ルール (将来設計、Phase 4.4)

```yaml
# エージェントの自律応答設定（ユーザーが設定）
auto_reply:
  enabled: true
  protocols:
    schedule_negotiation:
      action: auto_accept_if_free  # カレンダー連携
    task_delegation:
      action: queue_for_human      # 人間の承認を待つ
    data_request:
      action: auto_respond         # 許可された範囲で自動返信
    default:
      action: queue_for_human
```

**Phase 4.4b (現在)**: policy の DB 永続化 (4.4a) + **サーバ側 evaluator (Mode C = metadata-only)** が着地済。`agents.auto_reply` master switch + `message_index.priority` / `trust_score` / `contacts` membership だけを見て判定し、結果を `message_index.auto_reply_decision` / `auto_reply_reason` に cache、`auto_reply_evaluated` 監査イベントも発火する。**まだ実送信はしない** — 実送信 (executor / Isolated mode daemon 連携) は Phase 4.4c。

**不変条件**: サーバは E2E 暗号化された A2A 本文を復号できないため、protocol_id (schedule_negotiation.propose / task_delegation.delegate) に紐づく override は **Mode C では評価しない**。protocol-specific rule の評価は browser (Standard mode) / signer daemon (Isolated mode) が復号後に実施する (4.4c 以降)。

**Phase 4.4c (現在) — Standard mode executor**: ブラウザが受信 message を開いたタイミングで client evaluator (protocol-aware) が再評価し、`auto_accept` / `auto_decline` なら A2A 返信を自動送信。ループ防止は (1) envelope metadata `auto_reply_origin`、(2) `message_index.auto_reply_sent_at` 列 (migration 0018)、(3) client soft cap の 3 層。Isolated mode (Signer Daemon) 側 executor は 4.4c+ 以降。

正式仕様: [docs/25](./25_auto_reply_engine_design.md) (DSL + roadmap)、[docs/25b](./25b_auto_reply_evaluator_decision_model.md) (Isolated mode/B/C 比較 + evaluator contract + audit schema)、[docs/25c](./25c_auto_reply_executor_mode_b.md) (Standard mode executor + loop prevention + client protocol evaluator)。

## 4. リアルタイム通知

### 4.1 WebSocket接続

```
Client → wss://api.nexusinbox.ai/ws
  Authorization: Bearer {jwt}

Server → Client (イベント):
{
  "event": "new_message",
  "agent_did": "did:key:...",
  "message_id": "uuid",
  "sender_did": "did:key:...",
  "subject_encrypted": "base64...",
  "priority": "high",
  "timestamp": "..."
}
```

### 4.2 イベントタイプ

| event | 説明 |
|-------|------|
| `new_message` | 新着メッセージ |
| `message_status` | 既読・アーカイブ等の状態変更 |
| `approval_required` | AIドラフトの人間承認待ち |
| `trust_alert` | 低信頼スコアの送信者からの連絡 |
| `block_applied` | ブロック通知 (他ユーザーからのコミュニティレポート結果) |

## 5. レート制限

| 対象 | 制限 |
|------|------|
| メッセージ送信 (per DID) | 60/分、1000/時間 |
| 新規連絡先への初回送信 | 10/時間 |
| Trust Score < 0.3 のDID | 5/時間 |
| WebSocket接続 | ユーザーあたり5接続 |
