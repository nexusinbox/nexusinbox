# ADR 25c-A: Auto-reply Executor — Isolated mode (Signer Daemon / Agent Gateway)

**Status**: Accepted (2026-04-24, Phase 4.4c+ 実装)
**Related**: [docs/25_auto_reply_engine_design.md](./25_auto_reply_engine_design.md)、[docs/25b_auto_reply_evaluator_decision_model.md](./25b_auto_reply_evaluator_decision_model.md)、[docs/25c_auto_reply_executor_mode_b.md](./25c_auto_reply_executor_mode_b.md)、[docs/15_non_interactive_agent_access_design.md](./15_non_interactive_agent_access_design.md)
**Scope**: Isolated mode executor **only**。protocol-aware 再評価、Calendar、LLM は引き続き範囲外。

## 1. Context

4.4c で **Standard mode (browser) executor** が落ちた。しかし:

- 非対話型 agent (Claude Desktop / daemon-isolated / automation runtime) は browser を開かない
- browser タブを閉じた時間帯は auto-reply が止まる

MVP のユーザー体験として「24/7 応答するエージェント」を成立させるには **browser に依存しない executor** が必要。Signer Daemon は既に鍵を持ち長期常駐しているので、ここを executor の足場にする。

## 2. Decision

### 2.1 配置: Agent Gateway に乗せる

Signer Daemon / Agent Gateway / API の 3 プロセスのうち、どこに executor を置くかの比較:

| 置き場所 | Pros | Cons |
|---|---|---|
| **Agent Gateway** (採用) | reqwest / DPoP / token lifecycle / daemon IPC client が揃っており、polling loop を追加するだけ | gateway は「LLM runtime 向け HTTP/UDS proxy」という従来責務が拡張される |
| Signer Daemon | 鍵が近い、HTTP 外部依存 0 で完結 | daemon は「鍵操作だけ」に留めたい (attack surface 最小化)。HTTP / polling を乗せると責務がぼやける |
| 新規 binary (`auto-reply-daemon`) | 責務分離が最も綺麗 | 3 つ目のプロセスを追加すると運用・enrollment の footprint が増える |

Gateway は既に長期常駐 + HTTP client + Daemon IPC を全部持っているので、そこに 1 つ tokio::spawn を足すのが最小変更。

### 2.2 Daemon に 1 RPC を追加

既存 RPC: `sign_assertion` / `sign_envelope` / `unwrap_content_key` / `get_public_key` / `status`。Isolated mode executor が返信メッセージを送るためには **送信側の content key wrap** が必要。これだけ daemon に追加:

```
method: "wrap_content_key"
params: {
  recipient_encryption_pub: String  // base64url X25519 pubkey
  content_key_b64: String          // base64 32-byte AES key
}
result: {
  wrapped_key: String              // "x25519v1:ephemeral:nonce:ciphertext"
}
```

`unwrap_content_key` と対称。これで daemon は「自分の鍵を使う側」(sign + unwrap) と「他人の鍵に wrap する側」の両方を担える。署名鍵/復号鍵を外に出さずに済む。

### 2.3 Executor のスコープ

**Phase 4.4c+A (初期)**: Gateway は サーバが既に計算した `auto_reply_decision` をそのまま信じて action を決める。protocol override は Standard mode (browser) でのみ効いた。

**Phase 4.4c+B (追加実装済)**: `services/agent-gateway/src/policy_evaluator.rs` に TS 版 client evaluator を Rust に port し、executor が A2A payload をパース後に再評価するようになった。これで:

- Standard mode と同じ方法で `protocols.<type>.<action>` を honour
- Mode C が queue に倒した decision を protocol override で auto_accept に「上書き」できる
- `master_off` 等 server-side が強い拒否条件を出した場合は merge ルールで sticky に残る

evaluator は pure で副作用なし。`ExecutorBackend` trait に `fetch_policy` / `fetch_contact_dids` を追加し、gateway が tick 毎に 1 回ずつ fetch して全メッセージで再利用する。

### 2.4 Loop prevention は既存 3 層で十分

1. Outgoing envelope metadata に `auto_reply_origin: "daemon_protocol_v1"` → 受信側サーバの evaluator skip
2. `auto_reply_sent_at` column (migration 0018) を PATCH で立てる → 次 poll が候補から外れる
3. API 側 L3 rate limit (200/day/credential) → 暴走防止

Standard mode と Isolated mode が同時稼働しても、(2) の conditional UPDATE で片方だけが勝つ。重複送信は不可能。

### 2.5 Polling 設計

- Interval: 30 秒 (`AGENT_INBOX_MODE_A_EXECUTOR_INTERVAL_SECS` で上書き可能)
- 1 tick 最大 10 件処理 (pagination で自然 throttle、起動直後に queue を一気に食い潰さない)
- 1 tick 毎に fresh token を `sign_assertion → /agent-auth/token` で取得 (stateless)
- エラーは log + continue、`auto_reply_sent_at` は NULL のまま → 次 tick で自然 retry

## 3. Execution model

```
ツール: reqwest (gateway) + daemon IPC (gateway → daemon UDS)

1 tick:
  token = POST /agent-auth/token (JWS via daemon.sign_assertion)
  GET /messages?auto_reply_pending=1  (limit 10, 新 query param)
    → [{id, sender_did, auto_reply_decision, thread_id, ...}, ...]

  for entry where decision in ["auto_accept", "auto_decline"]:
    content = GET /messages/:id/content  (encrypted_content, encrypted_key, nonce)
    content_key = daemon.unwrap_content_key(encrypted_key)
    plaintext = aes_gcm_decrypt(encrypted_content, content_key)   ← Rust-side
    a2a_block = parse_a2a_payload(plaintext, content_type)
    if a2a_block is None: skip

    reply_payload = match (a2a_block.type, decision):
      (schedule_negotiation, auto_accept)  → build_schedule_accept(first_candidate)
      (schedule_negotiation, auto_decline) → build_schedule_decline(default reason)
      (task_delegation,      auto_accept)  → build_task_accept()
      (task_delegation,      auto_decline) → build_task_decline(default reason)

    reply_body = serialize(A2AMessagePayload { v:1, body:"", protocol: reply_block })
    recipient = GET /recipients/resolve?identifier=<sender_did>
    content_key = random 32 bytes
    encrypted_subject = aes_gcm_encrypt("Re: (auto-reply)", content_key)
    encrypted_body    = aes_gcm_encrypt(reply_body, content_key)
    wrapped_key       = daemon.wrap_content_key(recipient.encryption_public_key, content_key)
    signature         = daemon.sign_envelope(our_did, recipient_did, payload_b64)

    POST /messages {
      envelope: { encrypted_content, encrypted_key, nonce, signature,
                  metadata: { subject_encrypted, content_type: A2A,
                              auto_reply_origin: "daemon_protocol_v1",
                              thread_id } },
      sender_did, recipient_did
    }
    → reply_message_id

    PATCH /messages/:id/auto-reply-sent {
      reply_message_id,
      executor_mode: "daemon_protocol_v1"
    }
```

## 4. API changes

### 4.1 `GET /messages?auto_reply_pending=1`

Existing list handler gains one optional query param. When set, adds:

```sql
AND auto_reply_decision IS NOT NULL
AND auto_reply_sent_at IS NULL
AND auto_reply_decision IN ('auto_accept', 'auto_decline')
```

Uses the partial index from migration 0018 (`idx_message_index_auto_reply_pending`). Pagination unchanged (default limit 50, gateway caps at 10/tick).

### 4.2 `mark_auto_reply_sent` body extension

`MarkAutoReplySentRequest` gets optional `executor_mode: String`. The audit event `auto_reply_sent` uses that value when present (default `"client_protocol_v1"` for legacy Standard mode). Isolated mode sends `"daemon_protocol_v1"`.

## 5. Feature flag

- `AGENT_INBOX_MODE_A_EXECUTOR=off` (default): polling ループ起動せず、gateway は従来通り LLM runtime IPC のみ
- `AGENT_INBOX_MODE_A_EXECUTOR=on`: polling loop を `tokio::spawn`
- `AGENT_INBOX_MODE_A_EXECUTOR_INTERVAL_SECS=<n>`: poll 間隔 (default 30)

Rollback: off に戻せば即停止。既存の LLM runtime IPC は影響なし。

## 6. Out of scope

- ~~**Protocol-aware 再評価**~~ → Phase 4.4c+B で実装済 ([policy_evaluator.rs](../services/agent-gateway/src/policy_evaluator.rs)、§2.3)
- **Daemon 自身への polling 配置** — 今フェーズでは gateway を採用
- **新規 binary 分離** — 今フェーズでは gateway 内モジュールに留める
- **Calendar** `auto_accept_if_free` — Phase 4.4d
- **LLM** `delegate_to_llm` — Phase 4.4e
- **Server push** (SSE / WebSocket) — 後続最適化
- **Per-agent observability** (Prometheus / OpenTelemetry) — 別 issue

## 7. リスク

1. **Daemon ↔ Gateway IPC の稀な失敗** — log + continue、次 tick で自然 retry
2. **Isolated mode / Standard mode 同時稼働の race** — DB conditional UPDATE で解決済
3. **非対話型 agent が L3 rate limit を食い潰す** — 429 受領 → log + skip、翌日リセット
4. **Token expiry** — 毎 tick 再発行で問題回避
5. **Gateway 再起動時の一気食い** — 1 tick 10 件制限で自然スロットル
6. **AES-GCM の format drift** — TS 版と bit-wise 互換であるべき。テストで round-trip (TS encrypt → Rust unwrap) を保証

## 8. 将来の ADR

- **ADR 25c+B**: Rust 版 protocol-aware client evaluator、Isolated mode も override を honor
- **ADR 25d**: Calendar freebusy (`auto_accept_if_free`)
- **ADR 25e**: LLM delegate (`delegate_to_llm`)
