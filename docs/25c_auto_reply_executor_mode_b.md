# ADR 25c: Auto-reply Executor (Phase 4.4c) — browser-side Standard mode

**Status**: Accepted (2026-04-24, Phase 4.4c 実装)
**Related**: [docs/25_auto_reply_engine_design.md](./25_auto_reply_engine_design.md)、[docs/25b_auto_reply_evaluator_decision_model.md](./25b_auto_reply_evaluator_decision_model.md)、[docs/24_a2a_protocol_design.md](./24_a2a_protocol_design.md)
**Scope**: 4.4c の **Standard mode (browser) executor のみ**。Isolated mode (Signer Daemon polling) は別 ADR 25c-A 予定。Calendar (4.4d) / LLM (4.4e) は引き続き範囲外。

## 1. Context

Phase 4.4b で server-side evaluator (Mode C) が decision を audit + `message_index.auto_reply_decision` に記録するまで実装した。しかし executor は無いので、**policy を `default_action: auto_accept` に設定しても実際の返信は 1 通も飛ばない** — UX として中途半端な状態。

Phase 4.4c は executor を足す。ただしサーバは A2A 本文を復号できず、protocol_id や payload 内の候補時刻を見られないため、**executor は鍵を持つ process に置かざるを得ない**。ADR 25b §2 の Isolated mode (Signer Daemon) / Standard mode (Browser) のうち、MVP の interactive agent が browser に鍵を保持している現状に合わせて **Standard mode 優先**。Isolated mode (daemon polling) は非対話型 agent 向けに別セッションで追加する。

## 2. Decision

### 2.1 Standard mode を採用、Isolated mode は後続

| Aspect | Isolated mode (Daemon) | Standard mode (Browser) ← 採用 |
|---|---|---|
| 鍵の所在 | Signer Daemon | Browser IndexedDB / memory |
| 受信時対応 | 背景 poll → decrypt → reply | inbox open → decrypt → reply |
| 遅延 | 秒オーダー | タブ open 時 |
| 24/7 性 | あり | なし (タブ閉じたら止まる) |
| MVP 対象 | 非対話型 agent のみ | interactive agent 全員 |
| 実装コスト (本 ADR 除く) | 25-30h | 16-17h |
| Landing 順 | 4.4c+ | **4.4c (本 ADR)** |

Standard mode は "best effort" だが、MVP ユーザの大半に即値が出る。Isolated mode は後続で追加し、同じ agent の鍵が両方にあるケースでは "先に動いたほうが勝ち" (idempotency 列で排他) とする。

### 2.2 実行モデル

```
1. ユーザが /agent/<did> を開く (inbox 表示)
2. messagesQuery のデータ到着後、useEffect が autoReplyExecutor をキック
3. executor は eligible entries を列挙:
     auto_reply_decision IS NOT NULL
   AND auto_reply_sent_at IS NULL
   AND decision.action IN ("auto_accept", "auto_decline")
4. entry ごとに直列処理 (concurrency 1):
   a. message content を fetch + decrypt (既存パス)
   b. A2A envelope なら parseA2APayload
   c. client evaluator で再評価 (protocol_id 込み)
   d. 最終 action が accept / decline でなければ skip
   e. buildReplyPayload + sendProtocolReply(autoReplyOrigin="client_protocol_v1")
   f. markAutoReplySent(message_id)
   g. queryClient.invalidateQueries
5. 完了後、inbox カードのバッジが "自動返信済 · HH:MM" に切り替わる
```

### 2.3 鍵不在時のフォールバック

- Interactive agent の signing key が IndexedDB に無い → executor は skip
- Daemon-isolated agent / bridged restore のみ復号できる agent → executor skip (Isolated mode が別途対応)
- skip 時の audit: `auto_reply_skipped_no_signing_key`

## 3. Loop Prevention (3 層)

### 3.1 出力 metadata `auto_reply_origin`

送信する envelope metadata に `auto_reply_origin: "client_protocol_v1"` を載せる。サーバ側 `send_message` はこの flag を見て **evaluator の起動を skip** する。将来 Isolated mode で送る場合は `"daemon_protocol_v1"` を載せる。

Skip 時の audit: `auto_reply_skipped_incoming_is_auto_reply`、detail `{reason, origin, sender_did, recipient_did}`。

### 3.2 Idempotency column `message_index.auto_reply_sent_at`

新規 migration 0018 で `TIMESTAMPTZ NULL` を追加。送信完了時に server が `NOW()` を立てる (`PATCH /messages/:id/auto-reply-sent`)。UPDATE に `WHERE auto_reply_sent_at IS NULL` を付けて 2 タブ / refresh race を自然排他する。

Partial index:

```sql
CREATE INDEX idx_message_index_auto_reply_pending
  ON message_index(owner_user_id, created_at DESC)
  WHERE auto_reply_decision IS NOT NULL AND auto_reply_sent_at IS NULL;
```

"まだ返信していない auto-reply 候補" のクエリを即応化。

### 3.3 Soft cap (browser-side 50/day/agent)

TanStack Query の既存 messagesQuery データから「今日 自 agent が送信した件数」を近似。閾値 50 に達したら warn + skip (hard-fail ではない)。精密な per-day counter は別 issue (server 側 column)。

## 4. Client-side evaluator (TS)

Rust の `evaluate_auto_reply_policy` と **同じルール** を TS で再実装する。差分は:

- **入力**: EvaluationContext に `protocol?: { type: "schedule_negotiation" | "task_delegation", action: string }` を追加
- **出力**: `evaluator_mode: "client_protocol_v1"`
- **protocol override を honor**:
  1. 基本順序は Rust 版と同じ (master → empty → v != 1 → default_action → default_conditions)
  2. 追加ステップ: protocol が非 None なら `policy.protocols[protocol.type][protocol.action]` を探し、存在すれば override。override 内の `action` / `conditions` を再評価し、matched_rule_path を `protocols.<type>.<action>` にする
  3. default_conditions と override の両方がある場合、**override が default_conditions を置き換える** (AND しない)

### 4.1 Merge rule (server + client の 2-stage)

```
final = merge(serverDecision, clientDecision)

function merge(server, client) {
  // master_off は常に強い
  if (server.reason === "master_off") return server
  // client がある場合は client を採用 (protocol-aware > metadata-only)
  return client
}
```

これで Mode C (metadata only) が queue に倒していても、client が protocol 見て auto_accept に上書きできる。逆に Mode C が auto_accept でも、client が protocol 確認して条件に合わないと判断したら queue に戻せる。

### 4.2 Rust-TS equivalence

両 evaluator は同じ `policy` + `context` で **同じ decision.action と reason** を返すべき。ADR 25c §9 に equivalence test 表を記載し、TS / Rust の両方に同名 unit test を配置して drift を検出する。

## 5. API 変更点

### 5.1 `SendMessageRequest.envelope.metadata.auto_reply_origin` (optional)

- 型: `string` (validate しない、存在有無のみ見る)
- 推奨値: `"client_protocol_v1"` (Standard mode), `"daemon_protocol_v1"` (Isolated mode、将来)
- 受信側 server が evaluator の spawn 条件に組み込む
- OpenAPI では `metadata` object の追加 optional property

### 5.2 `PATCH /messages/{id}/auto-reply-sent` (新規)

| 要件 | 値 |
|---|---|
| 認証 | dual-auth (Cookie or Agent Token `messages.send`) |
| 権限 | `owner_user_id = current_user` の row のみ |
| Effect | `UPDATE message_index SET auto_reply_sent_at = NOW() WHERE id = $1 AND owner_user_id = $2 AND auto_reply_sent_at IS NULL` |
| 200 OK | 新規 or 既に set 済 (idempotent) |
| 404 | row が無い / owner 違い |
| Response | `{ "auto_reply_sent_at": "2026-04-24T21:34:00Z" }` (既存値 or `NOW()`) |

### 5.3 `GET /messages` レスポンス拡張

- `auto_reply_sent_at: Option<String>` (ISO-8601) を MessageIndexEntry に追加

## 6. 監査イベント

| Event | Detail |
|---|---|
| `auto_reply_sent` | `{message_id, policy_revision, reply_message_id, decision}` (client が markAutoReplySent を呼んだ時に API が発火) |
| `auto_reply_skipped_incoming_is_auto_reply` | `{message_id, sender_did, origin}` (受信側 evaluator が skip した時) |
| `auto_reply_skipped_no_signing_key` | (本フェーズでは client audit 無し、将来 client → audit endpoint で) |

既存の `auto_reply_evaluated` (4.4b) は変更なし。

## 7. Feature flag

- `AGENT_INBOX_AUTO_REPLY_EVALUATOR` (既存) は引き続き server side evaluator を gate
- Client-side executor は runtime flag を持たない (evaluator が off なら decision 列が空なので executor も何もしない = 自然な gate)

Rollback:
- `AGENT_INBOX_AUTO_REPLY_EVALUATOR=off` で新規メッセージの evaluation を止める → executor は eligible 行を見つけられず停止
- 過去に decision が立っていた行は client が markAutoReplySent を呼ぶと送信されてしまう懸念 → 緊急時は `UPDATE message_index SET auto_reply_decision = NULL, auto_reply_reason = NULL;` で手動止血

## 8. Out of scope

- **Isolated mode (Signer Daemon) executor** — 別 ADR 25c-A
- **Google Calendar** (`auto_accept_if_free`) — Phase 4.4d
- **LLM** (`delegate_to_llm`) — Phase 4.4e
- **Policy 変更後の過去メッセージ再評価** — 別 issue
- **Multi-tab leader election** — 3.2 の DB idempotency で 2 タブ race は解消、leader election は不要
- **Retry loop** — 初回失敗は `auto_reply_sent_at` が NULL のまま残り、次回 inbox open 時に自然 retry される
- **Cross-device dedup** — 同一 user が 2 device で inbox を同時に開いた race も DB idempotency で排他

## 9. Rust-TS evaluator equivalence matrix

| Scenario | Context | Policy | Expected decision |
|---|---|---|---|
| master_off | master=false | any | `queue_for_human` / `master_off` |
| no policy | master=true | `{}` | `queue_for_human` / `no_policy` |
| default auto_accept | master=true | `{v:1, default_action:"auto_accept"}` | `auto_accept` / `default_match` |
| trust below min | master=true, trust=0.3 | `{min_trust_score:0.5}` | `queue_for_human` / `trust_below_threshold` |
| priority over ceiling | master=true, priority=high | `{priority_at_most:"normal"}` | `queue_for_human` / `priority_exceeds_policy` |
| require_contact, stranger | master=true, is_contact=false | `{require_contact:true}` | `queue_for_human` / `not_a_contact` |
| allowlist match | sender in allowlist | `{sender_in_allowlist:[sender]}` | `auto_accept` |
| allowlist miss | sender not in | `{sender_in_allowlist:[other]}` | `queue_for_human` / `sender_not_in_allowlist` |
| auto_accept_if_free | — | `{default_action:"auto_accept_if_free"}` | `queue_for_human` / `calendar_unavailable` |
| delegate_to_llm | — | `{default_action:"delegate_to_llm"}` | `queue_for_human` / `llm_unavailable` |
| protocol override honored (TS only) | protocol=propose | `{default:queue, protocols.schedule_negotiation.propose.action:auto_accept}` | TS: `auto_accept` / matched=`protocols.schedule_negotiation.propose` / Rust (4.4b): `queue_for_human` / `default_match` |
| protocol override condition reject | protocol=propose, trust=0.3 | override `{action:auto_accept, conditions:{min_trust_score:0.5}}` | TS: `queue` / `trust_below_threshold` |

TS 側のテストケースは上記の 1-10 を共通、11-12 は TS 専用。

## 10. リスク

1. **Mode C と client evaluator のルールずれ** — §4.2 equivalence test で CI 検出
2. **loop prevention 攻撃** — `auto_reply_origin` は詐称可能だが悪用方向は policy を弱めるだけなので許容 (§3.1)
3. **soft cap の誤発動** — 50/day は近似、厳密 count は Isolated mode / 後続で
4. **browser IndexedDB が消えた端末で executor が動かない** — 現状の MVP 不変条件 (鍵消失 = 送信不可) と整合
5. **auto_reply_origin metadata が復号しないと見えない** — 復号せずに使う必要がある。envelope metadata は平文なので OK。content_type と同じ扱い

## 11. 将来の ADR 25c-A / 25d 予告

- **25c-A (Phase 4.4c+)**: Isolated mode daemon executor。Signer Daemon 内 polling、Policy L1/L2 連携、non-interactive agent 全対応
- **25d (Phase 4.4d/e)**: Calendar freebusy 統合 (`auto_accept_if_free`)、LLM delegate (Groq Llama 3.1 8B)
