# ADR 25b: Auto-reply Evaluator — decision model & evaluator placement

**Status**: Accepted (2026-04-24, Phase 4.4b 実装)
**Related**: [docs/25_auto_reply_engine_design.md](./25_auto_reply_engine_design.md) (Phase 4.4 全体)、[docs/24_a2a_protocol_design.md](./24_a2a_protocol_design.md)、[docs/04_messaging_protocol.md](./04_messaging_protocol.md)
**Scope**: 4.4b (evaluator placement + decision schema + audit)。executor (4.4c) / Calendar (4.4d) / LLM (4.4e) / protocol-aware eval は範囲外。

## 1. Context

Phase 4.4a で policy の **宣言的 DSL + DB 永続化 + CRUD API + UI panel** が landed した。policy は保存されているが、**受信経路にはまだ hook が無く** 評価されていない。ユーザが Settings で `default_action: auto_accept` を保存しても、受信メッセージには何も起きない。

本 ADR は evaluator の **どこで / いつ / 何のメタデータで** を決める:

- **どこで** — server / browser / signer daemon のどれが policy を評価するか
- **いつ** — 受信時 (post-commit) / fetch 時 (lazy) / daemon の pull ループで
- **何のメタデータで** — 暗号境界の制約上、どれだけ context を見られるか

Phase 4.4c (executor — 実際に reply を送る) は本 ADR の範囲外だが、evaluator の decision shape が executor の入力になるため、contract は 4.4c で再利用できるよう設計する。

## 2. Mode 比較

A2A メッセージ本文は受信者の公開鍵で暗号化されており、**サーバは平文を見られない** (docs/04 §2 の E2E 暗号化不変条件)。protocol_id (`schedule_negotiation.propose` / `task_delegation.delegate`) は暗号文内にあるため、server-side 評価からは見えない。

この制約下で、evaluator を配置できる場所は 3 つ:

### Isolated mode — Signer Daemon

Signer Daemon (docs/15 §2) は at-rest 暗号化された秘密鍵を保持しており、受信メッセージを復号できる。

- ✅ **protocol_id を直接参照可能** → `protocols.schedule_negotiation.propose` の override を evaluator に渡せる
- ✅ **executor とも近い** (4.4c で daemon が reply に署名するのと同じプロセス内)
- ❌ **設置が重い** — 非対話型 agent access (P0-P8) をユーザが事前 setup している必要がある。MVP ユーザの大半はまだ設置していない
- ❌ **Daemon の online/offline 差分が出る** — daemon が止まっている間は evaluator が動かない
- ❌ **導入コストが大きい** — 4.4c (executor) とセットで実装するのが自然

### Standard mode — Browser

ブラウザは E2E 暗号化の復号側であり、`/inbox` を開いたときに初めて本文を復号する。

- ✅ **protocol_id を参照可能** — 復号後に MIME dispatch すればよい
- ✅ **UI と同じコンテキスト** — ユーザが今見ている inbox card にバッジを表示するだけなら最小コスト
- ❌ **受信と評価の timing がずれる** — メッセージ到着時には評価されず、ユーザが inbox を開くまで decision が出ない
- ❌ **バックグラウンド自動送信が難しい** — タブを閉じると executor も止まる (best-effort)
- ❌ **evaluator ロジックが server と重複して定義される** — 同じルールを Rust と TS で 2 回実装する保守コスト

### Mode C — Server metadata-only (採用)

サーバは A2A 本文を復号できないが、`message_index` に入っている **平文メタデータ** (priority / trust_score / sender_did / 受信者 agent) だけで policy の一部は評価できる。

- ✅ **受信時に即時評価** — `send_message` の post-commit で走り、audit log に確実に残る
- ✅ **決定論的 & 監査容易** — pure function、pool 1 回だけ touch、eval 結果を DB に persist
- ✅ **Daemon / browser 両方の Mode と共存可能** — Mode C の decision は "server_metadata_v1" と tag 付けされ、後段の Isolated mode/B が必要に応じて上書きする (§4)
- ❌ **protocol_id を見られない** — `protocols.schedule_negotiation.propose` override は本 mode では評価できない。`default_action` + metadata conditions のみ
- ❌ **4.4a の UI は protocol override 編集を既に提供している** — ユーザが protocol override を保存しても Mode C では fire しない (UI で explicit に注記する必要)

## 3. Decision

**Mode C (server metadata-only) を Phase 4.4b で採用**。

理由:

1. 最小の変更で evaluator の vertical slice が動き始める。DB column 2 つ + audit event 1 種 + pure function 1 つ
2. Isolated mode (daemon) は 4.4c の executor と同セッションで実装するほうが結合度が適切
3. Standard mode (browser) は executor 不要時の補助として将来追加できる設計 (decision schema が共通)
4. 復号境界を動かさず、security posture が変わらない

### 3.1 Mode C の評価対象

Mode C evaluator は以下のメタデータだけを見る:

| メタデータ | 取得元 | 変更不要 |
|---|---|---|
| master switch | `agents.auto_reply` (0001_init.sql) | ✅ |
| priority | `message_index.priority` (send_message で計算済) | ✅ |
| trust_score | `message_index.trust_score` (send_message で計算済) | ✅ |
| sender_did | `message_index.sender_did` | ✅ |
| is_contact | `contacts (owner_user_id, did)` の COUNT | ✅ |
| policy JSON | `agent_auto_reply_policies.policy` (4.4a 追加) | ✅ |
| policy revision | `agent_auto_reply_policies.revision` | ✅ |

protocol_id は本 mode では常に `None`。`policy.protocols.*` は **存在を許可するが評価では touch しない** — forward-compat (ADR 25 §9) に沿う。

### 3.2 多段 evaluator の合成 (将来)

後続フェーズで Isolated mode / B が追加された場合の合成ルール (本 ADR で invariant だけ決めておく):

| 現行 Mode C decision | 次の mode が追加する decision | 最終 decision |
|---|---|---|
| `queue_for_human (master_off)` | 何でも | `queue_for_human (master_off)` (master は常に強い) |
| `queue_for_human (no_policy)` | 何でも | 上位 mode の decision (no_policy は "保留")  |
| `queue_for_human (<metadata 違反>)` | `auto_accept` from protocol override | 上位 mode の decision (より厳密な情報が勝つ) |
| `auto_accept` from default | `queue_for_human` from protocol override | 上位 mode の decision (protocol override は more specific) |

原則: **より多くの情報を持つ mode が勝つ**。Isolated mode (daemon) > Standard mode (browser) > Mode C (server)。ただし master switch off は全 mode に共通の拒否条件。

本フェーズでは Mode C しか存在しないので、この合成ロジックはまだ実装しない (単に最新 decision を `message_index.auto_reply_decision` に書くだけ)。

## 4. Evaluator contract

### 4.1 Pure function

```rust
fn evaluate_auto_reply_policy(
    policy: &serde_json::Value,
    ctx: &EvaluationContext,
) -> Decision;
```

副作用なし。DB / ネットワーク / 時計に依存しない。context だけで決まる。

### 4.2 EvaluationContext

```rust
struct EvaluationContext {
    master_auto_reply_enabled: bool,
    priority: MessagePriority,           // high | normal | low | background
    trust_score: f64,                    // 0.0 – 1.0
    sender_did: String,
    is_contact: bool,
    // Always None in Mode C. Reserved for Isolated mode/B future merging.
    protocol: Option<ProtocolKey>,
}
```

### 4.3 Decision

```rust
enum Action {
    QueueForHuman,      // 既定 / 安全側フォールバック
    AutoAccept,
    AutoDecline,
    AutoAcceptIfFree,   // 4.4d で Calendar 連携が入るまでは queue にフォールバック
    DelegateToLlm,      // 4.4e で LLM が入るまでは queue にフォールバック
}

struct Decision {
    action: Action,
    reason: Cow<'static, str>,    // "master_off" | "no_policy" | "default_match" | "trust_below_threshold" ...
    matched_rule_path: &'static str,  // "default" | "protocols.<type>.<action>"
    fallback_reason: Option<&'static str>,  // "calendar_unavailable" | "llm_unavailable" | None
    evaluator_mode: &'static str,  // "server_metadata_v1"
}
```

### 4.4 評価順序 (Mode C)

1. `!ctx.master_auto_reply_enabled` → `queue_for_human (master_off)`
2. policy が空 (`{}`) → `queue_for_human (no_policy)`
3. schema version が 1 以外 → `queue_for_human (unsupported_schema)`
4. `default_action` を読み、`default_conditions` の全条件を評価 (AND):
   - `priority_at_most` 違反 → `queue_for_human (priority_exceeds_policy)`
   - `min_trust_score` 違反 → `queue_for_human (trust_below_threshold)`
   - `require_contact=true && !is_contact` → `queue_for_human (not_a_contact)`
   - `sender_in_allowlist` が配列で sender_did がそこに無い → `queue_for_human (sender_not_in_allowlist)`
5. 条件通過: `default_action` を採用
   - `auto_accept_if_free` → `queue_for_human (calendar_unavailable)`, fallback_reason=`calendar_unavailable`
   - `delegate_to_llm` → `queue_for_human (llm_unavailable)`, fallback_reason=`llm_unavailable`
   - それ以外 (`auto_accept` / `auto_decline` / `queue_for_human`) はそのまま
6. `policy.protocols.*` は Mode C では touch しない (forward-compat)

## 5. 受信経路への組み込み

### 5.1 Hook 位置

[services/api/src/lib.rs](../services/api/src/lib.rs) の `send_message` handler — Phase 3 audit ループ (現 lib.rs:9474 付近) の **直後**。

理由:

- `tx.commit()` 済の post-commit 区間 → evaluator の query が transaction を延長しない
- message_index の recipient row が既に存在 → `UPDATE ... WHERE id = $message_id` で decision を書ける
- `record_audit_event` と同じ fire-and-forget パターン ([lib.rs:7911](../services/api/src/lib.rs:7911))

### 5.2 Recipient 判定

- cross-user 送信: 常に recipient row に対して evaluator を呼ぶ
- same-user 送信: folder が `inbox` / `spam` / `pending_approval` の場合のみ (sent folder は自分宛ではない)

### 5.3 DB query (evaluator の前提 context 取得)

`resolve_auto_reply_context()` を新設:

```sql
SELECT
  a.auto_reply       AS master_auto_reply_enabled,
  p.policy           AS policy,
  p.revision         AS policy_revision,
  EXISTS (
    SELECT 1 FROM contacts c
    WHERE c.owner_user_id = $1 AND c.did = $2
  ) AS is_contact
FROM agents a
LEFT JOIN agent_auto_reply_policies p ON p.agent_id = a.id
WHERE a.id = $3 AND a.user_id = $1
LIMIT 1;
```

(agent_id は send_message 内で解決済のため、agent_identity_keys を再 JOIN する必要はない。)

### 5.4 結果の persist

evaluator 実行後:

1. `record_audit_event(pool, user_id, None, None, "auto_reply_evaluated", detail_json)` — fire-and-forget
2. `UPDATE message_index SET auto_reply_decision = $action, auto_reply_reason = $reason WHERE id = $message_id AND owner_user_id = $recipient_user_id` — 失敗時は `eprintln!` で log 継続 (audit が source of truth)

## 6. 監査イベント

新規 event: `auto_reply_evaluated`

```json
{
  "message_id": "uuid",
  "agent_id": "uuid",
  "sender_did": "did:key:...",
  "decision": {
    "action": "queue_for_human",
    "reason": "trust_below_threshold",
    "matched_rule_path": "default",
    "fallback_reason": null
  },
  "policy_revision": 3,
  "evaluator_mode": "server_metadata_v1"
}
```

`evaluator_mode` で将来 `client_protocol_v1` / `daemon_protocol_v1` と区別する。ADR 25 §7.4 の監査イベント一覧に追加。

## 7. Feature flag

環境変数 `AGENT_INBOX_AUTO_REPLY_EVALUATOR`:

| 値 | 挙動 |
|---|---|
| `off` | evaluator を呼ばない。message_index の decision 列は NULL のまま、audit も出ない |
| `log` (default) | 評価して audit + message_index UPDATE。**送信はしない** (本 mode の Mode C の上限) |
| `send` | 将来 (4.4c 以降)。evaluator + executor 両方有効 |

**段階的 rollout**:
1. 4.4b landing 時点では prod も `log` で start (silently evaluated、UI にバッジ表示)
2. 問題無ければ flag は残すが default のまま
3. 4.4c (executor) が landing したら `send` が選択可能に

### 7.1 Rollback

`AGENT_INBOX_AUTO_REPLY_EVALUATOR=off` で即座に既存挙動に戻せる。migration 0017 の追加列は NULL 許容で既存行に影響なし。

## 8. Out of scope (Phase 4.4b)

- **Protocol-aware 評価 (Isolated mode / B)** — daemon / browser 側の evaluator 実装。本 ADR §2 で述べた合成ルールの実装
- **Executor** (4.4c) — 実際の auto-reply 送信、rate limit、loop block
- **Google Calendar** (4.4d) — `auto_accept_if_free` の実装
- **LLM delegate** (4.4e) — `delegate_to_llm` の実装
- **Inbox フィルタ** — decision を基にした inbox の filtering / sorting (別 issue)
- **Policy 変更の即時反映** — policy を PUT した後、過去のメッセージを再評価する機能は将来 feature

## 9. リスク

1. **Evaluator のレイテンシ** — `tokio::spawn` の fire-and-forget で送信レスポンスには影響しない。DB query は 1 つに統合
2. **audit と message_index の非原子性** — audit が source of truth、UPDATE 失敗時でも decision は復元可能
3. **policy が壊れた JSON の場合** — `unsupported_schema` で安全側フォールバック、4.4a の PUT validation を通る限りは発生しない
4. **protocols.* が UI で保存可能なのに fire しない** — ADR 25 §2.5 に「server mode では protocols.* は Isolated mode/B が実装されるまで deferred」と追記、UI 側に注記
5. **env flag の regression** — unit + integration テスト両方で `off` ケースをカバー

## 10. 将来の ADR 25c / 25d 予告

- **ADR 25c (Phase 4.4c — Executor)**: Signer Daemon を Isolated mode として活性化、rate limit 階層、loop 防止、Isolated mode/C 合成の具体ロジック
- **ADR 25d (Phase 4.4d/e — Calendar / LLM)**: `auto_accept_if_free` の Calendar freebusy 呼び出し、`delegate_to_llm` の Groq/OpenRouter 統合
