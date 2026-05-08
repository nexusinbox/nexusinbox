# ADR 25: Auto-reply Engine (Phase 4.4) — hub / overview

**Status**: Accepted (2026-04-24, updated 2026-04-25 after 4.4b / 4.4c / 4.4d / 4.5 landings)
**Supersedes**: `docs/04_messaging_protocol.md` §3.3 (sketch)
**Related**:
- [docs/24_a2a_protocol_design.md](./24_a2a_protocol_design.md)
- [docs/25b_auto_reply_evaluator_decision_model.md](./25b_auto_reply_evaluator_decision_model.md)
- [docs/25c_auto_reply_executor_mode_b.md](./25c_auto_reply_executor_mode_b.md)
- [docs/25c-a_auto_reply_executor_mode_a.md](./25c-a_auto_reply_executor_mode_a.md)
- [docs/25d_calendar_freebusy_auto_accept.md](./25d_calendar_freebusy_auto_accept.md)
- [docs/25e_llm_delegate_cancelled.md](./25e_llm_delegate_cancelled.md)
- [docs/25f_ai_draft_human_approval.md](./25f_ai_draft_human_approval.md)

## 1. Context

A2A (docs/24) により `schedule_negotiation` / `task_delegation` の構造化メッセージが landed し、Phase 4.4 ではその上に **policy-driven auto-reply** を積み上げた。本 ADR 25 は、Phase 4.4 全体の **ハブ / overview** として位置づける。

このドキュメント自体の役割は次の 3 つ:
1. 4.4 全体の設計意図と invariant をまとめる
2. 4.4a〜4.5 の各 ADR への入口を提供する
3. どこまで landed していて、何が cancelled / future なのかを一目で分かるようにする

## 2. Current status snapshot

| Phase | 内容 | Status | Source of truth |
|---|---|---|---|
| 4.4a | Policy DSL + DB + CRUD API | ✅ landed | docs/25 + code |
| 4.4b | Evaluator decision model | ✅ landed | [25b](./25b_auto_reply_evaluator_decision_model.md) |
| 4.4c | Standard mode executor | ✅ landed | [25c](./25c_auto_reply_executor_mode_b.md) |
| 4.4c+ | Isolated mode executor | ✅ landed | [25c-A](./25c-a_auto_reply_executor_mode_a.md) |
| 4.4d | Calendar freebusy / `auto_accept_if_free` | ✅ landed (Standard mode) | [25d](./25d_calendar_freebusy_auto_accept.md) |
| 4.4d-A | Isolated mode Calendar | ⏳ future | follow-on ADR |
| 4.4e | `delegate_to_llm` auto-send | ❌ cancelled | [25e](./25e_llm_delegate_cancelled.md) |
| 4.5 | AI draft + human approval | ✅ landed | [25f](./25f_ai_draft_human_approval.md) |
| 4.6 | Tone toggle + Regenerate | ✅ landed | [25f §6](./25f_ai_draft_human_approval.md#6-phase-46--tone-toggle--regenerate-landed-2026-04-25) |

## 3. What remains normative here

この ADR 25 に残す正本は次のみ:
- auto-reply 全体の目的
- policy DSL の top-level invariant
- `agents.auto_reply` master switch の扱い
- phase 分割の理由
- follow-on ADR の索引

Evaluator / executor / Calendar / LLM / AI draft の詳細仕様は、それぞれの follow-on ADR を正本とする。

### 3.1 なぜフェーズ分割したか (歴史的経緯)

- 4.4 を一気通貫で実装すると DB 変更 + evaluator + executor + Calendar + LLM が同 PR に混じり、レビュー粒度が破綻 (CONTRIBUTING の Security-sensitive changes review が成立しなくなる)
- 特に **evaluator の署名主体** (Isolated mode: Signer Daemon / Standard mode: ブラウザ) は暗号境界と責任分担に直結するため別 ADR で詰めた (25b → 25c / 25c-A)
- 4.4a は署名主体に依存しない「宣言的 DSL」の形状確定だけに留めて landing し、後続を follow-on ADR として積み上げた

### 3.2 4.4a で確定した polciy DSL の top-level invariant

- `agents.auto_reply` BOOL を master switch として利用、policy 行は専用テーブル `agent_auto_reply_policies` に分離
- ETag + If-Match による楽観ロック
- 監査イベント `auto_reply_policy_{created,updated,deleted}` を fire-and-forget 記録
- DSL 値は forward-compat 重視 (例: `delegate_to_llm` は 4.4e cancel 後も DSL から削除しない)

## 2. Decision

### 2.1 Policy は declarative JSON DSL (runtime-agnostic)

Policy は evaluator の runtime から独立した **宣言的 DSL** として定義する。`"daemon_worker_id"` のような runtime-specific field は持たない。これにより:

- Isolated mode (Signer Daemon) が policy を fetch して評価できる
- Standard mode (ブラウザ) が同じ policy を評価できる
- 将来サーバ side evaluator を追加する選択肢も残る

### 2.2 永続化は専用テーブル `agent_auto_reply_policies`

```sql
CREATE TABLE agent_auto_reply_policies (
  agent_id           UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
  schema_version     INT NOT NULL DEFAULT 1,       -- policy JSON の v に対応
  revision           BIGINT NOT NULL DEFAULT 1,    -- 楽観ロック用 (行更新ごとに ++)
  policy             JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_by_user_id UUID NOT NULL REFERENCES users(id),
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

- 1 agent = 最大 1 policy 行。行がなければ "default (queue_for_human)" 扱い
- `schema_version` (policy JSON の `v`) と `revision` (行の楽観ロック) は別概念なので別列
- `ON DELETE CASCADE`: agent 削除で policy も消える

### 2.3 `agents.auto_reply` BOOL は master switch として残存

既存の `agents.auto_reply` BOOLEAN ([services/api/migrations/0001_init.sql:19](../services/api/migrations/0001_init.sql)) と /settings/agents の既存 toggle UI はそのまま残す。evaluator (4.4b) は以下の invariant に従う:

- `auto_reply = FALSE` → policy が存在しても evaluator は `queue_for_human` を返す
- `auto_reply = TRUE` かつ policy 行なし → default (queue_for_human)
- `auto_reply = TRUE` かつ policy 行あり → policy を評価

### 2.4 API 形状

| Method | Path | 用途 |
|---|---|---|
| GET | `/agents/:id/auto-reply-policy` | 現在の policy 取得、`ETag: "<revision>"` 付き |
| PUT | `/agents/:id/auto-reply-policy` | policy 全体置換、`If-Match: "<revision>"` 推奨 |
| DELETE | `/agents/:id/auto-reply-policy` | policy 行削除 (= default に戻す) |

- 認証: Cookie 認証 (`authenticated_user_id`)、`agents.user_id` と一致しなければ **404** (存在漏洩防止)
- PUT は body に `revision` を含めることもできる (If-Match が proxy / CDN で stripped されるケースの保険)
- PUT 成功時、`revision++` してレスポンスに新 ETag 同梱
- エラーコード: 401 (no session) / 404 (ownership fail) / 409 (revision mismatch) / 422 (schema invalid)
- 全 CRUD で audit log を `record_audit_event` で fire-and-forget 記録

### 2.5 Evaluator 不変条件 (Phase 4.4b で詳細設計)

Phase 4.4a の policy DSL は以下の invariant を満たす前提で 4.4b 設計を進める:

1. **署名主体から独立**: policy JSON はどの runtime (daemon / browser / server) からも評価可能
2. **Conditions は pure**: 外部 I/O を要する唯一の例外は `action: "auto_accept_if_free"` (Phase 4.4d の Calendar API 呼び出し)
3. **Policy 不在 / master off は queue_for_human と等価**

### 2.6 Follow-on ADR ownership

詳細仕様は本 ADR では扱わず、それぞれの follow-on ADR を正本とする:

- Evaluator の詳細: [25b](./25b_auto_reply_evaluator_decision_model.md)
- Standard mode executor の詳細: [25c](./25c_auto_reply_executor_mode_b.md)
- Isolated mode executor の詳細: [25c-A](./25c-a_auto_reply_executor_mode_a.md)
- Calendar freebusy の詳細: [25d](./25d_calendar_freebusy_auto_accept.md)
- `delegate_to_llm` の取消: [25e](./25e_llm_delegate_cancelled.md)
- AI draft + human approval の詳細: [25f](./25f_ai_draft_human_approval.md)

この ADR 25 では、それらを future work としてではなく **landed / cancelled / follow-on** の整理対象として扱う。

## 3. Alternatives Considered

| # | 案 | 却下理由 |
|---|---|---|
| (a) | `agents` テーブルに JSONB 列を直接追加 | hot table (messages 送信ごとに agents を参照) なので migration footprint が大きい |
| (b) | 既存 PATCH /agents に `policy` field を追加 | 監査粒度が雑 (label 更新と policy 更新が同じ event) になる |
| (c) | Flat rule list (Stripe webhook filter 風) | 4.4a では overkill、将来の複雑化で schema bump が容易 |
| (d) | `default_action` を `protocols.default` に nest | UI mapping が面倒、意味的な違いなし |
| (e) | Policy JSON を agents 行に nest | schema migration の footprint が大、既存 UI 全体を touch する必要あり |

## 4. Consequences

### Positive

- 既存 UI (agents.auto_reply toggle) を壊さない
- Evaluator の runtime (daemon / browser / server) 決定を 4.4b に延期できる
- 監査ログが policy 変更を独立イベントとして記録、後からの diff 検索が容易
- Phase 4.4a が小さな足場として landing、UI / evaluator / executor / Calendar / LLM は後続セッションで段階導入

### Negative

- 2 つの状態 (`agents.auto_reply` BOOL + `agent_auto_reply_policies` row) で整合性確保が必要。evaluator で明示的 invariant 化
- Isolated mode/B の signing 主体判断を 4.4b に延期することで、policy DSL が「両対応」を保つ責任が 4.4a に生じる
- fire-and-forget audit log は policy CRUD のような security-sensitive 操作では silent drop が残るリスク (§7.5 で既知)

## 5. Payload Schema (normative)

### 5.1 TypeScript 型

```ts
export type AutoReplyAction =
  | "queue_for_human"
  | "auto_accept"
  | "auto_decline"
  | "auto_accept_if_free"   // Phase 4.4d (Calendar)
  | "delegate_to_llm";       // Phase 4.4e (LLM)

export interface AutoReplyConditions {
  min_trust_score?: number;         // 0.0-1.0
  require_contact?: boolean;
  priority_at_most?: "high" | "normal" | "low" | "background";
  sender_in_allowlist?: string[];   // DIDs
}

export interface AutoReplyProtocolAction {
  action: AutoReplyAction;
  conditions?: AutoReplyConditions;
  note_template?: string;           // ≤ 2000 chars
}

export interface AutoReplyPolicy {
  v: 1;
  default_action: AutoReplyAction;   // fallback for unspecified (type, action)
  protocols?: {
    schedule_negotiation?: {
      propose?: AutoReplyProtocolAction;
    };
    task_delegation?: {
      delegate?: AutoReplyProtocolAction;
    };
  };
}
```

### 5.2 JSON 例 (会議は自動承諾、タスクは queue)

```json
{
  "v": 1,
  "default_action": "queue_for_human",
  "protocols": {
    "schedule_negotiation": {
      "propose": {
        "action": "auto_accept_if_free",
        "conditions": {
          "min_trust_score": 0.5,
          "require_contact": true,
          "priority_at_most": "normal"
        },
        "note_template": "OK, scheduled via my agent."
      }
    },
    "task_delegation": {
      "delegate": {
        "action": "queue_for_human"
      }
    }
  }
}
```

### 5.3 Validation ルール (Phase 4.4a で実装)

- `v === 1` 必須
- `default_action` が `AutoReplyAction` enum のいずれか
- `protocols.*.*.action` も同 enum
- `conditions.min_trust_score` は `[0, 1]` の数値
- `conditions.priority_at_most` は `"high" | "normal" | "low" | "background"`
- `conditions.sender_in_allowlist` は最大 100 要素、各要素 DID 文字列形
- `note_template` は最大 2000 文字
- 未知 field は無視 (forward compatibility)

## 6. API Contract

### GET /agents/:id/auto-reply-policy

**Auth**: Cookie, `agents.user_id` 一致必須。

**Response 200**:
```json
{
  "agent_id": "uuid",
  "schema_version": 1,
  "revision": 1,
  "policy": { /* AutoReplyPolicy or {} if no row */ },
  "updated_at": "2026-04-24T12:34:56Z"
}
```
`ETag: "1"` header 付き。policy 行がない場合は `revision: 0` + `policy: {}` を返す。

### PUT /agents/:id/auto-reply-policy

**Auth**: Cookie + ownership。

**Request** (JSON body):
```json
{
  "policy": { /* AutoReplyPolicy */ },
  "revision": 1
}
```

`If-Match: "1"` header 推奨。Body の `revision` field は If-Match が proxy で stripped された場合の保険。両方指定があれば header を正とする。

**Response 200**: GET と同じ shape、`revision++` 済み、新 ETag。

**エラー**:
- 409 Conflict: If-Match or body.revision が DB の revision と不一致
- 422 Unprocessable Entity: policy schema invalid
- 404: ownership fail

### DELETE /agents/:id/auto-reply-policy

**Auth**: Cookie + ownership。**Response 204**: policy 行を削除 (= default 扱いに戻る)。

## 7. Security & Loop Prevention

### 7.1 脅威モデル

- **Policy 改ざん**: authenticated user のみ。ownership check で user_id mismatch は 404 (存在漏洩防止)
- **Auto-reply 誘発**: 攻撃者が propose を送るだけで auto-reply が発火。rate limit + trust score + loop 防止で緩和 (4.4c)
- **Calendar side-channel (4.4d)**: `auto_accept_if_free` の結果で Calendar の空き状況が送信者に漏れる。ADR 25 で explicit、4.4d の ADR で mitigation

### 7.2 Rate Limit 階層

- 既存 L3 (`POLICY_L3_MAX_SENDS_PER_CREDENTIAL_PER_DAY = 200`) はそのまま適用
- auto-reply 専用サブ cap: **50/day/agent** を Phase 4.4c で導入
- Sub cap 超過時は `auto_reply_rate_limited` audit event、queue_for_human にフォールバック

### 7.3 Loop 防止 Invariant

Phase 4.4b/c で実装する loop prevention ルール (ADR 25 で約束):

1. **Self-to-self block**: sender が recipient user の別 agent なら auto-reply しない
2. **Blocked DID**: sender が recipient の block list にいれば auto-reply しない (既存 evaluate_block_decision 呼び出し)
3. **Reply chain depth ≤ 3**: `protocol.reply_to` を辿って 3 段以上のチェーンは auto-reply 禁止 (bot 同士の echo 防止)
4. **Duplicate suppression**: 同一 `protocol.id` への auto-reply は 1 回限り (docs/24 §7.2)

### 7.4 監査イベント一覧

**Phase 4.4a で追加**:
- `auto_reply_policy_created` (detail: `{next, revision_after: 1}`)
- `auto_reply_policy_updated` (detail: `{prev, next, revision_before, revision_after}`)
- `auto_reply_policy_deleted` (detail: `{prev, revision_before}`)

**Phase 4.4b で追加**:
- `auto_reply_evaluated` (detail: `{decision, reason, matched_rule_path}`)
- `auto_reply_loop_blocked` (detail: `{reason: "self_to_self" | "blocked_did" | "chain_depth" | "duplicate"}`)

**Phase 4.4c で追加**:
- `auto_reply_sent` (detail: `{credential_id, original_protocol_id, reply_protocol_id}`)
- `auto_reply_rate_limited` (detail: `{cap, current_count}`)

### 7.5 fire-and-forget audit log の現状

`record_audit_event` は tokio::spawn で発行しており、DB 書き込み失敗時は silent drop される ([services/api/src/lib.rs:7434](../services/api/src/lib.rs))。policy CRUD のような security-sensitive 操作では望ましくない可能性がある。**本 ADR の範囲外**だが、別 issue で改善検討。

### 7.6 LLM 導入 (4.4e) 時の追加 review 要件

- **Prompt injection**: 受信 A2A メッセージの本文が LLM prompt に混入すると、送信者が prompt を注入できる。mitigation: 本文は LLM system prompt ではなく user prompt に、かつ明示的に "this is untrusted user content" でラップ
- **Content safety**: LLM が暴言 / 漏洩 / hallucinated reference を返す可能性。mitigation: 送信前の filter service (Layer 2 spam filter の再利用候補) 経由
- **Cost**: Groq 無料枠 (14.4k RPM) を超える想定ユーザ数でコスト試算
- **Key leakage**: LLM response に `agt_` / `agr_` / `ens_` 等の鍵マテリアルが混入しないよう出力 sanitize (既存 Gateway L2 sanitizer を流用)

### 7.7 CONTRIBUTING 適合の明言

本機能は CONTRIBUTING.md の "Security-sensitive changes" の 3 つの trigger を跨ぐ:

- "Anything that changes **what a token can do**" — auto-reply は agent の token を使って自動で送信する
- "Anything that changes **what is logged**" — 新 audit event 5+ 件
- "Anything that changes **who sees plaintext**" — LLM 統合 (4.4e) で LLM provider に内容が送られる

従って **implementation + docs + help copy + settings copy の 4 surface を同一 PR で更新** する契約を ADR 内で宣言する。4.4a は docs + (後続 PR の) settings copy のみ対象、help copy は UI 実装時 (別セッション) に同時更新。

## 8. Phase 4.4 Roadmap

| Phase | Scope | ADR | 本セッション |
|---|---|---|---|
| **4.4a** | Policy DSL + DB + CRUD API + ADR 25 | 25 (本 ADR) | ✅ 実装 |
| 4.4a+ | Settings UI panel + TS types + hooks | 25 | ✅ 実装 |
| **4.4b** | Evaluator (Mode C = server metadata-only、decision を DB persist、audit) | [25b](./25b_auto_reply_evaluator_decision_model.md) | ✅ 実装 |
| **4.4c (Standard mode)** | Browser executor + 3 層 loop prevention + client-side protocol evaluator | [25c](./25c_auto_reply_executor_mode_b.md) | ✅ 実装 |
| **4.4c+ (Isolated mode)** | Agent Gateway polling executor + `wrap_content_key` daemon RPC + `?auto_reply_pending` filter (非対話型 agent 向け) | [25c-A](./25c-a_auto_reply_executor_mode_a.md) | ✅ 実装 |
| **4.4c+B** | Rust 版 protocol-aware client evaluator (Isolated mode でも `protocols.*` override を honour、merge rule) | [25c-A §2.3](./25c-a_auto_reply_executor_mode_a.md#23-executor-のスコープ) | ✅ 実装 |
| **4.4d** | Google Calendar freebusy (`auto_accept_if_free`、Standard mode / browser GIS) | [25d](./25d_calendar_freebusy_auto_accept.md) | ✅ 実装 |
| 4.4d-A (Isolated mode Calendar) | Gateway daemon 側 Calendar 対応 (server-side OAuth + 暗号化 refresh_token) | 25d-A 予定 | 後続 |
| ~~4.4e~~ | ~~LLM 応答生成 (`delegate_to_llm`)~~ | [25e](./25e_llm_delegate_cancelled.md) | ❌ **Cancelled** (E2E 暗号破壊・prompt injection・幻覚コミットリスク) |
| **4.5** | AI ドラフト + 人間承認 UI (BYOK Anthropic、browser から直接) | [25f](./25f_ai_draft_human_approval.md) | ✅ 実装 |

## 9. Versioning Policy

Policy JSON の `v` は A2A と同じ方針 (docs/24 §9):

- Additive-only change (新 action enum 値、新 condition field、新 protocol type) → 同 `v` のまま
- Breaking change (field 削除、enum 値削除、意味変更) → `v++`
- Evaluator は未知 field を無視 (forward compatibility)

### 想定される future additive change

- `conditions.max_duration_hours` (schedule_negotiation 用)
- `conditions.quiet_hours` (時間帯制限)
- `note_template_i18n` (多言語テンプレート)
- `protocols.data_request.request` / `protocols.status_update.update` (新 A2A protocol type 追加時)

## 10. Out of Scope (Phase 4.4a の範囲外)

- ~~評価エンジン (Phase 4.4b) — ADR 25b で詳細化~~ → [ADR 25b](./25b_auto_reply_evaluator_decision_model.md) で Mode C (server metadata-only) を採用、実装済
- ~~実際の auto-reply 送信 (Phase 4.4c)~~ → [ADR 25c](./25c_auto_reply_executor_mode_b.md) で Standard mode (browser) executor を実装済。Isolated mode (Daemon) は後続
- ~~Google Calendar 連携 (Phase 4.4d)~~ → [ADR 25d](./25d_calendar_freebusy_auto_accept.md) で browser-side GIS 方式を採用、Standard mode 実装済。Isolated mode (daemon) は 25d-A 予定
- ~~LLM 応答生成 (Phase 4.4e)~~ → [ADR 25e](./25e_llm_delegate_cancelled.md) で **cancelled**。代替は Phase 4.5 (AI ドラフト + 人間承認 UI)
- Settings UI の policy 編集 panel (4.4a の次セッション)
- Rust DB integration test (docker compose 必須、別セッション)
- TypeScript client / hooks / UI 全般
- Help copy / settings copy 更新 (UI 実装時に同時更新)

### 4.4a で敢えて入れない技術判断

- **server-side evaluator**: 暗号境界を跨ぎ評価責任を server に置くのは避ける
- **event-driven evaluator (WebSocket hook)**: 4.4b で決定
- **Redis-backed rate limit**: 4.4c で必要になったら別 issue
