# ADR 24: Agent-to-Agent (A2A) Protocol v1 — `schedule_negotiation` + `task_delegation`

**Status**: Accepted (2026-04-24, amended 2026-04-24 for `task_delegation`)
**Supersedes**: `docs/04_messaging_protocol.md` §3 (スケッチのみ)
**Related**: [docs/09_roadmap.md](./09_roadmap.md) Phase 4、[docs/04_messaging_protocol.md](./04_messaging_protocol.md)、[docs/21_message_visibility_ux_for_mcp_modes.md](./21_message_visibility_ux_for_mcp_modes.md)

## 1. Context

NexusInbox の差別化価値は「AI エージェント同士が自律的にやり取りする」こと。本 ADR 24 は、その土台となる **A2A envelope / MIME / payload schema / correlation invariant** の正本である。

初期 landing は **Phase 4.1 (基盤) + 4.2 (`schedule_negotiation`) + 4.3 (`task_delegation`)** だったが、その後:
- auto-reply engine (Phase 4.4, docs/25*)
- Google Calendar freebusy (`auto_accept_if_free`, docs/25d)
- AI draft + human approval (Phase 4.5, docs/25f)
- `/compose/propose` からの新規 propose UI

まで実装が進んでいる。

この ADR 24 自体は、そうした follow-on 機能の有無に依らず不変な **A2A schema / compatibility / security invariant** を扱う。具体的にはペイロード形式、`content_type` MIME、`protocol.id` / `reply_to` の correlation、署名対象、Ed25519 / X25519 + AES-GCM 互換性。

**現段階のゴール (本 ADR の責務)**:
- A2A envelope の wire format を確定する
- `schedule_negotiation` / `task_delegation` の payload schema を v=1 として固定する
- A2A メッセージとレガシー平文メッセージの共存ルールを示す
- 後続機能 (auto-reply / Calendar / AI draft) が依拠できる不変条件を明文化する

**明示的に範囲外** (§10): follow-on 機能群そのものの設計詳細は別 ADR を参照。

## 2. Decision

### 2.1 ペイロードは `encrypted_content` 内 JSON に埋め込む

A2A のメタデータ (type / action / payload) は暗号化境界の内側に置く。サーバは本文を見ないので、DB スキーマ・マイグレーションは不要。既存の Ed25519 署名は ciphertext に対するものなので、新フィールドが追加されても署名ロジックは不変。

### 2.2 content_type で UI 分岐

新 MIME: `application/vnd.nexusinbox.a2a+json; v=1`。`envelope.metadata.content_type` に乗せる。クライアントはこれで dispatch し、受信側で毎回 JSON.parse を試すことはしない (プレーンテキストが偶然 `{` から始まるケースで false positive を出したくないため)。

サーバ側は content_type を BYOS ciphertext と一緒に保存し、`/messages/:id/content` レスポンスで返す (詳細は §5.3)。

### 2.3 Payload 形 (トップレベル)

```json
{
  "v": 1,
  "body": "人間向けサマリー",
  "protocol": {
    "id": "UUIDv7",
    "type": "schedule_negotiation",
    "action": "propose" | "accept" | "decline" | "counter",
    "reply_to": "UUIDv7 | null",
    "payload": { /* type-specific */ }
  }
}
```

- `v` はトップレベル。`protocol` を持たない `{ v: 1, body }` も同じ v で表現できる。
- `body` は空文字列を許容するが、**強く推奨** は「旧クライアントでも読める short human-readable 要約」を入れること。
- `protocol.id` は **UUIDv7** (時系列ソート可能、推測困難)。既存の `message_id` とは別空間。
- `reply_to` は protocol レベルの相関 (元 propose の `protocol.id` を指す)。envelope 側の `thread_id` とは直交。

### 2.4 `schedule_negotiation` の action と payload

| action | payload |
|---|---|
| `propose` | `{ event_title, candidates[], required_participants[], response_deadline? }` |
| `accept` | `{ selected_candidate: { start, end } }` |
| `decline` | `{ reason? }` |
| `counter` | `{ candidates[], reason? }` |

Validation:
- `candidates.length` ∈ [1, 20]
- 各 candidate: `end > start` かつ `end - start ≤ 24h`
- `event_title` は必須・非空
- 時刻は **ISO 8601 + タイムゾーン必須** (`Z` or `±HH:MM`)

### 2.4b `task_delegation` の action と payload

| action | payload |
|---|---|
| `delegate` | `{ title, description?, due_date?, priority? }` |
| `accept` | `{ note? }` |
| `decline` | `{ reason? }` |
| `complete` | `{ result? }` |

Validation:
- `title` は必須・非空、≤ 200 文字
- `description` 任意、≤ 4000 文字
- `due_date` 任意。指定時は ISO 8601 + タイムゾーン必須
- `priority` 任意、`"high" | "normal" | "low"` のいずれか
- `note` 任意、≤ 2000 文字
- `reason` 任意、文字列
- `result` 任意、≤ 4000 文字

`accept` と `decline` は `schedule_negotiation` と同一の action トークンを共有する。UI dispatcher は `protocol.type` で分岐し、各型の payload バリデータ (`assertValidScheduleNegotiationPayload` / `assertValidTaskDelegationPayload`) を呼び分ける。

### 2.5 時刻は ISO 8601 + TZ offset 必須

UTC 固定は採用しない。理由: propose 側が「東京時間 15:00」として提示した意図を accept 側が保持したい。UTC 固定だとフロントで現地 TZ に戻す処理が必要になり、元意図が失われる。

### 2.6 Accept / Decline の操作主体 (UI invariant)

```ts
const canRespond =
  message.folder !== "sent" &&              // recipient 側だけ
  protocol.action === "propose" &&          // propose に対してのみ
  !isProposeExpired(protocol.payload);      // response_deadline 経過なら出さない
```

- recipient 側の `propose`: Accept / Decline ボタンを表示
- sender 側 (sent view): 同じカードを read-only 描画
- `accept` / `decline` / `counter` action のメッセージ: 送信者・受信者を問わず常に read-only

### 2.7 Thread の扱い

- A2A reply は元 message の `thread_id` を引き継ぐ (envelope.metadata.thread_id)
- `protocol.reply_to` は protocol レベル相関、`thread_id` は inbox UI レベルのグルーピング
- A2A メッセージではこの 2 つは**両方必須で埋める**

## 3. Alternatives Considered

| # | 選択肢 | 却下理由 |
|---|---|---|
| (a) | サーバに `protocol_type` カラム追加、DB index | 暗号化境界違反。サーバがペイロードの構造を観測するのは E2E 原則と相容れない |
| (b) | 独立した `/a2a` エンドポイント | 既存の spam filter / block list / trust score を再実装する羽目になる |
| (c) | content_type なし、常に JSON.parse を試行 | プレーンテキストで偶然 `{` から始まる本文で false positive |
| (d) | 時刻を UTC 固定 | 元意図の TZ 情報喪失、multi-timezone 調整で不便 |
| (e) | candidate に `candidate_id` を持たせる | 今時点では echo back (start/end) で十分、candidate 編集 UI が入るタイミングで additive に足せる (v=1 forward-compat) |

## 4. Consequences

### Positive
- サーバ改修ゼロ (DB スキーマ変更なし)
- 既存 E2E 暗号化 invariant を維持
- レガシーなプレーンテキストメッセージは引き続き動作 (新クライアントは `content_type` 不在 → legacy fallback)
- 署名検証ロジックは変更不要

### Negative
- 旧 UI (未アップデートクライアント) で A2A メッセージを受信すると、生 JSON が見える。body に human-readable サマリを入れる運用で軽減。
- サーバは protocol-level の統計を持てない (例: 「schedule_negotiation を何件送ったか」はサーバからは見えない)
- 時刻パースはクライアント責務 (iOS Safari 等 browser の `Date` 実装差異を吸収する必要あり)

## 5. Payload Schemas (normative)

### 5.1 TypeScript 型

`packages/core/src/a2a.ts` が一次情報源。要点のみ転記:

```ts
export interface A2AMessagePayload {
  v: 1;
  body: string;
  protocol?: A2AProtocolBlock;
}

export interface A2AProtocolBlock {
  id: string;                           // UUIDv7
  type: "schedule_negotiation";
  action: "propose" | "accept" | "decline" | "counter";
  reply_to: string | null;              // 元 propose の protocol.id
  payload: ScheduleNegotiationPayload;
}

export interface ScheduleCandidate {
  start: string;   // ISO 8601 with TZ offset
  end: string;     // ISO 8601 with TZ offset
}

export type ScheduleNegotiationPayload =
  | { event_title: string; candidates: ScheduleCandidate[]; required_participants: string[]; response_deadline?: string }     // propose
  | { selected_candidate: ScheduleCandidate }                                                                                   // accept
  | { reason?: string }                                                                                                         // decline
  | { candidates: ScheduleCandidate[]; reason?: string };                                                                       // counter
```

### 5.2 JSON 例 (propose)

```json
{
  "v": 1,
  "body": "6/1 15:00 or 6/2 10:00 で打合せ設定をお願いします。",
  "protocol": {
    "id": "01932f7c-a8d4-7e01-b3f5-2c9a1b6d4e80",
    "type": "schedule_negotiation",
    "action": "propose",
    "reply_to": null,
    "payload": {
      "event_title": "Q2 kickoff sync",
      "candidates": [
        { "start": "2026-06-01T15:00:00+09:00", "end": "2026-06-01T16:00:00+09:00" },
        { "start": "2026-06-02T10:00:00+09:00", "end": "2026-06-02T11:00:00+09:00" }
      ],
      "required_participants": ["did:key:z6Mk...abc"],
      "response_deadline": "2026-05-28T23:59:59+09:00"
    }
  }
}
```

### 5.3 サーバ側のフィールド追加

`/messages/:id/content` レスポンスに `content_type?: string` を追加。BYOS に保存する `StoredMessageContent` にも `content_type: Option<String>` を追加。いずれも `#[serde(default)]` + `skip_serializing_if=Option::is_none` で後方互換。

## 6. Compatibility Matrix

| 送信側クライアント | 受信側クライアント | 動作 |
|---|---|---|
| 旧 (text/plain) | 旧 | そのまま表示 (既存挙動、不変) |
| 旧 (text/plain) | 新 | legacy fallback で plain 表示 (既存挙動、不変) |
| 新 (text/plain) | 旧 | そのまま表示 (content_type を見ないので) |
| 新 (text/plain) | 新 | plain 表示 |
| 新 (A2A JSON) | 旧 | **生 JSON が見える**。body フィールドが最初に来るので人間は読める |
| 新 (A2A JSON) | 新 | ProtocolMessageCard で構造化描画 |

## 7. Security & Correlation

### 7.1 Context binding (not replay defense)

Accept で `selected_candidate: { start, end }` を echo back するのは、replay 防御そのものではなく **どの候補への accept か** を proposal/reply 間で明示するためのもの。propose 側が候補を編集した場合の取り違え防止、UI idempotency ロジックの単純化に役立つ。

### 7.2 Replay resistance

- sender の Ed25519 署名で本人特定 (既存)
- `protocol.id` は UUIDv7 でグローバル一意、重複は client-side bug
- 同一 `(thread_id, protocol.id, action)` ペアの二度目は**黙って ignore** する (UI errr は出さない、duplicate ack で混乱しないため)。この invariant はサーバ側では強制できないため client-side defense。

### 7.3 sender_did spoofing

既存の envelope 署名検証 (Ed25519) で防御済み。A2A で追加の攻撃面はなし。

### 7.4 `required_participants` は送信者の申告値

UI で「(送信者による申告)」注記を付ける。信頼しない方針。将来複数人スケジューリングを実装する際は別途 server-side trust フローが必要。

### 7.5 auto-reply (Phase 4.4) 導入前の追加 review 要件

本 ADR は**人間が Accept/Decline を押す半自動**まで。自律応答を入れる際は以下を再 review 必須:
- Accept の自動送信基準 (カレンダー空き判定のみで十分か、スパム判定が要るか)
- required_participants への自動応答ポリシー
- 悪意ある propose が連鎖ペイロードを送ってくるケース (rate limit 設計)

## 8. Testing

### 自動
- [`packages/core/tests/a2a.test.ts`](../packages/core/tests/a2a.test.ts): propose/accept/decline/counter の roundtrip、legacy fallback、validation (39 テスト)
- `apps/web/__tests__/ScheduleNegotiationCard.test.tsx`: render + Accept/Decline コールバック (Step 7 で追加)

### 手動 QA — self-to-self propose (DevTools スニペット)

本物の 2 ユーザー seed は重いので、まずは **自分のエージェント 2 つを使った self-to-self** で propose → Accept の通しを確認する。手順:

1. `pnpm --dir apps/web dev` で dev server を起動し、World ID でログイン
2. `/settings/agents` で **エージェントを 2 つ以上作成**。compose 画面で一方から他方へテキストメッセージを一度送っておき、スレッドが立つことを確認 (鍵交換の動作確認)
3. DevTools Console で [scripts/a2a-demo/seed-propose.mjs](../scripts/a2a-demo/seed-propose.mjs) の内容をコピペして実行。スクリプトは `window` 上のブラウザ keystore を読んで自分の鍵で暗号化する。自分の agent A から agent B への propose として送信される
4. `/inbox` を開く → 候補日時カード + Accept/Decline ボタンが表示される (recipient 側 = agent B でログインしていれば)
5. Accept をクリック → confirm → 送信成功
6. Alice 側 (sender 側) 画面を reload → 同じ thread に accept メッセージが届いている、read-only カードで確定時刻が表示される
7. DevTools Network で `/messages/{id}/content` のレスポンスに `"content_type": "application/vnd.nexusinbox.a2a+json; v=1"` が含まれることを確認

### 自動: API 統合テスト

`services/api/tests/messages_test.rs` の `post_message_roundtrips_a2a_content_type_through_byos` と `post_message_omits_content_type_from_response_when_sender_omitted_it` が content_type round-trip の regression を守る (hermetic、`cargo test --test messages_test` で実行)。

## 9. Versioning Policy

- `v` インクリメントは **breaking change のみ** (フィールド削除、型変更、action enum の既存値変更)
- **additive-only は同じ v** のまま (新 action 追加、新 payload フィールド追加、新 protocol.type 追加)
- クライアントは **未知フィールドを無視** (forward-compat)
- content_type の `; v=1` 部分と payload JSON の `v: 1` は二重化。UI は payload JSON の `v` を正、content_type の v は hint 扱い

### 次の順当な拡張 (今回は入れない)

- `candidate_id` を ScheduleCandidate に追加 → candidate 編集可能 UI のタイミングで additive
- `protocol.type` に `task_delegation`、`data_request`、`status_update` を追加 (Phase 4.3 以降)
- `envelope.metadata.protocol_type_hint` を untrusted hint として追加 (index/filter 用途、暗号化境界は維持)

## 10. Out of Scope

以下は本 ADR の schema 正本の外側にある **follow-on 機能**:

- auto-reply engine (Phase 4.4) → [docs/25_auto_reply_engine_design.md](./25_auto_reply_engine_design.md) と follow-on ADR 群
- Google Calendar 連携 (`auto_accept_if_free`) → [docs/25d_calendar_freebusy_auto_accept.md](./25d_calendar_freebusy_auto_accept.md)
- AI draft + 人間承認 UI → [docs/25f_ai_draft_human_approval.md](./25f_ai_draft_human_approval.md)
- `data_request`, `status_update`, `ack` などの未実装 protocol type
- `task_delegation` の `complete` を Web UI から送る専用導線
- サーバ側の protocol 型 enum / DB 保存 (暗号化境界維持のため)

注:
- `/compose/propose` はすでに landed 済み
- `schedule_negotiation` / `task_delegation` の card 表示と reply 送信も landed 済み
- 本 ADR では、それらの UI ではなく envelope / payload 仕様を正本とする

### 追加された UI サーフェス (2026-04-24 時点)

- `apps/web/app/_components/protocol/ScheduleNegotiationCard.tsx` — schedule_negotiation: propose / accept / decline / counter (Phase 4.1-4.3)
- `apps/web/app/_components/protocol/TaskDelegationCard.tsx` — task_delegation: delegate / accept / decline / complete (Phase 4.3 相当)
- `apps/web/app/_components/protocol/ProtocolMessageRouter.tsx` — `protocol.type` で dispatch、`canRespondToProtocol` で per-type invariant を中央管理
- `apps/web/app/compose/propose/page.tsx` — `/compose/propose` で新規 schedule propose を人間が作成できるフォーム
- `CounterForm` / `/compose/propose` は共通ヘルパ `apps/web/lib/protocol/candidateInput.ts` (validation + ISO 8601 + TZ offset 変換) を共有
