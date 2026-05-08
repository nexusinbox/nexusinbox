# ADR 25f: AI Draft + Human Approval (Phase 4.5 + 4.6) — BYOK Anthropic

**Status**: Accepted (2026-04-25, Phase 4.5 + 4.6 実装)
**Related**: [docs/25_auto_reply_engine_design.md](./25_auto_reply_engine_design.md)、[docs/25e_llm_delegate_cancelled.md](./25e_llm_delegate_cancelled.md)、[docs/25d_calendar_freebusy_auto_accept.md](./25d_calendar_freebusy_auto_accept.md)、[docs/20_mcp_skill_strategy.md](./20_mcp_skill_strategy.md)
**Scope**: AI draft generation for user-reviewed replies. BYOK Anthropic only for this iteration.

## 1. Context

Phase 4.4 全体 (a–d) が着地し、policy ベースの自動返信は機能している。`auto_accept` / `auto_decline` / `auto_accept_if_free` と構造化返信はカバーできるが、**自由文返信** は依然としてユーザが手書きする必要がある。

ADR 25e で `delegate_to_llm` (自動送信 LLM) は cancelled にしたが、理由は:

- E2E 暗号境界を壊す (サーバ or 第三者が平文を見る)
- Prompt injection で悪意ある返信が送信される
- 小モデルの幻覚で誤ったコミットメントを作る

Phase 4.5 (本 ADR) はこれら全ての問題を **「人間が最終承認する」** 工程を挟むことで解決する:

- LLM 呼出は **browser から直接** → サーバは平文を見ない
- Draft は常に textarea に表示され、**ユーザが読んで編集** → prompt injection 誘導に気付く機会がある
- **Send ボタンは手動クリック** → 幻覚が commitments になる前にユーザが気付ける
- **API key は BYOK** → サーバが key を見ない、コストはユーザ負担

## 2. Decision

### 2.1 BYOK (Bring Your Own Key)

ユーザが自分の Anthropic API key を入力 → browser IndexedDB に保存 → browser から直接 `api.anthropic.com` を叩く。サーバはこの key を一度も見ない。

代替案と却下理由:

| 案 | 却下理由 |
|---|---|
| Server-side shared key | サーバがユーザメッセージを LLM に送信 = E2E 破壊 |
| Server-side proxy (key は server、proxy 経由) | 同上、メッセージ本文がサーバを経由 |
| Local LLM (Ollama 等) | ユーザ環境依存、ほとんどのユーザは未設定 |
| MCP runtime 経由 (Claude Desktop 内ローカル処理) | 別トラック (docs/20)。本 ADR と共存可だが今フェーズでは対象外 |

### 2.2 Anthropic のみ (将来拡張可)

Phase 4.5 初回リリースは **Anthropic 1 プロバイダ固定**。理由:

- `claude-haiku-4-5` はコスト (~$0.0001/reply)・速度 (p50 ~1s)・品質バランスが良い
- CORS 公式サポート済 (`anthropic-dangerous-direct-browser-access: true`)
- 内部抽象 (`llmProvider` type) は将来 OpenAI / Groq 追加できる形で用意

OpenAI / Groq 対応は `llmProvider` の追加実装で足りるが、本フェーズではスコープ外。

### 2.3 LLM 接続は opt-in

- API key 未設定でも NexusInbox は完動する (通常 compose / 自動返信 / Calendar 等すべて)
- 「AI Draft Approve」ボタンは常に表示、クリック時に key 未設定ならトーストで Settings 案内
- 「AI アシスタントが無いと使えない」状態は作らない

### 2.4 Draft 生成タイミング

既存の受信カード → "AI Draft Approve" ボタン → `/compose?reply=<id>&ai=1` navigate が既に実装済 (4.4 以前)。Phase 4.5 はこの遷移時に自動生成する:

```
1. Reader pane → "AI Draft Approve" クリック
2. /compose?reply=<id>&ai=1 に遷移
3. Compose ページが messageContent を decrypt (既存)
4. `ai=1` && key 接続済 → generateReplyDraft() 自動呼出 + loading banner
5. 完了 → textarea に draft がプリフィル
6. ユーザが読む → 編集 → Send (通常の compose send path)
```

ユーザが textarea を編集し始めたら再生成しない (`bodyEdited` ref で抑制)。

### 2.5 Prompt injection の扱い

**自動サニタイズはしない**。理由:

- 汎用サニタイズは false positive が多く、正常な受信文を壊す
- 悪意あるテキスト検出は完全性に欠ける (敵対的 prompt は多様)
- **ユーザが draft を読むのが defense** — この「人間による review」が本フェーズ採用理由そのもの

代わりに以下の UX:

- Compose ページに常時 banner:「ドラフトは Anthropic に送信されます。**送信者が悪意あるテキストを含めている可能性があるため、必ず内容を確認してから送信してください**」
- `Send` は手動クリックのみ、auto-send の抜け穴は無い

## 3. Security invariants

1. **API key は server に送らない** — 全ての LLM 呼出は browser → `api.anthropic.com` 直接
2. **Draft は常にユーザが review** — `Send` ボタンの手動クリックが必須
3. **API key は IndexedDB のみ** — localStorage / cookie / URL / server には絶対入れない
4. **Auto-send の抜け穴を作らない** — ADR 25e の cancellation 判断を尊重
5. **CORS proxy は使わない** — サーバ経由すると送信メッセージをサーバが見ることになる

## 4. Provider 抽象

```typescript
// apps/web/lib/llm/llmAuth.ts
type StoredLLMKey = {
  provider: "anthropic";   // future: | "openai" | "groq"
  api_key: string;
  model: string;
  created_at: number;
};

// apps/web/lib/llm/anthropicDraft.ts
async function generateReplyDraft(input: {
  incomingBody: string;
  incomingSubject?: string;
  protocolBlock?: A2AProtocolBlock;
  apiKey: string;
  model: string;
  fetcher?: typeof fetch;  // test injection
}): Promise<string>;
```

将来 OpenAI 対応時は `openaiDraft.ts` を追加、`llmAuth.ts` の provider enum を拡張、caller (compose page) で dispatch。

## 5. Prompt template

System prompt:

```
You are drafting a reply to an incoming message on the user's behalf.
The reply will be shown to the user for review and editing before sending.

- Be concise.
- Match the tone of the incoming message.
- Do not commit to specific actions (dates, payments, tasks) unless the
  incoming message clearly requested them.
- If the message is ambiguous, err on the side of asking a clarifying question.
- Write in the same language as the incoming message.
```

User message (plain text case):

```
Incoming subject: <subject>

Incoming body:
<body>
```

User message (A2A schedule_negotiation.propose):

```
The sender is proposing a meeting via a structured protocol.

Proposed candidates: <candidates joined>
Event title: <title>

Please draft a short acceptance or polite decline response text.
```

A2A task_delegation.delegate:

```
The sender is delegating a task via a structured protocol.

Task: <title>
Description: <description>
Due date: <due_date>
Priority: <priority>

Please draft a short acceptance or polite decline response text.
```

## 6. Out of scope

- OpenAI / Groq / ローカル LLM — 将来拡張
- ストリーミング応答 (現在は 1 ショット)
- 多ターンチャット / リファイン
- Tone 調整 / 複数ドラフト候補
- Reader pane インライン draft (今回は compose page 経由のみ)
- 自動サニタイズ層
- MCP Skills との統合 (docs/20 別トラック)
- Auto-generate on inbox render (明示クリックのみ)
- Model 選択 UI (固定: claude-haiku-4-5)
- Usage / cost tracking UI

## 7. Future expansion paths

### 7.1 マルチプロバイダ

`llmProvider` 抽象に OpenAI / Groq を追加、settings で切替。

### 7.2 MCP Skills との統合

docs/20 で提案されている「LLM runtime が message を read する」トラックと共存可能。Phase 4.5 は browser-side draft UI で、MCP Skill は別 process の LLM runtime が API 経由で read する。両者とも E2E 境界を跨がない。

### 7.3 Reader pane インライン draft

compose page 経由ではなく、reader pane 内で inline に draft → edit → send のほうが UX が滑らか。ただし compose の暗号化 pipeline を reader 側に持ち込む必要があり、スコープ大。段階的に。

### 7.4 複数候補 / tone 切替

「丁寧 / カジュアル」「長 / 短」のトグルで複数 draft を生成。ユーザが選ぶ UI。

## 6. Phase 4.6 — Tone toggle + Regenerate (landed 2026-04-25)

ADR 25f 初版 (Phase 4.5) は **1 ショット生成 → 手動編集** のみだった。Phase 4.6 でその上に小さな UX 拡張を載せた:

- **Tone toggle**: `default` / `formal` / `casual` / `brief` / `detailed` の 5 ボタン。クリックで現在の draft を上書きして指定トーンで再生成
- **Regenerate**: 同じトーンでもう 1 回呼ぶ
- ユーザが textarea を編集後 (`bodyEdited === true`) に押すと `window.confirm()` で警告 → OK で再生成 / Cancel で何もしない

実装ポイント:
- `generateReplyDraft` に optional `tone?: DraftTone` を追加。トーン文字列は固定 enum (ユーザ自由入力ではない) なので prompt injection 経路にはならない
- system prompt の末尾にトーン指示を 1 行追記する形 — `BASE_SYSTEM_PROMPT` は不変
- 4 トーン × 各 1 ケース + tone 省略時の base prompt 維持を vitest で確認

範囲外 (引き続き follow-on):
- 編集指示 (refine 入力 chat)
- 複数候補同時生成
- streaming 表示
- tone preference の永続化

## 8. リスクと緩和策

| リスク | 緩和 |
|---|---|
| Prompt injection による悪意ドラフト | ユーザ review (UI banner で警告常時表示) |
| API key 漏洩 | IndexedDB は origin 分離、既存 MVP XSS 境界と同じ |
| Rate limit / quota exceeded | 通常 compose にフォールバック (手書き可能) |
| 幻覚による事実誤認 | ユーザ read + edit |
| CORS issue | Anthropic 公式対応 (`anthropic-dangerous-direct-browser-access`) |
| API key typo | 送信時の 401 エラーで判明、再入力促す |
| 将来プロバイダ切替時 interface 変更 | `llmProvider` 抽象で吸収 |

## 9. 変更された主要ファイル

- `apps/web/lib/llm/llmAuth.ts` (新規)
- `apps/web/lib/llm/anthropicDraft.ts` (新規)
- `apps/web/app/integrations/IntegrationsPanel.tsx` (AI card 追加)
- `apps/web/app/compose/page.tsx` (`?ai=1` ハンドラ)
- `apps/web/lib/i18n/locales/{en,ja}.json` (新 keys)

ドキュメント:
- docs/25 §8 roadmap 更新 (4.5 ✅)
- docs/09 roadmap 更新
- docs/00 index 追加
