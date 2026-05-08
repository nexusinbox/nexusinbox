# ADR 25d: Calendar Freebusy — `auto_accept_if_free` via browser GIS (Phase 4.4d)

**Status**: Accepted (2026-04-25, Phase 4.4d 実装)
**Related**: [docs/25_auto_reply_engine_design.md](./25_auto_reply_engine_design.md)、[docs/25b_auto_reply_evaluator_decision_model.md](./25b_auto_reply_evaluator_decision_model.md)、[docs/25c_auto_reply_executor_mode_b.md](./25c_auto_reply_executor_mode_b.md)、[docs/25c-a_auto_reply_executor_mode_a.md](./25c-a_auto_reply_executor_mode_a.md)、[docs/06_storage_byos.md](./06_storage_byos.md)
**Scope**: **Standard mode (browser) のみ**。Isolated mode (gateway daemon) での Calendar 対応は別 ADR 25d-A で後続。

## 1. Context

Phase 4.4a-c+B で policy DSL、server evaluator、Standard mode / Isolated mode の executor、protocol-aware 再評価が全て landing した。しかし `auto_accept_if_free` action は未だに `calendar_unavailable` に常時フォールバックしており、ユーザが設定しても何も起きない。本フェーズはこの穴を埋める。

**基本アイデア**: 「schedule_negotiation.propose 受信 → 自分の Google カレンダーで空き確認 → 空いていれば最初の空き候補で accept、全部 busy なら queue_for_human」。これで「AI エージェント同士が勝手にミーティングを組んでくれる」という NexusInbox のコア体験が成立する。

## 2. Decision

### 2.1 OAuth は Google Identity Services (browser-only)

既存の Google Drive OAuth は env ベースの単一 credential 方式 (docs/06 §4)。これは admin 運用向けで、**ユーザ個別のカレンダーには使えない** (1 人分のカレンダーしか参照できない)。そこで Calendar は:

| 方式 | 採用 | 理由 |
|---|---|---|
| **GIS (Google Identity Services) implicit flow** | ✅ | Browser 内でのみ token を扱う。Server は見ない → E2E 不変条件と整合。multi-user で自然に動く。追加 DB なし。refresh_token 不要 (implicit flow) |
| Server-side OAuth + refresh_token を DB 暗号化保存 | ❌ | 暗号境界を跨ぎ、server が user の private Calendar access を握る。Isolated mode 対応時に必要になるので、別 ADR (25d-A) で扱う |
| Env 単一 credential (Drive 方式の流用) | ❌ | ユーザ個別のカレンダーを見ないと意味がない |

### 2.2 暗号境界 invariant (強め)

- Server は **`NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID` しか知らない** (public 値、誰でも見られる)
- Access token は browser IndexedDB にのみ存在、expires_at = `Date.now() + expires_in * 1000`
- Refresh token は取得しない (implicit flow)
- 1 時間ごとに silent renewal (hidden iframe、`prompt: "none"`) で更新、失敗したらユーザに「再接続が必要」を表示
- Server の audit event には Calendar 情報 (busy 時刻等) を含めない (client 側の audit のみ)

### 2.3 執行モデル (Standard mode)

```
Evaluator (TS autoReplyClientEvaluator.ts):
  auto_accept_if_free を raw で返す (fallback しない)

Executor (TS autoReplyExecutor.ts):
  final decision が auto_accept_if_free のとき:
    1. getCalendarToken() — 無ければ queue_for_human ("calendar_unavailable")
    2. findFirstFreeCandidate(candidates, token) — freebusy API 呼び出し
    3. free 候補あり → build accept(selected_candidate=free) → 送信 → markAutoReplySent
    4. 全部 busy → 送信せず markAutoReplySent with reason=calendar_all_busy → inbox バッジは "auto_reply_sent" の代わりに policy result を示す
    5. API error → markAutoReplySent with reason=calendar_api_error
```

### 2.4 Freebusy アルゴリズム

```
POST https://www.googleapis.com/calendar/v3/freebusy
body: {
  timeMin: <min(candidate.start)>,
  timeMax: <max(candidate.end)>,
  items: [{ id: "primary" }]
}

isCandidateFree(candidate, busy[]):
  return busy.every(b =>
    !(candidate.start < b.end && b.start < candidate.end)
  )

findFirstFreeCandidate(candidates, busy[]):
  return candidates.find(c => isCandidateFree(c, busy))
```

Overlap 判定は半開区間 (`[start, end)`) として扱う — 候補の end ちょうどで次の busy が始まるケースは free 扱い (一般的な予定間隔の常識と整合)。

### 2.5 Busy 全滅時の挙動

候補が全て busy な場合、2 択:

| 案 | 採用 | 理由 |
|---|---|---|
| `auto_decline` を自動送信 | ❌ | 「断る」という強い意志表示を自動化するのは行き過ぎ。ユーザが「reschedule したい」と思うケースを奪う |
| `queue_for_human` に倒す (reason=`calendar_all_busy`) | ✅ | 「自分の都合がつかない」は human review に渡すのが安全側。ユーザが見てから counter / decline / reschedule を選べる |

### 2.6 Isolated mode (daemon) Calendar の延期

Isolated mode (gateway polling executor) で Calendar 連携するには:
- 個別ユーザの refresh_token を DB 暗号化保存 (Argon2id + XChaCha20)
- Server-side OAuth callback (`/auth/google/callback`)
- Google OAuth app verification (scope が "sensitive" 扱いになる可能性)
- 20-30h 程度の追加作業

本フェーズでは Standard mode のみ対応。Isolated mode 側は引き続き `calendar_unavailable` フォールバック。ユーザが browser を開いていないと `auto_accept_if_free` は動かないが、**Mode C evaluator は default_action 以外 (他の protocol override等) はそのまま動く** ので UX は大きく壊れない。

別 ADR 25d-A で後続。

## 3. Settings UI

`/settings/integrations` ページに 1 枚 card を追加:
- タイトル「Google カレンダー連携」
- 説明「ポリシーで `auto_accept_if_free` を選んだとき、空いている候補のみ自動承諾します」
- 未接続: "Connect" ボタン → `requestCalendarToken()`
- 接続済み: email、scope、expires_at、"Disconnect"
- 失効: バッジ「再接続が必要」

GIS SDK (`https://accounts.google.com/gsi/client`) は Next.js `<Script>` で **このページでのみ lazy load**。他のページには読み込まない (privacy 配慮: ページ訪問で Google に信号を送らない)。

## 4. API / endpoints

**新規なし**。既存の `PATCH /messages/:id/auto-reply-sent` に executor が reason を引き続き送る形で audit に現れる。

Server 側のコード変更も無い。本 ADR はフロントエンド + 2 新 ADR の docs のみ。

## 5. 監査イベント

`mark_auto_reply_sent` の request body に `executor_mode` と並んで `reason` を送れる形 (既存) で、Calendar 固有の理由が audit に記録される:

- `reason: "calendar_unavailable"` (token なし / 失効)
- `reason: "calendar_all_busy"` (候補全滅)
- `reason: "calendar_api_error"` (ネットワーク or 429)
- `reason: "calendar_free"` (free 候補見つけた、accept 送信済)

既存の `auto_reply_sent` audit event の detail にこれらが入るだけ、新イベント不要。

## 6. Feature flag / rollback

- **Soft flag**: `NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID` が未設定なら Settings UI は `disabled`、connect ボタン non-functional。既存 `calendar_unavailable` フォールバックに戻る
- **Hard rollback**: ユーザが Settings で "Disconnect" を押すと IndexedDB の token 削除 → 次回 executor tick から `calendar_unavailable` フォールバック

## 7. Out of scope

- **Isolated mode (daemon) Calendar** — ADR 25d-A
- **Calendar event 書き込み** (accept 時の自動登録) — 今フェーズでは freebusy のみ。Accept 返信が飛ぶだけで、ユーザのカレンダーには何も書き込まれない。これは意図的 (ユーザが return message 確認後に自分でカレンダー登録)
- **Outlook / iCloud / その他の Calendar** — Google のみ。他プロバイダは需要が出てから
- **複数カレンダー** (`items: [{ id: "primary" }, { id: "secondary" }]`) — primary のみ参照
- **Timezone negotiation** — ScheduleCandidate は ISO 8601 with timezone で到着、そのまま RFC 3339 として freebusy に渡す
- **Privacy policy 文書の更新** — 別 task (docs/18 production_bootstrap runbook を更新)

## 8. リスク

1. **Silent renewal の失敗率** — 1 時間毎 refresh、ネットワーク瞬断で失敗しうる。UX: 「再接続してください」表示、fallback は `calendar_unavailable`
2. **XSS による token 漏洩** — IndexedDB も `localStorage` と同じく JS からアクセス可。MVP の既存 XSS defense (CSP + nonce + frame-ancestors) が境界。新 attack surface ではない
3. **Google OAuth app verification** — scope `calendar.freebusy` は "Non-sensitive" で軽い確認のみ。ただし MVP 公開時に consent screen 設定が必要
4. **Popup blocker** — GIS は user gesture から呼ぶので通常は通過。間接呼び出しや delay を避ける
5. **quota** — freebusy 1,000,000 queries/day/project。100 users × 100 msgs/day = 10,000 queries/day で余裕
6. **Timezone mismatch** — 候補が `Asia/Tokyo +09:00`、freebusy response が `UTC` でも overlap 判定は Date.parse 経由で統一、TZ は失われる心配なし

## 9. 4.4e (LLM delegate) のステータス

Phase 4.4e (`delegate_to_llm` で LLM が返信文を生成) は **cancelled**。理由は ADR 25e に詳述。本 ADR は `delegate_to_llm` 値を DSL から削除しない (forward-compat、かつ将来 Phase 4.5 で human-approval 付き draft として復活する可能性)。evaluator は引き続き `llm_unavailable` fallback。

## 10. 将来の ADR

- **ADR 25d-A (Phase 4.4d-A)**: Isolated mode daemon Calendar。Rust freebusy client + 暗号化 refresh_token + server-side OAuth callback
- **ADR (Phase 4.5)**: AI ドラフト生成 + 人間承認 UI。Calendar 連携の拡張として、busy 時に LLM がドラフト decline / counter を書き、ユーザが承認
