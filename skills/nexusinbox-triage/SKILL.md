---
name: nexusinbox-triage
description: NexusInbox の受信箱を確認・要約・返信する時に使う。"agent inbox" / "受信箱" / "メッセージを整理" / "返信を下書き" のような指示で triggered。MCP server "nexusinbox" が接続されていることが前提。
requires_mcp:
  - nexusinbox
---

# NexusInbox Triage

NexusInbox に接続された MCP server を使って、受信箱を読み取り、要約し、
必要に応じて返信を下書き → 人間の確認のあと実送信する手順をまとめた
Skill。**read-first / draft-default / send requires confirmation** の 3
原則で動く。

## 前提

ユーザーの環境で `@nexusinbox/mcp-server` が起動しており、以下のツールが
MCP 越しに見えていること:

| Tool | 役割 | リスク |
|------|------|--------|
| `list_my_agents` | 使えるエージェントを列挙 | low |
| `list_inbox` | `agent_aid` の受信箱を一覧 | low |
| `read_message` | subject / body を復号して返す | medium (平文) |
| `resolve_recipient` | `aid` / `did` → 現在の did / 暗号化公開鍵 | low |
| `send_text_message` | `mode: "draft" | "send"` | high |
| `reply_to_message` | 返信。`mode: "draft" | "send"` | high |

`send_text_message` / `reply_to_message` を `mode: "send"` で呼ぶ場合は
**必ず `confirmed_by_user: true`** を付ける。ユーザーの明示的な「送信して
いいです」という返答の後でのみ true を入れること。事前許可は無効。

## 基本フロー

### 1. 読む

ユーザーが「受信箱チェック」系の指示を出した時:

1. `list_my_agents` で自分の `aid` を確認 (通常 1 件)。
2. `list_inbox({ agent_aid, folder: "inbox", status: "unread" })` で
   未読だけ引く。長くなりそうなら `folder: "inbox", status: "all"` で
   最新 50 件を取るのも可。
3. 各メッセージの subject は `list_inbox` では暗号文。件名を知るには
   `read_message` を呼ぶ必要がある。全件 read_message は避け、
   **上位数件に絞る** (sender / created_at / folder で triage)。
4. 読んだ内容は会話内で要約して返す。**平文をそのまま長文で貼らない** —
   ユーザーが既に本文を見ている前提で、差し支えある個人情報・固有名詞を
   そのまま引用するのは避け、必要な粒度で要約する。

### 2. 下書く

「返信の下書きを作って」系の指示:

1. 対象 message_id を特定 (ユーザーが指定するか、直近リストから選ぶ)。
2. `reply_to_message({ incoming_message_id, body_markdown, mode: "draft" })`
   を呼ぶ。`provider_hint` には自分の provider/model 識別子を入れる
   (例: `"claude-sonnet-4.5"` / `"cursor-inline"`)。
3. 返ってきた envelope (`recipient_aid`, `subject`, `body_markdown`,
   `draft_body_hash`) をユーザーに提示。
4. 件名は auto-prefill で `Re: <元件名>` になる。変えたければ
   `subject` フィールドで override する。

### 3. 送る (人間確認が先)

ユーザーが draft を見て「送信して」と明示的に言った時のみ:

1. **直前の draft と同じ body_markdown** を使う。内容をこっそり書き
   換えない。改行・空白レベルで一致させる (draft_body_hash が一致すれば
   audit 上リンクできる)。
2. `reply_to_message({ ..., mode: "send", confirmed_by_user: true })`
   を呼ぶ。
3. 結果の `message_id` をユーザーに伝える。

ユーザーが「内容修正して」と言った場合は **送らずに draft を作り直す**。
新しい draft_body_hash が発行される。

## やっていいこと / 避けること

### やっていい

- 未読の triage (カテゴリ分け・要約・優先度づけ)
- 返信の下書き作成
- 件名の提案
- 対話的に文面を推敲する (何度でも draft 可)
- 新規メッセージの下書き (`send_text_message` mode: "draft")

### 避ける

- **mode: "send" を勝手に付ける** — 必ずユーザーの "送信してよい" を聞く
- **内容を変更して send** — draft と bodyが違う状態で confirmed=true は
  ポリシー違反 (audit の draft_body_hash が合わなくなる)
- **block / reject / approval 系の破壊的操作** — これらの tool は
  そもそも Phase 1 では公開されていない。ユーザーが要求した場合は
  「現時点では MCP から操作できないため、Web UI で実施してください」と
  案内する
- **大量の read_message** — N 件未読で N 回 read_message を回すと
  LLM コンテキストも埋まるので、要約のため上位数件に限定する
- **subject / body に機密情報を長文で貼る** — 復号後の平文は LLM が
  処理できるが、会話に copy-paste する必要はない。要約や引用で済ます

## エラーパターン対応

| 症状 | 原因 | 対応 |
|------|------|------|
| `recipient not found (404)` | aid → 旧 did を送ってしまった、またはユーザーが削除 | aid で resolve し直す。aid も無効なら「相手が存在しない」と報告 |
| `confirmed_by_user=true` 要求エラー | send を draft 工程なしで呼んだ | draft を先に作り、ユーザーに確認、then mode:"send" + confirmed_by_user:true |
| `decryption failed` 混在 | 送信時の鍵と受信側鍵がズレた (稀) | read_message のレスポンスにはそのまま placeholder が入る。ユーザーに「一部復号できないメッセージがあります」と伝える |
| `Phase 1A で mode=send 不可` | 旧版サーバー (1B 未適用) | 該当 tool は draft のみで応答。ユーザーに「この MCP server は send 未対応」と伝える |

## 返信フローのお手本 (1 ラリー)

```
User: 昨日の alice からのメッセージに「明日13時なら大丈夫です」と返信して

[LLM] list_inbox({ agent_aid, folder: "inbox" })
      → 候補メッセージを特定 (alice 送信、昨日 created_at)

[LLM] read_message({ message_id: "m-ABC" })
      → subject / body を復号し、何の件か内部で把握

[LLM] reply_to_message({
        incoming_message_id: "m-ABC",
        body_markdown: "明日13時なら大丈夫です。",
        mode: "draft",
        provider_hint: "claude-sonnet-4.5"
      })
      → draft envelope を受け取る (draft_body_hash = "abc123...")

LLM → User:
  alice さん宛に「明日13時なら大丈夫です。」という返信を
  下書きました。件名は "Re: 打ち合わせ日程" になります。
  送信していいですか？

User: OK 送って

[LLM] reply_to_message({
        incoming_message_id: "m-ABC",
        body_markdown: "明日13時なら大丈夫です。",   ← 完全一致
        mode: "send",
        confirmed_by_user: true,
        provider_hint: "claude-sonnet-4.5"
      })
      → { mode: "send", message_id: "m-NEW", status: "delivered",
          draft_body_hash: "abc123..." }  ← 同じハッシュ

LLM → User:
  送信しました (message_id: m-NEW)
```

このパターンで draft → 確認 → send を回せば、audit 側で draft と実送信が
`draft_body_hash` でリンクされ、「ユーザーはこの文面に confirm した」が
事後追跡できる。

## 関連ドキュメント

- `docs/20_mcp_skill_strategy.md` — 上流の設計判断 (read-first /
  draft-default / provider_hint 等)
- `packages/mcp-server/README.md` — tool 仕様、起動手順、監査ログ形式
- NexusInbox Help (Web UI) — AID / DID / BYOS 等の製品用語
