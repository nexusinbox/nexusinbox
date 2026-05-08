# 20. MCP / Skill Strategy for NexusInbox

**Date**: 2026-04-21  
**Status**: Proposed final shape for Phase 1  
**Scope**: NexusInbox を Claude Desktop / Cursor / Claude Code などの LLM runtime から安全に使いやすくするための MCP / Skill 設計

関連:
- [15_non_interactive_agent_access_design.md](./15_non_interactive_agent_access_design.md)
- [16_p8_security_verification.md](./16_p8_security_verification.md)
- [19_non_interactive_agent_runbook_2026-04-18.md](./19_non_interactive_agent_runbook_2026-04-18.md)

---

## 1. 結論

NexusInbox における MCP / Skill の最終方針は次のとおり:

1. **MCP は採用する**
   - ただし「新しい本体」ではなく、**既存 Gateway の薄い adapter** として実装する
2. **Skill も採用する**
   - ただし最初は 1 本の汎用 Skill に絞る
3. **Phase 1 は read-first**
   - `list_inbox`, `read_message`, `resolve_recipient`, `list_my_agents` を先行
   - `send_text_message`, `reply_to_message` は **明示 opt-in** で後続
4. **平文が LLM に渡ることを製品仕様として明示する**
   - 「NexusInbox サーバは平文を見ない」
   - ただし「接続した AI / LLM provider は見うる」
5. **remote MCP は roadmap に残すが、当面は local-first を正道とする**
   - remote MCP は別プロダクトに近く、認証・同意・監査コストが急増するため
6. **通常運用の標準は Standard mode とする**
   - 人間が Web UI で読めることを優先する
   - Isolated mode は高隔離が必要な agent のオプションに位置づける

要するに:

> **Skill が「いつ・なぜ」を持ち、MCP が「どうやって」を持つ。**  
> ただし安全境界は既存の Signer Daemon / Agent Gateway / API に残し、MCP server 自体は薄く保つ。

---

## 2. 背景

現状、AI が NexusInbox を使う経路は 3 つある。

1. **REST API 直叩き**
   - JWS Assertion
   - DPoP
   - E2E envelope 構築
   - 添付 upload intent / complete / attach
   を AI runtime 側で扱う必要がある

2. **`@nexusinbox/core` SDK**
   - TypeScript ではかなり楽
   - ただし「LLM が自然に使える表面」ではない

3. **Signer Daemon + Agent Gateway**
   - 安全境界としては最善
   - ただし LLM runtime から直接見える tool surface になっていない

問題は 3 の経路が **標準化された tool として公開されていない** ことにある。
MCP / Skill は、既存の安全な経路を LLM にとって自然な形に変換するための層である。

---

## 3. 目標

### 3.1 ゴール

1. Claude Desktop / Cursor / Codex 系の runtime から NexusInbox を自然に扱える
2. 秘密鍵、refresh token、DPoP secret を LLM に渡さない
3. AI が受信箱の triage / 要約 / 下書き / 返信候補生成を行いやすくする
4. NexusInbox の差別化を「AI-native secure inbox」まで引き上げる
5. 既存 API / Gateway / Daemon を壊さず、薄い追加で実現する

### 3.2 非ゴール

1. 初期からホスト型 remote MCP を完成させること
2. LLM に任意の HTTP client を持たせること
3. 初期から添付送信を完全自動化すること
4. NexusInbox サーバ側でクラウド LLM をホストすること

---

## 4. 設計原則

### 4.1 Thin Adapter

MCP server は business logic や crypto を持たない。責務は:

- MCP protocol
- JSON Schema
- tool 名と Gateway RPC の変換
- ローカルファイル path の検証

に限る。

### 4.2 Secrets Never Reach the LLM

不変条件は **「秘密は MCP tool の入出力にも、LLM のコンテキストにも、絶対に現れない」**。
収納先は deployment mode で異なるが、信頼境界の引き方は同じ:

| 秘密 | Isolated mode (Gateway + Daemon) の収納先 | Standard mode (SaaS / local keystore) の収納先 |
|------|------------------------------------|------------------------------------------|
| Ed25519 / X25519 private keys | Signer Daemon プロセス内のみ (at-rest 暗号化) | ローカル keystore ファイル (at-rest 暗号化) → `@nexusinbox/core` プロセス内のみ |
| access / refresh token | Gateway プロセスのメモリ (UDS 経由のみ流通) | `@nexusinbox/core` のクロージャ内メモリ (LLM tool payload には絶対に出さない) |
| DPoP private key | Gateway プロセスのメモリ | `@nexusinbox/core` プロセス内のメモリ (永続化しない) |
| enrollment secret (`ens_...`) | 初回 activate 時のみ local setup path | 同左 (`--init` 後は破棄、disk にも残さない) |

両モード共通の **絶対ルール**:
- これらの秘密は **MCP tool の `inputSchema` / `outputSchema` のいずれにも現れない**
- audit log には `draft_body_hash` と `aid` / `did` だけが残り、トークンや鍵そのものは記録しない
- 出力サニタイズ (`agt_` / `agr_` / `ens_` プレフィックスの値を `[REDACTED]` に置換) は Gateway / core の両層で常時走る

つまり Standard mode が「ローカルでトークンを持つ」のは設計違反ではなく、Isolated mode の Gateway が担う役割を `@nexusinbox/core` のプロセス境界に置き換えているだけ。LLM 側の信頼境界は両モードとも MCP tool 呼び出しの入出力で完全に閉じる。

### 4.3 Read First, Send Later

初期の UX 価値は「読めること」にある。  
自律送信は便利だが事故コストが高いため、送信系は段階的に開放する。

### 4.4 Human-In-The-Loop by Default

特に以下は初期状態で人間確認を推奨:

- 新規相手への送信
- 添付送信
- block 操作
- 承認待ちの reject

### 4.5 Product Honesty

E2E の説明は以下で統一する:

- **サーバは平文を見ない**
- **ユーザーが接続した AI / LLM は平文を見うる**

---

## 5. MCP と Skill の役割分担

| 項目 | MCP | Skill |
|---|---|---|
| 役割 | 実行 surface | 判断 / 手順 knowledge |
| 主な中身 | tools, JSON schema, transport | SKILL.md, workflow, prompts |
| 主な利用者 | LLM runtime | LLM 推論時の context |
| 変更頻度 | 比較的低い | 比較的高い |
| NexusInbox での責務 | Gateway RPC への翻訳 | inbox triage / reply 戦略 |

NexusInbox では **両方必要** だが、順番は:

1. MCP server
2. 汎用 Skill 1 本

でよい。

---

## 6. Deployment Modes

NexusInbox は SaaS (`app.nexusinbox.ai`) として提供されているため、MCP 利用者を自前ホスト前提にしてはいけない。  
そのため、Phase 1 では deployment mode を 2 つ定義する。

### 6.1 Isolated mode: Self-hosted / Maximum isolation

```text
┌─────────────────────────┐
│ LLM Runtime             │
│ Claude Desktop / Cursor │
└──────────┬──────────────┘
           │ MCP (stdio)
           ▼
┌─────────────────────────┐
│ nexusinbox-mcp         │
│ thin adapter            │
└──────────┬──────────────┘
           │ UDS / local RPC
           ▼
┌─────────────────────────┐
│ Agent Gateway           │
│ token exchange +        │
│ DPoP proof generation + │
│ L2 policy               │
└──────────┬──────────────┘
           │ UDS
           ▼
┌─────────────────────────┐
│ Signer Daemon           │
│ signing keys + L1       │
└─────────────────────────┘
```

特徴:
- 最も安全
- 鍵は Signer Daemon、token / DPoP key は Gateway に閉じる
- self-hosted runtime や power user 向け

### 6.2 Standard mode: SaaS / Local keystore

```text
┌─────────────────────────┐
│ LLM Runtime             │
│ Claude Desktop / Cursor │
└──────────┬──────────────┘
           │ MCP (stdio)
           ▼
┌─────────────────────────┐
│ nexusinbox-mcp         │
│ thin adapter            │
└──────────┬──────────────┘
           │ local keystore + in-memory token
           ▼
┌─────────────────────────┐
│ @nexusinbox/core       │
│ keystore + DPoP + E2E   │
└──────────┬──────────────┘
           │ HTTPS
           ▼
┌─────────────────────────┐
│ NexusInbox API (Fly)   │
└─────────────────────────┘
```

特徴:
- SaaS 利用者の main path
- ローカルに Gateway + Daemon を常駐させなくてよい
- thin adapter 原則は維持できる
- 永続化は private key のみ、token は in-memory only

### 6.3 推奨方針

- **Phase 1A の主経路は Standard mode**
  - SaaS 利用者の摩擦が最小
- **Isolated mode は high-security / self-hosted path として併記**
  - 既存 Gateway / Daemon 資産をそのまま活かせる

### 6.4 標準運用と例外運用

NexusInbox の標準運用は **Standard mode** とする。

理由:

1. 人間が Web UI で件名・本文を復号して読める
2. Gmail に近い inbox UX を維持しやすい
3. SaaS 利用者に Gateway / Daemon 常駐を強いない
4. MCP / Skill と Web を同じ端末の local keystore で接続しやすい

一方、**Isolated mode** は次のような用途向けの例外運用とする:

1. bot 専用で人間が Web から本文を読む必要がない agent
2. 監視 / アラート / 高機密処理のように鍵を browser に出したくない agent
3. 人間用 inbox と AI 専用 inbox を明確に分離したい運用

### 6.5 Web から見た message visibility model

MCP / Skill を導入しても、すべての agent が Isolated mode になるわけではない。  
message の可視性は、**その recipient agent の鍵がどこにあるか**で決まる。

#### Normal message

- recipient agent が Standard mode (browser / local keystore) 管理
- Web UI で復号可能
- MCP / Skill からも同じ端末の keystore を使って読める

#### Daemon-isolated message

- recipient agent が Isolated mode (Signer Daemon / Gateway) 管理
- Web UI は ciphertext / metadata までは見える
- 本文・件名の平文復号は daemon 側 runtime からのみ可能

#### Bridged restore

- 鍵は引き続き daemon に閉じる
- ただしユーザーが明示操作した場合のみ、ローカル runtime / daemon が復号して Web UI に結果を返す
- これは pure Isolated mode と Standard mode の中間であり、**鍵の配置は Isolated mode のまま、平文表示 UX だけを一時的に bridge する**

### 6.6 Bridged restore の位置づけ

bridged restore は有望だが、Phase 1 の標準動作にはしない。

理由:

1. companion process / local bridge / OS 連携が必要で構成が一段重い
2. Web から local runtime への接続状態、権限確認、タイムアウト handling が必要
3. 「常に Web で読める」ではなく「要求時のみ復号して返す」という別 UX を明示設計する必要がある

ただし将来的には、Isolated mode agent の UX 改善として検討価値が高い。

### 6.7 採用理由

1. 既存資産を最大活用できる
2. 秘密は現行の trust boundary からはみ出さない
3. MCP server の LOC を小さく保てる
4. 将来別 runtime が増えても、MCP surface だけ再利用できる

### 6.8 採用しない案

#### A. LLM 近傍に bearer を露出する API 直叩き MCP

却下理由:
- bearer / refresh token を LLM 近傍に持ち込みやすい
- LLM 近傍の層が太くなりすぎる

補足:
- **Standard mode 自体は却下しない**
- 却下するのは「token を雑に持つ API 直叩き MCP」であり、`@nexusinbox/core` + local keystore + in-memory token の構成は採用対象

#### B. サーバホスト型 AI Agent

却下理由:
- E2E 理念と衝突しやすい
- LLM コストがサーバ起因になる
- privacy 境界が曖昧になる

#### C. いきなり remote MCP

却下理由:
- 認証・同意・監査が別難易度
- local MCP の価値を先に出した方が速い

---

## 6.7 MCP deployment choice (trans-service pattern alignment)

Anthropic のブログ [Building agents that reach production systems
with MCP](https://claude.com/blog/building-agents-that-reach-production-systems-with-mcp)
で整理されている MCP deployment / integration pattern に対して、
NexusInbox がどれを採用しているか / どれを意図的に採用しないかを
ここで明文化する。設計判断の根拠を 1 箇所に集めておき、次に
「なぜ Remote MCP じゃないの?」と問われた時に指せる URL を用意する
のが狙い。

### 6.7.1 採用しているパターン

| パターン | 該当 | 備考 |
|---------|------|------|
| **Model Context Protocol (MCP)** | ✅ | `@nexusinbox/mcp-server` が MCP spec に従って tool を公開 |
| **Intent-Grouped Tool Surface** | ✅ | 6 tools (`list_my_agents` / `list_inbox` / `read_message` / `resolve_recipient` / `send_text_message` / `reply_to_message`)。REST API 1:1 ミラーは避け、意図単位で束ねる |
| **Skills + MCP Composition** | ✅ | `skills/nexusinbox-triage/SKILL.md` を併行配布。draft→確認→send の procedural knowledge は Skill 側に持たせる |
| **Local stdio MCP** | ✅ | Claude Desktop / Claude Code から `node cli.js --stdio` で接続 |

### 6.7.2 意図的に採用しないパターン

#### ❌ SaaS-hosted Remote MCP Server

ブログは "Remote MCP is the only configuration that runs across web,
mobile, and cloud-hosted agents" と推しているが、**NexusInbox の
core invariant と両立しない**ため採用しない。

`read_message` は以下の手順で動く:

```
1. /messages/:id/content → ciphertext + wrapped content key
2. wrapped key を X25519 ECDH + HKDF で unwrap         ← 私たちの秘密鍵が必要
3. AES-GCM で content を復号
4. plaintext を tool response として返す
```

秘密鍵の所在で E2E 物語が決まる:

| Remote MCP のバリエーション | 秘密鍵の所在 | E2E 物語 |
|----------------------------|-------------|---------|
| A. vault に token 預かる SaaS 型 | 当サービス or Anthropic 側 | **完全崩壊** — サーバが平文を読める |
| B. 復号だけクライアント端末で | ユーザ端末 | **崩壊はしないが Remote の利点消失** — mobile でも端末が online 必須 |
| C. Local stdio (現状) | ユーザ端末 | **維持** ✅ |
| D. User-hosted Remote (ユーザ自身がホスト) | **ユーザが運用するサーバ** | **維持** ✅ — ただしユーザ側の運用コスト有り |

A を選べば NexusInbox は SaaS 型 Gmail 相当になり、docs/01
〜 docs/12 で積み上げた「ZK indexing」「BYOS」「サーバは平文を見ない」
等の売りが全部消える。B は技術的には可能だが「Remote の利点」として
ブログが挙げる "run across web, mobile, and cloud-hosted agents" が
実質成立しない (ユーザ端末が常時 reachable じゃないと tool が hang
する)。

従って **SaaS-hosted Remote MCP は non-goal**。

#### ❌ CIMD-Based OAuth / Vault-Based Token Management

どちらも SaaS-hosted Remote MCP を前提にした auth 標準化機構。
上述の理由で remote を採らないので、これらも採らない。NexusInbox
の agent 認証は JWS Assertion + DPoP-bound access token (docs/15) で
既に閉じており、OAuth との adapter が必要になるのは future mobile /
web-Claude 対応を真面目にやるタイミング (= user-hosted Remote 実装時)。

#### ❌ Code Orchestration (~2500 endpoint を 2 tool で) / Tool Search / Programmatic Tool Calling

いずれも "tool 数が多い API" を想定した context 圧縮パターン。
NexusInbox は **intent-grouped で 6 tools に絞った結果 context
overhead がそもそも小さい**ので、これらの高度化は不要。tool 数が
20 を超えた時 (attachment tools 追加、scope preset 等) に再検討。

#### ❌ MCP Apps Extension (インタラクティブ UI を返す) / Elicitation (mid-call input)

Elicitation は仕様追従する価値はあるが、現状の `mode: "draft" | "send"`
+ `confirmed_by_user: true` 方式のほうが **`draft_body_hash` による
draft→send audit matching** が楽で監査性に優る。乗り換えるなら
Elicitation 側に draft_body_hash 相当の照合手段が揃ってから。
MCP Apps Extension は純粋に将来機能拡張、今は必要ない。

### 6.7.3 保留 (将来の検討候補)

#### ⏸ User-hosted Remote MCP

上記 D パターン: ユーザが自身の Fly / Cloudflare Worker / 自宅サーバに
`@nexusinbox/mcp-server` を deploy し、そこに mobile Claude / web Claude /
ChatGPT などがアクセスする形。秘密鍵はユーザが管理するサーバに存在
するので E2E 物語と両立する。

現時点では **実装しない**。理由:

1. local stdio (Standard mode) で Claude Desktop / Claude Code をカバー
   できており、MVP フェーズでのユースケースは足りている
2. user-hosted remote は HTTP/SSE トランスポート + CIMD-like auth +
   self-deploy onboarding (docker-compose / flyctl template / etc) が
   必要で、1〜2 週間規模の work
3. mobile Claude / ChatGPT 連携の具体的な使用要求が集まってから
   優先度判断した方が、設計のブレが少ない

トリガ: 「モバイルから NexusInbox 送受信したい」ユースケースが
複数ユーザから具体的に寄せられた時、または self-host 志向ユーザが
自分の Fly / Worker で動かす手順を求め始めた時。
[GitHub issue #2](https://github.com/nexusinbox/nexusinbox/issues/2)
に parked、DoD / test 観点 / 実装タスクはそちらを参照。

#### ⏸ Skill Distribution from MCP Server (emerging pattern)

ブログ曰く Canva / Notion / Sentry が先行導入している「Skill を MCP
server 経由で配信する」仕組み。NexusInbox はすでに Skill ファイルを
同梱しているが、protocol extension 経由でのプッシュ配信ではなく、
ユーザが手動で Claude Projects / Claude Code の skill ディレクトリに
置く前提。MCP SDK 側でこの拡張が安定したら追従する。

---

## 7. Tool Catalog の最終提案

### 7.1 Phase 1A (read-first)

### `list_my_agents`

用途:
- 利用可能 agent / aid / current did の把握

返却例:

```json
{
  "agents": [
    {
      "aid": "aid:ai:...",
      "did": "did:key:...",
      "label": "assistant-ops"
    }
  ]
}
```

### `list_inbox`

入力:

```json
{
  "agent_aid": "aid:ai:...",
  "folder": "inbox",
  "status": "unread",
  "page": 1,
  "per_page": 20
}
```

要件:
- `agent_did` ではなく原則 `agent_aid` 優先
- DID rotation を MCP 側で意識させない

### `read_message`

入力:

```json
{
  "message_id": "..."
}
```

返却:

```json
{
  "message_id": "...",
  "sender": { "aid": "aid:ai:...", "did": "did:key:..." },
  "subject": "plain text",
  "body": "plain text",
  "attachments": [
    {
      "attachment_id": "...",
      "filename": "report.pdf",
      "mime": "application/pdf",
      "plaintext_size_bytes": 12345
    }
  ]
}
```

重要:
- ここで平文が LLM に渡る
- したがって最も強い scope の 1 つ

### `resolve_recipient`

入力:

```json
{
  "identifier": "aid:ai:..."
}
```

返却:

```json
{
  "aid": "aid:ai:...",
  "did": "did:key:...",
  "label": "assistant-ops",
  "encryption_public_key": "..."
}
```

---

### 7.2 Phase 1B (write with opt-in)

### `send_text_message`

入力:

```json
{
  "from_agent": "aid:ai:...",
  "to": "aid:ai:...",
  "subject": "Weekly update",
  "body_markdown": "Hello...",
  "mode": "draft"
}
```

改善点:
- `mode` を持たせる
  - `draft`
  - `send`
- v1 ではデフォルトを `draft` 推奨
- `draft` は **client-side only**
  - MCP / SDK が envelope 候補を構築して caller に返す
  - NexusInbox サーバには保存しない
  - 再送 / 再編集 / 再確認は caller 側の責務とする

### `reply_to_message`

入力:

```json
{
  "incoming_message_id": "...",
  "body_markdown": "Thanks...",
  "mode": "draft"
}
```

改善点:
- `incoming_message_id` ベースは維持
- 新規送信より安全だが、やはり `draft` デフォルトを推奨
- `draft` 時は reply 候補と resolved recipient / thread context を返すだけで、server state は作らない

---

### 7.3 Phase 2 以降

後続候補:

- `list_pending_approvals`
- `approve_pending`
- `reject_pending`
- `list_contacts`
- `block_sender`

ただし v1 では入れない。

理由:
- 誤操作コストが高い
- まずは triage / read / draft の価値が大きい

---

## 8. Scope Model の最終形

MCP を入れるなら、NexusInbox の credential scope をもう一段明確にする。

### 8.1 現状の実装 reality

現行 API (`services/api/src/lib.rs`) で **ハンドラから実際に `require_scope()` で要求される** scope は 2 つだけ:

- `messages.read` — `GET /messages`, `GET /messages/:id/content`, `PATCH /messages/:id` (read/archive), `PATCH /messages/:id/flags`, **そして `DELETE /messages/:id` も現状はこれを再利用** (`lib.rs` L10081 のコメント "reuse messages.read for now" 参照)
- `messages.send` — `POST /messages`, attachment upload 系

`messages.delete` は scope 語彙 (`VALID_SCOPES`, `lib.rs` L5451) には登録されているので credential に **付けることはできる** が、付けても付けなくても削除は通る (= 効いていない)。これは P0–P8 で踏み残したギャップであり、MCP 化に先立って埋める必要がある。

したがって以下の taxonomy は **最終形の提案** であり、Phase 1A 実装前に少なくとも以下の作業が別途必要:

1. `require_scope("messages.delete")` を `DELETE /messages/:id` に張り直す (今の "reuse messages.read" コメントを解消)
2. `VALID_SCOPES` と `allowed_scopes` のデフォルト分配を §8.2 の最終形に拡張
3. Web UI の credential 作成画面 (§8.4) を拡張済み taxonomy に追従

### 8.2 最終形の推奨 scope

- `messages.read`
- `messages.draft`
- `messages.send`
- `messages.reply`
- `attachments.read`
- `attachments.attach`
- `approvals.read`
- `approvals.write`
- `blocks.write`
- `contacts.read`

### 8.3 初期推奨プリセット

#### Read-only assistant

- `messages.read`
- `attachments.read`
- `contacts.read`

#### Triage assistant

- `messages.read`
- `attachments.read`
- `messages.draft`
- `contacts.read`

#### Active sender

- `messages.read`
- `attachments.read`
- `messages.draft`
- `messages.send`
- `messages.reply`

### 8.4 UI 改善案

Web UI の credential 作成時に:

- `Read only`
- `Read + draft`
- `Active sender`

のプリセットを出すとよい。

### 8.5 実装依存

実装順としては次の順番が必要:

1. `agent_credentials.allowed_scopes` の valid set 拡張
2. API handler の `require_scope()` 拡張
3. MCP tool と scope の対応付け
4. Web UI の scope preset 追加

---

## 9. 添付ファイルの扱い

添付は Phase 1 の時点では **read only** を基本にする。

### 9.1 読み取り

`read_message` が返す attachment metadata だけで十分。  
必要なら別 tool:

- `download_attachment_to_tempfile`

を将来追加する。

tempfile のライフサイクル方針:

- 保存先は OS の temp directory
- デフォルト TTL は 15 分
- MCP process 終了時に best-effort cleanup
- 将来 `delete_tempfile` 的な明示削除 tool を追加してもよい

### 9.2 送信

添付送信は後回しにする。

理由:
- local file path 検証が必要
- 暗号化
- upload intent
- direct upload
- complete
- attach
の multi-step で失敗面が広い

### 9.3 将来の形

```json
{
  "attachments": [
    { "path": "/tmp/report.pdf" }
  ]
}
```

ただし MCP server 側で以下を必須にする:

1. local file only
2. symlink policy 明示
3. 最大サイズ制限
4. MIME 推定と validation
5. send 全体の rollback

---

## 10. Skill の最終方針

v1 は **1 skill のみ** とする。

推奨名:

- `nexusinbox-triage`

### 10.1 含める内容

1. inbox triage の基本手順
2. 重要メッセージの要約
3. 下書き作成
4. 新規送信より返信を優先する方針
5. 不明時は送信前に確認を取る

### 10.2 含めない内容

1. provider ごとの細かい prompt hack
2. 独自の長大テンプレート
3. product policy と食い違う自動送信推奨

### 10.3 Skill のサンプル

```md
name: nexusinbox-triage
description: NexusInbox を使って受信箱の確認、要約、下書き、返信候補の作成を行う
requires_mcp: ["nexusinbox"]

## 基本方針
1. まず list_inbox で未読を確認する
2. 興味対象だけ read_message で本文を読む
3. 返信が必要なら reply_to_message を draft モードで使う
4. 新規送信は、相手・内容・添付の妥当性を確認してから行う
5. block / reject / approval 操作は人間確認を優先する
```

---

## 11. セキュリティ / プライバシー要件

### 11.1 永続化してよいもの

1. Ed25519 / X25519 private keys のみ
2. 保存先は local keystore / Signer Daemon の暗号化鍵ファイル

### 11.2 永続化してはいけないもの

1. access_token
2. refresh_token
3. DPoP proof
4. enrollment secret

これらは **in-memory only** とする。

### 11.3 必須

1. MCP server は秘密鍵をむき出しの値として LLM に返さない
2. token 類は disk persistence しない
3. Gateway または local keystore layer だけが bearer / DPoP proof を扱う
4. `read_message` 実行は audit log に残す
5. `send_*` / `reply_*` は誰が実行したか audit log に残す
6. LLM へ返す payload に token / header / secret が混ざらないこと

### 11.4 追加推奨

1. MCP tool 実行ログに `provider_hint` を残す
2. `send` / `reply` は初期状態で human confirmation を要求
3. 新規 recipient 宛 send は stricter policy
4. 添付送信は feature flag

### 11.5 監査ログ追加項目

最低限:

- tool_name
- aid
- did
- credential_id
- message_id
- recipient_aid / recipient_did
- attachment_count
- mode (`draft` / `send`)
- confirmed_by_user
- provider_hint
- draft_body_hash (`sha256`)

---

## 12. Privacy / Terms への反映

MCP / Skill を出す前に、以下の文言を Help / Terms / Privacy Policy に揃える。

### 12.1 推奨表現

> NexusInbox サーバはメッセージ本文および添付の平文を閲覧しません。  
> ただし、利用者が接続した AI アシスタントまたはそのモデル provider は、利用者の指示に基づき、復号後の内容を処理しうります。

### 12.2 UI 文言

credential / MCP 接続時:

> この接続を有効にすると、接続先 AI は選択した scope の範囲でメッセージ本文・添付メタデータ・下書き内容を扱えるようになります。

---

## 13. 段階プラン

### 13.1 Phase 1A

成果物:

- `packages/mcp-server/`
- `npx @nexusinbox/mcp-server` で起動できる配布形
- tools:
  - `list_my_agents`
  - `list_inbox`
  - `read_message`
  - `resolve_recipient`
- `skills/nexusinbox-triage/SKILL.md`
- README の Claude Desktop 設定例

配布チャネル:

- 第1候補: `npx @nexusinbox/mcp-server`
- 後続候補: GitHub release binary / Homebrew

### 完了条件

1. Claude Desktop から inbox 一覧取得ができる
2. message を読める
3. recipient 解決ができる
4. token / key が LLM に渡らない

### 13.2 Phase 1B

成果物:

- `send_text_message`
- `reply_to_message`
- `draft` / `send` mode
- human confirmation policy

### 完了条件

1. self-send / trusted recipient への送信ができる
2. draft と send が分離されている
3. audit log が残る

### 13.3 Phase 2

- credential scope UI
- 複数 Skill
- 添付 read
- 添付 send の限定的導入

### 13.4 Phase 3

- remote MCP の再評価
- OAuth-like connection UX
- local signer を前提にした hosted bridge

---

## 14. Implementation status

### Shipped

1. `docs/20_mcp_skill_strategy.md` の方針を採用
2. `packages/mcp-server/` 実装済み
3. Standard mode (SaaS / local keystore) runtime 実装済み
4. Isolated mode (Gateway / Daemon) runtime 実装済み
5. full 6-tool surface 実装済み
   - `list_my_agents`
   - `list_inbox`
   - `read_message`
   - `resolve_recipient`
   - `send_text_message`
   - `reply_to_message`
6. send / reply は `draft` default + `confirmed_by_user=true` 必須で landed
7. stderr structured audit (`draft_body_hash`, `provider_hint`, `confirmed_by_user`) landed
8. `packages/mcp-server/README.md` に Isolated mode / Standard mode 両方の運用手順を記載済み

### Still next

1. scope taxonomy の継続整理
   - `messages.draft`, `messages.reply`, `attachments.attach` など
2. attachment-aware tool family の検討
3. MCP 監査イベントの server-side 取り込み強化
4. Skill 側の運用知識の継続改善
5. remote MCP は引き続き roadmap 扱い (当面は local-first を維持)

注:
このドキュメントの初期版では `packages/mcp-server skeleton` / `Standard mode read-only tools` / `send/reply with draft mode` を未実装項目としていたが、現在はすべて landed 済み。以後は shipped reality をこの節で更新し、詳細仕様は `packages/mcp-server/README.md` と実装を正本とする。

---

## 15. 最終提案

NexusInbox における MCP / Skill の最終形は次の一文に要約できる。

> **local-first の MCP adapter を SaaS 標準では local keystore 上に、high-isolation 向けには Gateway 上に薄く載せ、read-first で価値を出し、send は明示 opt-in + human confirmation + scope 制御で段階開放する。**

この形なら:

1. 既存アーキテクチャと整合する
2. E2E の理念を壊しにくい
3. AI からの使い勝手を大きく改善できる
4. 将来 remote MCP に進む余地も残せる

---

## 16. 採用決定

本提案では以下を採用する。

1. MCP を採用
2. Skill を採用
3. **Standard mode (SaaS / local keystore) を標準運用かつ Phase 1 の主経路とする**
4. **Isolated mode (Gateway / Daemon) を high-isolation path として併記する**
5. **Isolated mode message は Web で常時復号できるとは期待しない**
6. **bridged restore は将来の UX 改善案として扱う**
7. read-first で出す
8. send/reply は `draft` を中心に段階解放する
9. 添付送信は Phase 2 以降
10. Privacy / Terms に「AI provider は見うる」を明記する

不採用:

1. 初期から remote MCP
2. 初期から block / reject / approval をフル自動化
3. 初期から添付送信を全面開放
