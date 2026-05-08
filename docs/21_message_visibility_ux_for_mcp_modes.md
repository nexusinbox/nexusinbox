# 21. Message Visibility UX for MCP Modes

**Date**: 2026-04-22  
**Status**: Proposed  
**Scope**: NexusInbox において、Standard mode の通常メッセージ、Isolated mode の daemon-isolated message、将来の bridged restore をどう見せ分けるかの画面単位 UX 設計

関連:
- [08_ui_ux.md](./08_ui_ux.md)
- [15_non_interactive_agent_access_design.md](./15_non_interactive_agent_access_design.md)
- [20_mcp_skill_strategy.md](./20_mcp_skill_strategy.md)

---

## 1. 結論

NexusInbox の UX は次の 3 種類のメッセージ可視性を明示的に扱う。

1. **通常メッセージ**
   - browser / local keystore で復号できる
   - 現在の inbox UX の標準
2. **daemon-isolated message**
   - 鍵は daemon / runtime にのみ存在し、Web UI では平文復号できない
   - pure Isolated mode の正しい挙動
3. **bridged restore**
   - 鍵は daemon に置いたまま、ユーザーが明示操作したときだけ local runtime が平文を Web に返す
   - 将来の改善案

重要なのは、**「復号中」と「この端末では復号できない」を UI 上で明確に分けること**。

---

## 2. 背景

Isolated mode agent に対して MCP + Skill を使うと、Claude Code / Claude Desktop / Cursor 側では message を読めても、Web UI では同じ message を復号できないことがある。

これは不具合ではなく、鍵配置の結果である:

- Standard mode: browser 側 keystore に復号鍵あり
- Isolated mode: daemon / runtime 側にのみ復号鍵あり

したがって Web UI は、復号不能を loading のまま見せるのではなく、**鍵の所在に基づく状態**として表示しなければならない。

---

## 3. UX 原則

### 3.1 Standard First

標準 UX は通常メッセージを中心に設計する。  
Isolated mode は高隔離オプションであり、標準 inbox 体験を壊す前提にはしない。

### 3.2 State, Not Mystery

ユーザーに「なぜ読めないのか」を説明する。  
`復号中` の無限表示は禁止。

### 3.3 No Fake Transparency

Web で読めない message を、読めるふりで見せない。  
復号不能なら、復号不能であることと理由を明示する。

### 3.4 Recovery Path Matters

読めない場合でも「次に何をすればよいか」を必ず示す:

1. Claude Code / runtime で開く
2. message id をコピーする
3. 将来は bridged restore を使う

---

## 4. Visibility State Model

message detail の復号状態は少なくとも次の 4 状態に分ける。

### 4.1 `decrypting`

- envelope 取得済み
- local keystore / daemon bridge から復号結果待ち
- 一時状態

### 4.2 `readable`

- この端末で復号済み
- 件名 / 本文 / 添付 metadata を表示

### 4.3 `unavailable_on_this_device`

- この端末には該当鍵がない
- pure Isolated mode message
- Web UI では継続待機せず説明 UI に遷移

### 4.4 `decrypt_failed`

- 鍵はあるはずだが unwrap / decrypt に失敗
- データ破損、古い ciphertext、互換性不整合の可能性

---

## 5. Message Type Definition

### 5.1 通常メッセージ

条件:

- browser / local keystore に必要鍵がある
- Web UI で復号できる

期待 UX:

- 現在の Gmail-like 3 カラム UI のまま
- 件名プレビュー、本文、添付一覧を表示

### 5.2 daemon-isolated message

条件:

- recipient agent が Isolated mode 管理
- ブラウザに必要鍵がない
- runtime / daemon からは読める

期待 UX:

- メッセージ行には「daemon-isolated」バッジ
- 詳細画面では本文 placeholder ではなく explanatory card を出す

### 5.3 bridged restore

条件:

- daemon-isolated message
- local runtime / bridge が起動している
- ユーザーが明示的に restore を要求した

期待 UX:

- `復元して表示` ボタンを出す
- 実行時に local bridge 経由で復号依頼
- 成功時だけ平文を一時表示

---

## 6. 画面単位の設計

### 6.1 Inbox List (`/`, `/agent/[did]`)

#### 通常メッセージ

- 件名プレビューを通常表示
- 本文 preview も表示
- 特別なバッジ不要

#### daemon-isolated message

- 件名 preview は表示しない
- 代わりに以下を表示:
  - `Daemon-isolated`
  - `本文は runtime 側で確認`
- sender / timestamp / folder / unread などの metadata は通常どおり表示

推奨表示:

```text
[Daemon-isolated]  assistant-ops
本文は Claude Code / runtime 側で確認
```

#### bridged restore 対応後

- list 上では復元ボタンは出さない
- row click で detail に誘導
- detail でのみ復元アクションを許可

### 6.2 Message Detail (`/agent/[did]/message/[id]` 相当)

#### 通常メッセージ

- 件名 / 本文 / 添付 metadata を通常表示

#### daemon-isolated message

- 件名欄:
  - `この端末では復号できません`
- 本文欄:
  - 説明カードを表示

推奨文言:

> このメッセージは daemon-isolated agent 宛です。  
> 復号鍵はこのブラウザには保存されていないため、本文は Claude Code などの runtime 側からのみ確認できます。

CTA:

1. `Message ID をコピー`
2. `Agent ID をコピー`
3. `Runtime で確認する` ヘルプ導線

禁止事項:

- `復号中` の無限表示
- 空欄だけ表示
- generic error だけ出して終える

#### bridged restore 対応後

追加 CTA:

- `復元して表示`

押下時の状態:

1. `runtime に接続しています`
2. `復号を要求しています`
3. 成功: 一時平文表示
4. 失敗: bridge 未起動 / 権限拒否 / timeout の明示

### 6.3 Compose / Reply (`/compose`)

compose 時点で送信先 agent の mode がわかるなら、以下を表示する。

#### recipient が通常メッセージになる場合

- 現行 UX のまま

#### recipient が daemon-isolated agent の場合

- 送信前ヒントを表示:

> この送信先は daemon-isolated agent です。  
> 返信本文は Web UI ではなく runtime 側から確認される可能性があります。

目的:

- 人間が「なぜ相手の Web で読めないのか」を理解しやすくする

### 6.4 Agent Settings (`/settings/agents`)

agent ごとに visibility mode を表示する。

#### 表示項目

- `Standard (Web + Runtime)`
- `Daemon-isolated`
- 将来: `Daemon-isolated + Bridged restore`

#### 説明文

`Standard`
- この端末の Web UI と runtime の両方で本文を読めます

`Daemon-isolated`
- 復号鍵は daemon / runtime 側だけにあります
- Web UI では plaintext を直接表示できません

`Daemon-isolated + Bridged restore`
- 鍵は daemon に残したまま、要求時だけ Web UI に平文を返します

#### 重要

agent 作成時のデフォルトは `Standard` とする。  
`Daemon-isolated` は advanced option に置く。

### 6.5 Help / SDK / Templates

MCP / SDK ドキュメントで次を明記する。

1. MCP は Isolated mode / Standard mode の両方で動く
2. pure Isolated mode では Web で読めない message がある
3. その場合は runtime 側で読む
4. 将来 bridged restore を提供する可能性がある

---

## 7. Interaction Design for Bridged Restore

bridged restore は将来案だが、UI 契約を先に定義しておく。

### 7.1 基本フロー

1. ユーザーが daemon-isolated message を開く
2. Web UI が `復元して表示` ボタンを見せる
3. クリック時に local bridge への接続を試みる
4. bridge が local runtime / daemon に復号依頼
5. 平文を Web UI に一時返却
6. 画面離脱または TTL 経過で平文を破棄

### 7.2 前提条件

- ユーザー自身のローカル環境に runtime / bridge がある
- bridge はローカルホストまたは OS-level IPC に限定
- サーバは plaintext を保持しない

### 7.3 セキュリティ方針

1. 復元は明示操作のみ
2. 自動 restore はしない
3. bridge は origin / session / local user の整合確認を行う
4. 平文は server round-trip で保存しない
5. UI には `一時表示` であることを明示する

---

## 8. 実装優先順位

### Phase 1

1. `decrypting` と `unavailable_on_this_device` を分離
2. daemon-isolated バッジ追加
3. detail の explanatory card 追加
4. message / agent id copy action 追加
5. Help に運用説明を追加

### Phase 2

1. agent settings に mode 表示
2. compose の送信先 mode ヒント
3. runtime 側確認導線の改善

### Phase 3

1. bridged restore の technical design
2. local bridge companion 実装
3. temporary plaintext 表示 UX

---

## 9. 最終提案

NexusInbox の message visibility UX は次の原則で整理する。

1. **標準は通常メッセージ**
2. **daemon-isolated message は「読めないこと」を正しく説明する**
3. **bridged restore は将来の利便性改善として別設計で導入する**

一文で言うと:

> **Web は「読める message を快適に読み、読めない message には正しい理由と次の行動を示す」。Isolated mode の制約を loading でごまかさない。**
