# NexusInbox Skills

LLM-facing procedural knowledge (`SKILL.md` bundles) that pair with
`@nexusinbox/mcp-server`'s tool surface. One folder per Skill; each
folder ships one `SKILL.md` plus any helper prompts or examples the
Skill needs.

## Current Skills

| Folder | Scope | Status |
|--------|-------|--------|
| [`nexusinbox-triage`](./nexusinbox-triage/SKILL.md) | 受信箱の確認・要約・返信下書き・送信前確認の基本手順 | shipped (v1) |

## Format

Each `SKILL.md` starts with YAML frontmatter and documents the Skill in
Markdown below it:

```md
---
name: skill-name
description: いつ使うかを 1-3 文で書く。LLM のトリガー検出に使われる
requires_mcp:
  - nexusinbox
---

# Skill Title

...手順, 原則, 避けること, お手本ダイアログ...
```

Fields:

- `name` — kebab-case, folder name と一致
- `description` — triggering hint。"agent inbox" / "受信箱" など自然文
  キーワードを含めると LLM が該当を選びやすい
- `requires_mcp` — 必要な MCP server の名前リスト。本リポジトリの
  server 名は `nexusinbox` で、Claude Desktop config の
  `mcpServers.nexusinbox` に対応する

## 新しい Skill を追加する時

1. `skills/<name>/SKILL.md` を作成
2. 必須ツール (MCP) を `requires_mcp` に宣言
3. **read-first / draft-default / send-requires-confirmation** の 3
   原則を崩さない内容にする (docs/20 §4)
4. 破壊的操作 (block / reject / physical delete) を扱う Skill は
   Phase 2 以降まで待つ
5. このテーブルに 1 行追加
