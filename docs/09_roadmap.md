# 09. 実装ロードマップ

## フェーズ概要

```
Phase 1: MVP (Core)          ──── 基本的なメッセージング + World ID認証
Phase 2: Security & Filter   ──── 階層型ブロック + Trust Score + AIフィルタ
Phase 3: BYOS拡張            ──── IPFS/S3対応 + Auto-Purge + ストレージ移行
Phase 4: A2A Protocol        ──── エージェント間プロトコル + 自律応答
Phase 5: Community           ──── 共有ブラックリスト + ネットワーク防御
```

---

## Phase 1: MVP (Core)

### 目標
World ID認証でログインし、DIDベースのエージェントでメッセージを送受信できる最小構成。

### 実装項目

| # | タスク | 技術 | 依存 |
|---|--------|------|------|
| 1.1 | プロジェクト初期化 (monorepo構成) | Turborepo + pnpm | - |
| 1.2 | World ID認証統合 | IDKit SDK + Axum | - |
| 1.3 | ユーザー・エージェントDB | PostgreSQL + SQLx | 1.1 |
| 1.4 | DID生成・管理 | Ed25519/X25519 (ring) | 1.2 |
| 1.5 | E2E暗号化メッセージ送受信 | X25519 ECDH + HKDF-SHA256 + AES-GCM-256 (Web Crypto) | 1.4 |
| 1.6 | ローカルストレージAdapter | Tauri FS API | 1.1 |
| 1.7 | Google Drive Adapter | Google Drive API v3 | 1.1 |
| 1.8 | message_index (ZK Indexing) | PostgreSQL | 1.5 |
| 1.9 | WebSocket通知 | Axum WS + Redis PubSub | 1.5 |
| 1.10 | Web UI: ログイン画面 | Next.js + IDKit | 1.2 |
| 1.11 | Web UI: ダッシュボード + 受信箱 | Next.js + TanStack Query | 1.8 |
| 1.12 | Web UI: メッセージ作成・返信 | Next.js | 1.5 |
| 1.13 | Web UI: エージェント管理 | Next.js | 1.4 |

### MVP完了条件
- [ ] World IDでログインできる
- [ ] エージェント（DID）を作成できる
- [ ] メッセージをE2E暗号化して送受信できる
- [ ] Google Drive or ローカルにメッセージが保存される
- [ ] 複数エージェントの受信箱を切り替えて閲覧できる
- [ ] 統合ビュー（All Inboxes）で全エージェントのメッセージを一覧できる

---

## Phase 2: Security & Filter

### 実装項目

| # | タスク | 依存 |
|---|--------|------|
| 2.1 | L1 DID Blockの実装 | Phase 1 |
| 2.2 | L2 Identity Ban（World ID逆引き + 遮断） | Phase 1 |
| 2.3 | L3 Network Stealth（DID Resolution遮断） | 2.2 |
| 2.4 | Trust Score算出エンジン | Phase 1 |
| 2.5 | スパム判定 Layer 1（ルールベース） | 2.4 |
| 2.6 | スパム判定 Layer 2（LLM分析） ※リリース後送り | 2.5 |
| 2.7 | AIカテゴリ分類 + 優先度自動設定 | 2.6 |
| 2.8 | Proof of Personhood Gate | Phase 1 |
| 2.9 | 「承認待ち」キュー + UI | 2.4 |
| 2.10 | ブロック管理UI | 2.1-2.3 |
| 2.11 | Selective Ingestion（ブロック時ストレージ保護） | 2.1-2.3 |

---

### 2.6 Layer 2 LLM スパム判定 — ポストリリース改善案 (deferred)

Phase 1 では `apply_layer2_spam_filter` をスタブとして残し、リリース後の改善項目として扱う。

**Why deferred**:
- メッセージ本文は E2E 暗号化されているため、サーバ側 Layer 2 では sender DID パターン / 頻度 / envelope サイズなど **メタデータしか参照できない**。Layer 1 (deny-list + burst detection) でカバー可能な範囲とほぼ重複し、ROI が低い。
- 真の本文ベース判定はクライアント (Web/Desktop) で復号後に行う方が筋がよい。

**実装する場合の推奨構成**:
- マイクロサービス: `services/filter/` (Python + FastAPI)
- LLM プロバイダ: **Groq Llama 3.1 8B** が第一候補 (≈$0.00003/件、200ms 以下、14.4k RPM 無料枠)
- プライバシー最重視なら local llama.cpp を同梱
- API 側フックは `services/api/src/lib.rs` の `apply_layer2_spam_filter` (FUTURE IMPROVEMENT ブロック参照)
- 環境変数 `AGENT_INBOX_FILTER_SERVICE_URL` でゲート、1〜2 秒のハードタイムアウト + fail-open

**コスト試算 (Groq Llama 8B)**:
| 月間メッセージ数 | LLM 判定数 (~5%) | 月額 |
|---|---|---|
| 100 万通 | 5 万 | ~$1.50 |
| 1,000 万通 | 50 万 | ~$15 |

Issue tag: `future/layer2-llm-filter`

---

## Phase 3: BYOS拡張

### 実装項目

| # | タスク | 依存 |
|---|--------|------|
| 3.1 | IPFS Storage Adapter | Phase 1 |
| 3.2 | S3互換 Storage Adapter | Phase 1 |
| 3.3 | Auto-Purge Policy Engine | Phase 2 |
| 3.4 | ストレージ移行機能 | Phase 1 |
| 3.5 | ストレージ使用量ダッシュボード | Phase 1 |
| 3.6 | クライアント側全文検索 | Phase 1 |

---

## Phase 4: A2A Protocol

### 実装項目

| # | タスク | 依存 |
|---|--------|------|
| 4.1 | エージェント間プロトコル基盤 | Phase 1 |
| 4.2 | schedule_negotiation プロトコル | 4.1 |
| 4.3 | task_delegation プロトコル | 4.1 |
| 4.4 | 自律応答エンジン (auto-reply) — ADR は [docs/25](./25_auto_reply_engine_design.md) | 4.1 |
| 4.4a | Policy DSL + DB + CRUD API (本項目の最小足場) | 4.2 / 4.3 |
| 4.4b | Evaluator (Mode C = server metadata-only、decision の DB persist、inbox バッジ) — ADR は [docs/25b](./25b_auto_reply_evaluator_decision_model.md) | 4.4a |
| 4.4c (Standard mode) | Browser executor + 3 層 loop prevention + client protocol evaluator — ADR は [docs/25c](./25c_auto_reply_executor_mode_b.md) | 4.4b |
| 4.4c+ (Isolated mode) | Agent Gateway polling executor + Rust protocol-aware evaluator (非対話型 agent 向け) — ADR は [docs/25c-A](./25c-a_auto_reply_executor_mode_a.md) | 4.4c (Standard mode) |
| 4.4d | Google Calendar 連携 (`auto_accept_if_free`、Standard mode / browser GIS) — ADR は [docs/25d](./25d_calendar_freebusy_auto_accept.md) | 4.4c |
| 4.4d-A | Isolated mode Calendar (gateway daemon 側 server-side OAuth) | 4.4d, 4.4c+ |
| ~~4.4e~~ | ~~LLM 応答生成 (`delegate_to_llm`)~~ → [docs/25e](./25e_llm_delegate_cancelled.md) で **cancelled** | — |
| **4.5** | AI ドラフト + 人間承認 UI (BYOK Anthropic、browser から直接 `api.anthropic.com`) — ADR は [docs/25f](./25f_ai_draft_human_approval.md) | 4.4e (cancelled) |
| **4.6** | Tone toggle + Regenerate (5 トーン × 再生成) — ADR は [docs/25f §6](./25f_ai_draft_human_approval.md) | 4.5 |
| **4.7** | Inbox 検索 + folder/status filter + URL 同期 (件名 + 送信者の client 側 fuzzy match、`?q=&folder=&status=`) | 4.5 |
| 4.6 | トーン変更・編集UI | 4.5 |

---

## Phase 5: Community

### 実装項目

| # | タスク | 依存 |
|---|--------|------|
| 5.1 | コミュニティ通報機能 | Phase 2 |
| 5.2 | 共有ブラックリスト集計 | 5.1 |
| 5.3 | 異議申立てフロー | 5.2 |
| 5.4 | Community Trust Score反映 | 5.2 |
| 5.5 | Desktop App (Tauri) | Phase 1 |
| 5.6 | Mobile PWA最適化 | Phase 1 |

---

## プロジェクト構成 (Monorepo)

```
nexusinbox/
├── apps/
│   ├── web/                  # Next.js Web App
│   ├── desktop/              # Tauri Desktop App
│   └── docs/                 # ドキュメントサイト
├── packages/
│   ├── core/                 # 共有型定義・ユーティリティ
│   ├── crypto/               # E2E暗号化ライブラリ
│   ├── storage-adapters/     # BYOS Adapter群
│   └── ui/                   # 共有UIコンポーネント
├── services/
│   ├── api/                  # Rust (Axum) メインAPI
│   ├── filter/               # Python (FastAPI) AIフィルタ
│   └── resolver/             # DID Resolver
├── docs/                     # 設計ドキュメント
├── docker-compose.yml
├── turbo.json
└── package.json
```

## 技術的リスクと対策

| リスク | 影響度 | 対策 |
|--------|-------|------|
| World ID SDK の breaking change | 高 | SDK バージョン固定 + 移行テスト |
| E2E暗号化によるサーバ側検索不能 | 中 | クライアント側検索 + ZK Indexing |
| BYOS遅延（Google Drive API制限） | 中 | ローカルキャッシュ + バッチ取得 |
| Trust Score のゲーム化 | 中 | 複数シグナルの組み合わせ + 定期見直し |
| ストレージコスト増大 | 低 | Auto-Purge + ユーザー通知 |
