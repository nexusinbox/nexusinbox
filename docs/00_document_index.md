# NexusInbox - 実装ドキュメント一覧

## ドキュメント構成

| # | ドキュメント | 概要 |
|---|------------|------|
| 01 | [アーキテクチャ設計書](./01_architecture.md) | システム全体構成、技術スタック選定、コンポーネント図 |
| 02 | [データモデル設計書](./02_data_model.md) | DB スキーマ、暗号化戦略、Zero-Knowledge Indexing |
| 03 | [認証・ID設計書](./03_identity_auth.md) | World ID統合、DID発行・管理、鍵管理 |
| 04 | [通信プロトコル設計書](./04_messaging_protocol.md) | メッセージ送受信フロー、エージェント間プロトコル、暗号化 |
| 05 | [セキュリティ・フィルタリング設計書](./05_security_filtering.md) | 階層型ブロック、Trust Score、スパム判定 |
| 06 | [ストレージ設計書 (BYOS)](./06_storage_byos.md) | Google Drive / IPFS / ローカル統合、Auto-Purge |
| 07 | [API設計書](./07_api_design.md) | REST / WebSocket API エンドポイント一覧 |
| 08 | [UI/UX設計書](./08_ui_ux.md) | 画面一覧、エージェント・マトリクス、ワイヤーフレーム |
| 09 | [実装ロードマップ](./09_roadmap.md) | フェーズ分割、MVP定義、マイルストーン |
| 10 | [MVP Issue実行計画](./10_mvp_issue_execution_plan.md) | Issueテンプレート準拠の実装計画とDoD |
| 11 | [MVP受け入れチェック (2026-04-11)](./11_mvp_acceptance_check_2026-04-11.md) | MVP完了条件の達成判定と次スプリントIssue案 |
| 12 | [セキュリティレビュー (2026-04-11)](./12_security_review_2026-04-11.md) | 現進捗の脆弱性レビュー、修正優先度、DoD |
| 13 | [Private運用とOSS公開準備ガイド](./13_private_ops_and_oss_release_checklist.md) | Secrets/Variables登録手順と公開前チェックリスト |
| 14 | [ログイン/セッション運用Runbook (2026-04-11)](./14_login_session_runbook_2026-04-11.md) | World ID認証後の遷移・cookie定着を含む運用手順と障害対応 |
| 15 | [Non-interactive Agent Access設計](./15_non_interactive_agent_access_design.md) | Signer Daemon / Agent Gateway / DPoP sender-constrained token の設計 |
| 16 | [Agent Identifier ADR](./16_adr_agent_identifier.md) | `aid` 導入理由、`did:key` ローテーション方針、識別子設計の決定記録 |
| 16 | [P8 セキュリティ検証レポート](./16_p8_security_verification.md) | DPoP / enrollment proof 修正内容、残存リスク、DB integration test 実行手順（docker-compose + 実コマンド例付き） |
| 17 | [添付ファイルアップロード仕様書 (R2)](./17_attachment_upload_r2_spec.md) | presigned URL、upload intent、R2 direct upload/download、GC、監査ログを含む本番仕様 |
| 18 | [本番初期セットアップガイド (2026-04-18)](./18_production_bootstrap_2026-04-18.md) | Vercel / Supabase / Fly.io / R2 前提の初期セットアップ手順、環境変数整理表、無料/最小課金スタート案 |
| 18a | [本番セットアップ Runbook](./18_production_bootstrap_runbook.md) | Dockerfile / fly.toml / vercel.json が揃った前提の実行チェックリスト、secrets 登録コマンド、疎通確認手順、切り戻し |
| 19 | [Non-interactive Agent 実行 Runbook (2026-04-18)](./19_non_interactive_agent_runbook_2026-04-18.md) | signer-daemon / agent-gateway の起動、自己宛フローテスト、API 直接送信テストの手順 |
| 20 | [MCP / Skill Strategy](./20_mcp_skill_strategy.md) | NexusInbox を MCP / Skill で AI runtime へ開くための最終方針、tool catalog、scope、privacy、段階プラン |
| 21 | [Message Visibility UX for MCP Modes](./21_message_visibility_ux_for_mcp_modes.md) | 通常メッセージ、daemon-isolated message、bridged restore を Web UI 上でどう見せ分けるかの画面単位設計 |
| 22 | [Bridged Restore Design](./22_bridged_restore_design.md) | Daemon-isolated message を Web UI で一時復号するアーキテクチャ (ADR)。Option 比較、脅威モデル、Phase 3a/b/c のロールアウト計画 |
| 23 | [Signer Daemon 上位鍵管理ポリシー](./23_key_management_policy.md) | at-rest baseline (Argon2id + XChaCha20) の採用根拠、OS keychain / TPM / KMS / HSM への移行閾値、再評価トリガー |
| 24 | [A2A Protocol v1 (Phase 4.1 + schedule_negotiation)](./24_a2a_protocol_design.md) | エージェント間構造化通信の v=1 仕様。`application/vnd.nexusinbox.a2a+json; v=1` MIME、propose / accept / decline / counter、context binding、compatibility matrix |
| 25 | [Auto-reply Engine (Phase 4.4)](./25_auto_reply_engine_design.md) | 受信 A2A メッセージに対する自動応答ポリシー DSL。Phase 4.4a-e のロードマップ、declarative DSL、ETag/If-Match 楽観ロック、loop 防止、監査イベント |
| 25b | [Auto-reply Evaluator Decision Model (Phase 4.4b)](./25b_auto_reply_evaluator_decision_model.md) | Isolated mode (daemon) / B (browser) / C (server metadata-only) の比較と Mode C 採用。evaluator の pure contract、送信経路への hook、audit event `auto_reply_evaluated`、feature flag `AGENT_INBOX_AUTO_REPLY_EVALUATOR` |
| 25c | [Auto-reply Executor — Standard mode (Phase 4.4c)](./25c_auto_reply_executor_mode_b.md) | Browser-side executor。3 層 loop prevention (`auto_reply_origin` metadata / `auto_reply_sent_at` DB flag / client soft cap)、protocol-aware client evaluator、server + client decision の merge rule、`PATCH /messages/:id/auto-reply-sent`、監査 `auto_reply_sent` / `auto_reply_skipped_incoming_is_auto_reply` |
| 25c-A | [Auto-reply Executor — Isolated mode (Phase 4.4c+)](./25c-a_auto_reply_executor_mode_a.md) | Agent Gateway 配置の polling executor。daemon に `wrap_content_key` RPC 追加、`GET /messages?auto_reply_pending=1` クエリ、`executor_mode: "daemon_protocol_v1"` audit 区別、`AGENT_INBOX_MODE_A_EXECUTOR` feature flag。非対話型 agent 向け |
| 25d | [Calendar Freebusy `auto_accept_if_free` (Phase 4.4d)](./25d_calendar_freebusy_auto_accept.md) | Google Identity Services (ブラウザ側) + Calendar freebusy API で空き確認。`NEXT_PUBLIC_GOOGLE_OAUTH_CLIENT_ID`、IndexedDB に token 保存、server は token を見ない。busy 全滅時は queue_for_human にフォールバック。Isolated mode (daemon) は 25d-A 予定 |
| 25e | [`delegate_to_llm` — Cancelled (Phase 4.4e)](./25e_llm_delegate_cancelled.md) | LLM auto-send は E2E 暗号破壊・prompt injection・幻覚コミットメントリスクで cancel。`delegate_to_llm` 値は DSL から削除せず forward-compat で残す。代替は Phase 4.5 (AI ドラフト + 人間承認) |
| 25f | [AI Draft + Human Approval (Phase 4.5)](./25f_ai_draft_human_approval.md) | BYOK Anthropic で browser から直接 `api.anthropic.com` を叩き、受信メッセージのドラフト返信を生成。ユーザが review/編集して送信。E2E 境界維持、auto-send なし、API キーは IndexedDB のみ |
| 26 | [Rename: Agent Inbox → NexusInbox](./26_rename_agent_inbox_to_nexusinbox.md) | ブランド・コード・security primitive 一斉リネームの履歴と operator migration ガイド。`AGENT_INBOX_*` env var prefix・Postgres role は意図的に保持 |
| 27 | [Local Dev → Production 反映フロー](./27_local_dev_workflow.md) | 日常運用手順を 1 箇所に固定。3 ターミナル起動・コミット前チェック・本番 deploy の経路 (Vercel / Fly) 判別表・rollback 手順 |

## 前提ドキュメント
- サービス仕様書 v1.1（本プロジェクトの出発点）
