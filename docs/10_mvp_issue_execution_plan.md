# 10. MVP Issue実行計画 (DoD付き)

このドキュメントは、MVPを「リポジトリ雛形 → API契約 → 画面骨組み」の順で着手するためのIssue分解です。  
各Issueは `.github/ISSUE_TEMPLATE/mvp-task.md` を使って作成してください。

## 0. 運用ルール (全Issue共通)

- すべての実装はTDDで進める（`RED → GREEN → REFACTOR`）。
- 1 Issue = 1つの振る舞い（または1つの明確な成果物）。
- PRには「失敗テストを先に書いた証跡」を残す。
- マージ条件: `test + lint + build` がグリーン。

## 1. 着手順ロードマップ

1. Track A: リポジトリ雛形
2. Track B: API契約
3. Track C: 画面骨組み
4. Track D: 統合と安定化

## 2. Issue一覧 (優先順)

### A-1 Monorepo初期化
- Title: `[MVP][A-1] Turborepo + pnpm workspace の初期化`
- Scope:
  - `apps/web`, `services/api`, `packages/{core,crypto,ui,storage-adapters}` の雛形作成
  - ルート `package.json`, `pnpm-workspace.yaml`, `turbo.json` の整備
- Dependencies: なし
- DoD:
  - [ ] `pnpm -w install` が成功する
  - [ ] 各workspaceが認識される
  - [ ] 最小 `build/test/lint` タスクが実行可能

### A-2 開発基盤整備
- Title: `[MVP][A-2] Lint/Format/Test 基盤を整備`
- Scope:
  - TypeScript系: ESLint + Prettier + Vitest
  - Rust系: `rustfmt`, `clippy`, `cargo test`
  - Git hooks or CIで基本チェックを実行
- Dependencies: A-1
- DoD:
  - [ ] `pnpm lint` / `pnpm test` が実行できる
  - [ ] `cargo fmt --check` / `cargo clippy -- -D warnings` / `cargo test` が実行できる
  - [ ] サンプル失敗テストを1つ追加し、RED→GREENを確認

### A-3 ローカル実行基盤
- Title: `[MVP][A-3] Docker Compose で PostgreSQL/Redis 起動`
- Scope:
  - `docker-compose.yml` に `postgres`, `redis` を定義
  - ヘルスチェック付き起動確認
- Dependencies: A-1
- DoD:
  - [ ] 1コマンドでDB/Redis起動
  - [ ] ヘルスチェックが通る
  - [ ] 接続確認の統合テストがグリーン

### A-4 環境変数と開発手順
- Title: `[MVP][A-4] .env.example と開発手順の整備`
- Scope:
  - `.env.example` 作成（Web/API共通）
  - ローカル起動手順のREADME追記
- Dependencies: A-1, A-3
- DoD:
  - [ ] 必須環境変数が明文化されている
  - [ ] 新規開発者が手順のみでローカル起動可能

### B-1 OpenAPI初版
- Title: `[MVP][B-1] MVP対象APIの OpenAPI 3.1 契約定義`
- Scope:
  - 対象: `/auth/verify`, `/agents`, `/messages`, `/messages/{id}/content`, `/messages/{id}`, `/ws`
  - 共通エラー・ページング・認証ヘッダ定義
- Dependencies: A-1
- DoD:
  - [ ] OpenAPIファイルがバリデーション通過
  - [ ] MVP必須エンドポイントの入出力型が定義済み
  - [ ] 非機能（認証/主要エラー）が仕様化

### B-2 契約テスト基盤
- Title: `[MVP][B-2] API契約テストを導入`
- Scope:
  - OpenAPI準拠検証のテスト基盤導入
  - CIで契約テストを実行
- Dependencies: B-1
- DoD:
  - [ ] 契約違反時にテストが失敗する
  - [ ] 正常系・異常系で最低1ケースずつ検証
  - [ ] CIで自動実行される

### B-3 Agents API実装
- Title: `[MVP][B-3] GET/POST /agents を契約駆動で実装`
- Scope:
  - エージェント一覧取得、作成
  - DB永続化（`agents` テーブル）
- Dependencies: A-3, B-2
- DoD:
  - [ ] 契約テストがグリーン
  - [ ] 単体/統合テストがグリーン
  - [ ] 入力バリデーションとエラーハンドリング実装済み

### B-4 Messages API実装 (Index中心)
- Title: `[MVP][B-4] POST/GET/PATCH /messages を契約駆動で実装`
- Scope:
  - `message_index` への記録と一覧取得
  - 既読/アーカイブ更新
- Dependencies: A-3, B-2
- DoD:
  - [ ] 送信・一覧・状態更新の契約テストがグリーン
  - [ ] ページング/フィルタが仕様通り
  - [ ] 統合テストでDB状態を検証

### B-5 Auth Verify API実装
- Title: `[MVP][B-5] POST /auth/verify のMVP実装`
- Scope:
  - World ID検証のI/Fを実装（モック検証可）
  - JWT発行
- Dependencies: B-2
- DoD:
  - [ ] 認証成功/失敗の契約テストがグリーン
  - [ ] JWTクレーム最低要件を満たす
  - [ ] セキュリティテスト（期限切れ/改ざん）を追加

### B-6 WebSocket接続仕様の土台
- Title: `[MVP][B-6] /ws 接続と new_message イベント最小実装`
- Scope:
  - JWT認証付きWS接続
  - `new_message` イベント配信の最小経路
- Dependencies: A-3, B-2
- DoD:
  - [ ] 接続/切断/認証失敗のテストがある
  - [ ] `new_message` 受信を統合テストで確認

### C-1 Next.js骨組み
- Title: `[MVP][C-1] Webアプリのルーティング骨組み作成`
- Scope:
  - `/login`, `/`, `/agent/[did]`, `/compose`, `/settings/agents`
  - App Routerでページ雛形を配置
- Dependencies: A-1
- DoD:
  - [ ] 主要ルートに遷移可能
  - [ ] 404/エラーバウンダリの最小対応
  - [ ] ルート単位の描画テストがグリーン

### C-2 共通レイアウト実装
- Title: `[MVP][C-2] Header/Sidebar/List/Detail のレイアウト骨組み`
- Scope:
  - Desktop 3カラム、Tablet/Mobile切り替え
  - プレースホルダデータで表示
- Dependencies: C-1
- DoD:
  - [ ] レスポンシブ切り替えテストがある
  - [ ] キーボード操作の基本導線が通る

### C-3 APIクライアントとQuery設計
- Title: `[MVP][C-3] TanStack Query + APIクライアント層を整備`
- Scope:
  - Query key規約
  - API型とUI型の変換層
- Dependencies: B-1, C-1
- DoD:
  - [ ] API呼び出しをコンポーネントから分離
  - [ ] `GET /agents`, `GET /messages` の取得フックがテスト済み

### C-4 Inbox系コンポーネント実装
- Title: `[MVP][C-4] AgentSwitcher / MessageList / MessageDetail の骨組み`
- Scope:
  - 一覧表示、選択、詳細表示（本文はダミー可）
- Dependencies: C-2, C-3
- DoD:
  - [ ] コンポーネントテストで描画/選択操作を検証
  - [ ] ローディング/エラー表示を実装

### C-5 Compose画面骨組み
- Title: `[MVP][C-5] Composeフォーム実装（送信I/F接続）`
- Scope:
  - 送信先DID、件名、本文、送信ボタン
  - `POST /messages` との接続
- Dependencies: B-4, C-3
- DoD:
  - [ ] フォームバリデーションテストがある
  - [ ] 送信成功/失敗のUI挙動をテスト

### C-6 Agents管理画面骨組み
- Title: `[MVP][C-6] エージェント一覧/作成UI実装`
- Scope:
  - `GET /agents` 一覧
  - `POST /agents` 作成
- Dependencies: B-3, C-3
- DoD:
  - [ ] 一覧表示テストがある
  - [ ] 作成フローの成功/失敗をテスト

### D-1 Web↔API統合
- Title: `[MVP][D-1] モック依存を外し実APIに統合`
- Scope:
  - UIの主要画面を実APIに接続
  - モックと実装の差分を解消
- Dependencies: B-3, B-4, C-4, C-5, C-6
- DoD:
  - [ ] 主要フローが実APIで動作
  - [ ] 契約テスト・統合テスト・UIテストが全グリーン

### D-2 MVP E2Eシナリオ固定
- Title: `[MVP][D-2] E2E: ログイン→受信箱→詳細→作成 の導線を固定`
- Scope:
  - PlaywrightでMVPデモシナリオを自動化
  - CIで定常実行
- Dependencies: D-1
- DoD:
  - [ ] 主要E2Eシナリオが安定実行
  - [ ] flaky対策（待機条件・データ初期化）を実装

### D-3 MVP受け入れチェック
- Title: `[MVP][D-3] MVP完了条件チェックとギャップ整理`
- Scope:
  - ロードマップ記載のMVP完了条件を検証
  - 未達項目を次スプリントIssue化
- Dependencies: D-2
- DoD:
  - [ ] MVP完了条件に対する達成状況を記録
  - [ ] 未達項目のIssue化が完了

## 3. 2週間の実行計画 (提案)

1. Day 1-2: A-1, A-2, A-3
2. Day 3: A-4, B-1
3. Day 4: B-2
4. Day 5-6: B-3
5. Day 7-8: B-4, B-5
6. Day 9: B-6, C-1
7. Day 10: C-2, C-3
8. Day 11: C-4
9. Day 12: C-5, C-6
10. Day 13: D-1
11. Day 14: D-2, D-3

## 4. Issue作成時のコピペ最小セット

- `Summary`: 何を作るか、なぜ必要か
- `Scope`: in/out を明確化
- `Dependencies`: 先行Issue
- `TDD Plan`: RED/GREEN/REFACTOR
- `Test Cases`: Unit/Contract/Integration/E2E
- `DoD`: 完了定義のチェックリスト
- `Verification Commands`: ローカル検証コマンド

