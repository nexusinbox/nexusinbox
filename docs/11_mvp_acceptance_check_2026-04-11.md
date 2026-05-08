# 11. MVP受け入れチェック (2026-04-11)

このドキュメントは `docs/09_roadmap.md` の「MVP完了条件」に対する、2026-04-11 時点の達成状況です。  
判定は `達成 / 部分達成 / 未達` の3段階で記録します。

## 1. 判定サマリ

| MVP完了条件 | 判定 | 根拠 | ギャップ |
|---|---|---|---|
| World IDでログインできる | 部分達成 | `/auth/verify` は実装済み。`/login` はUI骨組みと導線のみ。 | Web側でIDKit連携と本番検証フロー未実装。 |
| エージェント（DID）を作成できる | 達成 | `POST /agents` 実装済み。`/settings/agents` から作成可能。 | 入力値/鍵管理の厳密バリデーションは強化余地あり。 |
| メッセージをE2E暗号化して送受信できる | 部分達成 | `POST /messages`, `GET /messages`, `GET /messages/{id}/content`, `PATCH /messages/{id}` 実装済み。UI送受信導線あり。 | 現状は `enc:*` ダミー文字列。真正な暗号処理（X25519 + XChaCha20-Poly1305）未実装。 |
| Google Drive or ローカルにメッセージが保存される | 未達 | `storage_ref` は `byos://...` 形式で保持。 | BYOS Adapter（Local FS / Google Drive）と実保存処理未実装。 |
| 複数エージェントの受信箱を切り替えて閲覧できる | 達成 | `/agent/[did]` が API 接続済み。 | エージェント切替UIのUX改善余地はあり。 |
| 統合ビュー（All Inboxes）で全エージェントのメッセージを一覧できる | 達成 | `/` で `agent_did=all` を利用し一覧取得。 | 高度検索・並び替えは今後拡張。 |

## 2. D-2 (E2E固定) の確認

- 対象シナリオ: `ログイン -> 受信箱 -> 詳細 -> 作成`
- 自動化: `apps/web/e2e/mvp-flow.spec.ts`
- 実行コマンド: `pnpm --filter @nexusinbox/web test:e2e`
- 2026-04-11 実行結果: `1 passed`

## 3. 検証コマンド (2026-04-11 時点)

```bash
pnpm --filter @nexusinbox/web lint
pnpm --filter @nexusinbox/web test
pnpm --filter @nexusinbox/web test:e2e
pnpm --filter @nexusinbox/web build
pnpm contract:check
cargo test -q --manifest-path services/api/Cargo.toml
```

## 4. 次スプリントIssue案 (未達項目のIssue化)

### NS-1 World ID実装統合
- Title: `[MVP][NS-1] /login に IDKit 実連携を実装`
- Scope:
  - Web で World ID proof を取得
  - `/auth/verify` へ接続してトークン確立
  - エラー/キャンセル時のUI制御
- DoD:
  - E2Eで `World ID検証成功 -> トークン保持` を確認
  - 失敗時のハンドリングがUIに反映

### NS-2 E2E暗号の実装
- Title: `[MVP][NS-2] メッセージ暗号化を実装 (X25519 + XChaCha20-Poly1305)`
- Scope:
  - `packages/crypto` に暗号化/復号ユーティリティ実装
  - `/compose` 送信前に暗号化、受信時に復号
  - 鍵管理（最低限の安全な保管）
- DoD:
  - 暗号ラウンドトリップの単体テスト
  - UIの送受信で平文がAPI層へ流れないことを確認

### NS-3 BYOS Local FS Adapter
- Title: `[MVP][NS-3] Local FS Adapterで本文保存を実実装`
- Scope:
  - `storage_ref` の実保存先を Local FS へ接続
  - `GET /messages/{id}/content` で読み出し可能にする
- DoD:
  - 保存/取得の統合テストがグリーン
  - 再起動後も取得可能

### NS-4 BYOS Google Drive Adapter
- Title: `[MVP][NS-4] Google Drive Adapter実装`
- Scope:
  - Drive API接続、ファイル保存・読み出し
  - Local FS と切替可能にする
- DoD:
  - Adapter切替テストが通る
  - 実ファイル保存の疎通確認

### NS-5 受け入れ最終化
- Title: `[MVP][NS-5] MVP完了条件を100%達成し受け入れ完了`
- Scope:
  - NS-1〜4 完了後に再チェック
  - 受け入れ判定を更新
- DoD:
  - `docs/09_roadmap.md` のMVP完了条件が全て達成
  - D-2 E2Eと契約テストが継続的に成功
