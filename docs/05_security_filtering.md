# 05. セキュリティ・フィルタリング設計書

## 1. 階層型ブロックシステム

### 1.1 ブロックレベル詳細

```
L1: DID Block
  ├── 粒度: 特定のエージェント（DID）単位
  ├── 効果: そのDIDからの受信を拒否
  ├── 相手の別DIDからは連絡可能
  └── 応答: 202 Accepted（送信者には正常送信に見せる）

L2: Identity Ban
  ├── 粒度: World ID単位
  ├── 効果: 対象World IDに紐づく全DIDからの受信を拒否
  ├── DIDを新規作成しても回避不可
  └── 応答: 404 Not Found（受信者は存在しないと返答）

L3: Network Stealth
  ├── 粒度: World ID単位
  ├── 効果: L2に加え、DID Resolverにも非公開化
  ├── 対象者からはエンドポイント自体が見えない
  └── 応答: DNS/DID Resolution段階で存在しないと返答
```

### 1.2 ブロック判定フロー

```
受信メッセージ
  │
  ├─ sender_did → blocksテーブル (L1) 照合
  │   └─ Hit → 202返却 & 破棄
  │
  ├─ sender_did → agentsテーブル → user_id → world_id_hash取得
  │   └─ blocksテーブル (L2/L3) 照合
  │       └─ Hit → 404返却 & 破棄 (ストレージに一切書き込まない)
  │
  └─ Pass → Trust Score評価へ
```

### 1.3 ブラックボックス通知

受信者がブロックされた場合の送信者への通知:
- **L1**: 送信成功に見える（サイレントドロップ）
- **L2**: `404 Not Found` → 送信者のUIに「送信先が見つかりません」表示
- **L3**: DID Resolution失敗 → 送信者のUIに「このエージェントは存在しません」表示

送信者が自身のブロック状態を確認できるAPI:
```
GET /v1/status/reachability?target_did={did}
→ { "reachable": false, "reason": "not_found" }
```
※理由は一律 "not_found" とし、ブロックレベルの詳細は開示しない

## 2. Trust Score

### 2.1 スコア算出式

```
Trust Score = w1 * age_score
            + w2 * verification_score
            + w3 * report_penalty
            + w4 * block_penalty
            + w5 * activity_score

where:
  age_score         = min(account_age_days / 365, 1.0)       # 最大1年で満点
  verification_score = { device: 0.3, orb: 0.7, orb_recent: 1.0 }
  report_penalty    = max(0, 1.0 - report_count * 0.1)       # 通報10件で0
  block_penalty     = max(0, 1.0 - block_count * 0.05)       # ブロック20件で0
  activity_score    = 正常な通信の成功率

weights:
  w1 = 0.15, w2 = 0.30, w3 = 0.25, w4 = 0.20, w5 = 0.10
```

### 2.2 スコアに基づくアクション

| スコア範囲 | 分類 | アクション |
|-----------|------|-----------|
| 0.8 - 1.0 | Trusted | 即時配信、AIの自律返信可 |
| 0.5 - 0.8 | Normal | 通常配信 |
| 0.3 - 0.5 | Cautious | AI一次フィルタ適用、低優先フォルダへ |
| 0.0 - 0.3 | Untrusted | 「承認待ち」キュー、レート制限強化 |

### 2.3 Trust Scoreの更新トリガー

| イベント | スコア変動 |
|---------|-----------|
| ユーザーがブロック | -0.05 per block |
| コミュニティ通報 | -0.10 per report |
| 通報が誤報と判明 | +0.05 recovery |
| Orb再認証 | +0.15 |
| 正常な通信30日継続 | +0.02 |
| スパム判定 | -0.20 |

## 3. AIフィルタリング

### 3.1 スパム判定パイプライン

```
Layer 1: ルールベース（高速）
  ├── 既知のスパムパターンマッチ（正規表現）
  ├── 送信頻度の異常検知
  ├── 大量一斉送信の検知
  └── 判定: spam / not_spam / uncertain

Layer 2: LLM分析（uncertainの場合のみ）
  ├── メッセージ内容の意図分析
  ├── 送信コンテキストの評価
  └── 判定: spam / legitimate / low_priority
```

### 3.2 AIカテゴリ分類

```python
categories = {
    "urgent":      "即座の対応が必要",
    "actionable":  "アクションが必要だが緊急ではない",
    "informational": "情報共有のみ",
    "social":      "挨拶・雑談",
    "low_priority": "優先度低（ニュースレター等）",
    "background":  "バックグラウンドフォルダへ自動集約",
}
```

### 3.3 AI要約フィルタ設定

```json
{
  "ai_filter": {
    "enabled": true,
    "auto_categorize": true,
    "background_threshold": "low_priority",
    "auto_archive_after_days": 30,
    "summarize_long_threads": true,
    "max_summary_length": 200
  }
}
```

## 4. 共有ブラックリスト (Community Defense)

### 4.1 仕組み

```
1. ユーザーAが World ID X を通報
2. ユーザーBも World ID X を通報
3. 通報が閾値（5件/30日）を超える
4. Community Trust Scoreに反映（全ユーザーの算出に影響）
5. 閾値（20件/30日）を超える → Community Block候補リストに追加
6. モデレーターレビュー → 確定時、全ユーザーに警告通知
```

### 4.2 プライバシー保護

- 通報者の身元は他ユーザーに公開しない
- 通報内容（証拠メッセージ）はハッシュのみ共有、本文は共有しない
- 共有ブラックリストへの参加はユーザーがopt-in（デフォルトOFF）

### 4.3 異議申立て

```
1. ブロック対象者が異議申立てリクエスト
2. 自動レビュー: Orb再認証 + 通報の整合性チェック
3. 人間モデレーターによる最終判断
4. 解除時: Trust Scoreを0.5にリセット（完全回復はしない）
```

## 5. Selective Ingestion（ストレージ保護）

ブロック済み送信者からのメッセージは:
- BYOSに一切書き込まない
- message_indexにも記録しない
- APIコスト・ストレージコストともにゼロ
- サーバログにはブロック統計のみ記録（個別メッセージ内容は記録しない）
