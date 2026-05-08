# ADR-16: エージェント識別子の方式決定

**Status**: Accepted
**Date**: 2026-04-16
**Deciders**: @mizumoto
**関連**: `docs/03_identity_auth.md`, `docs/15_non_interactive_agent_access_design.md` (v2 §3)

---

## 1. コンテキスト

NexusInbox では、各エージェントに `did:key:z6Mk...` を発番している。`did:key` は Ed25519 公開鍵から決定論的に導出されるため、**鍵を変えると DID も変わる**。これにより:

- 鍵漏洩時のローテで全連絡先が切れる
- Signer Daemon の鍵ストア移行で DID が変わる
- 長期運用での鍵更新ができない

非対話型エージェントアクセス (docs/15) を実装するにあたり、鍵ローテを可能にする安定識別子が必要。

## 2. 意思決定の前提

プロジェクトの現在地と方針:

| 観点 | 状況 |
|---|---|
| フェーズ | MVP。World ID + did で AI エージェントのメッセージングが成立するか市場検証 |
| 他サービスとの DID 相互運用 | **今は不要**。まずこの仕組みが受け入れられるか確認してから |
| 運用形態 | 個人開発。ランニングコストを抑えたい |
| OSS 化 | 視野に入れている。外部の優秀なエンジニアが参加しやすい構造が望ましい |
| 識別子の寿命 | NexusInbox サービスの寿命に依存して OK。10 年不変を前提としない |

## 3. 選択肢

### Option A: Logical Agent ID (`aid:ai:...`)

NexusInbox 独自の安定 ID (ULID ベース)。内部テーブルで `did:key` 履歴にマップ。

| | |
|---|---|
| 実装コスト | 低。追加テーブル + API レスポンスに `aid` フィールド追加 |
| 外部依存 | なし (DNS / TLS / ホスティング不要) |
| 鍵ローテ | `agent_identity_keys` に新行を追加するだけ |
| 相互運用 | NexusInbox 内のみ。外部からは解決不能 |
| ランニングコスト | 追加なし |
| OSS フレンドリー | フォーク・自前デプロイですぐ動く |

### Option B: `did:web`

W3C 標準。`did:web:agentinbox.ai:u:01HX...` → HTTPS で DID Document を配信。

| | |
|---|---|
| 実装コスト | 中〜高。DID Document エンドポイント、キャッシュ、検証ライブラリ |
| 外部依存 | ドメイン + TLS + 常時稼働 HTTPS エンドポイント |
| 鍵ローテ | DID Document 更新で対応 |
| 相互運用 | W3C 標準。外部 DID-aware サービスから resolve 可 |
| ランニングコスト | DID Document ホスティング層の追加。ドメイン維持が必須 |
| OSS フレンドリー | フォークした人が独自ドメインを用意する必要あり |

### Option C: `did:key` のまま (ローテ不可)

鍵漏洩時は新 DID を作って連絡先を再構築。

| | |
|---|---|
| 実装コスト | ゼロ (現状維持) |
| 鍵ローテ | 不可能。漏洩 = DID 破棄 = 全連絡先喪失 |
| 相互運用 | did:key は広く認知されている |
| ランニングコスト | なし |
| OSS フレンドリー | 最もシンプル |

### Option D: ハイブリッド (A をベースに、将来 B を拡張点として追加)

`aid:ai:...` を canonical とし、`agent_identity_keys` に `external_did TEXT NULL` を予約。将来 `did:web` エイリアスを追加発行可能にする。

| | |
|---|---|
| 実装コスト | A と同等 (NULL カラム 1 本の差) |
| 鍵ローテ | A と同じ。内部完結 |
| 相互運用 | MVP では A 相当 (内部のみ)。将来 did:web を足せば外部にも開放 |
| ランニングコスト | MVP では追加なし |
| OSS フレンドリー | A と同等 + コミュニティが did:web プラグインを追加できる拡張点 |

## 4. 決定

**Option D を採用する。**

### 理由

1. **MVP は市場検証フェーズ**。"World ID + AI エージェント + did ベースのメッセージング" というコンセプトが受け入れられるかを確認するのが最優先。相互運用性は受け入れ確認後に投資する
2. **ランニングコスト抑制**。DID Document ホスティングという追加インフラを持たない
3. **OSS 化しやすい**。フォーク時にドメイン準備や DID Document 配信の設定が不要。`git clone` → `docker compose up` で動く方が参入障壁が低い
4. **可逆性**。A → D → 将来 B 追加は自然な拡張。B → A への逆行は困難。不可逆な決定を避ける
5. **鍵ローテは確実に必要**。Option C (現状維持) は非対話型アクセスのセキュリティ要件を満たさない

### 採用しなかった選択肢の理由

- **B (did:web)**: MVP で相互運用性に投資するタイミングではない。ドメイン依存はコスト・OSS フレンドリーの観点で不利
- **C (did:key のまま)**: 鍵漏洩 = 全連絡先喪失は許容できない。非対話型アクセスでは鍵ローテが必須
- **A (aid のみ)**: D とほぼ同等だが、将来の拡張点を閉じるメリットがない。D にしておいて損はない

## 5. 仕様

### 5.1 `aid` のフォーマット

```
aid:ai:<ULID>
```

- プレフィックス `aid:ai:` は "NexusInbox" の略
- ULID (26 文字、Crockford Base32) でタイムスタンプ + ランダムの両方を含む
- 例: `aid:ai:01HX5K2N3PQRS8TVWXYZ0ABCDE`

### 5.2 DB スキーマ

```sql
-- 安定識別子
CREATE TABLE agent_identities (
    aid         TEXT PRIMARY KEY,       -- "aid:ai:01HX..."
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 鍵の履歴 (1 aid に複数の did:key)
CREATE TABLE agent_identity_keys (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aid                     TEXT NOT NULL REFERENCES agent_identities(aid) ON DELETE CASCADE,
    did                     TEXT NOT NULL UNIQUE,    -- "did:key:z6Mk..."
    signing_public_key      TEXT NOT NULL,
    encryption_public_key   TEXT NOT NULL,
    status                  TEXT NOT NULL CHECK (status IN ('active','rotating','retired','compromised')),
    external_did            TEXT,                    -- 将来の did:web 等 (v1 は NULL)
    activated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at              TIMESTAMPTZ,
    rotation_proof          TEXT                     -- 旧鍵で新鍵に署名した JWS (連続性証明)
);
CREATE INDEX idx_aik_active ON agent_identity_keys(aid) WHERE status = 'active';
```

### 5.3 既存スキーマとの関係

- `agents.did` は **そのまま残す** (現行アクティブ DID のショートカット)
- `agent_identities` は `agents.id` を参照
- エージェント作成時に自動的に `agent_identities` + `agent_identity_keys` も INSERT
- 既存の `/messages*` は `did:key` で引き続き動作。`aid:ai:...` での宛先指定は新規パスとして追加

### 5.4 API の変更

```
# エージェント一覧 (既存を拡張)
GET /agents
Response:
  { "agents": [
      {
        "id": "uuid",
        "aid": "aid:ai:01HX...",     ← 追加
        "did": "did:key:z6Mk...",
        "label": "秘書",
        ...
      }
  ]}

# メッセージ送信 (recipient に aid も許可)
POST /messages
  { "recipient_did": "aid:ai:01HX..." }
  → サーバが agent_identity_keys から現行 did:key に解決

# DID 解決 (aid → DID Document)
GET /resolve/aid:ai:01HX...
  → 現行 did:key の DID Document を返す
```

### 5.5 鍵ローテ手順

1. 人間が UI or API で `/agent-credentials/:id/rotate` を発行
2. Signer Daemon が新 Ed25519 + X25519 鍵ペアを生成
3. **旧秘密鍵で新公開鍵に署名** (rotation_proof)
4. `POST /agent-credentials/:id/activate` に新公開鍵 + rotation_proof を送付
5. サーバが rotation_proof を旧公開鍵で検証
6. `agent_identity_keys` に新行 (`status='active'`)、旧行を `status='rotating'`
7. `agents.did` を新 `did:key` に更新
8. 猶予期間 (デフォルト 7 日) 後、旧行を `status='retired'`
9. 外部から見える `aid:ai:...` は不変

## 6. 結果

### プラスの影響
- 鍵ローテが可能になり、非対話型アクセスのセキュリティ基盤が成立
- 既存機能は無修正で動き続ける (aid は追加)
- 将来の did:web 対応への拡張点が残る

### マイナスの影響
- `aid:ai:` は NexusInbox 独自なので、このプロジェクトが普及しなければただの独自 scheme で終わる
- ユーザに「did と aid の 2 つの識別子がある」ことを説明する必要がある (UI で上手く隠す)

### リスク
- OSS 化後に「did:web にすべき」という強い意見が出た場合、マイグレーションが必要 → ただし `external_did` カラムで共存可能なので致命的ではない

## 7. 次のアクション

1. ~~ADR を書く~~ (本ドキュメント)
2. `docs/15_*.md` v2 の §3 は本 ADR と整合済み。微修正は不要
3. P0 実装に着手:
   - `0006_agent_identities.sql` マイグレーション
   - `create_agent` ハンドラに `agent_identities` + `agent_identity_keys` INSERT を追加
   - `/agents` レスポンスに `aid` フィールドを追加
   - UI は `aid` を表示用に使い始める (既存 did 表示と並列)
