# 02. データモデル設計書

## 1. 全体方針

- **サーバDB (PostgreSQL 17)**: Identity、Trust Score、ブロックリスト、メッセージ Index (メタデータのみ)、セッション、エージェントトークン (hash 保存)、DPoP replay nonce、監査ログ
- **ユーザーストレージ (BYOS)**: 暗号化されたメッセージ本文、添付ファイル (AES-GCM-256 暗号化済みの blob)。既定は Cloudflare R2 (S3 互換)、他に Local FS / Google Drive / IPFS が選択可能
- **キャッシュ層**: 現行 Phase では導入していない。設計書 (docs/15) で想定した Redis は、PostgreSQL 直接参照と in-memory カウンタで代替している

## 2. サーバ側スキーマ

### users (World ID認証ユーザー)
```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    world_id_hash   TEXT NOT NULL UNIQUE,  -- World IDのハッシュ（生値は保存しない）
    nullifier_hash  TEXT NOT NULL UNIQUE,  -- World IDの一意識別子
    display_name    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_verified   TIMESTAMPTZ,          -- 最後のOrb再認証日時
    is_suspended    BOOLEAN NOT NULL DEFAULT false
);
```

### agents (ユーザーのAIエージェント = DID)
```sql
CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    did             TEXT NOT NULL UNIQUE,  -- did:key:z6Mk... 形式
    label           TEXT NOT NULL,         -- 「秘書」「技術専門家」等
    public_key      BYTEA NOT NULL,       -- Ed25519公開鍵
    encryption_key  BYTEA NOT NULL,       -- X25519公開鍵（メッセージ受信用）
    is_active       BOOLEAN NOT NULL DEFAULT true,
    auto_reply      BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ
);
CREATE INDEX idx_agents_user_id ON agents(user_id);
CREATE INDEX idx_agents_did ON agents(did);
```

### message_index (Zero-Knowledge Indexing: メタデータのみ)
```sql
CREATE TABLE message_index (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_did   TEXT NOT NULL,         -- 宛先エージェントDID
    sender_did      TEXT NOT NULL,         -- 送信元エージェントDID
    thread_id       UUID,                  -- スレッドグルーピング
    subject_hash    TEXT,                  -- 件名のハッシュ（検索用）
    subject_encrypted BYTEA,              -- 暗号化された件名（表示用）
    storage_ref     TEXT NOT NULL,         -- BYOSストレージ内のパス/ID
    status          TEXT NOT NULL DEFAULT 'unread',
                    -- unread / read / archived / auto_purged
    priority        TEXT NOT NULL DEFAULT 'normal',
                    -- high / normal / low / background
    ai_category     TEXT,                 -- AIが分類したカテゴリ
    is_spam         BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at         TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ           -- Auto-Purge期限
);
CREATE INDEX idx_msg_recipient ON message_index(recipient_did, created_at DESC);
CREATE INDEX idx_msg_thread ON message_index(thread_id);
CREATE INDEX idx_msg_status ON message_index(recipient_did, status);
```

### trust_scores (Trust Score管理)
```sql
CREATE TABLE trust_scores (
    world_id_hash   TEXT PRIMARY KEY,
    score           REAL NOT NULL DEFAULT 0.5,  -- 0.0〜1.0
    report_count    INTEGER NOT NULL DEFAULT 0,
    block_count     INTEGER NOT NULL DEFAULT 0,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_updated    TIMESTAMPTZ NOT NULL DEFAULT now(),
    verification_level TEXT NOT NULL DEFAULT 'device',
                    -- device / orb / orb_recent
    account_age_days INTEGER NOT NULL DEFAULT 0
);
```

### blocks (階層型ブロックリスト)
```sql
CREATE TABLE blocks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    blocker_user_id UUID NOT NULL REFERENCES users(id),
    block_level     TEXT NOT NULL,  -- 'did' / 'identity' / 'stealth'
    target_did      TEXT,           -- L1: 特定DID
    target_world_id TEXT,           -- L2/L3: World IDハッシュ
    reason          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT valid_block CHECK (
        (block_level = 'did' AND target_did IS NOT NULL) OR
        (block_level IN ('identity', 'stealth') AND target_world_id IS NOT NULL)
    )
);
CREATE INDEX idx_blocks_blocker ON blocks(blocker_user_id);
CREATE INDEX idx_blocks_target_did ON blocks(target_did);
CREATE INDEX idx_blocks_target_wid ON blocks(target_world_id);
```

### community_reports (共有ブラックリスト用)
```sql
CREATE TABLE community_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_user_id UUID NOT NULL REFERENCES users(id),
    target_world_id TEXT NOT NULL,
    reason_category TEXT NOT NULL,  -- spam / abuse / impersonation / other
    evidence_hash   TEXT,          -- 証拠メッセージのハッシュ
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(reporter_user_id, target_world_id)
);
```

## 3. BYOSストレージ構造

ユーザーのストレージ内のディレクトリ構造:

```
nexusinbox/
├── config.json              -- ストレージ設定（暗号化）
├── keys/
│   ├── master.key.enc       -- マスター鍵（パスフレーズで保護）
│   └── agents/
│       ├── {agent_id}.key.enc
│       └── ...
├── messages/
│   ├── {agent_did}/
│   │   ├── inbox/
│   │   │   ├── {message_id}.enc   -- 暗号化メッセージ本文
│   │   │   └── ...
│   │   ├── sent/
│   │   ├── drafts/
│   │   └── archive/
│   └── ...
└── attachments/
    └── {message_id}/
        ├── {filename}.enc
        └── ...
```

### メッセージファイル構造 (復号後)
```json
{
  "id": "uuid",
  "from": "did:key:sender...",
  "to": "did:key:recipient...",
  "thread_id": "uuid",
  "subject": "件名",
  "body": "本文（Markdown対応）",
  "body_format": "markdown",
  "attachments": [
    { "name": "file.pdf", "size": 102400, "ref": "attachments/{id}/file.pdf" }
  ],
  "agent_protocol": {
    "type": "schedule_negotiation",
    "payload": { ... }
  },
  "signature": "Ed25519署名",
  "created_at": "2026-04-10T12:00:00Z"
}
```

## 4. Zero-Knowledge Indexing フロー

```
1. 送信者がメッセージを受信者の公開鍵で暗号化
2. 暗号化済みメッセージをBYOSに保存 → storage_ref取得
3. メタデータ（送信者DID、暗号化件名、storage_ref）をサーバのmessage_indexへ
4. 検索時: サーバ側indexでフィルタ → storage_refでBYOSから本文を取得・復号
```

**サーバが見えるもの**: 送信者DID、受信者DID、タイムスタンプ、暗号化された件名
**サーバが見えないもの**: メッセージ本文、添付ファイル、復号された件名
