# 06. ストレージ設計書 (BYOS 2.0)

## 1. BYOS (Bring Your Own Storage) 概要

ユーザーが自身のストレージを指定し、メッセージ本文をそこに保管する。
NexusInboxサーバはメタデータ（Index）のみを管理。

## 2. 対応ストレージバックエンド

| バックエンド | Phase | 接続方式 | 特徴 |
|-------------|-------|---------|------|
| ローカルファイルシステム | Phase 1 (MVP) | Tauri FS API | オフライン完全対応 |
| Google Drive | Phase 1 | OAuth 2.0 (drive.file scope) | 15GB無料 |
| IPFS (Pinata/Infura) | Phase 2 | API Key | 分散・永続化 |
| S3互換 (R2/MinIO) | Phase 2 | Access Key | 大容量・低コスト |
| iCloud Drive | Phase 3 | CloudKit | Apple ecosystem |

## 3. Storage Adapter インターフェース

```rust
#[async_trait]
pub trait StorageAdapter: Send + Sync {
    /// Initialize the storage connection
    async fn connect(&mut self, config: &StorageConfig) -> Result<()>;

    /// Store an encrypted message, returns storage reference
    async fn store_message(
        &self,
        agent_did: &str,
        folder: Folder,       // Inbox, Sent, Draft, Archive
        message_id: &str,
        encrypted_data: &[u8],
    ) -> Result<StorageRef>;

    /// Retrieve an encrypted message by reference
    async fn retrieve_message(
        &self,
        storage_ref: &StorageRef,
    ) -> Result<Vec<u8>>;

    /// Delete a message
    async fn delete_message(
        &self,
        storage_ref: &StorageRef,
    ) -> Result<()>;

    /// List messages in a folder (metadata only)
    async fn list_folder(
        &self,
        agent_did: &str,
        folder: Folder,
    ) -> Result<Vec<StorageRef>>;

    /// Store an encrypted attachment
    async fn store_attachment(
        &self,
        message_id: &str,
        filename: &str,
        encrypted_data: &[u8],
    ) -> Result<StorageRef>;

    /// Check available storage space
    async fn available_space(&self) -> Result<u64>;

    /// Bulk delete for Auto-Purge
    async fn bulk_delete(
        &self,
        refs: &[StorageRef],
    ) -> Result<usize>;
}
```

## 4. Google Drive Adapter 詳細

### 4.1 OAuth Scopes
```
https://www.googleapis.com/auth/drive.file
```
- `drive.file`: NexusInboxが作成したファイルのみアクセス可能
- ユーザーの他のファイルには一切触れない

> **Note**: Phase 4.4d で追加された **Google Calendar 連携** は別 OAuth client として扱う。scope は `https://www.googleapis.com/auth/calendar.freebusy` で、Drive とは独立の token を browser 側 (IndexedDB) にのみ保持する。詳細は [ADR 25d](./25d_calendar_freebusy_auto_accept.md)。

### 4.2 フォルダ構造 (Google Drive上)
```
NexusInbox/                        ← アプリ作成フォルダ
├── .config.enc                     ← 暗号化設定
├── agents/
│   ├── {agent_did_short}/
│   │   ├── inbox/
│   │   │   ├── 2026-04/           ← 月別サブフォルダ
│   │   │   │   ├── {msg_id}.enc
│   │   │   │   └── ...
│   │   │   └── ...
│   │   ├── sent/
│   │   ├── drafts/
│   │   └── archive/
│   └── ...
└── attachments/
    └── {msg_id}/
        └── {filename}.enc
```

### 4.3 StorageRef形式
```json
{
  "backend": "google_drive",
  "file_id": "1abc...xyz",          // Google DriveのFile ID
  "path": "agents/did_short/inbox/2026-04/msg_id.enc",
  "size": 4096,
  "created_at": "2026-04-10T12:00:00Z"
}
```

## 5. ローカルファイルシステム Adapter

### 5.1 デフォルトパス
```
macOS:   ~/Library/Application Support/NexusInbox/storage/
Linux:   ~/.local/share/nexusinbox/storage/
Windows: %APPDATA%/NexusInbox/storage/
```

### 5.2 カスタムパス設定
```json
{
  "storage": {
    "backend": "local",
    "path": "/Users/username/NexusInbox",
    "max_size_gb": 10
  }
}
```

## 6. Auto-Purge Policy

### 6.1 設定
```json
{
  "auto_purge": {
    "enabled": true,
    "rules": [
      {
        "condition": "ai_category == 'background' AND unread_days > 30",
        "action": "delete"
      },
      {
        "condition": "ai_category == 'low_priority' AND unread_days > 90",
        "action": "archive"
      },
      {
        "condition": "storage_usage > 80%",
        "action": "archive_oldest",
        "target_usage": 70
      }
    ],
    "protected_senders": ["did:key:important..."],
    "require_confirmation": false
  }
}
```

### 6.2 Purgeフロー
```
1. 日次バッチ: message_indexからPurge候補を抽出
2. 条件判定: AI分類 × 未読日数 × ストレージ残量
3. 対象メッセージをBYOSから削除 or アーカイブ先へ移動
4. message_indexのstatusを "auto_purged" に更新
5. ユーザーに日次サマリ通知（削除件数・解放容量）
```

## 7. Zero-Knowledge Indexing

### 7.1 サーバが管理するIndex

```
┌──────────────────────────────────────────────┐
│ message_index (PostgreSQL)                   │
│                                              │
│ - recipient_did     (平文: ルーティングに必要)│
│ - sender_did        (平文: ブロック判定に必要)│
│ - subject_encrypted (暗号化: 表示用)         │
│ - storage_ref       (平文: ストレージ参照)    │
│ - status            (平文: フィルタリング)    │
│ - priority          (平文: ソート)            │
│ - created_at        (平文: ソート)            │
└──────────────────────────────────────────────┘
```

### 7.2 検索の仕組み

```
全文検索:
  1. クライアントが検索クエリを送信
  2. サーバはmessage_indexのメタデータでフィルタ（送信者、日付範囲等）
  3. 候補のstorage_refリストをクライアントに返却
  4. クライアントがBYOSからメッセージを取得・復号
  5. クライアント側で本文の全文検索を実行

  → サーバは検索クエリもメッセージ本文も見ない
```

## 8. ストレージ移行

```
既存ストレージ → 新ストレージ への移行フロー:

1. 新ストレージのAdapterを設定・接続
2. message_indexから全storage_refを取得
3. 旧ストレージから暗号化データを読み取り
4. 新ストレージへ暗号化データを書き込み
5. message_indexのstorage_refを新しい参照に更新
6. 検証（ランダムサンプリングで復号テスト）
7. 旧ストレージのデータを削除（ユーザー確認後）
```

## 9. 現在の実装メモ（2026-04-12）

- `storage_ref` は `localfs:v1://{message_id}` / `gdrive_mock:v1://{message_id}` / `gdrive:v1://{file_id}` を採用。
- 旧形式 `localfs://{message_id}` / `gdrive://{message_id}` は読取互換を維持。
- LocalFS保存はテンポラリファイルに書き込んでから `rename` する原子的反映に変更。
- ストレージI/Oの監査ログ（構造化JSON）を標準エラーに出力。
  - `event`: `storage_write` / `storage_read`
  - `result`: `ok` / `error`
  - `reason`: `encode_failed` / `persist_failed` / `read_failed` / `payload_corrupted` / `invalid_storage_ref`
- 障害時は `storage_error` を返却し、暗号本文や鍵断片はレスポンスに含めない。

### Google Drive（本実装）設定値

- `AGENT_INBOX_STORAGE_BACKEND=google_drive` （または `gdrive`）
- `AGENT_INBOX_GDRIVE_ACCESS_TOKEN`（必須）
- `AGENT_INBOX_GDRIVE_CLIENT_ID` / `AGENT_INBOX_GDRIVE_CLIENT_SECRET` / `AGENT_INBOX_GDRIVE_REFRESH_TOKEN`（任意: 自動更新用）
- `AGENT_INBOX_GDRIVE_FOLDER_ID`（任意: 保存先を専用フォルダへ固定）

### OAuth失効時の挙動

- API呼び出しで `401` を受けた場合、refresh token設定があれば1回だけ自動更新して再試行。
- refresh が `invalid_grant` などで失敗した場合は `storage_error` を返し、再認可（トークン再発行）が必要。
