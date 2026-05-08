# 17. 添付ファイルアップロード仕様書 (Cloudflare R2 / E2E暗号化)

## 1. 概要

本仕様書は、NexusInbox における添付ファイルアップロード機能を、Cloudflare R2 を保存先として採用しつつ、NexusInbox のコアバリューである **E2E暗号化でサーバは内容を見れない** を維持するための設計を定義する。

採用方針:
- ブラウザは presigned URL を使って R2 に直接アップロードする
- ただしアップロード前に **ブラウザで添付ファイルを暗号化** する
- Rust API は upload intent、認可、opaque な object metadata、監査のみを扱う
- ダウンロードも presigned GET URL で R2 から直接取得し、**復号はブラウザ側** で行う

本仕様により:
- サーバは添付ファイル平文を見ない
- サーバは添付ファイル名、Content-Type、本文由来メタデータを見ない
- R2 には暗号化済み blob のみを保存する

---

## 2. コア原則

### 2.1 NexusInbox の一貫した暗号化原則

本文と添付は同じ原則に従う。

| 項目 | 本文 | 添付 |
|---|---|---|
| 内容 | E2E暗号化 | E2E暗号化 |
| ファイル名 | 暗号化 | 暗号化 |
| MIME | 暗号化 | 暗号化 |
| 復号 | クライアント | クライアント |
| サーバ可視 | ルーティング/Index最小限のみ | opaque metadata のみ |

### 2.2 サーバが見えてよい情報

サーバが扱ってよい情報は以下に限定する。

- `attachment_id`
- `owner_user_id`
- `sender_did`
- `object_key`
- `ciphertext_size_bytes`
- `status`
- `issued_at`
- `upload_expires_at`
- `uploaded_at`
- `attached_message_id`

### 2.3 サーバが見てはいけない情報

- 添付ファイル平文
- 元ファイル名
- 実際の MIME / Content-Type
- 添付の hash（平文由来）
- 添付内テキスト

---

## 3. 全体構成

```text
Browser
  │
  │ 1. POST /attachments/intents
  ▼
Rust API
  │
  │ 2. presigned PUT URL + attachment_id を発行
  ▼
Browser
  │
  │ 3. 添付ファイルをブラウザで暗号化
  │ 4. 暗号化 blob を R2 へ direct PUT
  ▼
Cloudflare R2

Browser
  │
  │ 5. POST /attachments/{id}/complete
  ▼
Rust API
  │
  │ 6. HEAD で opaque object を検証
  ▼
Cloudflare R2

Browser
  │
  │ 7. POST /messages
  │    - 本文暗号文
  │    - 添付 metadata 暗号文
  │    - attachment_id 一覧
  ▼
Rust API

Browser
  │
  │ 8. POST /messages/{id}/attachments/{attachmentId}/download
  ▼
Rust API
  │
  │ 9. 認可後に presigned GET URL を返す
  ▼
Browser
  │
  │ 10. 暗号化 blob を R2 から取得
  │ 11. ブラウザで復号
  ▼
Cloudflare R2
```

---

## 4. 暗号化モデル

### 4.1 添付暗号化の基本方針

各添付はブラウザで以下の手順で暗号化する。

1. 添付ごとにランダムな `attachment_content_key` を生成する
2. 添付バイト列を `AES-GCM` で暗号化する
3. 暗号化結果を R2 にアップロードする
4. `attachment_content_key` は受信者向けと送信者向けの両方に wrap する
5. 添付 metadata も別途暗号化する

### 4.2 添付 metadata の対象

以下は平文保存せず、暗号化 metadata としてメッセージ送信 payload に含める。

```json
{
  "filename": "proposal.pdf",
  "mime": "application/pdf",
  "plaintext_size_bytes": 5242880,
  "cipher_algorithm": "aes-gcm-256",
  "cipher_nonce": "base64url...",
  "attachment_key_wraps": [
    {
      "recipient_did": "did:key:z6MkRecipient...",
      "wrapped_key": "x25519v1:..."
    },
    {
      "recipient_did": "did:key:z6MkSender...",
      "wrapped_key": "x25519v1:..."
    }
  ],
  "sha256_plaintext": "base64url..."
}
```

### 4.3 推奨形式

初期形式:

```json
{
  "attachment_id": "uuid",
  "blob_ref": {
    "backend": "r2",
    "object_key": "attachments/.../att_.../blob.bin"
  },
  "metadata_encrypted": "base64url...",
  "metadata_nonce": "base64url..."
}
```

ここで:
- `blob_ref.object_key` は opaque key
- `metadata_encrypted` の中に filename / MIME / size / wrap 情報を含める

### 4.4 受信側の復号

受信側は:
- presigned GET で暗号化 blob を取得
- メッセージ内の `metadata_encrypted` を復号
- metadata 内の `attachment_key_wraps` から、自分の DID に一致する wrap を選んで `attachment_content_key` を復元
- blob を復号

送信者側も同様に、自分向け wrap を使って自分の送った添付を再表示できる。

---

## 5. セキュリティ要件

### 5.1 必須条件

1. presigned URL は短命にする
- upload PUT: 5分
- download GET: 1分

2. object key はサーバ側のみで生成する
- クライアント指定禁止

3. bucket は private にする
- public URL 不可

4. upload intent を DB で追跡する
- `issued`
- `uploaded`
- `attached`
- `deleted`
- `expired`
- `quarantined`

5. complete 時に API が R2 object を HEAD 検証する
- object exists
- object key 一致
- ciphertext_size が上限内
- object metadata 上の `attachment_id`, `owner_user_id` が intent と一致

6. `POST /messages` 時にも attachment を再検証する
- owner 一致
- status = `uploaded`
- object 存在
- attached 前状態

7. download URL は認可後に毎回発行する
- 恒久URL禁止

8. 復号鍵や平文 metadata は API に送らない

9. `POST /attachments/intents` にレート制限を設ける
- 同一ユーザー: 1分あたり 20 回まで
- 同一IP: 1分あたり 60 回まで
- バースト許容量を超えた場合は `429 Too Many Requests`
- intent の大量発行による presigned URL 量産、R2 コスト増、DB 肥大化を抑止する

### 5.2 追加で必須採用する推奨事項

本仕様では以下も必須とする。

- 1ファイル上限
- 1メッセージ合計上限
- 添付数上限
- 孤児 object cleanup
- 監査ログ
- 将来のマルウェアスキャン拡張余地
- `Content-Disposition: attachment`

### 5.3 重要な設計上の割り切り

添付 metadata もサーバから隠す場合、サーバは **真の MIME を強制検証できない**。

つまりサーバ側で厳密に enforce できるのは主に:
- ciphertext size
- attachment count
- object ownership
- TTL
- attachment lifecycle

`filename` / `mime` の allowlist はクライアント実装上の制約としてもたせるが、サーバはその平文を保持しない。

このトレードオフは、NexusInbox のコア価値を優先した意図的な選択である。

---

## 6. 添付ファイル制約

初期制約:
- 1ファイル最大: 5MB
- 1メッセージ合計: 25MB
- 1メッセージ最大添付数: 5

クライアント側 allowlist:
- `image/png`
- `image/jpeg`
- `image/webp`
- `application/pdf`
- `text/plain`

クライアント側 denylist:
- `text/html`
- `application/javascript`
- `application/x-msdownload`
- `application/x-sh`
- `application/zip`

備考:
- これは UX / 安全性のためのクライアント制御であり、サーバは MIME 平文を保存しない

---

## 7. オブジェクトキー設計

### 7.1 キー形式

```text
attachments/{user_id}/{draft_or_message_id}/{attachment_id}/blob.bin
```

例:

```text
attachments/3f2d.../draft_01J.../att_01J.../blob.bin
```

ルール:
- key は opaque にする
- filename を key に含めない
- object key から利用者の業務情報が推測できないようにする

---

## 8. データモデル

### 8.1 attachment_uploads

```sql
CREATE TABLE attachment_uploads (
    id                    UUID PRIMARY KEY,
    owner_user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender_did            TEXT,
    draft_id              TEXT,
    r2_bucket             TEXT NOT NULL,
    object_key            TEXT NOT NULL UNIQUE,
    ciphertext_size_limit BIGINT NOT NULL,
    ciphertext_size_bytes BIGINT,
    status                TEXT NOT NULL CHECK (
        status IN ('issued', 'uploaded', 'attached', 'deleted', 'expired', 'quarantined')
    ),
    issued_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    upload_expires_at     TIMESTAMPTZ NOT NULL,
    uploaded_at           TIMESTAMPTZ,
    attached_message_id   UUID,
    deleted_at            TIMESTAMPTZ,
    last_verified_at      TIMESTAMPTZ
);
```

### 8.2 message_attachments

```sql
CREATE TABLE message_attachments (
    id                         UUID PRIMARY KEY,
    message_id                 UUID NOT NULL REFERENCES message_index(id) ON DELETE CASCADE,
    attachment_upload_id       UUID NOT NULL REFERENCES attachment_uploads(id) ON DELETE RESTRICT,
    owner_user_id              UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender_did                 TEXT NOT NULL,
    recipient_did              TEXT NOT NULL,
    metadata_encrypted         TEXT NOT NULL,
    metadata_nonce             TEXT NOT NULL,
    ciphertext_size_bytes      BIGINT NOT NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

サーバが持たないもの:
- original filename
- content_type
- plaintext size

---

## 9. API 仕様

### 9.1 POST /attachments/intents

添付 upload intent を発行する。

Request:

```json
{
  "sender_did": "did:key:z6Mk...",
  "draft_id": "draft_01J...",
  "ciphertext_size_bytes": 4194304
}
```

Response 201:

```json
{
  "attachment_id": "uuid",
  "upload_url": "https://<r2-presigned-put>",
  "upload_method": "PUT",
  "upload_expires_at": "2026-04-17T12:00:00Z",
  "required_headers": {
    "Content-Type": "application/octet-stream",
    "x-amz-meta-attachment-id": "uuid",
    "x-amz-meta-owner-user-id": "00000000-0000-0000-0000-000000000001",
    "x-amz-meta-issued-at": "2026-04-17T11:55:00Z"
  },
  "max_ciphertext_size_bytes": 5242880
}
```

Rate Limit:
- per-user: 20 requests / minute
- per-ip: 60 requests / minute
- over limit: `429 Too Many Requests`

### 9.2 POST /attachments/{id}/complete

アップロード完了後、API が opaque object を検証する。

Request:

```json
{
  "ciphertext_size_bytes": 4194304
}
```

Server action:
- HEAD object
- object exists
- ciphertext size 一致
- metadata の `attachment_id` / `owner_user_id` 一致

Response 200:

```json
{
  "attachment_id": "uuid",
  "status": "uploaded"
}
```

### 9.3 POST /messages

既存送信 API を拡張し、添付参照と暗号化 metadata を受け取る。

Request 追加項目:

```json
{
  "attachment_ids": [
    "uuid-1",
    "uuid-2"
  ],
  "attachments": [
    {
      "attachment_id": "uuid-1",
      "metadata_encrypted": "base64url...",
      "metadata_nonce": "base64url..."
    }
  ]
}
```

Server action:
- `attachment_ids` が owner に属することを確認
- status = `uploaded` を確認
- object existence を再確認
- `message_attachments` を保存
- `attachment_uploads.status = 'attached'`

### 9.4 GET /messages/{id}/attachments

添付一覧を返す。

Response 200:

```json
{
  "attachments": [
    {
      "attachment_id": "uuid",
      "metadata_encrypted": "base64url...",
      "metadata_nonce": "base64url...",
      "ciphertext_size_bytes": 7340032
    }
  ]
}
```

### 9.5 POST /messages/{id}/attachments/{attachmentId}/download

閲覧権限確認後に presigned GET URL を返す。

Response 200:

```json
{
  "download_url": "https://<r2-presigned-get>",
  "expires_at": "2026-04-17T12:00:00Z"
}
```

ルール:
- TTL は 1分
- `Content-Type` は `application/octet-stream`
- `Content-Disposition: attachment`
- presigned URL 生成時に `response-content-disposition=attachment` を署名対象に含め、ブラウザ側での inline 表示を禁止する

認可条件:
- 送信者: 対応 message の `sender_did` を所有している場合は常に許可
- 受信者: 対応 message の `recipient_did` を所有し、message がそのユーザーの一覧/詳細から閲覧可能な状態である場合に許可
- L1/L2/L3 block により配送されなかった message には、受信者側 download 権限は発生しない
- メッセージ削除後は、送信者/受信者ともに download 不可
- `attachment_uploads.status != 'attached'` の場合は download 不可

### 9.6 DELETE /attachments/{id}

未送信の添付を削除する。

---

## 10. R2 設定

### 10.1 Bucket

- bucket 名例: `nexusinbox-attachments-prod`
- public access: disabled
- object versioning: optional
- 保存オブジェクトは常に暗号化済み blob

### 10.2 CORS

本番:
- origin: `https://app.nexusinbox.ai`
- methods: `PUT`, `GET`, `HEAD`
- allowed headers:
  - `Content-Type`
  - `x-amz-meta-attachment-id`
  - `x-amz-meta-owner-user-id`
  - `x-amz-meta-issued-at`

### 10.3 Object metadata

平文 metadata は最小限に限定する:
- `x-amz-meta-attachment-id`
- `x-amz-meta-owner-user-id`
- `x-amz-meta-issued-at`

禁止:
- original filename
- true MIME
- plaintext hash

---

## 11. フロー

### 11.1 upload 正常系

1. ユーザーが添付を選択
2. ブラウザがクライアント側制約で MIME / サイズを確認
3. ブラウザが添付を暗号化
4. ブラウザが `POST /attachments/intents`
5. API が intent と presigned PUT を返す
6. ブラウザが暗号化 blob を R2 に direct PUT
7. ブラウザが `POST /attachments/{id}/complete`
8. API が HEAD 検証して `uploaded`
9. ブラウザが `POST /messages`
10. API が attachment をメッセージに関連付ける

### 11.2 download 正常系

1. ブラウザが添付一覧を取得
2. ブラウザが download URL 発行 API を呼ぶ
3. API が認可確認
4. presigned GET を返す
5. ブラウザが暗号化 blob を取得
6. ブラウザが metadata と blob を復号する

---

## 12. ライフサイクル管理

### 12.1 孤児 cleanup

対象:
- `issued` のまま TTL 超過
- `uploaded` のまま 24時間超過
- `deleted` 済み object

ルール:
- `issued` → 30分で `expired`
- `uploaded` → 24時間で `expired`
- cleanup job が object を削除し監査ログを残す

### 12.2 メッセージ削除

- `message_attachments` を削除
- object を削除
- `attachment_uploads.status = 'deleted'`

---

## 13. セキュリティ詳細

### 13.1 この方式の意味

この方式では、添付の機密性は本文と同じくクライアント暗号に依存する。

したがって:
- R2 が侵害されても平文添付は漏れない
- サーバ管理者は添付内容を読めない
- プライバシーポリシーで「メッセージ内容と添付内容はサーバ側で閲覧できない」と整合する

### 13.2 トレードオフ

サーバが MIME 平文を知らないため、サーバ側でできる安全制御は主に以下になる。
- サイズ制限
- attachment count 制限
- object ownership
- intent / TTL
- ダウンロード時の強制 attachment disposition

これにより、「サーバが完全に中身を把握しない」ことと「サーバが内容ベース制御をする」ことは両立しない。
本仕様では前者を優先する。

### 13.3 監査ログ

最低限記録する:
- owner_user_id
- sender_did
- recipient_did
- message_id
- attachment_id
- object_key
- ciphertext_size_bytes
- client_ip
- user_agent
- event
- outcome
- timestamp

---

## 14. 実装上の注意

### 14.1 Rust API

- presigned URL 発行のみを担う
- 暗号化/復号はしない
- R2 秘密情報は server secret のみ

### 14.2 Web

- 暗号化完了前に upload しない
- complete 成功前に送信 payload に含めない
- 復号失敗時はプレースホルダ表示にする

### 14.3 将来拡張

将来追加しやすいように以下を残す:
- encrypted thumbnail
- encrypted preview manifest
- optional client-side virus scanning hook
- encrypted attachment dedup via ciphertext hash
- per-tenant retention

---

## 15. DoD

- 添付平文はサーバに送られない
- filename / MIME は DB 平文保存しない
- R2 には暗号化 blob のみ保存される
- presigned PUT/GET は短命 TTL
- object key はサーバ生成のみ
- upload intent が DB 追跡される
- complete 時に HEAD 検証がある
- `POST /messages` で attachment 再検証がある
- download は認可後に毎回 presigned GET を発行する
- private bucket + 最小 CORS が設定される
- orphan cleanup が動作する
- 監査ログが記録される

---

## 16. 推奨実装順

1. DB スキーマ追加 (`attachment_uploads`, `message_attachments`)
2. R2 bucket / CORS / secret 設定
3. ブラウザ側添付暗号化ユーティリティ
4. `POST /attachments/intents`
5. direct PUT + complete API
6. `POST /messages` の attachment 統合
7. 添付一覧 API
8. download URL 発行 API
9. クライアント復号
10. delete / cleanup / audit log
