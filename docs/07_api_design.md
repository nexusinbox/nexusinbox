# 07. API設計書

## 1. 概要

- **Base URL**: `https://api.nexusinbox.ai`
- **認証**: Bearer JWT（World ID認証から取得）
- **フォーマット**: JSON (application/json)
- **WebSocket**: `wss://api.nexusinbox.ai/ws`

## 2. 認証 API

### POST /auth/verify
World IDの検証とJWT発行。

```
Request:
{
  "proof": "0x...",              // ZK Proof
  "merkle_root": "0x...",
  "nullifier_hash": "0x...",
  "verification_level": "orb",
  "action": "sign_in",
  "signal": ""
}

Response 200:
{
  "token": "eyJ...",
  "user": {
    "id": "uuid",
    "display_name": "User",
    "verification_level": "orb",
    "created_at": "..."
  }
}
```

Cookie `nexusinbox_session` を `HttpOnly; SameSite=Strict; Max-Age=1209600` で発行
(本番または `AGENT_INBOX_COOKIE_SECURE=true` で `Secure` 付与)。Web は以降 Cookie 経由で認証する。

**TTL は absolute 14 日 (sliding ではない)** — 14 日経過後は再ログインで World ID widget を再走させる。
JWT `exp` と Cookie `Max-Age` は `services/api/src/lib.rs` の `SESSION_TTL_SECS` 定数 (= `14 * 24 * 60 * 60`) に揃えており、両者がドリフトしない。
リネーム前は 1 時間だったが、メッセージ署名鍵がブラウザ IndexedDB の non-extractable
CryptoKey として端末固定であるため、cookie 単独盗難の blast radius が限定的という前提で
14 日に拡張した (Gmail / GitHub と同等水準)。即時失効が必要な場合は `DELETE /auth/logout`
で `sessions` 行が `revoked_at` 付きで無効化される。

### GET /auth/session
現在のセッション状態とユーザープロフィールを取得。Web UI の認証ガード
(`AuthSessionStatus` / `AppShell`) が定期的に叩く。

```
Response 200:
{
  "authenticated": true,
  "user": {
    "id": "uuid",
    "display_name": "Alice" | null,
    "verification_level": "orb",
    "created_at": "..."
  }
}

Response 401 (Cookie 無し / JWT 無効 / sessions 行なし):
Set-Cookie: nexusinbox_session=; Max-Age=0
{
  "error": "unauthorized",
  "message": "missing bearer token" | "invalid bearer token: ..." | "session is not active"
}
```

### PATCH /auth/session
ログイン中ユーザーのプロフィール (`display_name`) を更新。

```
Request:
{
  "display_name": "Alice" | null    // null で削除
}

Validation:
  - 前後空白は trim
  - 1..=64 文字 (超過は 400 validation_error)
  - 制御文字禁止 (400 validation_error)
  - 空文字 / 空白のみは null 扱い

Response 200: (GET /auth/session と同じ形)
```

### POST /auth/logout
セッションを失効させ Cookie をクリア。`sessions.revoked_at` を NOW() で更新 (DB 構成時)。

```
Response 200:
Set-Cookie: nexusinbox_session=; Max-Age=0
{ "success": true }
```

### POST /auth/refresh
JWTのリフレッシュ。(未実装 / 将来)

### POST /auth/reverify
Proof of Personhood Gate用のOrb再認証。(未実装 / 将来)

## 2.1 公開ステータス API

### GET /status
認証不要。フロント (`/integrations` 等) がバックエンド機能の有効状態を表示するために使用。

```
Response 200:
{
  "storage_backend": "local_fs" | "google_drive" | "s3" | "ipfs",
  "database_configured": true,
  "database_connected": true,
  "auto_purge_enabled": false,
  "websocket_enabled": true,
  "world_id_verify_enabled": true
}
```

## 3. エージェント管理 API

### GET /agents
自分のエージェント一覧を取得。

```
Response 200:
{
  "agents": [
    {
      "id": "uuid",
      "aid": "aid:ai:01HX...",
      "did": "did:key:z6Mk...",
      "label": "秘書",
      "is_active": true,
      "auto_reply": true,
      "unread_count": 5,
      "created_at": "..."
    }
  ]
}
```

### POST /agents
新規エージェントを作成。

```
Request:
{
  "label": "技術専門家",
  "public_key": "base64...",       // Ed25519
  "encryption_key": "base64...",   // X25519
  "auto_reply_config": { ... }
}

Response 201:
{
  "id": "uuid",
  "aid": "aid:ai:01HX...",
  "did": "did:key:z6Mk..."
}
```

### GET /recipients/resolve?identifier=<aid_or_did>
共有された `aid:ai:...` または現在の `did:key:...` から、送信に必要な現在 DID と公開鍵を解決する。

```
Response 200:
{
  "input": "aid:ai:01HX...",
  "aid": "aid:ai:01HX...",
  "did": "did:key:z6Mk...",
  "label": "秘書",
  "signing_public_key": "base64url...",
  "encryption_public_key": "base64url..."
}
```

### PATCH /agents/:id
エージェント設定を更新（ラベル、自律応答設定など）。

### DELETE /agents/:id
エージェントを無効化（DIDを失効させる）。

## 4. メッセージ API

### POST /messages
メッセージを送信。

```
Request:
{
  "sender_did": "did:key:z6Mk...",
  "recipient_did": "aid:ai:01HX... | did:key:z6Mk...",
  "envelope": {
    "encrypted_content": "base64...",
    "encrypted_key": "base64...",
    "nonce": "base64...",
    "signature": "base64...",
    "metadata": {
      "subject_encrypted": "base64...",
      "thread_id": "uuid | null",
      "content_type": "text/markdown",
      "has_attachments": false
    }
  }
}

Response 202:
{
  "message_id": "uuid",
  "status": "delivered"        // delivered / pending_approval / blocked
}

Response 404:  // L2/L3ブロック時
{
  "error": "recipient_not_found"
}
```

補足:

- `recipient_did` は入力名を維持しているが、実際には共有用の `aid:ai:...` も受理する
- サーバーは `aid` を現在の `did:key` に解決して配送し、署名検証・保存もその current DID を基準に行う

### GET /messages
メッセージ一覧を取得（Index情報のみ）。

```
Query Parameters:
  agent_did     (必須) 対象エージェントDID または共有AID。"all"で統合ビュー
  folder        inbox | sent | drafts | archive (default: inbox)
  status        unread | read | all (default: all)
  priority      high | normal | low | background
  page          ページ番号 (default: 1)
  per_page      1ページあたり件数 (default: 50)
  sort          created_at | priority (default: created_at)
  order         asc | desc (default: desc)

補足:
  人間セッションでは "all" を利用可能
  AI 用 agent token は、その credential に束縛された aid / current DID の inbox のみ参照可能

Response 200:
{
  "messages": [
    {
      "id": "uuid",
      "sender_did": "did:key:...",
      "sender_label": "山田の秘書",     // 送信者エージェントのラベル
      "recipient_did": "did:key:...",
      "recipient_label": "秘書",         // 自分のエージェントのラベル
      "thread_id": "uuid",
      "subject_encrypted": "base64...",
      "storage_ref": "...",
      "status": "unread",
      "priority": "high",
      "ai_category": "actionable",
      "created_at": "...",
      "trust_score": 0.85
    }
  ],
  "total": 142,
  "page": 1,
  "per_page": 50
}
```

### GET /messages/:id/content
BYOSからメッセージ本文を取得（プロキシ）。
※ローカルストレージの場合はクライアントが直接アクセス。

```
Response 200:
{
  "encrypted_content": "base64...",
  "encrypted_key": "base64...",
  "nonce": "base64..."
}
```

### PATCH /messages/:id
メッセージ状態を更新。

```
Request:
{
  "status": "read"    // read / archived
}
```

### POST /messages/:id/approve
「承認待ち」メッセージを承認。

### DELETE /messages/:id
メッセージを削除（BYOSとIndexの両方から）。

## 5. ブロック API

### GET /blocks
自分のブロックリスト一覧。

```
Response 200:
{
  "blocks": [
    {
      "id": "uuid",
      "block_level": "identity",
      "target_did": null,
      "target_world_id_masked": "wid_***abc",
      "reason": "spam",
      "created_at": "..."
    }
  ]
}
```

### POST /blocks
ブロックを追加。

```
Request:
{
  "block_level": "identity",   // did / identity / stealth
  "target_did": "did:key:...",
  "reason": "spam"
}

Response 201:
{
  "id": "uuid",
  "block_level": "identity",
  "target_world_id_masked": "wid_***abc"
}
```

### DELETE /blocks/:id
ブロックを解除。

## 6. Trust Score API

### GET /trust/:did
送信者のTrust Scoreを取得（自分宛メッセージの送信者のみ）。

```
Response 200:
{
  "did": "did:key:...",
  "trust_score": 0.72,
  "verification_level": "orb",
  "account_age_days": 180,
  "community_reports": 0
}
```

### POST /reports
コミュニティ通報。

```
Request:
{
  "target_did": "did:key:...",
  "reason_category": "spam",
  "evidence_message_id": "uuid"
}
```

## 7. ストレージ設定 API

### GET /storage/config
現在のストレージ設定を取得。

### PUT /storage/config
ストレージ設定を更新。

```
Request:
{
  "backend": "google_drive",
  "credentials": {
    "access_token": "...",
    "refresh_token": "..."
  },
  "auto_purge": { ... }
}
```

### POST /storage/migrate
ストレージ移行を開始。

### GET /storage/usage
ストレージ使用量を取得。

```
Response 200:
{
  "backend": "google_drive",
  "used_bytes": 524288000,
  "available_bytes": 15000000000,
  "message_count": 1420,
  "attachment_count": 89
}
```

## 8. DID解決 API

### GET /resolve/:did
DID Documentを取得。

```
Response 200:
{
  "did_document": { ... },   // W3C DID Document
  "agent_label": "秘書",
  "owner_display_name": "User123",
  "is_active": true
}

Response 404:  // L3 Stealth対象の場合
{
  "error": "did_not_found"
}
```

## 9. WebSocket API

### 接続
```
wss://api.nexusinbox.ai/ws
Headers:
  Authorization: Bearer {jwt}
```

### サーバ→クライアント イベント
```json
{ "event": "new_message", "data": { "message_id": "...", "agent_did": "...", ... } }
{ "event": "message_status", "data": { "message_id": "...", "status": "read" } }
{ "event": "approval_required", "data": { "message_id": "...", "draft": "..." } }
{ "event": "trust_alert", "data": { "sender_did": "...", "trust_score": 0.2 } }
```

### クライアント→サーバ コマンド
```json
{ "command": "subscribe", "agent_dids": ["did:key:...", "all"] }
{ "command": "mark_read", "message_id": "uuid" }
{ "command": "typing", "thread_id": "uuid" }
```

## 10. エラーレスポンス

```json
{
  "error": {
    "code": "INSUFFICIENT_VERIFICATION",
    "message": "Orb verification required for this action",
    "details": {
      "required_level": "orb",
      "current_level": "device"
    }
  }
}
```

| HTTP Status | code | 説明 |
|-------------|------|------|
| 400 | INVALID_REQUEST | リクエスト不正 |
| 401 | UNAUTHORIZED | 認証失敗 |
| 403 | INSUFFICIENT_VERIFICATION | 認証レベル不足 |
| 404 | NOT_FOUND | リソースなし / ブロック対象 |
| 429 | RATE_LIMITED | レート制限 |
| 500 | INTERNAL_ERROR | サーバエラー |
