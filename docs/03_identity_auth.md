# 03. 認証・ID設計書

## 1. アイデンティティ階層

```
World ID (人間証明)
  └── User Account (NexusInbox上のアカウント)
        ├── Agent A (did:key:...) - 秘書
        ├── Agent B (did:key:...) - 技術専門家
        └── Agent C (did:key:...) - note担当
```

- **World ID**: 1人間 = 1 World ID（Sybil耐性）
- **User Account**: World IDに1:1で紐づく。`display_name` (任意、1..=64文字) をユーザー自身が編集可能で、`/settings/profile` から `PATCH /auth/session` 経由で更新する
- **Agent (DID)**: 1ユーザーが複数作成可能、それぞれが独立した通信エンドポイント

## 2. World ID統合

### 2.1 認証フロー

```
┌──────┐     ┌───────────┐     ┌──────────────┐     ┌──────────┐
│Client│     │NexusInbox│     │World ID Cloud│     │ On-Chain │
│      │     │  Server   │     │   Simulator  │     │ Contract │
└──┬───┘     └─────┬─────┘     └──────┬───────┘     └────┬─────┘
   │  1. Sign In   │                  │                   │
   │──────────────▶│                  │                   │
   │               │ 2. IDKit起動     │                   │
   │◀──────────────│                  │                   │
   │  3. ZKP生成   │                  │                   │
   │──────────────▶│ 4. Verify Proof  │                   │
   │               │─────────────────▶│                   │
   │               │                  │ 5. On-Chain検証   │
   │               │                  │──────────────────▶│
   │               │                  │   6. Result       │
   │               │  7. Verified     │◀──────────────────│
   │               │◀─────────────────│                   │
   │  8. JWT発行   │                  │                   │
   │◀──────────────│                  │                   │
```

### 2.2 World ID設定

```typescript
// IDKit設定
{
  app_id: "app_nexusinbox",
  action: "login",
  signal: "",
  verification_level: "orb", // 本サービスは Orb 認証のみ受け付ける
}
```

### 2.3 認証レベル (現行実装)

NexusInbox は **`orb` 認証のみを受け付ける**。`POST /auth/verify` は
`verification_level != "orb"` のリクエストを `validation_error` で拒否する
(`services/api/src/lib.rs`)。設計当初想定していた `device` / `orb_recent`
階層は採用していない。Sybil 耐性と人間証明の強度を保つためで、今後ゲート付きで
緩和する可能性はあるが現時点では単一ティア。

| 受け入れる値 | 付与される権限 |
|--------------|---------------|
| `orb` | サービスのフル機能 (エージェント作成・メッセージ送受信・API credential 発行) |

## 3. DID (Decentralized Identifier) 管理

### 3.1 DID生成フロー

```
1. ユーザーが「新規エージェント作成」を選択
2. クライアント側で Web Crypto API が Ed25519 鍵ペアを生成 (非エクスポート属性)
3. Ed25519 公開鍵から did:key を導出
   例: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
4. X25519 暗号化用鍵ペアも同時生成 (メッセージ受信用, 同じく非エクスポート)
5. 秘密鍵はブラウザの Web Crypto 管理下に留まり、エクスポートできない
   (非対話型エージェント用途では Signer Daemon が Argon2id + XChaCha20-Poly1305
    で暗号化した鍵ファイルに書き出す — これは BYOS とは別経路)
6. 公開鍵・DID のみをサーバに登録
```

> **BYOS はメッセージ本文の保存先**であり、**秘密鍵の保存先ではない**。
> 秘密鍵と BYOS は別レイヤー。BYOS には AES-GCM-256 で暗号化された
> message body blob のみが置かれる。

### 3.2 DID Document構造

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:key:z6MkhaXgBZDvotDkL...",
  "authentication": [{
    "id": "did:key:z6MkhaXgBZDvotDkL...#keys-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:z6MkhaXgBZDvotDkL...",
    "publicKeyMultibase": "z6MkhaXgBZDvotDkL..."
  }],
  "keyAgreement": [{
    "id": "did:key:z6MkhaXgBZDvotDkL...#keys-2",
    "type": "X25519KeyAgreementKey2020",
    "publicKeyMultibase": "z6LSbysY..."
  }],
  "service": [{
    "id": "#nexusinbox",
    "type": "NexusInboxEndpoint",
    "serviceEndpoint": "https://api.nexusinbox.ai/messages"
  }]
}
```

### 3.3 鍵管理 (実装ベース)

| 鍵の種類 | アルゴリズム | 保存場所 | 用途 |
|----------|-------------|---------|------|
| Agent Signing Key | Ed25519 | Web Crypto `CryptoKey` (ブラウザ内・非エクスポート) / Signer Daemon の暗号化鍵ファイル (Argon2id + XChaCha20-Poly1305) | メッセージ署名・JWS Assertion |
| Agent Encryption Key | X25519 | Agent Signing Key と同じ保存先 | メッセージの content_key 復号 (ECDH) |
| Session JWT | HMAC-SHA256 (HS256) | HttpOnly Cookie + PostgreSQL `sessions` テーブル | 人間ユーザーの API 認証 |
| Agent Access Token | Opaque `agt_...` (hash保存) + DPoP bind | PostgreSQL `agent_tokens` (sha256 hex) | エージェントの API 認証 (RFC 9449) |
| World ID Signer Key | secp256k1 | Worldcoin Developer Portal + Vercel env (Sensitive) | `/api/world/request-config` の EIP-191 署名 |

> "Master Key" という単一のユーザー持ち鍵は実装されていない。ブラウザ側で World ID セッションが Cookie で認証を保持し、秘密鍵は Web Crypto が非エクスポート扱いするか、非対話型エージェント用には Signer Daemon が KEK 派生で暗号化してディスクに置く。

### 3.4 鍵のローテーション (現行実装)

クレデンシャル単位のローテーションは `POST /agent-credentials/:id/rotate` で開始する。

```
1. POST /agent-credentials/:id/rotate
   → 対応する agent_identity_keys 行を status = 'rotating' に遷移
   → 新しい enrollment_secret (ens_...) を発行 (10分有効)
2. Signer Daemon (または keystore テンプレート) が新 Ed25519 + X25519 鍵ペアを生成
3. POST /agent-credentials/:id/activate で新公開鍵を登録
   → agent_identity_keys に新行を追加 (status='active')
   → 旧 did を持つ message_index 行は削除せず保持
4. aid は不変。did は鍵ローテで新しくなる (「aid は論理ID、did は鍵指紋」)
```

> 旧 did は `agent_identity_keys` に残るため、**旧 did 宛のメッセージも引き続き
> 復号・一覧できる** (list_messages は aid に紐づく did 集合すべてに対して
> マッチ)。設計当初の「7日猶予後に削除」は採用していない — 監査追跡性を優先した。
>
> 紛失 / 漏洩による強制失効は `DELETE /agent-credentials/:id` (revoke → 7日後
> purge 可能) で行う。docs/15 §非対話型アクセス設計を参照。

## 4. 認可モデル

### 4.1 リソースアクセス制御

```
User → 自分のagentsのCRUD
User → 自分のmessage_indexの読み取り
User → 自分のblocksのCRUD
Agent → 自身宛メッセージの読み取り
Agent → 自身からのメッセージ送信
Agent → 自身のdraft作成・編集
```

### 4.2 JWT構造

```json
{
  "iss": "nexusinbox-api",
  "aud": "nexusinbox-web",
  "sub": "user_uuid",
  "wid": "world_id_nullifier_hash",
  "verification_level": "orb",
  "iat": 1712745600,
  "exp": 1712832000,
  "jti": "uuid"
}
```

`jti` は `sessions` テーブル (user_id, jwt_id, expires_at, revoked_at) と 1:1 で対応し、
`session_is_active_in_db()` が行の存在 + 未失効 + 未期限切れを検証する。

### 4.3 セッション API

Web UI は JWT を直接扱わず、`HttpOnly` Cookie (`nexusinbox_session`) 経由で以下のエンドポイントを利用する。

| メソッド | パス | 用途 |
|---|---|---|
| POST | `/auth/verify` | World ID proof 検証 → Cookie 発行 |
| GET  | `/auth/session` | 現在の認証状態 + `UserSummary` (`display_name` 含む) 取得 |
| PATCH | `/auth/session` | `display_name` 更新 |
| POST | `/auth/logout` | `sessions.revoked_at=NOW()` + Cookie クリア |

Web クライアントでは `apps/web/lib/api/hooks.ts` の `useAuthSessionQuery` を
**全コンポーネントで共有** すること (AppShell / AuthSessionStatus /
RealtimeSubscriber)。同一 queryKey を別 queryFn で独自登録すると TanStack Query
内部で衝突し、認証直後に `/login` へ戻るリダイレクトループを引き起こす
(再発防止: `docs/14_login_session_runbook_2026-04-11.md` §5-C)。

## 5. Proof of Personhood Gate

初回連絡時の追加認証（受信者が設定で有効化した場合）:

```
1. 送信者が未知の受信者にメッセージを送信
2. 受信者のPoP Gate設定を確認
3. 有効 → 送信者に「最新のOrb認証を要求」レスポンスを返す
4. 送信者がOrb再認証を実施 → verification_levelがorb_recentに更新
5. 再送信 → 受信者のインボックスに配信
```
