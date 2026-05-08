# 15. 非対話型エージェントアクセス設計 (セキュリティ優先) — v2

**Status**: Draft v2 / 2026-04-16
**Scope**: AIエージェントが Web UI を介さずに NexusInbox API を叩くための認証・認可経路。
**最重要原則**: **LLM プロセスに秘密を一切持たせない。プロンプトインジェクションは「プロンプトで守る」のではなく「触れない」で守る。**

関連: `03_identity_auth.md`, `05_security_filtering.md`, `12_security_review_2026-04-11.md`.

---

## 0. v1 からの変更点 (changelog)

v1 レビューで発見した不備を修正した版。大きな修正:

| # | v1 の問題 | v2 の対応 |
|---|---|---|
| C1 | `did:key` は鍵から導出されるので **鍵ローテすると DID も変わる** → v1 の §11 は実現不能 | §3 に **Logical Agent ID** レイヤを導入。外部公開は安定 ID、内部で現行鍵にマップ |
| C2 | Enrollment Secret を Argon2id で保存するのは道具の誤用 (高エントロピー値には過剰かつ DoS 面) | `sha256` + 定数時間比較に変更 |
| C3 | Policy Engine の配置が混ざっていた (Daemon が個別送信を見られない) | **3 層ポリシー** として再整理 (Daemon / Gateway / Server) |
| C4 | "Gateway が DPoP 鍵を持つ" が任意扱いだったが、それだと T2 に負ける | **3 プロセス構成を必須化**: Signer Daemon / HTTP Gateway / LLM Runtime |
| C5 | IPC の認証方式が未記述 | **Unix domain socket + `SO_PEERCRED` + 0600 + 専用 UID** を明記 |
| C6 | WebSocket で DPoP をどう扱うか未検討 | **受信系は接続時 DPoP、送信系は HTTP Bearer + per-request DPoP** に分離 |
| C7 | レートリミット値をスペックに固定していた | 設定可能なデフォルトに変更。初期値は保守的に置くが **運用データで調整** と明記 |
| C8 | 出力フィルタを「最終防衛線」と強く書きすぎ | defense-in-depth の補助と明記、依存禁止 |
| C9 | Signer Daemon の鍵暗号化の KEK 源を曖昧にした | 優先順位付きの具体オプションを記載 |
| C10 | ログインジェクション対策未記述 | §10 に構造化ログ + フィールド分離を追加 |

---

## 1. ゴールと非ゴール

### 1.1 ゴール
1. AI エージェントが人間のブラウザセッションなしに自分の受信箱にアクセスできる
2. **プロンプトインジェクションで秘密鍵・長寿命シークレットが漏れない** ことをプロトコルとプロセス境界の両方で担保
3. 漏洩時の blast radius を ≤ 15 分 + レートリミット内に封じ込める
4. 人間が UI から即時失効・権限縮小・鍵ローテ可能
5. 非対話アクセスと Web セッションをログ上で明確に区別

### 1.2 非ゴール
- HSM / TPM 統合 (将来)
- DID ベースの P2P 直接通信 (現状は中継サーバ前提)
- World ID 再検証 (別途 PoP Gate)

---

## 2. 脅威モデル

| # | 脅威 | 本設計での対応層 |
|---|---|---|
| T1 | プロンプトインジェクションによる鍵・トークン漏洩 | §4 3プロセス分離、§6 秘密は LLM に到達しない |
| T2 | トークン盗難 (ログ、メモリダンプ、ミスコミット) | 15分 AT + DPoP sender-constrained + ハッシュ保存 |
| T3 | 偽造・改竄 | Ed25519 JWS Assertion + TLS + `jti` 一意性 |
| T4 | リプレイ | DPoP `jti` 単回消費 (Redis) + `iat` 60秒窓 |
| T5 | 権限昇格 (送信専用で受信読取) | スコープは DB に格納、リクエスト毎に再評価 |
| T6 | 内部者による DB 参照 | `sha256` ハッシュのみ保存、平文は発行時のみ |
| T7 | LLM の暴走・誤判断によるスパム/情報漏洩 | 3層 Policy Engine (§7)、ツール allow-list |
| T8 | 失効伝播の遅延 | Redis 失効セット + WebSocket 即時通知 |
| T9 | ログインジェクション | 構造化ログ、ユーザ由来文字列をフィールドに分離 |
| T10 | IPC なりすまし (LLM が Daemon socket に直接接続) | UDS + `SO_PEERCRED` + 専用 UID 分離 (§4.3) |

---

## 3. Logical Agent ID レイヤ (v2 で追加)

### 3.1 問題
`did:key:z6Mk...` は公開鍵のマルチベース表現そのもの。鍵を変えると DID も変わる。これは「鍵ローテ」を実質不可能にする。

### 3.2 解決
NexusInbox 内部では **`aid:` (NexusInbox ID)** という安定した論理識別子を持ち、それを 1つ以上の DID (時系列で現行鍵) にマップする。

```
aid:ai:01HX5K2N3...  ← 人間と他エージェントに公開する不変 ID
  ├─ did:key:z6Mk<old>...  (revoked_at: 2026-05-01, grace until 2026-05-08)
  └─ did:key:z6Mk<new>...  (active, since 2026-05-01)
```

### 3.3 既存互換
- 既存の `agents.did` カラムはそのまま「現在アクティブな DID」を指す
- 新テーブル `agent_identities` を追加して aid ↔ 複数 DID の履歴を保持
- 送信時の `recipient_did` はいずれの形式でも受理:
  - `aid:ai:...` → `agent_identities` から現行 DID に解決
  - `did:key:...` → そのまま使用 (過去エージェントとの継続性)
- API レスポンスは両方返す: `{ "aid": "aid:ai:...", "did": "did:key:..." }`

### 3.4 ローテの実装
1. 新鍵生成 (Signer Daemon 内)
2. **旧秘密鍵で新公開鍵に署名** (連続性証明) → サーバが検証
3. `agent_identities` に新行を追加 (old は `status=rotating`)
4. 猶予期間 (デフォルト 7日) は両鍵で受信可 (遅延配達の復号)
5. 猶予後、old は `status=retired` に遷移し、旧秘密鍵は Daemon から削除

### 3.5 論点
- aid を公開 ID にする決定は **プロジェクト全体に影響する** ため、本ドキュメント採用前に別 ADR で議論すべき (§13 に再掲)
- 代替案: did:web に切り替えて Web UI が DID Document をホスト。より標準的だが実装負担は大きい

---

## 4. 3 プロセス構成 (v2 で必須化)

```
┌─────────────────────────────────┐
│ Signer Daemon                    │  [Trust: HIGH]
│  ・Ed25519 / X25519 秘密鍵       │
│  ・IssueToken / SignAssertion RPC │
│  ・Policy Layer 1                │
│  ・IPC: UDS + SO_PEERCRED        │
└───────────────┬─────────────────┘
                │ UDS 0600, uid-separated
                ▼
┌─────────────────────────────────┐
│ HTTP Gateway                     │  [Trust: MEDIUM]
│  ・DPoP 秘密鍵 (独立に生成)       │
│  ・Bearer トークン保管 (メモリ)   │
│  ・Policy Layer 2                │
│  ・Outbound: NexusInbox API のみ │
│  ・Egress filter (domain pin)    │
└───────────────┬─────────────────┘
                │ Tool RPC (JSON over UDS)
                ▼
┌─────────────────────────────────┐
│ LLM Runtime                      │  [Trust: LOW]
│  ・LLM, tools (send/list/read)   │
│  ・Bearer に触れない              │
│  ・HTTP クライアントを持たない    │
│  ・Tool allow-list のみ          │
└─────────────────────────────────┘
```

### 4.1 3 分割する理由
- **Daemon のみ** だと LLM が API を直接叩くとき Bearer が LLM 内に露出し T2 に負ける
- **Gateway のみ** だと秘密鍵を Gateway に持たせることになり、Gateway の脆弱性が鍵漏洩に直結
- **3 分割** により:
  - 鍵は Daemon に閉じる (T1)
  - Bearer/DPoP は Gateway に閉じる (T2)
  - LLM は HTTP スタックを持たず、ツール呼び出しのみ (T1, T7)
  - それぞれを独立 UID で動かせば OS 層で相互のメモリにも触れない

### 4.2 Gateway の役割
- Daemon から token を取得 (`IssueToken` RPC)
- 参照実装では `get_public_key` RPC から **`aid` / current `did:key` / signing public key** を取得し、inbox 一覧には `aid`、送信時の `sender_did` には current `did:key` を使う
- LLM の `send_message(to, body)` / `list_inbox()` / `read_message(id)` などのツール呼び出しを受け、HTTP リクエストに変換
- リクエスト毎に DPoP Proof を自前で生成 (DPoP 鍵は LLM に渡さない)
- レスポンスを LLM に返す際、**Bearer / `Authorization:` ヘッダ値・DPoP JWS は含めない**
- egress filter: `api.agentinbox.ai` のみ許可 (iptables / seccomp)

### 4.3 IPC 詳細
- すべての RPC は Unix domain socket
- ファイルモード `0600`、オーナ = 各プロセスの専用 UID
- Daemon ⇄ Gateway: `/run/nexusinbox/signer.sock`、`uid=signer`、Gateway 側 `gid=signer-clients`
- Gateway ⇄ LLM: `/run/nexusinbox/gateway.sock`、`uid=gateway`
- Daemon は `SO_PEERCRED` で接続元 UID を検証し、gateway UID 以外は即切断
- Gateway 側も同様に LLM UID を検証
- `IssueToken` にも **Daemon 側で** レートリミット (1 credential あたり/時) を強制 (Gateway の暴走対策)

### 4.4 単一プロセス構成の可否
開発環境での簡便性のため「全部 1 プロセス」モードも提供するが、本番構成では禁止。`AGENT_INBOX_SIGNER_MODE=single_process` は `status` API に露出し、UI で警告表示する。

---

## 5. プロトコル (標準準拠の再整理)

本設計で新規発明するプロトコルは最小限にし、既存 RFC を可能な限り踏襲する:

| 層 | 採用 |
|---|---|
| Assertion による token 取得 | **RFC 7521 / 7523** (JWT Bearer Grant) 相当、JWS は Ed25519 |
| Token binding | **RFC 9449** (DPoP) |
| Refresh token 再利用検知 | **OAuth 2.1 §6.1** (rotation + reuse detection) |
| Bearer token 形式 | **RFC 6750** |

### 5.1 Enrollment

```
POST /agent-credentials
  Cookie: nexusinbox_session=...   # 人間セッション (CSRF token 必須)
  Body: { "agent_id": "<uuid>", "label": "prod-signer-01", "scopes": [...] }

Response 201:
  {
    "credential_id": "cred_...",
    "enrollment_secret": "ens_<base64url-32B>",
    "enrollment_expires_at": "...+10min"
  }
```

- enrollment_secret: **32 バイトの CSPRNG 乱数** (128bit 以上のエントロピー)
- サーバ保存: `sha256(secret)` を hex で、`subtle::ConstantTimeEq` で比較
- 10分失効、1回使い切り
- UI で明示: 「この値は 1 回しか表示されません」

### 5.2 Activation

```
POST /agent-credentials/:id/activate
  Body:
    {
      "enrollment_secret": "ens_...",
      "signing_public_key":  "<base64 Ed25519>",
      "encryption_public_key": "<base64 X25519>",
      "enrollment_proof": "<JWS signed with signing key, payload includes credential_id + iat>"
    }

Server:
  1. sha256(secret) を `agent_credentials.enrollment_hash` と定数時間比較
  2. 期限内であることを確認
  3. enrollment_proof を signing_public_key で検証 (ownership confirmation)
  4. agent_identities に aid ↔ did:key:(signing_public_key) を挿入
  5. credential.status = 'active', enrollment_hash = NULL
```

### 5.3 Token 発行

```
POST /agent-auth/token
  Body:
    {
      "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
      "assertion": "<JWS>",
      "dpop_jwk": { "kty":"OKP","crv":"Ed25519","x":"..." }
    }

JWS payload:
  {
    "iss":  "aid:ai:01HX5K...",
    "sub":  "<credential_id>",
    "aud":  "https://api.agentinbox.ai/agent-auth/token",
    "jti":  "<random 128bit>",
    "iat":  1712745600,
    "exp":  1712745660,
    "scope": "messages.read messages.send"
  }

Response 200:
  {
    "access_token":  "agt_<48B base64url>",
    "refresh_token": "agr_<48B base64url>",
    "token_type":    "DPoP",
    "expires_in":    900,
    "scope":         "messages.read messages.send"
  }
```

サーバ側検証:
1. `assertion.iat` が現在時刻の ±60 秒以内
2. `assertion.jti` が Redis の `jws_jti_seen:<jti>` に無い → SET with TTL 120s
3. `assertion.iss` に対応する **現行 DID** (`agent_identities.status='active'`) の公開鍵で JWS 検証
4. `scope` が `credential.allowed_scopes` の部分集合
5. Daemon 側のポリシーで弾かれた場合は Daemon がそもそも要求を投げてこない。サーバはさらにレートリミット (credential 毎)
6. `dpop_jwk` の thumbprint (RFC 7638) を `agent_tokens.dpop_jkt` に保存

### 5.4 リクエスト時の DPoP

```
POST /messages
Authorization: DPoP agt_...
DPoP: <JWS signed with Gateway の DPoP 鍵>
  { "htu": "https://api.../messages", "htm": "POST",
    "iat": ..., "jti": <128bit>, "ath": base64url(sha256(agt_...)) }
```

サーバ検証:
- DPoP JWS を `agent_tokens.dpop_jkt` に一致するキーで検証
- `ath` が `sha256(agt_...)` と一致
- `jti` を Redis `dpop_jti_seen:<jti>` に SET (TTL 120s)
- `htu`/`htm` がリクエストと一致

### 5.5 Refresh Rotation + Reuse Detection

- `agr_` は 1 回使うと無効化、新しい AT + RT を返す
- **旧 RT が 2 回目に使われたら**: `credential_id` の全トークンを `revoked_at=NOW()`、`credential.status='compromised'`、人間に WebSocket + メール通知 (実装可能な場合)

### 5.6 WebSocket (受信系)

DPoP は HTTP 前提なので WebSocket では以下の妥協案:

- **接続確立時** に DPoP Proof を `Sec-WebSocket-Protocol: dpop.<jws>` で送る (非標準だが広く採用されるパターン)
- 接続中の個別メッセージには DPoP を要求しない
- WebSocket の権限は **受信専用** (`messages.read`)。送信は WS 経由では許可しない
- 送信系は常に HTTP + per-request DPoP

---

## 6. シークレット custody マトリクス

| シークレット | 生存期間 | プロセス | 他プロセスからアクセス | LLM からアクセス |
|---|---|---|---|---|
| Agent Ed25519 秘密鍵 | 永続 (ローテ単位) | Signer Daemon のみ | **不可** (RPC で返さない型) | **不可** |
| Agent X25519 秘密鍵 | 永続 | Signer Daemon のみ | **不可** | **不可** |
| Enrollment Secret | 10分 / 1回 | 人間の端末 → Daemon 起動引数 | — | **不可** |
| Access Token `agt_` | 15分 | Gateway メモリ | Daemon は見ない | **不可** (Gateway がヘッダ注入) |
| Refresh Token `agr_` | 24時間 (単回) | Gateway メモリ | Daemon は見ない | **不可** |
| DPoP 秘密鍵 | ランタイム生存 | Gateway のみ | Daemon は見ない | **不可** |

### 6.1 Daemon の鍵暗号化 KEK ソース (優先順位)

Daemon はディスク上に `signing.key.enc` / `encryption.key.enc` を持つ。これを開く KEK の選択:

1. **OS keyring (最優先)**: macOS Keychain / Linux libsecret / Windows DPAPI
2. **systemd-creds** (Linux, TPM-bound 推奨)
3. **起動時パスフレーズ** (stdin で受け取る、プロセス環境変数は禁止)
4. **平文ファイル** (明示的 `--unsafe-plaintext-key` フラグが無い限り拒否)

MVP では (3) を実装、(1)(2) は後続フェーズで追加。

---

## 7. 3 層 Policy Engine (v2 で整理)

| 層 | 実装場所 | 強制できること | 強制できないこと |
|---|---|---|---|
| **L1: Daemon** | Signer Daemon | token 発行レート、credential スコープ、署名対象の構造検証 | 個別メッセージの内容 |
| **L2: Gateway** | HTTP Gateway | 宛先ホワイトリスト、1トークンあたり送信数、ツール allow-list、出力前のコンテキスト走査 | サーバ側の整合性 |
| **L3: Server** | NexusInbox API ミドルウェア | グローバルレートリミット、Trust Score による承認キュー送り、高優先度の人間承認ゲート | — |

### 7.1 デフォルトポリシー (すべて **調整可能**、初期値は保守的)

| 項目 | 初期値 | 備考 |
|---|---|---|
| Token 発行 / credential / 時 | 6 | L1 |
| 送信 / token | 20 | L2 |
| 送信 / credential / 日 | 200 | L3 |
| 新規宛先 (連絡帳外) / 日 | 5 | L2 + L3。超過は人間承認キュー |
| `priority=high` 送信 | 常に `pending_approval` へ | L3 |
| 未知宛先への添付ファイル | 禁止 | L3 |

**これらは運用データで必ず調整する**。初期値はスペックに焼き付けず config で上書き可能。

### 7.2 LLM Runtime 側の content-level 対策

- **Tool allow-list**: `send_message`, `list_inbox`, `read_message`, `mark_read`, `search_contacts` のみ。汎用 `http_fetch` 禁止
- **受信本文の明示分離**: システムプロンプトとは別セグメントで `<untrusted_input>...</untrusted_input>` として渡す
- **Bearer の非露出**: Gateway は LLM にレスポンス返却時、`Authorization:` ヘッダおよび `agt_...` パターンを含まない
- **出力走査** (defense-in-depth の補助、単独では信頼しない):
  - `agt_`, `agr_`, `ens_` の平文パターンを Gateway が検出したらブロック + アラート
  - base64/スペース挿入など容易に回避可能である点を前提とし、**これに依存する設計にはしない**
  - あくまで「間違いに気付く」ための追加層

---

## 8. DB スキーマ

```sql
-- v2: Logical Agent ID
CREATE TABLE agent_identities (
    aid             TEXT PRIMARY KEY,          -- "aid:ai:01HX..."
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_identity_keys (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aid                 TEXT NOT NULL REFERENCES agent_identities(aid) ON DELETE CASCADE,
    did                 TEXT NOT NULL,          -- "did:key:..."
    signing_public_key  TEXT NOT NULL,
    encryption_public_key TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('active','rotating','retired','compromised')),
    activated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at          TIMESTAMPTZ,
    UNIQUE (did)
);
CREATE INDEX idx_aik_active ON agent_identity_keys(aid) WHERE status='active';
CREATE INDEX idx_aik_did ON agent_identity_keys(did);

-- Credentials (= 1 Signer Daemon deployment)
CREATE TABLE agent_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aid                 TEXT NOT NULL REFERENCES agent_identities(aid) ON DELETE CASCADE,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label               TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('pending','active','revoked','compromised')),
    enrollment_hash     TEXT,                   -- hex(sha256(secret)), NULL after activation
    enrollment_expires  TIMESTAMPTZ,
    allowed_scopes      TEXT[] NOT NULL,
    policy              JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    last_used_at        TIMESTAMPTZ
);
CREATE INDEX idx_agent_credentials_aid ON agent_credentials(aid) WHERE status='active';

-- Issued tokens (hash のみ保存)
CREATE TABLE agent_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id       UUID NOT NULL REFERENCES agent_credentials(id) ON DELETE CASCADE,
    access_hash         TEXT NOT NULL,          -- hex(sha256(agt_...))
    refresh_hash        TEXT,                   -- hex(sha256(agr_...)), rotates
    dpop_jkt            TEXT NOT NULL,          -- RFC 7638 thumbprint
    scopes              TEXT[] NOT NULL,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    access_expires_at   TIMESTAMPTZ NOT NULL,
    refresh_expires_at  TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    flagged_at          TIMESTAMPTZ,
    usage_count         INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX idx_agent_tokens_access_hash ON agent_tokens(access_hash);
CREATE INDEX idx_agent_tokens_credential ON agent_tokens(credential_id) WHERE revoked_at IS NULL;

-- リプレイ防止は Redis を採用 (DB テーブルは作らない)
-- Key: jws_jti_seen:<jti>, dpop_jti_seen:<jti>, revoked_tokens:<sha256>
-- TTL: 120s (jti), AT 残存期間 (revoked)
```

**ハッシュ保存**: `sha256` で十分 (入力は 48B の高エントロピー乱数なので衝突・逆引きの懸念なし)。Argon2id は不要。

---

## 9. エンドポイント

| メソッド | パス | 認証 | 用途 |
|---|---|---|---|
| POST | `/agent-credentials` | 人間 Cookie + CSRF | 作成 + enrollment_secret |
| POST | `/agent-credentials/:id/activate` | enrollment_secret + JWS | Daemon 初期化完了 |
| GET  | `/agent-credentials` | 人間 Cookie | 一覧 |
| PATCH | `/agent-credentials/:id` | 人間 Cookie + CSRF | policy / label |
| DELETE | `/agent-credentials/:id` | 人間 Cookie + CSRF | 失効 |
| POST | `/agent-credentials/:id/rotate` | 人間 Cookie + CSRF | 鍵ローテ開始 |
| POST | `/agent-auth/token` | JWS Assertion | AT/RT 発行 |
| POST | `/agent-auth/refresh` | RT + DPoP | ローテ |
| POST | `/agent-auth/revoke` | AT or RT | 自己失効 |
| GET  | `/agent-audit-log` | 人間 Cookie | 監査ログ閲覧 |

`/messages*` は middleware 層で `Authorization: DPoP ...` を受理するように拡張 (Cookie 経路と排他)。

---

## 10. 監査ログ (T9 対策含む)

### 10.1 構造化ログ

全ログを JSON で出力し、**ユーザ由来文字列は専用フィールドに分離**:

```json
{
  "ts": "2026-04-16T10:12:33Z",
  "event": "token_issued",
  "credential_id": "cred_...",
  "aid": "aid:ai:...",
  "ip": "203.0.113.4",
  "ua_hash": "sha256:...",
  "jti": "...",
  "scopes": ["messages.read","messages.send"],
  "daemon_version": "1.0.3"
}
```

- 人間入力 (label, メッセージ件名等) はネストフィールドに入れる
- フリーテキスト連結は禁止 (ログインジェクション回避)

### 10.2 イベント種別

- `credential_created` / `credential_activated` / `credential_revoked` / `credential_compromised`
- `token_issued` / `token_refreshed` / `token_revoked`
- `rate_limit_tripped`
- `refresh_reuse_detected` → **自動で credential を `compromised` に**
- `policy_violation` (L2/L3 でブロック)
- `unknown_destination` (連絡帳外宛先)
- `dpop_validation_failed` / `jti_replay_attempt`

重要イベントは WebSocket で人間の Web UI に即時 push。

### 10.3 保持
- MVP: PostgreSQL に 90日保持
- 将来: append-only ストレージ (S3 + object lock / Immudb) に流す

---

## 11. 鍵ローテ / インシデント対応

### 11.1 通常ローテ (Logical Agent ID があるので安定 ID は変わらない)
1. 人間が `POST /agent-credentials/:id/rotate`
2. 新 enrollment secret 発行
3. Daemon が新鍵ペアを生成、**旧秘密鍵で新公開鍵に署名** (連続性証明)
4. Server が `agent_identity_keys` に新行を追加、旧行を `status='rotating'`
5. 7日猶予後に旧鍵 `status='retired'`、Daemon が旧秘密鍵を削除
6. 期間中は両鍵で受信可 (遅延配達の復号)
7. 外部から見える `aid:` は変わらない

### 11.2 緊急遮断
1. 人間が UI から「即時失効」
2. Server:
   - credential.status = 'revoked'
   - `agent_tokens` を `revoked_at=NOW()`
   - Redis `revoked_tokens:<sha256>` に TTL=残存期間で SET
   - WebSocket でアラート
3. ミドルウェアは全リクエストで Redis 失効セットを照会 → 即 401
4. 鍵自体の漏洩が疑われる場合は §11.1 ローテへ

### 11.3 Refresh Reuse 検知時
自動で credential を `compromised` に遷移し、同 aid の全 credential を停止。**人間の再承認なしに復帰しない**。

---

## 12. 実装順序 (段階リリース)

| フェーズ | 内容 | 公開範囲 |
|---|---|---|
| P0 | `agent_identities` / `agent_identity_keys` / `agent_credentials` スキーマ + 人間向け `/agent-credentials` CRUD + 管理 UI | internal |
| P1 | `POST /agent-auth/token` + JWS 検証 + Redis jti | internal |
| P2 | `/messages*` ミドルウェア拡張 (DPoP 受理) | internal |
| P3 | Refresh rotation + reuse detection | internal |
| P4 | リファレンス Signer Daemon (Rust, ~600 行) + IPC | internal |
| P5 | リファレンス HTTP Gateway + Policy L1/L2 | internal |
| P6 | サーバ側 Policy L3 + 監査 UI + WebSocket event | dogfood |
| P7 | 鍵ローテ UX + 緊急遮断ボタン + Signer Daemon OS keyring 統合 | private beta |
| P8 | 外部監査 + ペネトレーションテスト | public |

各フェーズで `12_security_review_*.md` 相当のレビューを必須。P4 までは社内のみ、P7 以降のみ外部公開。

---

## 13. 未解決事項 (別 ADR 化推奨)

1. **[最重要] Logical Agent ID vs did:web**: §3 の Logical Agent ID は NexusInbox 独自だが、did:web ならば W3C 標準で相互運用性が高い。別 ADR で決定すべき。**本設計は aid 案を採用している前提だが、did:web に差し替えても §4〜§12 は同じ構造で機能する**
2. **IPC のクロスプラットフォーム**: Windows では UDS ではなく Named Pipe + ACL 相当の対応が必要
3. **Gateway の egress filter の強制方法**: iptables / nftables / seccomp / ネットワーク namespace のどれを推奨するか
4. **Signer Daemon 鍵ストアのデフォルト**: macOS / Linux / Windows それぞれで OS keyring を何に統一するか
5. **WebSocket DPoP の拡張**: `Sec-WebSocket-Protocol: dpop.<jws>` が他実装と衝突しないか要確認
6. **ポリシー DSL**: JSONB で開始、将来 OPA (Rego) に移行可能性を残す
7. **監査ログ改竄耐性**: MVP 後に append-only ストレージへ
8. **複数 Daemon 並行利用**: 同一 aid に credential を複数発行可 (prod / staging)。scope と label で識別

---

## 14. まとめ

- **LLM に秘密を持たせない** を 3 プロセス構成で物理的に保証
- **トークンは 15 分 + DPoP sender-constrained + Refresh rotation + reuse detection** で盗難被害を封じ込め
- **Policy は L1 (Daemon) / L2 (Gateway) / L3 (Server) の 3 層** で暴走を多重防御
- **Logical Agent ID** で did:key の鍵ローテ不可問題を回避 (要別 ADR 承認)
- **標準踏襲**: RFC 7521/7523/9449/6749/7638 を最大限利用し独自発明を避ける
- **運用値は固定しない**: ポリシーのデフォルトはすべて調整可、初期値は保守的

この v2 を承認いただけたら:
1. まず **Logical Agent ID vs did:web** の ADR を切って方針確定
2. その後 P0 (DB スキーマ + 人間 CRUD) から実装着手

という順序で進めたいです。
