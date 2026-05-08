# 01. アーキテクチャ設計書

## 1. システム全体構成

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Layer                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────────┐  │
│  │ Web App  │  │ Desktop  │  │ Mobile (PWA / Native)    │  │
│  │(Next.js) │  │ (Tauri)  │  │                          │  │
│  └────┬─────┘  └────┬─────┘  └────────────┬─────────────┘  │
└───────┼──────────────┼────────────────────┼─────────────────┘
        │              │                    │
        ▼              ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                    API Gateway (Edge)                        │
│          Rate Limiting / Auth / Request Routing              │
└────────────────────────┬────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────────┐
        ▼                ▼                    ▼
┌──────────────┐ ┌──────────────┐  ┌──────────────────────┐
│ Identity     │ │ Messaging    │  │ Filter & Trust       │
│ Service      │ │ Service      │  │ Service              │
│              │ │              │  │                      │
│ - World ID  │ │ - 送受信     │  │ - Trust Score算出    │
│ - DID管理   │ │ - 暗号化     │  │ - スパム判定         │
│ - 鍵管理    │ │ - ルーティング│  │ - 階層型ブロック     │
└──────┬───────┘ └──────┬───────┘  └──────────┬───────────┘
       │                │                     │
       ▼                ▼                     ▼
┌─────────────────────────────────────────────────────────────┐
│                   Core Database Layer                        │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐ │
│  │ PostgreSQL   │  │ Redis         │  │ Index DB         │ │
│  │ (Identity/   │  │ (Session/     │  │ (ZK Indexing)    │ │
│  │  Trust/Block)│  │  Cache/PubSub)│  │                  │ │
│  └──────────────┘  └───────────────┘  └──────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│               BYOS Adapter Layer                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │ Local FS │  │ Google   │  │  IPFS    │  │ S3互換    │  │
│  │ Adapter  │  │ Drive    │  │ Adapter  │  │ Adapter   │  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 2. 技術スタック

### フロントエンド
| 技術 | 用途 | 選定理由 |
|------|------|----------|
| Next.js 15+ (App Router) | Web UI | SSR/RSC、PlayRoomとの技術統一 |
| Tauri v2 | Desktop App | ローカルストレージ直接アクセス |
| TanStack Query | データ取得 | キャッシュ・楽観的更新 |
| Tailwind CSS + shadcn/ui | UIコンポーネント | 高速開発 |

### バックエンド
| 技術 | 用途 | 選定理由 |
|------|------|----------|
| Rust (Axum) | Core API / Messaging | 暗号処理性能、メモリ安全性 |
| Python (FastAPI) | AI Filter / Trust Score (将来) | LLMライブラリ連携 |
| PostgreSQL 17 | Identity / Trust / Block / Session / Token / 監査ログ / DPoP nonce 共有 | 本 Phase のすべてのストレージ層 |

> **Redis は現 Phase では採用していない**。設計書 (docs/15) は Redis ベースの jti replay / revocation propagation を想定していたが、実装では `replay_nonces` / `sessions` / `agent_tokens` / `agent_audit_log` すべて PostgreSQL に集約し、単一依存で回している。sub-second propagation が必要になった段階で Redis 導入を再検討する。

### 認証・暗号
| 技術 | 用途 |
|------|------|
| World ID v4 (SDK) | 人間証明 (Proof of Personhood) |
| did:key / did:web | DID規格 |
| X25519 ECDH + HKDF-SHA256 + AES-GCM-256 | メッセージE2E暗号化 (Web Crypto API 実装) |
| Ed25519 | DID署名 / JWS Assertion |
| XChaCha20-Poly1305 + Argon2id | Signer Daemon 鍵ファイル at-rest 暗号化のみ |

### インフラ (本番の実態)
| 技術 | 用途 |
|------|------|
| Docker Compose | ローカル開発 (PostgreSQL + MinIO) |
| Vercel | フロントエンド (`app.nexusinbox.ai`) |
| Fly.io | Rust API (`api.nexusinbox.ai`) |
| Supabase | マネージド PostgreSQL 17 |
| Cloudflare R2 (S3 互換) | メッセージ暗号化 blob / 添付本体のデフォルト BYOS 先 |
| Cloudflare DNS | ドメイン解決 (CNAME flatten → Fly) |

> 初期設計段階の "Railway / Cloudflare Workers / Edge Gateway" は実装していない。現行構成は上記 6 つで完結する。

## 3. サービス間通信

```
Client ←→ API (Axum)   : HTTPS (REST) + WSS (リアルタイム通知)
API     ←→ PostgreSQL  : sqlx (コンパイル時型安全クエリ)
API     ←→ BYOS        : StorageAdapter 抽象 (LocalFS / GDrive / IPFS / S3)
API     ←→ Signer Daemon: UDS (Unix Domain Socket, 0600 パーミッション) *非対話型エージェント用
Gateway ←→ LLM Runtime : UDS / HTTP (ツール呼び出しのみ)
```

## 4. Phase 1 デプロイメント構成（単一VPS + Cloudflare Tunnel）

Phase 1 (MVP) は単一 VPS 上で全サービスを実行する構成。

```
Internet
  │
  ▼
┌─────────────────────────────┐
│   Cloudflare Named Tunnel   │  ← TLS 終端 (HTTPS → HTTP 変換)
│   app.nexusinbox.ai        │     HSTS: Next.js 側でも設定済み
└─────────────┬───────────────┘
              │ HTTP (localhost only)
              ▼
┌─────────────────────────────────────────────────────┐
│                   Single VPS                         │
│                                                     │
│  ┌──────────────────┐   ┌────────────────────────┐  │
│  │ Next.js (Web)    │──▶│ Rust/Axum (API)        │  │
│  │ :3000            │   │ :8080 (plain HTTP)     │  │
│  └──────────────────┘   └────────────┬───────────┘  │
│                                      │              │
│  ┌──────────────────┐   ┌────────────▼───────────┐  │
│  │ Signer Daemon    │◀──│ Agent Gateway          │  │
│  │ (UDS: 0600)      │   │ (UDS: 0600)            │  │
│  └──────────────────┘   └────────────────────────┘  │
│                                                     │
│  ┌──────────────┐  ┌──────────────┐                 │
│  │ PostgreSQL   │  │ Redis        │                 │
│  │ :5432        │  │ :6379        │                 │
│  └──────────────┘  └──────────────┘                 │
└─────────────────────────────────────────────────────┘
```

### TLS 終端

- **API サーバ (Rust/Axum) は plain HTTP で動作する。**
  TLS 終端は Cloudflare Named Tunnel が担当し、クライアント↔Cloudflare 間は HTTPS。
- VPS 上のポート 8080 は `iptables` / `ufw` でローカルホスト以外からのアクセスを遮断すること。
- HSTS ヘッダは Next.js `next.config.ts` で `max-age=31536000; includeSubDomains; preload` を設定済み。
- Phase 2 以降でロードバランサを導入する場合は、LB で TLS 終端に切り替える。

### 単一インスタンス依存のコンポーネント

Phase 1 は単一プロセスであるため以下の制約がある。
**複数インスタンス構成（Phase 2 以降）に移行する際は必ず対策が必要。**

| コンポーネント | Phase 1 (単一VPS) | Phase 2+ (複数インスタンス) |
|---------------|-------------------|--------------------------|
| DPoP jti replay cache | in-memory `HashMap` (120s TTL) | Redis `SET` + TTL |
| Rate limiting | in-memory per-IP counter | Redis sliding window |
| Token revocation check | DB polling | Redis pub/sub + local cache |
| WebSocket 接続管理 | per-process counter | Redis Adapter (sticky session) |

> **注意**: Phase 1 では DPoP jti replay protection は単一プロセスの in-memory キャッシュで動作する。
> 設計ドキュメント (docs/15) では Redis ベースを想定しているが、Phase 1 MVP では Redis 依存を最小化するため
> in-memory 実装を採用している。複数インスタンスに水平展開する前に Redis ベースに移行すること。

## 5. セキュリティ原則

1. **Zero Trust**: すべてのリクエストにWorld ID認証トークンを要求
2. **E2E暗号化**: メッセージ本文はクライアント側で暗号化、サーバは平文を見ない
3. **最小権限**: BYOS AdapterはOAuth scopeで最小限のアクセス権のみ要求
4. **監査ログ**: ブロック操作・鍵操作はすべて記録（改ざん防止）
