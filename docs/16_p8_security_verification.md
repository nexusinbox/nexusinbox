# 16. P8 セキュリティ検証レポート

**Date**: 2026-04-16
**Status**: Internal verification complete

---

## 1. 実装済みフェーズ一覧

| Phase | 内容 | Status |
|-------|------|--------|
| P0 | DB スキーマ (agent_identities, agent_identity_keys, agent_credentials, agent_tokens) | Done |
| P1 | POST /agent-auth/token — JWS 検証 + token 発行 | Done |
| P2 | /messages* dual-auth (Cookie + DPoP agent token) | Done |
| P3 | Refresh rotation + reuse detection | Done |
| P4 | Signer Daemon (Rust, Ed25519, XChaCha20-Poly1305, UDS, Policy L1) | Done |
| P5 | HTTP Gateway (token lifecycle, tool allow-list, Policy L2, output sanitization) | Done |
| P6 | Policy L3 + 監査ログ UI + audit events | Done |
| P7 | 緊急遮断 + 鍵ローテ UX | Done |
| P8 | セキュリティ検証 + ギャップ修正 | Done |

---

## 2. 脅威モデル対照表 (T1-T10)

| # | 脅威 | 設計上の対策 | 実装状況 |
|---|------|------------|---------|
| T1 | プロンプトインジェクションによる鍵/トークン漏洩 | 3プロセス分離 + LLM に秘密なし | **Implemented**: Signer Daemon / Gateway / LLM Runtime 分離済み。SO_PEERCRED で IPC 認証。 |
| T2 | トークン盗難 | DPoP sender-constrained + 15min AT + hash 保存 | **Implemented**: Gateway が token 取得時に `dpop_jwk` を送信し、各 `/messages*` リクエストで per-request DPoP proof を送出。API は JWK thumbprint + htm/htu/ath/iat/jti を検証。 |
| T3 | 偽造・改竄 | Ed25519 JWS Assertion | **Implemented**: token 発行時に JWS 署名検証 |
| T4 | リプレイ | jti 一意性 + iat 60秒窓 | **Partially implemented**: assertion の jti + iat 検証済み。DPoP proof の jti replay 検出はインメモリキャッシュ (TTL 120s, 定期 eviction) で単一インスタンス対応。複数インスタンス対応は未完。 |
| T5 | 権限昇格 | Scope DB 格納 + per-request 再評価 | **Implemented**: scopes は DB に格納、endpoint ごとに require_scope() で検証 |
| T6 | 内部者 DB 参照 | sha256 hash のみ保存 | **Implemented**: AT/RT とも sha256 hex で保存、平文は発行時のみ返却 |
| T7 | LLM 暴走/スパム | 3層 Policy Engine | **Implemented**: L1 (Daemon 6/hr), L2 (Gateway 20/token), L3 (Server 200/cred/day) |
| T8 | 失効伝播遅延 | Redis 失効セット | **Partial**: DB ベースの即時失効は実装済み。Redis 失効セット (sub-second propagation) は future work |
| T9 | ログインジェクション | 構造化 JSON ログ + フィールド分離 | **Implemented**: audit_log テーブルは JSONB detail フィールドにユーザ入力を分離 |
| T10 | IPC なりすまし | UDS + SO_PEERCRED + 専用 UID | **Implemented (P8)**: `--allowed-uid` フラグで SO_PEERCRED 検証。未指定時は 0600 ファイル権限のみ |

---

## 3. エンドポイント実装状況 (設計書 §9 対照)

| Method | Path | Status |
|--------|------|--------|
| POST | `/agent-credentials` | **Done** |
| POST | `/agent-credentials/:id/activate` | **Done (P8)** |
| GET | `/agent-credentials` | **Done** |
| PATCH | `/agent-credentials/:id` | **Done (P8)** |
| DELETE | `/agent-credentials/:id` | **Done** |
| POST | `/agent-credentials/:id/rotate` | **Done (P8)** |
| POST | `/agent-auth/token` | **Done** |
| POST | `/agent-auth/refresh` | **Done** |
| POST | `/agent-auth/revoke` | **Done (P8)** |
| GET | `/agent-audit-log` | **Done** |
| POST | `/agents/:id/emergency-shutdown` | **Done** (bonus) |

全 10 + 1 エンドポイント実装完了。

---

## 4. P8 で修正したギャップ

### 4.1 DPoP バリデーション (RFC 9449 完全準拠)
- `AgentAuthTokenRequest` に `dpop_jwk` フィールド追加
- `compute_jwk_thumbprint()` — RFC 7638 JWK Thumbprint 計算 (OKP, EC)
- `validate_dpop_proof()` — DPoP proof の鍵バインディング + typ/htm/htu/ath/iat/jti 検証
  - `typ: "dpop+jwt"` ヘッダ検証 (RFC 9449 §4.2)
  - `jti` replay 検出 (in-memory cache, TTL 120s, 64回ごとの eviction)
- `validate_agent_token()` に DPoP proof 検証統合 (`dpop_jkt != "none"` の場合)
- `agent_auth_refresh()` に DPoP proof 検証追加 — RT 窃取によるトークンローテーション防止 (RFC 9449 §6.1)
- `token_type` レスポンスを DPoP バインド有無で正確に返却 (`"DPoP"` or `"Bearer"`)
- Gateway が token 取得時に `dpop_jwk` を送り、`Authorization: DPoP ...` と `DPoP: <proof>` を全 API request + refresh に付与

### 4.2 欠落エンドポイント 4 件
- `POST /agent-credentials/:id/activate` — Daemon からの公開鍵登録 + JWS proof 検証 + did:key 導出
- `PATCH /agent-credentials/:id` — label / policy 更新
- `POST /agent-credentials/:id/rotate` — 鍵ローテ開始 (新 enrollment secret 発行 + 旧鍵 rotating)
- `POST /agent-auth/revoke` — エージェント自身によるトークン自己失効 (RFC 7009 準拠)

### 4.3 SO_PEERCRED (IPC 認証)
- Signer Daemon: `--allowed-uid` CLI オプション + `peer_cred()` による UID 検証
- Agent Gateway: 同上
- root (UID 0) と自プロセス UID は常に許可

### 4.4 enrollment_proof payload 検証
- `activate_agent_credential` で enrollment_proof の JWS payload をデコード・検証するように修正
- `credential_id` — proof 内の credential_id がパスパラメータと一致することを検証 (別 credential 向け proof の流用防止)
- `iat` — 現在時刻 ±60秒 のウィンドウで鮮度を検証 (古い proof の再利用防止)

### 4.5 バグ修正
- `agent_auth_token` の SQL が `user_id` を SELECT していなかった → 監査ログで panic する可能性。修正済み
- `constant_time_eq()` 関数が未定義だった → 追加
- Browser keystore が PKCS#8 文字列を JS へ戻していた → non-extractable `CryptoKey` 保存/読込へ変更
- `next.config.ts` の CSP コメントが XSS 耐性を過大評価していた → 実態に合わせて修正

---

## 5. テスト結果

| Crate | Tests | Status |
|-------|-------|--------|
| services/api | 111 | All passing |
| services/signer-daemon | 10 | All passing |
| services/agent-gateway | 12 | All passing |
| **Total** | **133** | **All passing** |

### 5.1 DB integration tests の実行手順

`activate` の `credential_id` / `iat` 異常系や block list の一部は、実 DB を使う integration test として用意している。通常の `cargo test` では自動スキップされるため、必要なときだけ以下を実行する。

1. Postgres を起動する

```bash
# from repo root
docker-compose up -d postgres
```

2. `DATABASE_URL` と `AGENT_INBOX_DB_TESTS` を設定する

```bash
export DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox
export AGENT_INBOX_DB_TESTS=1
```

3. マイグレーションを適用する

```bash
# from repo root
for f in services/api/migrations/*.sql; do
  psql "$DATABASE_URL" -f "$f"
done
```

4. 対象テストを実行する

```bash
# from repo root
cargo test --manifest-path services/api/Cargo.toml --test agent_credential_test -- --nocapture
cargo test --manifest-path services/api/Cargo.toml --test blocks_db_integration_test -- --nocapture
```

5. `activate` 系だけを絞って見る場合

```bash
# from repo root
AGENT_INBOX_DB_TESTS=1 cargo test --manifest-path services/api/Cargo.toml activate_ -- --nocapture
```

### 5.2 最短ルート: ローカル Postgres を立てて attachment / cross-user DB test を回す

P1/P2 の送受信回りを最短で確認したい場合は、repo 同梱の `docker-compose.yml` を使うのが一番速い。

1. Postgres を起動する

```bash
# from repo root
docker-compose up -d postgres
```

2. 起動確認をする

```bash
# from repo root
docker-compose ps
docker-compose logs postgres --tail=50
```

`database system is ready to accept connections` が見えれば OK。

3. attachment / cross-user の DB integration test を実行する

```bash
# from repo root
AGENT_INBOX_DB_TESTS=1 \
DATABASE_URL=postgres://agent_inbox:agent_inbox@127.0.0.1:5432/agent_inbox \
cargo test --manifest-path services/api/Cargo.toml \
  --test attachments_db_integration_test \
  --test cross_user_delivery_db_integration_test \
  -- --nocapture
```

4. 使い終わったら停止・破棄する

```bash
# from repo root
docker-compose down -v
```

### 5.3 よくあるつまずき

- `failed to lookup address information: nodename nor servname provided, or not known`
  - `DATABASE_URL=postgres://...` の `...` をそのまま使っている可能性が高い。
  - 上の実値入りコマンドをそのまま使うこと。

- `skipping: set AGENT_INBOX_DB_TESTS=1 to run DB integration tests`
  - `AGENT_INBOX_DB_TESTS=1` が付いていない。

- `connection refused`
  - Postgres が起動していない。`docker-compose up -d postgres` と `docker-compose logs postgres --tail=50` を確認する。

- 共有 DB を使ってよいか
  - 非推奨。これらの test は `TRUNCATE ... RESTART IDENTITY CASCADE` を実行するため、ローカルの開発用 DB か専用の test DB を使うこと。

補足:
- `AGENT_INBOX_DB_TESTS=1` が未設定だと、該当テストは `skipping: set AGENT_INBOX_DB_TESTS=1 ...` を出して終了する。
- テスト内で `TRUNCATE ... RESTART IDENTITY CASCADE` を実行するため、共有 DB ではなく開発用 DB を使うこと。
- `AGENT_INBOX_DATABASE_REQUIRED=true` は各 DB integration test 側で明示的に設定している。

---

## 6. 残存リスク (外部監査で重点確認推奨)

| # | リスク | 深刻度 | 備考 |
|---|--------|--------|------|
| R1 | DPoP per-request jti replay が単一プロセス内メモリ依存 | Medium | 複数 API インスタンス構成では Redis/DB ベースの共有 nonce store が必要 |
| R2 | DPoP `htu` は API の実パス基準 (`/messages...`) で照合 | Low | Next.js `/api/*` proxy 越し利用を Gateway 側で吸収しているが、将来 proxy 構成変更時は再確認が必要 |
| R3 | Redis 失効セット未実装 (T8) | Medium | DB ベースの失効は即時。sub-second propagation には Redis 必要 |
| R4 | Browser 内の秘密鍵利用は XSS 耐性そのものではない | Medium | raw export は抑止したが、同一オリジン JS による sign/derive 呼び出しはなお可能。CSP/依存管理が重要 |
| R5 | Gateway の search_contacts ツール未実装 | Low | 連絡帳外宛先制限は L3 で対応可能 |
| R6 | 監査ログの append-only ストレージ (S3 + object lock) | Low | MVP 後の対応 |
| R7 | Windows 対応 (Named Pipe + ACL) | Low | 設計書 §13.2 で認識済み |

---

## 7. 結論

P2〜P8 の実装により、設計書 `docs/15_non_interactive_agent_access_design.md` の核心要件は一通りカバーされた。全 10 エンドポイントが実装され、3 プロセス構成 + SO_PEERCRED + DPoP sender-constrained token が動作する。残課題は主に複数インスタンス運用時の replay/失効共有と、ブラウザ側 XSS 耐性の追加強化である。

外部ペネトレーションテストで R1-R3 の残存リスクを優先的に検証し、本番公開前に対処することを推奨。
