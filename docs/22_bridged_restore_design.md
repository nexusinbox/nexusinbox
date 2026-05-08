# 22. Bridged Restore — Daemon-Isolated Message on Web

**Date**: 2026-04-22
**Status**: Design / ADR (Phase 3 of docs/21)
**Scope**: Isolated mode (Signer Daemon) が握っている message を、ユーザーの明示操作時にのみ Web UI 上で一時表示するためのアーキテクチャ選定と採用方針

関連:
- [15_non_interactive_agent_access_design.md](./15_non_interactive_agent_access_design.md)
- [20_mcp_skill_strategy.md](./20_mcp_skill_strategy.md)
- [21_message_visibility_ux_for_mcp_modes.md](./21_message_visibility_ux_for_mcp_modes.md)

---

## 0. Decision summary (TL;DR)

- **採用: Option C — Daemon 自体に localhost HTTP listener を追加**
  - 別プロセス (companion / bridge) を増やさない
  - Origin / CSRF 検証は daemon 側で完結
  - `unwrap_content_key` は既存 UDS RPC を内部再利用
- **必須ガード**:
  - `127.0.0.1` / `::1` のみ listen (非公開バインド)
  - `Origin: https://app.nexusinbox.ai` のみ許可 + pre-flight `OPTIONS` で検証
  - Browser ↔ Daemon の pairing (session secret) を最初に人間が確認
  - 1 回 1 message のみ、都度 user consent
  - 復号結果はサーバ round-trip しない — browser memory のみ、TTL 5 分で破棄
  - audit: daemon stderr に `bridged_decrypt` 構造化ログを出力 (Phase 3a) + API `agent_audit_log` への per-event JWS 転送 (Phase 3c, opt-in)
- **Phase 分割**:
  - **3a (shipped)**: pairing なし (localhost + origin だけで防御) + single-message decrypt + local stderr 構造化 audit
  - **3b (shipped)**: pairing code UI + paired-sessions list + revoke-this / revoke-all + session-label audit
  - **3c (shipped)**: Policy L3 rate cap (per-min + per-day) + session nonce binding + API audit forwarding + audit dashboard preset + browser 側 bearer の at-rest AES-GCM 暗号化 (daemon 側 OS keychain は restart=revoke invariant を壊すので意図的に採用しない)

---

## 1. 問題設定

Phase 2.5 以降、Isolated mode (Signer Daemon) で運用される agent が持つ X25519 秘密鍵は daemon プロセスから一切出ない。これにより:

- **利点**: 鍵の at-rest / in-memory 露出面が最小。ブラウザ拡張 / localStorage の漏洩リスクから独立
- **欠点**: Web UI ではその agent 宛の本文を復号できず、inbox list / detail で "Daemon-isolated" bade + explanatory card が出る (docs/21 §3.2)

ユーザー目線のギャップ:

> 「このたった 1 通だけ、今ここで中身を見たい。Claude Desktop を立ち上げ直すほど大げさにしたくない」

このニーズを「鍵は daemon に据え置いたまま」安全に満たすのが **bridged restore**。

---

## 2. 不変条件 (Threat model)

設計が守るべき不変条件は 6 点:

1. **Private key never leaves daemon process memory**
   - X25519 秘密鍵が browser / network / disk に出ない
2. **No silent / automatic decryption**
   - 都度ユーザーの明示操作が必要。自動 restore / bulk restore は禁止
3. **No server-side plaintext**
   - 復号結果は browser ↔ daemon の LAN 内のみで流通。API サーバは一切見ない
4. **Browser memory TTL**
   - 復号結果は React state 等に保持されるが、タブ離脱 or TTL 満了で即破棄 + clipboard コピーも ephemeral
5. **Origin isolation**
   - `https://app.nexusinbox.ai` 以外の origin からの decrypt 依頼は全拒否
6. **Auditable**
   - 誰が / いつ / どの message を bridged decrypt したか追跡可能な audit トレイルが残る
   - **Phase 3a (実装済み)**: daemon プロセスが stderr に JSON Lines 形式で `bridged_decrypt` / `bridged_status` イベントを出力 (成功 / `unauthorized` / `forbidden_origin` / `bad_request` / `daemon_error` / `disabled` の全 outcome)。運用者は `2>> /var/log/nexusinbox-signer.log` 等で永続化・aggregate 可能。ペイロードは timestamp, source, event, outcome, aid, did, credential_id, origin, encrypted_key_hash (sha256), error_message。
   - **Phase 3c (実装済み)**: Phase 3b で追加した `bridged_pair_requested` / `_succeeded` / `_failed` / `_revoked` と合わせて全 6 種の `bridged_*` イベントを、daemon が `--bridge-forward-audit` で起動されているときに per-event JWS (credential の signing key で署名) を添付して `POST /agent-audit-log/bridge` へ fire-and-forget で転送。API は allow-list と stored `signing_public_key` で検証して `agent_audit_log` に格納。バースト吸収用の bounded mpsc (256 slots) overflow は stderr warn で落とすので `handle_unwrap` の hot path をブロックしない。stderr sink は並行稼働しているので、転送 opt-out しても従来通り永続化できる。`/settings/audit` には「Bridge events only」preset と `event_prefix` クエリ (alphanumeric + underscore にサニタイズ) が追加されており、6 種の bridge イベントは `EVENT_META` 経由で severity / label / description 付きで表示される。

### 2.1 想定脅威

| # | 脅威 | 対策 |
|---|------|------|
| T1 | 悪意あるブラウザ拡張が `127.0.0.1:PORT` を任意に叩いて decrypt させる | Origin header 厳格チェック + CORS preflight + pairing token |
| T2 | 同一マシン上の悪意あるローカルプロセスが daemon に decrypt リクエストを送る | pairing token は daemon 側では ephemeral memory のみ (再起動で必ず失効 = restart=revoke invariant、docs/22 §4.3)、browser 側は IndexedDB の非抽出 AES-GCM KEK で localStorage 値をラップ (docs/22 §8 Phase 3c.5) して passive dump 耐性を確保。OS keychain への永続化は restart=revoke invariant を壊すため意図的に採用しない |
| T3 | CSRF 経由で攻撃者サイトが `127.0.0.1` を叩く | `Origin` header を要求し、`app.nexusinbox.ai` 以外拒否。credentialless fetch も拒否 |
| T4 | Network proxy が `127.0.0.1` を外部公開 | daemon は loopback のみ bind、0.0.0.0 を禁止 |
| T5 | メモリダンプで復号後の plaintext が採取される | TTL で state をクリア、React 再レンダ制御、DevTools 経由の漏洩は受け入れ (host OS が侵害されている前提) |
| T6 | pairing secret が攻撃者に漏れる | secret は rotation 可能、invalidate コマンドを daemon に実装 |
| T7 | daemon が 1 秒間に大量の decrypt を要求される (abuse) | Policy L3: per-day cap (初期 50/day) + per-minute rate limit |
| T8 | 攻撃者が転送済みの bridge audit JWS を再送して `agent_audit_log` を汚染 / 別エンドポイントに流し込む | API 側 `/agent-audit-log/bridge` は `aud` を byte-equal で比較 (`AGENT_INBOX_PUBLIC_API_URL` または Host+X-Forwarded-Proto から合成) し suffix match は無効。`(credential_id, jti)` を 120 s の replay_nonces に記録、重複は 409 で reject (docs/22 §8 Phase 3c.3 ingest hardening) |

### 2.2 受容するリスク

- **Host OS 侵害**: マルウェアが動いている端末では、そもそも daemon プロセスのメモリにもアクセスできるので bridged restore に追加リスクは無い (包括)
- **DevTools 経由の plaintext 確認**: 明示操作で復号しているので user intent 上 OK

---

## 3. 方式比較

### 3.1 Option A — Browser が daemon の UDS を直叩き

```
Browser ── https://app.nexusinbox.ai (origin)
      ╲
       UDS?? ×  browser can't talk to Unix sockets directly
```

- **採用不可**: ブラウザは Unix Domain Socket に接続できない

### 3.2 Option B — 別プロセス (Local Bridge Companion)

```
Browser ──[https fetch to 127.0.0.1]── Local Bridge ──[UDS]── Daemon
```

- **利点**: bridge を daemon とは別の言語/実装で書ける (例: Electron menubar app with TLS cert)。daemon の attack surface を増やさない
- **欠点**:
  - 配布物が 2 つに増える (users must install companion)
  - pairing は bridge ↔ daemon + bridge ↔ browser の 2 段階
  - 自己署名 cert の信頼確立が煩雑
  - 開発コスト高 (Rust signer-daemon とは別 tree)

### 3.3 Option C — Daemon 内に localhost HTTP listener を追加 ★ 採用案

```
Browser ──[HTTP to 127.0.0.1:<daemon-http-port>]── Daemon
                                             │
                                             └── 既存 unwrap_content_key (内部 UDS RPC を再利用)
```

- **利点**:
  - Binary 増えない、users が追加インストール不要
  - Origin 検証 / pairing / policy がすべて 1 プロセスに集約
  - 既存 `unwrap_content_key` RPC をそのまま利用できる
  - Rust の `hyper` / `axum` は既存依存で lightweight に追加可能 (daemon は Tokio runtime 有り)
- **欠点**:
  - Daemon に HTTP 面が生える = attack surface がやや広がる (mitigated by 127.0.0.1 + origin + pairing)
  - TLS なし (loopback なので不要だが、browser の `fetch()` から HTTP origin に投げる形になる)
- **対処**:
  - `fetch(127.0.0.1:PORT)` は HTTPS ページから HTTP リクエストを出す形になるが、**loopback target は mixed-content exception** で許可される (Chrome ≥ 94, Firefox は localhost のみ特例)
  - Safari は loopback exception が無い → 初期リリースは Chrome / Arc / Edge / Firefox サポート、Safari はフォールバックで MCP runtime 利用を案内

### 3.4 Option D — Public API に proxy endpoint を置く

Web から `POST /api/bridge/decrypt` → API server が何らかの方法で daemon に届ける

- **採用不可**: 不変条件 3 (No server-side plaintext) に違反する可能性 / daemon が Fly.io から到達できない (常時 Public IP が必要)。また鍵が daemon に留まる設計なのに API server 経由にすると本末転倒

### 3.5 選定

| 項目 | Option B | Option C | 採用 |
|------|----------|----------|------|
| 追加バイナリ | companion (new) | なし | C |
| Attack surface | bridge (new) | daemon 内に HTTP (small) | C |
| 開発コスト | 高 (別 tree) | 低 (既存 Rust) | C |
| Pairing 複雑度 | 2 段 | 1 段 | C |
| Safari 対応 | (自己署名 cert 必要) | loopback exception 無し | 同等 |
| ユーザー体験 | 別アプリを常駐 | daemon だけ起動 | C |

**Option C を採用**。

---

## 4. 採用アーキテクチャの詳細

### 4.1 コンポーネント構成

```
┌──────────────────────── browser (Isolated mode user) ────────────────────────┐
│                                                                       │
│  app.nexusinbox.ai                                                   │
│  ├─ MessageUnavailableCard                                            │
│  │    "Bridged restore" button (新規、docs/21 §6.2 推奨)              │
│  │      ↓ click → consent dialog → pairing check → fetch()            │
│  ├─ BridgeClient (apps/web/lib/bridge/*)                              │
│  │    - detect()        : GET /v1/status → up?                        │
│  │    - pair(code)      : POST /v1/pair                               │
│  │    - unwrap(ck_wrap) : POST /v1/unwrap  (sends encrypted_key)      │
│  │    - invalidate()    : DELETE /v1/session                          │
│  └─ EphemeralPlaintextView                                            │
│       - Map<message_id, { subject, body, expiresAt }>                 │
│       - 自動 TTL 5 分で clear                                         │
│       - tab blur / route change で即 clear                            │
│                                                                       │
└─────────────┬─────────────────────────────────────────────────────────┘
              │  fetch("http://127.0.0.1:43417/v1/...", {
              │    method: "POST",
              │    headers: {
              │      "X-NexusInbox-Bridge": <pairing_token>,
              │      "Origin": "https://app.nexusinbox.ai"
              │    },
              │    body: { encrypted_key: "x25519v1:..." }
              │  })
              ▼
┌──────────────── signer-daemon (Rust, existing process) ────────────────┐
│                                                                        │
│  ┌──── UDS JSON-RPC (既存) ─────────┐   ┌──── HTTP listener (NEW) ─┐   │
│  │  sign_envelope                   │   │  GET  /v1/status         │   │
│  │  sign_assertion                  │   │  POST /v1/pair           │   │
│  │  unwrap_content_key ★            │   │  POST /v1/unwrap ★       │   │
│  │  get_public_key / status         │   │  DELETE /v1/session      │   │
│  └──────────────────────────────────┘   └──────────────────────────┘   │
│     ▲              ▲                                                   │
│     │              │                                                   │
│     │         内部で UDS ハンドラを呼び出し                            │
│     │         (HTTP エンドポイントは薄い皮)                            │
│     │                                                                  │
│  ┌──┴──────────── PolicyL3 (NEW) ────────────────────────┐             │
│  │  bridged_decrypts_per_day  (default 50)               │             │
│  │  bridged_decrypts_per_min  (default 3)                │             │
│  │  pairing_tokens  { token → { created_at, last_used }} │             │
│  └───────────────────────────────────────────────────────┘             │
│                                                                        │
│  ┌──────── audit sink (Phase 3a: stderr JSON Lines) ────────────────┐  │
│  │  毎回 request / outcome で 1 行 emit                              │  │
│  │  { timestamp, source: "signer-daemon-bridge",                    │  │
│  │    event: "bridged_decrypt" | "bridged_status",                  │  │
│  │    outcome: "ok" | "unauthorized" | "forbidden_origin"           │  │
│  │           | "bad_request" | "daemon_error" | "disabled",         │  │
│  │    aid, did, credential_id, origin, encrypted_key_hash,          │  │
│  │    error_message? }                                              │  │
│  │  Phase 3c で API の agent_audit_log への per-event JWS POST を   │  │
│  │  追加済み (--bridge-forward-audit, allow-list 6 種)。            │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### 4.2 HTTP endpoint の仕様

全エンドポイント共通:

- bind: `127.0.0.1:<HTTP_PORT>` + `::1:<HTTP_PORT>` (default 43417、`--bridge-port` で変更可)
- `Origin` ヘッダ必須: `https://app.nexusinbox.ai` (or `--allowed-origin` で上書き)
- `X-NexusInbox-Bridge: <pairing_token>` ヘッダ必須 (下記 §4.3)
- CORS pre-flight (`OPTIONS`) は `Access-Control-Allow-Origin: https://app.nexusinbox.ai` 固定
- レスポンスヘッダ:
  - `Cache-Control: no-store`
  - `Cross-Origin-Resource-Policy: same-origin`

#### `GET /v1/status`

```json
{
  "ok": true,
  "version": "0.1.0",
  "paired": true,
  "aid": "aid:ai:...",
  "did": "did:key:...",
  "policy": {
    "bridged_decrypts_per_day_used":  2,
    "bridged_decrypts_per_day_max":   50
  }
}
```

(pairing が済んでいない場合は `"paired": false` で上記以外は省略)

#### `POST /v1/pair` (Phase 3b)

Pairing は初回のみ。Daemon 起動時にユーザーが手動で QR / one-time code を入力する。

request:
```json
{ "pairing_code": "AIBX-1234-5678-9012" }
```

response:
```json
{ "pairing_token": "bt_<32 bytes base64url>", "expires_at": "2026-05-22T..." }
```

- `pairing_code` は daemon 起動時に stderr に 1 回だけ表示される (`Pairing code: AIBX-1234-5678-9012  (valid 5 min)`)
- コードは 5 分 TTL、消費で破棄
- 発行された `pairing_token` は ブラウザの IndexedDB に保存 (既存の recipient-keyring と同じ store)
- Token は daemon 再起動で invalidate (daemon はメモリに保持)。Long-lived にするなら将来 daemon が disk に at-rest 暗号化で保存するオプション

#### `POST /v1/unwrap` — メインエンドポイント

request:
```json
{ "encrypted_key": "x25519v1:<eph>:<salt>:<iv>:<ct>" }
```

処理:
1. pairing token 検証
2. Policy L3 check (per-day / per-minute rate)
3. 内部で既存 `unwrap_content_key` UDS ハンドラを呼ぶ (もしくは直接 `unwrap_content_key` 関数を再利用)
4. audit log を fire-and-forget で送信
5. response:

```json
{ "content_key": "c6fd..." }
```

失敗時:
- `401 Unauthorized` — pairing token 無効
- `403 Forbidden` — Origin 不一致
- `429 Too Many Requests` — Policy L3 超過
- `500 Internal Server Error` — daemon 側エラー (encrypted_key malformed 等は 400)

#### `DELETE /v1/session`

現在の pairing token を invalidate。ユーザーが Web UI から "Revoke this device" 押下で呼ぶ。

### 4.3 Pairing フロー詳細 (Phase 3b)

1. ユーザーは daemon を起動 — stderr に以下のように出力:
   ```
   [INFO] Bridge listener: http://127.0.0.1:43417
   [INFO] Pairing code:    AIBX-1234-5678-9012   (valid 5 minutes)
   ```
2. ブラウザで `/settings/agents/<agent>` → "Pair with Signer Daemon" ボタンを押す
3. モーダルが開き、`AIBX-` コードの入力フィールド
4. 入力して "Pair" → `POST /v1/pair` → `pairing_token` を受信 → IndexedDB に `nexusinbox:bridge-token:<aid>` として保存
5. 以降の restore 操作で自動付与

### 4.4 ユーザー操作フロー (正常系)

```
1. user opens daemon-isolated message
2. MessageUnavailableCard に "復元して表示" ボタン
   (pair 済みのときだけ表示 / 未 pair のときは "Set up bridge" → pairing guide)
3. user clicks
4. consent dialog "このメッセージ 1 通だけ復元しますか?"
5. user confirms
6. BridgeClient.unwrap(envelope.encrypted_key) → content_key
7. 既存の decryptEnvelopeTextWithContentKey で subject + body decrypt
8. EphemeralPlaintextView に表示 (TTL 5min, 離脱で即 clear)
9. daemon 側で audit log fire
```

### 4.5 コンポーネント別の作業量 (見積)

| コンポーネント | 内容 | 見積 |
|---------------|------|------|
| **Daemon HTTP listener (Phase 3a)** ✅ | - axum で 2 endpoint<br>- tokio 共有 runtime<br>- Origin / token middleware<br>- `unwrap_content_key` 再利用<br>- **stderr 構造化 audit (Phase 3a)** | 1 日 |
| **Daemon pairing (Phase 3b)** ✅ | - `pair` endpoint<br>- 起動時コード生成 + stderr 出力<br>- token inventory + TTL + revoke endpoints<br>- paired_sessions / session-label audit | 0.5 日 |
| **Daemon Policy L3 (Phase 3c.1)** ✅ | - per-day / per-min sliding-window rate limiter<br>- status endpoint 統合 + Web UI quota 表示 | 0.5 日 |
| **Session nonce binding (Phase 3c.2)** ✅ | - pair 時に CSPRNG nonce 生成 → sessionStorage<br>- daemon は sha256 hex のみ保持<br>- `nonce_missing` / `nonce_mismatch` audit outcome | 0.5 日 |
| **Daemon audit client (Phase 3c.3)** ✅ | - `reqwest` で API に per-event JWS POST<br>- bounded mpsc (256) + fire-and-forget<br>- stderr sink は並行稼働で残す | 0.5 日 |
| **Audit dashboard 統合 (Phase 3c.4)** ✅ | - `/settings/audit` の Bridge-only preset<br>- `event_prefix` クエリ (alphanumeric + underscore)<br>- `EVENT_META` 6 種 | 0.25 日 |
| **At-rest token encryption (Phase 3c.5)** ✅ | - IndexedDB に non-extractable AES-GCM KEK<br>- localStorage には ciphertext のみ<br>- 旧 plaintext 行の next-save 再暗号化 | 0.5 日 |
| **BridgeClient (web)** | - `apps/web/lib/bridge/client.ts`<br>- detect / pair / unwrap / invalidate<br>- AbortController で timeout | 0.5 日 |
| **BridgePairingDialog (web)** | - `apps/web/app/settings/agents/*` に統合<br>- pairing code 入力 UI + エラー処理 | 0.5 日 |
| **MessageUnavailableCard 統合** | - "復元して表示" ボタン追加<br>- consent modal<br>- `EphemeralPlaintextView` 状態管理<br>- TTL タイマー + タブ離脱ハンドラ | 1 日 |
| **API 側 audit event 追加** | - `agent_audit_log` の event_type に `bridged_decrypt` を許可<br>- Rust 側 validator 追加 | 0.25 日 |
| **設計書 / ADR** | (これ) + 実装後の post-mortem update | 0.5 日 |
| **テスト** | - 新 axum routes の unit test<br>- pairing e2e<br>- policy L3 境界 | 1 日 |

**合計**: Phase 3a+b+c で概ね **6〜7 人日**。Phase 3a だけなら 2.5 人日。

---

## 5. 代替案で検討して捨てた細部

- **TLS on loopback**: 自己署名 cert + browser trust inline は UX 負荷が高い。HTTPS 化は `Origin` ヘッダ検証で代替 (loopback なので中間者は不可)
- **WebSocket**: HTTP fetch で十分。WS のほうが origin 検証が弱いのも不利
- **daemon ↔ browser WebRTC DataChannel**: オーバーエンジニアリング、STUN/TURN 不要な経路に必要無し
- **Service Worker 介在**: Service Worker は `http://127.0.0.1` に対しては特別扱いしない。shipping しても利点無し

---

## 6. セキュリティ判定ポイント (review checklist)

- [ ] daemon bind が `127.0.0.1` / `::1` 固定、`0.0.0.0` を **絶対に** 許可しない
- [ ] `Origin` ヘッダ検証が missing / mismatch のとき 403
- [ ] `X-NexusInbox-Bridge` token 検証が constant-time compare
- [ ] Pairing token が stderr 以外に漏れない (web log / audit plaintext への混入が無い)
- [ ] Response body に `Set-Cookie` を含めない
- [ ] `Cache-Control: no-store` 設定済み
- [ ] Rate limit (L3) が独立した mutex で保護され、bypass 無い
- [ ] Audit event の `message_id_hash` が sha256 ベース (生 message_id 送らない)
- [ ] Daemon 再起動で pairing が invalidate される (セキュリティ境界のリセット)
- [ ] ブラウザ側 React state の plaintext が route change で消える (useEffect cleanup 確認)
- [ ] TTL タイマーが setTimeout leak しない

---

## 7. 計測 / observability

- Daemon が起動時に bind port / paired / pending-pairing 状態を `status` RPC と `GET /v1/status` に露出
- 毎 `/v1/unwrap` で counter 1 増 (policy L3 の per-day が status に出る)
- API 側の `agent_audit_log` で `event_type = 'bridged_decrypt'` の集計クエリを docs/12 セキュリティレビューに追加
- ブラウザ側で restore 実行した message の数をローカル Telemetry (opt-in) に記録して UX 評価

---

## 8. 段階的ロールアウト計画

### Phase 3a — MVP (shipped)

- Daemon HTTP listener + unwrap endpoint + origin check
- Pairing は **固定 env var** (`AGENT_INBOX_BRIDGE_TOKEN=...`)
- web 側に `/settings/agents` の Bridge Token panel + MessageUnavailableCard の "復元して表示" を配線
- **audit は daemon stderr に JSON Lines で emit** (全 outcome: ok / unauthorized / forbidden_origin / bad_request / daemon_error / disabled + bridged_status)
  - 運用者は stderr redirect で永続化。API `agent_audit_log` との統合は Phase 3c.3 で shipped (`--bridge-forward-audit`)。

### Phase 3b — User-facing pairing (shipped)

- `POST /v1/pair` endpoint (Origin + pairing-code consumed, no bearer required)
- `DELETE /v1/session` / `/v1/sessions` for per-browser / all-browsers revoke
- Daemon prints `AIBX-XXXX-XXXX-XXXX` pairing code on startup (5 min TTL, single-use, Crockford alphabet without 0/O/1/I/L)
- Token inventory is **daemon memory only** — restart = revoke all (docs/22 §11 decision)
- `GET /v1/status` expanded with `paired_sessions[]` so the UI lists peers with device_label + created_at + last_used_at, and can recognise "this browser" via sha256 of its stored token
- Audit events: `bridged_pair_requested` / `_succeeded` / `_failed` / `_revoked` plus existing `bridged_decrypt`; every successful decrypt now carries the resolved session's device label in `error_message`
- `/settings/agents` panel grows a Pair dialog (pairing code + device label + bridge URL), paired-sessions list, Revoke-this / Revoke-all buttons, and an Advanced-token fallback folded behind a disclosure for Phase 3a migration
- `--bridge-token` kept as optional shared-secret backward compat; leaving it unset puts the daemon in pairing-only mode

### Phase 3c — Hardening

- **Policy L3 rate cap (shipped)** — per-minute + per-day sliding
  windows, 429 `rate_limited` audit outcome, `--bridge-decrypts-per-day`
  / `--bridge-decrypts-per-min` CLI flags (defaults 50 / 3), quota
  surfaced via `GET /v1/status.policy` so the Web UI renders "残量:
  今日 N/M · 直近 1 分 K/L" and fades to amber past 80 %.
- **Session nonce (shipped)** — pair-time CSPRNG random → browser
  sessionStorage (dies with the tab), sha256 hex stored on the
  daemon. Privileged calls must echo the raw value in
  `X-NexusInbox-Bridge-Nonce`; localStorage-only exfil of the
  bearer (XSS, rogue extension) is useless without the matching
  nonce. New audit outcomes `nonce_missing` / `nonce_mismatch`
  distinguish "token exfil + wrong nonce" from "generic bad token"
  for alerting. Tradeoff: new tab / browser-restart means re-pair,
  which is the intended "one active browser per pairing" property.
- **At-rest token encryption (shipped, browser only, fail-closed)** —
  bearer の localStorage 記録を `{v:1, iv, ct}` AES-GCM 256 エンベ
  ロープに差し替え、KEK は IndexedDB に non-extractable で生成・保持
  (`apps/web/lib/bridge/at-rest.ts`)。`crypto.subtle.exportKey` も拡張
  の `chrome.storage` dump も平文を取り出せず、XSS からも `decrypt`
  呼び出しのバーは残るが passive 流出では無効化。KEK が materialise
  できない環境 (SSR、private mode quota miss、古いブラウザ) では
  `wrapBridgeToken` / `saveBridgeToken` が `BridgeSecureStorageUnavailableError`
  を throw し、Pair / Advanced token UI はペアリングを中断 — 平文
  localStorage への fallback は**行わない** (Help / tooltip コピーの
  "ciphertext only" 約束と一致させるため)。旧 plaintext 行は
  next-save で透過的に再暗号化 (re-pair 不要)。daemon 側 OS keychain
  は 3b の "restart = revoke" invariant を壊すので**意図的にスコープ
  外** — 再起動で invalidate する in-memory 保持のまま据え置き。
- **API audit transport (shipped)** — daemon ships each stderr
  event as a fire-and-forget POST to `/agent-audit-log/bridge`.
  Per-event JWS signed with the same Ed25519 credential key (iss =
  aid, sub = credential_id, aud = endpoint, iat ±60 s freshness,
  jti = random uuid). Server allow-lists `bridged_*` event types,
  verifies against the stored signing_public_key, then feeds through
  the existing `record_audit_event` sink into `agent_audit_log`.
  Bounded mpsc (256 slots) absorbs bursts; overflow drops with a
  stderr warn rather than stalling `handle_unwrap`. Opt-in via
  `--bridge-forward-audit`; stderr line keeps firing either way.
  **Ingest integrity hardening**: `aud` is byte-equal compared
  against `AGENT_INBOX_PUBLIC_API_URL` (or the request's Host +
  X-Forwarded-Proto when unset) so a JWS signed for any other
  endpoint — including another host with the same path suffix — is
  rejected. `jti` is required and logged into the shared
  `replay_nonces` table under scope `bridge_audit|<credential_id>`
  for a 120 s window (DB-backed when configured, in-memory
  fallback otherwise), so a passive capture of one forwarded
  envelope can't be re-POST'd. Duplicates return 409
  `replay_rejected`.
- **Audit dashboard (shipped)** — `/settings/audit` learned a
  "Bridge events only" preset backed by a new `event_prefix` query
  param on `GET /agent-audit-log` (sanitised to alphanumeric +
  underscore so the LIKE expression can't smuggle wildcards).
  The six bridge event kinds gained severity / label / description
  entries in the page's `EVENT_META` table so they slot into the
  existing row renderer unchanged.
- docs/12 のセキュリティレビューに正式追加

---

## 9. Open questions

- **Q1**: Safari サポートをどうするか (loopback exception が無いため fetch が block される)
  → **A**: 初期は Chrome / Arc / Edge / Firefox のみ動作保証、Safari は "Open in Claude Desktop" CTA にフォールバック
- **Q2**: daemon が止まっている時の UX
  → **A**: `GET /v1/status` を 500ms timeout で叩いて no-response なら "Daemon offline" を MessageUnavailableCard に表示、"Pair" ボタンで再開の手順へ
- **Q3**: ChromeOS / Linux の pairing code 表示どうする
  → **A**: stderr は一律。CLI が daemon を叩いて pairing を発動するサブコマンドを後で追加 (`nexusinbox-signer pair --show-code`)
- **Q4**: agent-gateway の allow-list に `bridged_decrypt` 相当を足すか
  → **A**: Gateway は今回無関係。Web ↔ Daemon 直結で、Gateway 経由にはしない (目的が違う)

---

## 10. 採用しない前提 (non-goals)

- モバイル / ネイティブ app との連携 (別設計)
- 複数 daemon (multi-device) の orchestration
- 長期 plaintext 保存 (TTL 満了で必ず消す)
- 復号後の clipboard コピー (plaintext を clipboard に載せない)
- bulk restore (複数 message を一括で平文化する UI) — 1 回 1 message のみ

---

## 11. 実装着手前に決める必要がある 2 点

1. **Pairing token の at-rest 保存場所** (Phase 3b → 3c.5 で完了)
   - browser 側: localStorage の bearer を IndexedDB KEK で AES-GCM 暗号化
     (Phase 3c.5, `apps/web/lib/bridge/at-rest.ts`)
   - daemon 側: in-memory only のまま据え置き。OS keychain 統合は Phase 3b
     の "restart = revoke" invariant を壊すので採用しない。
2. **Consent dialog の粒度** (Phase 3b)
   - (a) 毎回 — 面倒だが最安全
   - (b) セッション中 N 回まで — UX 良いが監査性低下
   - (c) 当日中のみ再確認スキップ — middle ground
   → **A 案**: (a) を初期、後で (c) に緩和可。実装負荷は同等なので先に (a)

---

## 12. 結論

Bridged restore は **docs/21 §6** の未実装 UX を成立させるために Phase 3 として実装する。Option C (daemon 内 HTTP listener) で追加バイナリなしに実現でき、既存の `unwrap_content_key` を再利用するので新しい crypto 経路も発生しない。Phase 3a (MVP) から始めて、pairing / policy / audit を段階的に強化する。

実装を次セッションで開始する際は、§4.5 の work item を todo 化 → Phase 3a 分を 1 PR にまとめる形で進める。
