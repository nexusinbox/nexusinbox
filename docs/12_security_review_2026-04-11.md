# NexusInbox Security Review (2026-04-11)

## Executive Summary

現時点の実装は、MVPの画面・API・契約テストを動かすための開発用ショートカットが多く残っている。プロダクトの性質上、NexusInbox は「人間証明」「DID署名」「E2E暗号化」「BYOS」の信頼で成立するため、下記の Critical / High は本番・外部デモ・公開検証の前に必ず解消する。

特に重要なのは以下の4点。

- 開発用 Bearer token で任意ユーザーになれるため、認証境界が成立していない。
- World ID proof は実検証されず、クライアントで作った文字列を受け入れている。
- E2E暗号化が公開フロントエンド内の固定パスフレーズに依存しており、第三者が復号可能になり得る。
- DID署名と送信元DID所有証明を検証していないため、送信者なりすましが可能。

## Scope

- 対象: `apps/web`, `packages/crypto`, `services/api`, `openapi`, `docs`
- 観点: 認証、認可、World ID、DID、E2E暗号化、BYOS、API契約、フロントエンドのトークン管理、運用上の信頼性
- 非対象: 外部ペネトレーションテスト、依存パッケージのCVE完全監査、Rust実装の形式検証

## Critical Findings

### SEC-CRIT-01: 任意の `dev-user-*` Bearer token で認証を通過できる

- Location: `services/api/src/lib.rs:469`
- Location: `services/api/src/lib.rs:477`
- Location: `apps/web/lib/api/client.ts:29`
- Location: `apps/web/lib/api/client.ts:50`
- Impact: 攻撃者が `Authorization: Bearer dev-user-victim` のような任意文字列でAPIにアクセスできる。ユーザー分離、メッセージ分離、WebSocket認証の前提が崩れる。
- Evidence: API側は `dev-user-` prefix の後ろが空でなければそのまま `user_id` として返す。Web側も認証情報がない場合に `dev-user-demo` を自動利用する。
- Required fix: `dev-user-*` bypass は `#[cfg(test)]` または明示的な `AGENT_INBOX_AUTH_MODE=dev` のときだけ許可する。本番・通常dev serverでは署名済みトークンのみ許可する。
- DoD: 既定設定で `Bearer dev-user-demo` が `401` になるテストを追加する。テスト環境だけで bypass を有効化するテストを分離する。

### SEC-CRIT-02: World ID proof が実検証されていない

Status (2026-04-11):
- 対応中。`NODE_ENV=production` では `AGENT_INBOX_WORLD_VERIFY_ENABLED=true` を必須化し、mock認証を禁止。
- `auth_verify_rejects_mock_mode_in_production` テストを追加し、本番モードで `503 world_verify_required` になることを検証。
- `action` に加えて `signal` も `WORLD_ID_SIGNAL`（既定空文字）との完全一致を必須化し、`auth_verify_rejects_unexpected_signal` を追加。
- mock認証は非本番でも既定拒否に変更し、`AGENT_INBOX_ALLOW_WORLD_VERIFY_MOCK=true` を明示設定した場合のみ許可。
- `auth_verify_rejects_mock_mode_by_default_in_non_production` テストで、未設定デフォルト拒否を固定化。

- Location: `services/api/src/lib.rs:416`
- Location: `services/api/src/lib.rs:426`
- Location: `services/api/src/lib.rs:440`
- Location: `apps/web/app/login/page.tsx:18`
- Location: `apps/web/app/login/page.tsx:20`
- Location: `apps/web/app/login/page.tsx:22`
- Impact: 誰でも任意の `nullifier_hash` を作って「人間証明済み」ユーザーになれる。Sybil耐性、Identity Ban、Trust Score の基盤が成立しない。
- Evidence: `/login` が `dev-proof-*`, `dev-root-*`, `dev-nullifier-*` を生成し、APIは必須項目と `verification_level` の文字列だけを検査している。
- Required fix: IDKit で proof を取得し、API側で World ID Cloud / Verify endpoint に対して `proof`, `merkle_root`, `nullifier_hash`, `verification_level`, `action`, `signal` を検証する。
- DoD: 偽 proof が `401`、有効 proof が `200` になる contract/integration test を追加する。`action` と `signal` の固定値検証、nullifier replay方針もテストする。

### SEC-CRIT-03: JWT署名鍵がハードコードされ、独自dev tokenとして発行されている

Status (2026-04-11):
- 対応済み。`jsonwebtoken` (HS256) に置換し、`JWT_SECRET` を環境変数必須化。
- API起動時に `validate_runtime_config()` で `JWT_SECRET` 未設定/32文字未満を拒否。
- token検証で `iss` / `aud` / `exp` を厳格検証。

- Location: `services/api/src/lib.rs:26`
- Location: `services/api/src/lib.rs:27`
- Location: `services/api/src/lib.rs:299`
- Location: `services/api/src/lib.rs:320`
- Impact: ソースを読める人はトークンを偽造できる。秘密鍵ローテーション、環境分離、漏えい時失効ができない。
- Evidence: `DEV_JWT_SECRET` が定数であり、`issue_dev_jwt` と `verify_dev_jwt` が同じ固定鍵を利用する。
- Required fix: `JWT_SECRET` またはKMS管理鍵から読み込み、未設定なら起動失敗にする。可能なら標準JWT crateで `iss`, `aud`, `sub`, `iat`, `exp`, `kid` を検証する。
- DoD: secret未設定時に本番モード起動が失敗するテスト、異なるsecretで署名されたtokenを拒否するテスト、期限切れtokenテストを追加する。

### SEC-CRIT-04: E2E暗号化が固定・公開パスフレーズ依存になっている

Status (2026-04-11):
- 対応中。Web側の固定デフォルトpassphrase (`nexusinbox-dev-passphrase`) を撤去し、メッセージごとのランダムcontent key化を実施。
- Compose送信時の `encrypted_key` も `kdf:*` 固定文字列からメッセージ固有値に変更。
- `encrypted_key` の暗号文埋め込み (`:ekb64:`) を廃止し、復号には分離された `encrypted_key` を必須化。
- composeでは件名/本文で同一content keyを共有し、`encrypted_key` 1本で整合した復号パスを維持。
- `encrypted_key` を `recipient_did` 束縛形式（`ckv2:`）に拡張し、宛先DID不一致時は復号不可に変更。
- Web Cryptoベースの X25519 鍵ラップ基盤（`x25519v1` wrap/unwrapユーティリティ + テスト）を追加。
- エージェント作成時にX25519鍵ペアを生成し、公開鍵を `encryption_key` として登録。秘密鍵はローカルkeyringの **メモリのみ** で保持（永続保存しない）。
- compose送信で recipient の `encryption_key` が利用可能な場合は `x25519v1` でcontent keyをラップし送信する実装に接続。
- 受信UIは一覧で件名を平文化せず、スレッド表示時のみ `encrypted_key` と recipient DID で件名/本文を復号する導線へ変更。
- compose送信は fail-closed に変更し、宛先公開鍵が未登録/不正形式の場合は送信を中止（暗黙フォールバックを禁止）。
- compose画面で送信前の可否判定（ボタン無効化 + 理由表示）を追加し、鍵不備状態で送信ボタンを押せないUXに統一。
- 方針確定: 本番前・既存データなしのため、`encrypted_key` は **x25519v1 のみ** 許可。`ckb64` / `ckv2` 互換は残さない。
- APIの `x25519v1` 検証を強化し、`ephemeral(32B) / salt(16B) / iv(12B) / ciphertext(>=16B)` の base64url妥当性と長さ検証を必須化。
- ただし受信者公開鍵ラップ（X25519 key wrapping）は未完了のため、引き続き本IssueはOpen。

- Location: `apps/web/lib/crypto/envelope.ts:8`
- Location: `apps/web/lib/crypto/envelope.ts:15`
- Location: `apps/web/lib/crypto/envelope.ts:28`
- Location: `apps/web/app/compose/page.tsx:51`
- Location: `packages/crypto/src/index.ts:7`
- Location: `packages/crypto/src/index.ts:44`
- Impact: `NEXT_PUBLIC_*` はブラウザに公開されるため、固定パスフレーズで暗号化されたメッセージは第三者に復号され得る。設計上の X25519 + XChaCha20-Poly1305 / recipient key wrapping ではない。
- Evidence: fallback passphrase は `"nexusinbox-dev-passphrase"`。`encryptedKey` は `"kdf:" + encryptedBody.kdfLabel` であり、受信者公開鍵でラップされた実鍵ではない。
- Required fix: メッセージごとにランダムな content key を生成し、受信者の X25519 公開鍵で key agreement / key wrapping を行う。署名は送信者 Ed25519 DID key で envelope 全体に対して付与する。
- DoD: 同一本文でも異なるciphertextになること、受信者秘密鍵なしでは復号できないこと、誤った受信者鍵では復号不能なこと、固定パスフレーズがbundleに存在しないことをテストする。

## High Findings

### SEC-HIGH-01: DID署名と送信元DID所有権を検証していない

Status (2026-04-11):
- 対応済み。送信時に `sender_did` と登録鍵の対応を再検証し、不一致は `401` で拒否。
- APIの envelope 署名検証を HMAC から Ed25519 検証へ移行（公開鍵で `signature` を検証）。
- Webは Ed25519 鍵ペア生成に変更し、公開鍵のみAPI登録。秘密鍵はローカル keyring の **メモリのみ** から署名時に利用。

- Location: `services/api/src/lib.rs:559`
- Location: `services/api/src/lib.rs:564`
- Location: `services/api/src/lib.rs:567`
- Location: `apps/web/lib/api/client.ts:136`
- Impact: 任意の `sender_did` を指定して他エージェントになりすませる。メッセージングの信頼性と監査性が損なわれる。
- Evidence: APIは `signature` を読み捨てており、Webテスト用clientは `dev-signature` を送る。
- Required fix: `sender_did` が認証ユーザー所有のagentであることを確認し、DID document / public key で envelope signature を検証する。
- DoD: 他ユーザー所有DIDでの送信が `403`、署名不一致が `401` または `422`、正しい署名のみ `202` になるテストを追加する。

### SEC-HIGH-02: `localfs:` storage_ref が絶対パスを漏えいし、読み出し時のroot検証がない

Status (2026-04-11):
- 対応中。`storage_ref` を `localfs://{message_id}` / `gdrive://{message_id}` のopaque形式へ変更し、ユーザーIDやファイルパスをレスポンスに含めないよう修正。
- 読み出し時は `storage_ref` からUUIDのみ復元し、`storage_root / backend / user_id / {message_id}.json` へ固定解決するよう更新。
- root配下検証（canonical path check）は継続。

- Location: `services/api/src/lib.rs:372`
- Location: `services/api/src/lib.rs:379`
- Location: `services/api/src/lib.rs:384`
- Location: `services/api/src/lib.rs:385`
- Location: `services/api/src/lib.rs:792`
- Location: `services/api/tests/messages_test.rs:91`
- Location: `services/api/tests/messages_test.rs:94`
- Impact: APIレスポンスからサーバのファイルシステム構造が漏れる。将来DB永続化・storage_ref更新・インポート機能が入ると、任意ファイル読み出しの足場になる。
- Evidence: `localfs:/absolute/path` をそのまま返し、読み出し時に `PathBuf::from(path)` している。テストも絶対パス露出を期待している。
- Required fix: storage_ref は `localfs://{message_id}` のようなopaque idにし、読み出し時は必ず `storage_root / backend / user_id / message_id.json` に解決する。canonicalize後にroot配下であることも確認する。
- DoD: APIレスポンスに `/Users`, `/tmp`, `nexusinbox-localfs` などの実パスが出ないテスト、`../` や絶対パスが拒否されるテストを追加する。

### SEC-HIGH-03: Zero-Knowledge Indexing と実装の責務境界が曖昧

Status (2026-04-11):
- 対応済み。`MessageRecord` はメタデータ + `storage_ref` のみを保持し、本文暗号データをindexに重複保持しない。
- `/messages/{id}/content` はstorage読み出し専用で、読み出し失敗時に本文fallbackを返さないことをテストで固定化。

- Location: `services/api/src/lib.rs:638`
- Location: `services/api/src/lib.rs:643`
- Location: `services/api/src/lib.rs:644`
- Location: `services/api/src/lib.rs:645`
- Location: `services/api/src/lib.rs:819`
- Impact: 設計ではサーバはメタデータのみを保持し本文はBYOSに置く方針だが、実装は暗号文・暗号鍵ラベル・nonceをメモリ内 `MessageRecord` にも保持している。暗号文とはいえ、侵害時に本文ciphertextをまとめて取得できる。
- Evidence: ファイル保存後も `encrypted_content`, `encrypted_key`, `nonce` を `MessageRecord` に保存し、storage read失敗時にメモリ値へfallbackする。
- Required fix: message index は `storage_ref`, sender/recipient DID, status, priority, timestamps のみに縮小する。`/content` はBYOS adapter経由のみで取得し、fallbackを削除する。
- DoD: `MessageRecord` から content fields が消えていること、storage read失敗時に本文を返さないこと、設計書のZK Indexingと実装が一致することをテストする。

### SEC-HIGH-04: localStorage token はXSS時に即時流出する

Status (2026-04-11):
- 対応済み。現行Webクライアントは `localStorage` 保存を使用せず、cookie (`credentials: include`) ベースを既定化。
- `NEXT_PUBLIC_DEV_BEARER_TOKEN` の暗黙読込を廃止し、明示指定時のみAuthorizationヘッダを付与。
- APIのsession cookieは `HttpOnly; SameSite=Lax` を維持し、`NODE_ENV=production` では `Secure` を強制。

- Location: `apps/web/lib/api/client.ts:30`
- Location: `apps/web/lib/api/client.ts:55`
- Location: `apps/web/lib/api/client.ts:160`
- Impact: XSSや悪意ある依存・ブラウザ拡張によりBearer tokenを窃取されると、APIアクセスを乗っ取られる。
- Evidence: token を `localStorage` に保存し、全APIリクエストで `Authorization` に付与している。
- Required fix: Webは httpOnly, Secure, SameSite cookie ベースのセッション、または短命access token + refresh token + in-memory保管へ移行する。CSPも同時に導入する。
- DoD: `localStorage` にtokenが保存されないこと、session cookieに `HttpOnly; Secure; SameSite=Lax/Strict` が付くこと、XSS smoke testでtokenをJSから読めないことを確認する。

### SEC-HIGH-05: Next.js側に明示的なセキュリティヘッダー/CSPがない

Status (2026-04-11):
- 対応済み。`next.config.ts` で CSP / X-Frame-Options / Referrer-Policy / X-Content-Type-Options / Permissions-Policy を設定。
- `apps/web/security-headers.test.ts` で主要セキュリティヘッダー設定の存在を自動検証。

- Location: `apps/web/package.json:6`
- Impact: E2E暗号化アプリではXSSがそのまま秘密情報流出につながる。CSP、frame制御、referrer policy などが未設定だと防御層が薄い。
- Evidence: `next.config.*` と `middleware.*` が存在せず、header設定が見当たらない。
- Required fix: `next.config.ts` で `Content-Security-Policy`, `X-Frame-Options` または `frame-ancestors`, `Referrer-Policy`, `X-Content-Type-Options`, `Permissions-Policy` を設定する。
- DoD: Playwrightまたはunit testで主要レスポンスにセキュリティヘッダーが付くことを確認する。

### SEC-HIGH-06: レート制限、サイズ制限、replay耐性が未実装

Status (2026-04-11):
- 対応済み。APIに `DefaultBodyLimit` / request timeout / request rate limit を適用。
- `auth_verify` の proof replay 拒否（nullifier + action）を実装済み。
- `send_message` で message nonce replay 拒否を追加し、同一 `sender_did + nonce` の再送を `422` で拒否するテストを追加。

- Location: `services/api/src/lib.rs:416`
- Location: `services/api/src/lib.rs:552`
- Location: `services/api/src/lib.rs:777`
- Impact: `/auth/verify` の総当たり・replay、`/messages` の大量投稿、巨大payloadによるメモリ/ディスク圧迫が可能になる。
- Evidence: endpointごとの rate limit、body size limit、idempotency/replay nonce の実装が見当たらない。
- Required fix: tower middleware で body limit / timeout / rate limit を追加し、World ID nullifier/action単位のreplay方針を明確化する。メッセージサイズ上限もOpenAPIに定義する。
- DoD: 上限超過payloadが `413`、高頻度リクエストが `429`、replayされたproof/nonceが拒否されるテストを追加する。

## Medium Findings

### SEC-MED-01: `GoogleDriveMock` が実Google Drive連携のように見えやすい

Status (2026-04-11):
- 対応済み。`AGENT_INBOX_STORAGE_BACKEND=gdrive` / `google_drive` ではmockを選択しないよう変更。
- mock選択は `gdrive_mock` / `google_drive_mock` のみ許可し、暗黙選択を防止。
- `gdrive` 指定時は `localfs` フォールバックになることをテストで固定化。

- Location: `services/api/src/lib.rs:47`
- Location: `services/api/src/lib.rs:59`
- Location: `services/api/src/lib.rs:67`
- Location: `services/api/src/lib.rs:380`
- Impact: 外部デモや仕様説明で「Google Drive対応済み」と誤解されると、ユーザー信頼を損なう。
- Required fix: config値を `gdrive_mock` に変更し、UI/API/ドキュメント上も「mock」と明記する。実Drive adapterはOAuth scope, token保存, file permissions, revocationまで別issueにする。
- DoD: `AGENT_INBOX_STORAGE_BACKEND=gdrive` がmockを暗黙選択しないこと、mock利用時はレスポンスまたはログにmock表記が残ること。

### SEC-MED-02: agent作成時に公開鍵形式とDID生成の整合性を検証していない

Status (2026-04-11):
- 対応済み。`POST /agents` で `public_key` に加えて `encryption_key` も base64url / 32bytes以上を必須検証。
- DID は常に `public_key` から `did:key:z...` を導出するため、入力値不整合による `did:key:{uuid}` 生成経路は解消済み。
- `invalid public_key` / `invalid encryption_key` を `422` で拒否するAPIテストを追加。

- Location: `services/api/src/lib.rs:512`
- Location: `services/api/src/lib.rs:519`
- Location: `services/api/src/lib.rs:528`
- Location: `services/api/src/lib.rs:529`
- Impact: 実DIDではない `did:key:{uuid}` が発行され、登録された `public_key` / `encryption_key` とDIDが結びつかない。後続の署名検証や鍵交換が成立しない。
- Required fix: クライアント生成鍵またはサーバ生成鍵のどちらを採用するかを決め、did:key codec と公開鍵材料の対応を検証する。
- DoD: 不正な公開鍵形式が `422`、did:key と公開鍵が一致しない入力が拒否されるテストを追加する。

### SEC-MED-03: `/messages` の宛先DID存在確認・ブロック/Trust Score判定が未接続

Status (2026-04-11):
- 対応済み。`POST /messages` で recipient DID の存在確認を必須化し、未登録宛先は `404` を返す。
- `AGENT_INBOX_BLOCKED_RECIPIENT_DIDS`（カンマ区切り）に含まれる宛先DIDは `404 recipient not found or blocked by policy` で拒否。
- `AGENT_INBOX_LOW_TRUST_SENDER_DIDS`（カンマ区切り）に含まれる送信元DIDは `202 pending_approval` を返し、即時 `delivered` しない。
- 受信者不在 / block対象 / low-trust sender の3ケースをAPIテストで追加して契約を固定化。

- Location: `services/api/src/lib.rs:587`
- Location: `services/api/src/lib.rs:663`
- Location: `openapi/openapi.yaml:112`
- Impact: API契約では `404 Recipient not found or blocked by policy` が定義されているが、実装は必須項目があれば `202 delivered` になる。ブロック機能やTrust Scoreを前提にした信頼境界がない。
- Required fix: recipient DID解決、所有者確認、block policy、trust score分類を送信フローに接続する。
- DoD: 存在しない宛先DID、L1/L2/L3ブロック対象、低trust senderのそれぞれで期待ステータスを返すテストを追加する。

### SEC-MED-04: `storage_ref` が画面プレビューに表示されている

Status (2026-04-11):
- 対応済み。ダッシュボードと `/agent/[did]` の一覧プレビューで `storage_ref` を表示しないよう変更。
- APIメッセージのプレビューは固定文言（「本文は開くまで表示しません」）に置換。

- Location: `apps/web/app/page.tsx:104`
- Location: `apps/web/app/agent/[did]/NexusInboxClient.tsx:77`
- Impact: localfs絶対パス問題と組み合わさると、ユーザーに内部パスが露出する。Google Drive file id なども今後表示すべきではない。
- Required fix: メッセージ一覧のpreviewは復号済み本文の短縮表示、または「本文を開くまで非表示」にする。storage_refはUI非表示にする。
- DoD: 画面テストで `localfs:` や `gdrive://` が表示されないことを確認する。

### SEC-MED-05: `.gitignore` にRust targetや環境別一時データが不足している

Status (2026-04-11):
- 対応済み。`target`, `services/api/target`, `*.log`, `test-results`, `playwright-report`, `nexusinbox-localfs`, `.env.*` などをignore対象に整備。

- Location: `.gitignore:1`
- Location: `.gitignore:6`
- Impact: 今後、ローカルストレージやビルド成果物、ログが誤ってコミットされると、暗号文・テストtoken・環境情報が漏れる可能性がある。
- Evidence: `services/api/target` が作成されているが `.gitignore` に `target/` がない。
- Required fix: `target`, `*.log`, local storage root例、Playwright artifact、coverage/tempを整理する。
- DoD: `git status` 上に生成物が出ないことを確認する。

## Positive Notes

- `/messages/{id}/content` はユーザー別の `messages_by_user` から message id を探しており、現状のin-memory実装では他ユーザーのmessage idを直接読めない構造になっている。
- `per_page <= 100` の制限があり、一覧APIの無制限取得は避けられている。
- OpenAPI契約テストとE2Eテストが既にあるため、上記のセキュリティ修正はTDDで進めやすい。

## Recommended Fix Order

1. `SEC-CRIT-01`: dev bearer bypassの本番無効化とテスト分離
2. `SEC-CRIT-03`: JWT secretのenv必須化とtoken検証の標準化
3. `SEC-CRIT-02`: World ID実検証または本番モードでのmock禁止
4. `SEC-CRIT-04`: E2E envelopeを固定パスフレーズからrecipient key wrappingへ移行
5. `SEC-HIGH-01`: DID ownership + signature verification
6. `SEC-HIGH-02`: opaque storage_ref とroot検証
7. `SEC-HIGH-03`: message indexから本文ciphertext fallbackを削除
8. `SEC-HIGH-04` / `SEC-HIGH-05`: cookie session + CSP/security headers
9. `SEC-HIGH-06`: rate limit / body limit / replay protection
10. `SEC-MED-*`: mock表記、DID鍵整合性、UI表示、`.gitignore` 整備

## Go / No-Go

現状は **No-Go for public beta / production**。ローカルMVPの検証としては前進しているが、外部ユーザーに「安全」「E2E」「World ID認証済み」と表現するには Critical Findings の解消が必要。
