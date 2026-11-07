# 29. ADR: Isolated mode 自動返信を本番で動かす

**Status**: Proposed (2026-11-07)
**Related**: [25c-A](./25c-a_auto_reply_executor_mode_a.md)、[25c](./25c_auto_reply_executor_mode_b.md)、[25b](./25b_auto_reply_evaluator_decision_model.md)、[28](./28_data_inventory_and_retention.md)、[15](./15_non_interactive_agent_access_design.md)
**Scope**: Agent Gateway 上の Isolated mode executor を本番で動く状態にするための、API、Gateway、Daemon、Web executor の変更。次の 3 つは範囲外: Calendar 連携 (25d-A)、LLM による自動送信 (25e で中止)、push 配信。

## 1. 背景

[28](./28_data_inventory_and_retention.md) で「運営は鍵を預からない」と決めた。この前提で人間が不在でもエージェントに応答させるには、鍵を持つ利用者側の常駐プロセスが返信を作るしかない。その役を担うのが 25c-A の Isolated mode executor だが、2026-11-07 時点では本番で 1 通も返信できない。

### 1.1 動かない理由 (2026-11-07 確認)

| # | 問題 | 根拠 |
|---|---|---|
| B1 | **設定を人間専用ルートから読んでいる** | `services/agent-gateway/src/main.rs` の `fetch_policy` / `fetch_master_switch` / `fetch_contact_dids`。`services/api/src/lib.rs` の `list_agents` / `list_contacts` / `get_auto_reply_policy` |
| B2 | **`sign_envelope` の呼び方が daemon と合っていない** | `main.rs` の `daemon_sign_envelope`、`auto_reply_executor.rs` の `envelope_payload_b64`、`services/signer-daemon/src/main.rs` の `SignEnvelopeParams` / `build_envelope_signing_payload` |
| B3 | **返信しない行に印を付けていない** | `auto_reply_executor.rs` の `dispatch_one` が返す `Skipped` |
| B4 | **Web にある検証が Gateway に無い** | `apps/web/lib/protocol/autoReplyExecutor.ts`、`a2aReply.ts` の `canRespondToProtocol`、`packages/core/src/a2a.ts` の `assertValidA2APayload` |
| B5 | **二重送信を防げていない** | `lib.rs` の `mark_auto_reply_sent`、`autoReplyExecutor.ts` (送信後に `markAutoReplySent` を呼ぶ) |
| B6 | **`our_did` が空のまま固定される** | `main.rs` の `GatewayExecutorBackend::new` |
| B7 | **通しのテストが無い** | `auto_reply_executor.rs` の `MockBackend` |

各問題の詳細:

- **B1**: ポリシーとマスタースイッチを `GET /agents` と `GET /agents/{id}/auto-reply-policy` から、連絡先を `GET /contacts` から取っている。3 つとも人間のセッション専用 (`authenticated_user_id`) なので、agent トークンでは 401 になる。そのエラーは握りつぶされ、ポリシーなし・連絡先は空・スイッチは off として評価されるので、全件が Skipped になる。なお `main.rs` には「agent トークンなら `/agents` は自分の行だけ返す」というコメントがあるが、これは誤り。
- **B2**: Gateway は `{sender_did, recipient, payload_b64}` を送っている。daemon が要求するのは 6 つのフィールド (`sender_did`, `recipient_did`, `subject_encrypted`, `encrypted_content`, `encrypted_key`, `nonce`) なので、-32602 が返る。加えて、署名対象のバイト列も違う。Gateway 側は `|` 区切りを base64 にしているが、daemon・API・Web は `\n` 区切りで組み立てる。
- **B3**: 返信しないと判断しても (A2A でない、依頼でない、評価が人間待ち) 印を付けないので、新しい順の上位 10 件を毎 tick 復号し直すことになる。それより古い行には永久に順番が回らない。
- **B4**: Web の `isAnswerableRequest` は次の点を確かめているが、Gateway には同じ検証が無い。そのため、期限切れの依頼にも accept を返しうる。
  - 送信済みフォルダの行でない
  - 依頼が期限切れでない
  - 候補数・タイムゾーン・時間幅が正しい
- **B5**: 25c-A §2.4 は「conditional UPDATE で片方だけが勝つ」としているが、そうなっていない。印付けは送信の後で、しかも `COALESCE` なので常に成功する。ブラウザの 2 つのタブ、あるいはブラウザと Gateway が同時に動くと、両方が送ってしまう。
- **B6**: 起動時に daemon が落ちていると、`our_did` が空のまま固定される。
- **B7**: テストはすべてモックで、Gateway・daemon・API を通して確かめるものが無い。B1 と B2 はこのため見逃された。

有効化の前に確かめること (2026-11-07 の状態):
- **受信用の鍵の指定**: daemon が `--encryption-key-file` 付きで起動しているか。無いと `unwrap_content_key` が失敗する。起動スクリプトで渡せるようにした (runbook 19 §7)。利用者の環境での設定が要る
- **鍵の形式 (コードで確認済み)**: `/recipients/resolve` が返す `encryption_public_key` は、daemon が要求する raw base64url 32 バイトの形になっている。エージェント作成時に API がこの形を検証しているため
- **相互運用 (テストベクタで確認済み、§7)**: Gateway (Rust) が作った `enc:v1:` の暗号文と鍵ラップを Web (TS) が開けること、その逆も開けること

## 2. 決定

方針: agent トークンに渡す情報は 2 つに限る。「そのエージェント自身の設定」と、「そのエージェント宛てのメッセージ 1 通ごとに 1 ビット」である。持ち主の連絡先一覧やほかのエージェントの情報は渡さない。

### 2.1 自分の設定だけを読む API を足す (B1)

`GET /agent-auto-reply/config` を足す。

- agent トークン専用とし、トークンの aid に束縛して、そのエージェントの分だけを返す
- scope は `messages.send` を要求する。返信しないエージェントには不要な情報だから
- 応答: `{ "auto_reply_enabled": bool, "policy": {...} | null, "revision": int }`

退けた案:
- `/agents` を agent トークンでも読めるようにする。持ち主の全エージェント (ラベルや鍵) が見えてしまう
- `/agents/{id}/auto-reply-policy` を両対応にする。id を知るために、結局 `/agents` が要る

### 2.2 連絡先一覧は渡さず、1 通ごとに 1 ビットだけ返す (B1)

- `GET /messages?auto_reply_pending=1` のときだけ、各行に `sender_is_contact: bool` を付ける
- 判定には、一覧を取った時点の contacts テーブルを使う (`EXISTS`)
- Gateway の `fetch_contact_dids` は削除する

退けた案: `/contacts` を両対応にする。名前を含む連絡先一覧の全体が agent トークンに渡ってしまう。

### 2.3 設定が取れない tick では何もしない

- 設定の取得に失敗したら、その tick では 1 件も評価しない
- 今のように「ポリシーなし」で評価して Skipped にすると、2.5 の印付けと組み合わさって、一時的な障害で返信すべき行を取りこぼす

### 2.4 署名は daemon の形に合わせ、形式を 1 か所で固定する (B2)

- `daemon_sign_envelope` は daemon の 6 フィールドで呼ぶ。値は `POST /messages` に載せるものと同じにする: `encrypted_content`、包んだ鍵、`nonce`、そして `/recipients/resolve` が返した DID
- `envelope_payload_b64` は削除する
- 署名対象の組み立て (6 項目を `\n` で連結) は、daemon・API・Web の 3 か所に実装がある。リポジトリ直下の `tests/` に共通のテストベクタを JSON で置き、同じ入力から同じバイト列になることを 3 か所とも確かめる

### 2.5 送る前に行を取り、返さない行にも印を付ける (B3, B5)

**行の取り方 (claim):**
- migration 0019 で `message_index.auto_reply_claimed_at TIMESTAMPTZ` を足す
- `POST /messages/{id}/auto-reply-claim` を足す。`auto_reply_sent_at IS NULL AND auto_reply_claimed_at IS NULL` の行だけを、条件付き UPDATE で取る。勝てば 200、負ければ 409 を返す
  - scope は `messages.send` を要求し、`enforce_agent_bound_message` を通す
- 送信するのは claim に勝った executor だけ。送信後は、今の `PATCH /messages/{id}/auto-reply-sent` で完了にする
- 一覧の条件に `auto_reply_claimed_at IS NULL` を足す
- Web (Standard mode) の executor も同じ claim を使う

**失敗したとき:**
- API が 4xx で受け付けを拒んだときだけ、`DELETE /messages/{id}/auto-reply-claim` で行を手放し、次の tick に回す
- 5xx やタイムアウトのように、送れたか分からないときは手放さない。二重に送るより、送らずに人間へ回す方を選ぶ
- 429 を受けたら、その tick を打ち切る
- 取ったまま完了しなかった行 (claimed あり、sent なし) は、受信箱で「自動返信は未完了」と表示し、人間が対応する

**返信しない行:**
- 返信しないと判断した行は、Web と同じく完了の印を付けて候補から外す

### 2.6 送る前の検証を Web と揃える (B4)

- Rust 側にも、`canRespondToProtocol` と `assertValidA2APayload` と同じ検証を持たせる:
  - 送信済みフォルダの行でないこと
  - schedule は期限切れでない `propose` であること
  - task は `delegate` であること
  - 候補数、タイムゾーン、時間幅が正しいこと
- 検証に落ちた行には返信せず、完了の印を付ける
- TS と Rust の判定がずれないよう、2.4 と同じ場所に共通のテストケースを置く

### 2.7 細かい修正 (B6 ほか)

- `our_did` が空なら、使う時点で daemon に問い直す
- スレッド ID は、Web と同じく `thread_id` が無ければ元メッセージの ID を使う
- 復号や送信のエラーが同じ行で 3 回続いたら、その行は人間に回す。回数は Gateway のメモリ上で数え、サーバには何も足さない
- `main.rs` にある「`/agents` は agent トークンだと自分の行だけ返す」という誤ったコメントを消す
- 25c-A §2.4 の「重複送信は不可能」という記述に、この ADR への注記を入れる

## 3. 情報の出入り

| 対象 | 変更 |
|---|---|
| agent トークンに新しく見えるもの | 自分の自動返信設定 (スイッチ、ポリシー、revision)。自分宛ての保留中メッセージごとの `sender_is_contact` |
| agent トークンからは見えないままのもの | 持ち主の連絡先一覧、ほかのエージェント。本文はもともと E2E で暗号化されている |
| サーバに新しく保存するもの | `auto_reply_claimed_at` (時刻 1 つ) |
| 鍵の置き場所 | 変わらない。復号と署名は、利用者のマシン上の daemon だけで行う |

## 4. テスト

- **API (DB 統合テスト)**:
  - `GET /agent-auto-reply/config` がほかのエージェントのトークンや人間のセッションに対して何を返すか
  - `sender_is_contact` の値
  - claim の競合: 2 つ同時に取りに行き、片方だけが 200 になること
  - 手放した後は再び取れること、完了した後は取れないこと
- **Gateway**: モック HTTP サーバを相手に、送る JSON の形を確かめる。claim、send、mark の順であること、`sign_envelope` が 6 フィールドであること
- **契約テスト**: 2.4 と 2.6 の共通ベクタを、daemon・API・Web・Gateway の 4 か所で読む
- **相互運用**: TS で暗号化・ラップしたものを Rust で開けること、その逆も開けることを確かめる
- **通し確認**: ローカルで daemon・Gateway・API を起動し、自分宛ての `schedule_negotiation` に accept が自動で返ることを見る。手順は runbook 19 に足す

## 5. 展開

1. API の変更 (2.1、2.2、2.5) を先に出す。Web の executor は、claim に切り替えるまで今の動きのまま
2. Web の executor を claim 方式に切り替える
3. Gateway を直し、`AGENT_INBOX_MODE_A_EXECUTOR=on` にして自分のエージェントだけで試す
4. 監査ログの `auto_reply_sent` (`executor_mode: daemon_protocol_v1`) で動きを確かめてから、runbook 19 に載せる

## 6. 範囲外

- Isolated mode での Calendar 連携 (25d-A)
- LLM による自動送信 (25e で中止したまま)
- ポーリングから push 配信への切り替え
- 利用者側ノードからのリモート MCP (別の ADR で扱う)

## 7. 進み具合 (2026-11-07)

- **API (済・本番反映)**:
  - `GET /agent-auto-reply/config` と、`POST` / `DELETE /messages/{id}/auto-reply-claim` を追加した。
  - 保留一覧に `sender_is_contact` を付け、claim 済みの行を除くようにした。
  - migration 0019 を追加した。
  - DB 統合テストは `auto_reply_claim_db_integration_test.rs`。
- **Web executor (済・本番反映)**: 送る前に claim する。claim を手放すのは、送れていないと確実に言える場合だけ (`sendCertainlyFailed`)。
  - 4xx の応答と、リクエストより前の失敗では手放す。
  - 5xx とネットワーク失敗では手放さない。
- **Gateway (済)**: 1.1 の B1〜B7 をすべて直した。
  - B1: `fetch_config`、`sender_is_contact`
  - B2: `EnvelopeSigningParams` を daemon と POST 本文の両方に使う
  - B3: 返信しない行に `mark_handled` で印を付ける。3 回失敗した行も印を付ける
  - B4: `a2a_rust::check_answerable`
  - B5: claim、release、`PostReplyError`
  - B6: `our_did` を問い直す
  - B7: テスト。daemon (UnixListener) と HTTP をモックにして、1 tick を通しで確かめる (`test_executor_tick_end_to_end_through_gateway_backend`)。
- **共通テストベクタ (済)**: `tests/vectors/` に 4 種類置いた。CI はこれらが変わると、読む側のジョブを走らせる。

  | ファイル | 確かめていること | 読む実装 |
  |---|---|---|
  | `envelope_signing.json` | 署名するバイト列が一致する | daemon・API・Web |
  | `x25519_wrap.json` | 鍵の包み方 | daemon・Web |
  | `content_encryption.json` | `enc:v1` の暗号文 | Gateway・Web |
  | `a2a_answerable.json` | 答えてよい依頼か、93 件 | Gateway・Web |

  Web が作ったものも daemon や Gateway が作ったものも、両方の実装で開けることを確かめた。
- **起動手順 (済)**: `scripts/run_noninteractive_stack.sh` で daemon に受信用の鍵を渡せるようにし、runbook 19 §7 に手順を書いた。
- **Web と挙動が違う点**: 人間待ちの判定 (master off を含む) と、Calendar が要る判定 (`auto_accept_if_free`) にも印を付ける。
  - Web はこれらに印を付けず、表示のたびに評価し直す。
  - Isolated mode のメッセージは鍵が daemon にしかなく、Web では復号できない。だから Web の executor がその行を拾うことは元々ない。
  - Isolated mode の Calendar 連携は 25d-A で扱う。
- **受信箱の表示 (済)**: 一覧の行に `auto_reply_claimed_at` を返す。claim 済みで送信が確認できていない行には「自動返信: 未完了 (要確認)」を出す。Web の executor は claim 済みの行を候補から外す
- **未着手**:
  - 本物の daemon・Gateway・API をつないだ確認 (runbook 19 §7.3)
  - Gateway が自動返信で送ったものを Policy L2 の送信回数に数えるかどうか。今は数えておらず、API 側の L3 (1 日 200 通) だけが掛かる
