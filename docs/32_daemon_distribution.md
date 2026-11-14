# 32. パソコン側プログラムの配布方法

**Status**: 実装済み (2026-11-08)。v0.1.0 を公開し、Homebrew の tap から入れられる
**Scope**: 利用者のパソコンで動く署名デーモン (`nexusinbox-signer`) とゲートウェイ (`nexusinbox-gateway`)、それを起動する `scripts/run_noninteractive_stack.sh`
**Related**: [31 使い始めの体験](./31_onboarding_ux.md) §5.6、[19 非対話型アクセス runbook](./19_non_interactive_agent_runbook_2026-04-18.md)

## 1. いまの状態と困りごと

- 利用者は、リポジトリを手元に置き (`git clone`)、Rust を入れ、`scripts/run_noninteractive_stack.sh connect <コード>` を実行する。初回はビルドに数分かかる
- 画面案 (docs/31) では `nexusinbox connect <コード>` の 1 コマンドにしたかったが、まだリポジトリのスクリプトを案内している
- MCP サーバ (`@nexusinbox/mcp-server`) も npm には出しておらず、リポジトリから使う
- 運営者以外が使い始めるには、ここが一番の壁になる

## 2. 前提 (守ること)

- 鍵はパソコンから出さない。配布の仕組みが鍵に触れることはない
- 配る実行ファイルが本物だと確かめられること (チェックサム、ビルド元の証明)
- 勝手に更新しない。更新は利用者の操作で行う (更新した版が鍵を扱うため)
- 費用を増やさない (公開リポジトリの GitHub Actions、Releases、Homebrew の tap はいずれも無料)

## 3. 選択肢

| 方式 | 利用者の手順 | 良い点 | 気になる点 |
|---|---|---|---|
| A. GitHub Releases + インストールスクリプト | `curl -fsSL …/install.sh \| sh` | Rust 不要。どの OS でも同じ | 「curl でスクリプトを実行」は警戒されやすい。更新の手段を別に用意する |
| B. Homebrew の tap | `brew install nexusinbox/tap/nexusinbox` | Mac の開発者に馴染みがある。sha256 を固定でき、`brew upgrade` で明示的に更新できる | macOS と Linuxbrew だけ。tap 用のリポジトリが 1 つ増える |
| C. npm (OS ごとのバイナリを同梱) | `npx @nexusinbox/node connect <コード>` | インストール不要の 1 行。Claude Desktop / Code の利用者は Node を持っていることが多い | npm のサプライチェーンへの依存。OS ごとのパッケージを管理する |
| D. `cargo install` | `cargo install nexusinbox` | 用意が一番簡単 | Rust とビルド時間が必要なまま。今の壁が残る |
| E. Docker | `docker run … nexusinbox/node` | Rust 不要 | Mac では Docker Desktop が要る。鍵やソケットをコンテナとホストで受け渡すことになり、MCP との連携も面倒 |

A・B・C のどれでも、CI で OS ごとの実行ファイルを作って GitHub Releases に置く仕組みが土台になる。D と E は今の壁を取り除けないので外す。

## 4. 推奨

1. **実行ファイルを 1 つにまとめる**: `nexusinbox connect | start | stop | status` を持つ 1 つの Rust の実行ファイルにする。署名デーモンとゲートウェイはサブコマンドとして同梱し、今のシェルスクリプトの役割もこれが引き継ぐ。画面に出すコマンドは `nexusinbox connect <コード>` になる
2. **GitHub Releases に、ビルド済みの実行ファイルを置く**: 公開リポジトリのタグを契機に、GitHub Actions が macOS (Apple Silicon / Intel) と Linux (x86_64 / arm64) 向けにビルドする。SHA-256 のチェックサムと、GitHub のビルド元証明 (artifact attestation) を付ける
3. **Mac は Homebrew の tap を正規の入口にする**: formula は Releases の実行ファイルを sha256 で固定して参照する。Linux は Releases から直接入れる (手順を docs に書く)
4. **npm は後回し**: MCP を中心に使う人が増えて、Homebrew がない環境の声が出てから検討する

### 4.1 推奨の理由

- Rust のビルドがなくなり、`brew install` と `nexusinbox connect <コード>` の 2 行で始められる
- 更新が `brew upgrade` という明示的な操作になり、「勝手に更新しない」を満たす
- Homebrew は sha256 で中身を固定し、Releases にはビルド元の証明が付く。配布物の真正性を確かめられる
- 費用は増えない

## 5. あとで決めること

- **Apple の公証 (notarization)**: Homebrew と curl では Gatekeeper に止められないので、当面は不要。ブラウザから直接ダウンロードさせるなら必要になる (Apple Developer Program、年 99 ドル)
- **ログイン時の自動起動**: docs/39 で決めた (Mac、選んだ人だけキーチェーン、v0.4.0)
- **Windows**: 利用者の声が出てから

## 6. 作業の順番 (推奨どおりに進める場合)

1. `nexusinbox` の実行ファイル (connect / start / stop / status) を作り、今のスクリプトと同じ動きを E2E で確かめる。スクリプトはしばらく残す
2. リリース用のワークフロー (タグ → ビルド → チェックサム → 証明 → Releases)。公開リポジトリで動かす
3. Homebrew の tap (`nexusinbox/homebrew-tap`) と formula
4. 画面の案内 (はじめての設定、状態カードの起動コマンド) を `nexusinbox …` に切り替え、docs/19 と README を直す

## 7. 実装 (2026-11-08)

### 7.1 推奨から変えた点

推奨では、署名デーモンとゲートウェイをサブコマンドとして 1 つの Rust の実行ファイルにまとめるとしていた。実装では、今の 2 つのプログラムをそのまま同梱し、起動スクリプト (`scripts/run_noninteractive_stack.sh`) を `nexusinbox` という名前で一緒に配る形にした。

- 理由: 鍵を扱う署名デーモンと、外とやり取りするゲートウェイを作り替えずに済む。connect / start / stop / status は、E2E で確かめてきたスクリプトがそのまま担う
- 利用者から見た違いはない。打つのは `nexusinbox connect <コード>` だけ
- スクリプトは、隣に 2 つのプログラムがあれば (配布物、Homebrew) それを使い、なければ (リポジトリ) cargo でビルドして使う
- Windows に対応するときは、この役割を Rust の実行ファイルに移す

### 7.2 配布物

- `scripts/package_release.sh <version> <target>` が、`nexusinbox`、`nexusinbox-signer`、`nexusinbox-gateway`、LICENSE、README をまとめた `nexusinbox-<version>-<target>.tar.gz` と、その SHA-256 を作る
- `.github/workflows/release.yml`: 公開リポジトリで `vX.Y.Z` のタグを打つと、macOS (Apple Silicon / Intel) と Linux (x86_64 / arm64) 向けに作り、ビルド元の証明 (`gh attestation verify` で確かめられる) を付けて Release に置く。使う action はコミット SHA で固定し、ビルド中のプログラムからトークンが見えないようにしている
- 手元で作った配布物を展開し、その `nexusinbox` で E2E (接続コードでの接続、従来の登録、自動返信) が通ることを確かめた

### 7.3 公開 (2026-11-08)

- [v0.1.0](https://github.com/nexusinbox/nexusinbox/releases/tag/v0.1.0) を公開した。4 つの配布物すべてで、SHA-256 とビルド元の証明 (`gh attestation verify`) が一致し、CPU 種別も正しいことを確かめた
- 1 回目は失敗した。GitHub の `macos-14` の実行環境が提供終了していて Mac のビルドが始まらず、Linux の 2 つだけが下書きに入った。`macos-15` に直し、公開前の下書きとタグを消して `v0.1.0` を打ち直した
- [nexusinbox/homebrew-tap](https://github.com/nexusinbox/homebrew-tap) を作った。formula は v0.1.0 の配布物を SHA-256 で固定している
- 運営者の Mac で `brew install nexusinbox/tap/nexusinbox` → `brew test` を通し、入った `nexusinbox` で E2E (接続コードでの接続、起動、自動返信、従来の登録) が通ることを確かめた
- 画面の案内 (はじめての設定、状態カードの起動コマンド)、ヘルプ、docs/19、README を `nexusinbox …` に切り替えた

### 7.4 新しい版を出すとき

1. 公開リポジトリに `vX.Y.Z` のタグを打つ (リリースが自動でできる)
2. tap の formula の `version`、4 つの `url`、`sha256` を新しい版に書き換える (`.sha256` ファイルの値)
3. `brew upgrade nexusinbox` で入れ替わることを確かめる

v0.2.0 (2026-11-09、公開 `7353fe8`): クラウドの AI (中継、docs/33 §12)。4 つの配布物のハッシュと来歴の証明を確かめ、tap を `c82186d` に上げ、運営者の Mac で `brew upgrade` → `brew test` が通った。入れた `nexusinbox` は中継の指定を渡し、`nexusinbox-gateway` に `--mcp-relay` がある

v0.2.1 (2026-11-10、公開 `391ed2f`): パソコン側で送ったメッセージ (自動返信、ローカルの MCP) にも本人用の鍵の包みを付ける (docs/35 §5)。4 つの配布物のハッシュと来歴の証明を確かめ、tap を `fce689c` に上げ、運営者の Mac で `brew upgrade` → `brew test` が通った

v0.3.0 (2026-11-12、公開 `1301077`): パソコン側 (自動返信、クラウドの AI の読み取り、ローカルの MCP) も、相手と自分の全端末の鍵で本文の鍵を包み、読むときは自分の端末の包みを先に使う (docs/38 段階 3)。4 つの配布物のハッシュと来歴の証明を確かめ、tap を `6dc333c` に上げ、運営者の Mac で `brew upgrade` → `brew test` が通った

v0.4.0 (2026-11-12、公開 `d3b4a6d`): Mac でログイン時に自動で起動できる (選んだ人だけ、パスフレーズはログインキーチェーンに、docs/39)。`autostart on|off`、`run`、フォルダの省略。4 つの配布物のハッシュと来歴の証明を確かめ、tap を `cdec999` に上げ、運営者の Mac で `brew upgrade` → `brew test` が通った。launchd への登録は手元では試していない (運営者の判断で、本物のエージェントで試す)

v0.5.0 (2026-11-13、公開 `52d33ac`): パソコン側も相手の端末名簿を確かめてから送る。名簿の鍵が変わったら止まり、`nexusinbox trust <aid>` で確かめてから覚え直す。長い接続コード (秘密 16 文字付き) で、ブラウザとパソコンが互いの鍵を確かめる (docs/40 段階 3)。4 つの配布物のハッシュと来歴の証明を確かめ、tap を `468f9b7` に上げ、運営者の Mac で `brew upgrade` → `brew test` が通った

v0.6.0 (2026-11-13、公開 `d99cbf2`): 署名 v2 と送り主の確かめ (docs/40 段階 4)。パソコン側も封筒全体に署名し、受け取ったメッセージの送り主を名簿で確かめ、確かめられたものにだけ自動で返す。4 つの配布物のハッシュと来歴の証明を確かめ、tap を `85a2762` に上げ、運営者の Mac で `brew upgrade` → `brew test` が通った

v0.6.1 (2026-11-13、公開 `75e42b8`): 移行の抜け道を閉じる (docs/40 段階 5)。名簿の無い相手には送らない、署名をやめた相手と 2027-02-11 以降の署名なしを警告にする。同時に API は v1 の署名を断るようになった (0.5.0 以前のパソコンは送れない)。4 つの配布物のハッシュと来歴の証明を確かめ、tap を `8ca93c7` に上げ、運営者の Mac で `brew upgrade` → `brew test` が通った

v0.7.0 (2026-11-14、公開 `07ba66a`): 確認番号と下書き (docs/40 段階 6)。`verify <aid>` で相手との確認番号 (20 桁) を出し、パソコンが作る下書きは自分のエージェントの名簿の端末だけが読む (確認用の鍵は使わない)。macOS (Intel) のビルドが 1 度ランナーを得ずに取り消されたので、そのジョブだけ再実行した。4 つの配布物のハッシュと来歴の証明を確かめ、tap を `8051455` に上げ、運営者の Mac で `brew upgrade` → `brew test` が通った

v0.8.0 (2026-11-14、公開 `dcd6e8b`): 2 つ目の署名できるブラウザの名簿を読む (docs/40 §17、確かめる側)。署名者を覚えていない名簿は、覚えた版 (または版 1) から `GET /recipients/device-lists` でたどって確かめる。署名者を足す前に、パソコンをこの版にしておく (0.7.0 以前は 2 つ目のブラウザの名簿を断る)。4 つの配布物のハッシュと来歴の証明を確かめ、tap を `2c36d23` に上げ、運営者の Mac で `brew upgrade` → `brew test` が通った
