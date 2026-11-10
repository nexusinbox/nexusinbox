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
- **ログイン時の自動起動**: 起動にはパスフレーズが要る。macOS のキーチェーンにパスフレーズを置けば自動起動できるが、ログインしている間ずっと鍵を開けておくことになる。便利さと安全性の釣り合いを別に決める
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
