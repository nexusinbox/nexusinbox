# 23. Signer Daemon 上位鍵管理ポリシー

**Status**: Accepted — policy doc (not a migration plan).
**Scope**: `services/signer-daemon` が保持する Ed25519 秘密鍵（= エージェントのサイン鍵）の at-rest / in-memory 保護方針。
**Audience**: 運用者、セキュリティレビュアー、将来の maintainers。

## 1. 目的

Signer Daemon は、エージェントの JWS Assertion を発行する唯一の場所であり、鍵漏えいは即座に「そのエージェントを名乗って何でもできる」事態を意味する。ただし対策の強度はホスト環境・ユーザ規模・脅威モデルによって妥当な水準が違う。

このドキュメントは**どの規模・脅威モデルで何を使うべきか**の基準を示す。実装の仕様は [`docs/15_non_interactive_agent_access_design.md`](./15_non_interactive_agent_access_design.md) と各サービスの README を参照。

## 2. 現状 (baseline)

| 項目 | 実装 | 根拠ファイル |
|------|------|-------------|
| at-rest 暗号化 | XChaCha20-Poly1305 (libsodium secretstream 互換) | `services/signer-daemon/src/main.rs` |
| KEK 導出 | Argon2id (interactive parameters) + per-file salt | 同上 |
| KEK 入力 | 対話 passphrase (起動時 TTY prompt) | 同上 |
| in-memory 保護 | プロセス常駐のみ、`mlock` なし、ファイル権限 0600 | 同上 |
| IPC | Unix Domain Socket 0600 + `SO_PEERCRED` (`--allowed-uid`) | 同上 |

この構成は **「ホストへの root 侵害が成立していない」** ことを前提にしている。root を取られた時点で (a) メモリダンプから鍵を抜く、(b) UDS を直接叩いて署名を強要する、のどちらも可能なので、ホスト侵害を防げない構成では daemon の at-rest 暗号化だけを厚くしても本質的な防御にはならない。

## 3. 脅威モデル別の妥当な水準

| # | シナリオ | 許容できる構成 |
|---|----------|---------------|
| T1 | 単一開発者の laptop / 個人 VPS、攻撃面は持ち出し・紛失 | baseline (対話 passphrase) で十分 |
| T2 | 小規模 self-host (〜数ユーザ)、ホストは専有、物理アクセス管理あり | baseline + OS keychain で起動自動化 |
| T3 | 本番 SaaS / マルチテナント、共有ホスト、root 昇格の二次被害を抑えたい | TPM / OS-level sealed storage、または Cloud KMS-backed KEK |
| T4 | 高機密運用 (企業ユーザ、コンプライアンス要件あり) | HSM (Nitro Enclave / CloudHSM / YubiHSM) で鍵自体を外出しさせない |

## 4. 採用基準

下記を全部満たす段階で上位 Tier へ移行する。ひとつでも欠けているならまだ不要。

### T1 → T2: OS keychain に切り替える基準

- 起動自動化 (systemd / launchd) が本番要件になった
- passphrase を暗号化なしでどこかに置きたくなっている
- 複数マシンで同じ daemon を立てる想定が出てきた

移行時は macOS Keychain / GNOME libsecret / Windows DPAPI を `--kek-source=os-keychain` のような起動オプションで選べる形にする（未実装、必要になったら追加）。

### T2 → T3: TPM / sealed storage もしくは Cloud KMS を使う基準

- ユーザ数が 2 桁以上、ホストが複数、root 侵害時の blast radius がユーザ横断になりえる
- 監査要件で「鍵は暗号化されていて、かつ復号権限が分離されている」を求められた
- ホストが信頼しきれない (cloud 上の共有テナント、コンテナ環境)

採用候補:
- **TPM 2.0 sealed storage** — ホストに TPM があり、Linux で tpm2-tools が使える場合の第一候補。passphrase の代わりに TPM PCR にシール。
- **AWS KMS / GCP KMS / Azure Key Vault で KEK を envelope 暗号化** — daemon 起動時だけ KMS に `Decrypt` を飛ばし、plaintext KEK をメモリに展開、その後 KMS credential を破棄。鍵自体はローカルに残り、「誰が復号できるか」を IAM で制御できる。

どちらも **daemon のホスト root を取られた瞬間に負け** という点は baseline と同じ。ただし (a) 鍵ファイルだけ流出させても復号不能、(b) IAM / PCR の差分で横展開が限定される、という防御が増える。

### T3 → T4: HSM に移行する基準

- 規制対応 (金融・医療・政府) で「鍵は HSM から出してはならない」が required になった
- 1 エージェントあたりの鍵利用回数が多く、in-process 署名のサイドチャネル懸念が出てきた
- 鍵ローテの証跡が監査ログだけでなく HSM 側にも必要

HSM モードでは Signer Daemon は「署名リクエストを HSM に転送するだけのプロキシ」に退縮する。鍵は daemon プロセスのメモリにも一切載らない。この形にするには既存の署名コードパスを trait で差し替え可能にする必要があり、対応工数はそれなりに大きい。

## 5. 非移行判断: 今のところ baseline で十分な理由

2026-04 時点の NexusInbox は T1–T2 の中間にいる:

- 運用は maintainer 1 名、ホストは専有 VPS (app.nexusinbox.ai)
- 日次アクティブエージェントは少数、コンプライアンス要件なし
- ホスト root 侵害時点で「鍵暗号化以外」の多数の被害が発生するため、鍵周りだけ先行して HSM 化する費用対効果が低い

従って現状は **baseline 継続 + 4 節の閾値を満たした時点で再評価**、とする。早すぎる最適化は運用を複雑にするだけ。

## 6. 再評価トリガー

次のいずれかが観測された時点で本ドキュメントを更新し、T2/T3 への移行チケットを切る。

- ユーザ数が 2 桁に乗る / マルチテナント運用が始まる
- `services/signer-daemon` を複数ホストで動かす構成が出る
- コンプライアンス / 企業契約で鍵保護水準の要件が降ってくる
- 外部セキュリティレビューで baseline 不十分の指摘が入る

## 7. 参照

- [`docs/15_non_interactive_agent_access_design.md`](./15_non_interactive_agent_access_design.md) — 3 プロセス構成全体像
- [`docs/16_p8_security_verification.md`](./16_p8_security_verification.md) — 鍵関連の既知リスク (R1 / R3)
- [`docs/12_security_review_2026-04-11.md`](./12_security_review_2026-04-11.md) — baseline 採用時点の脅威分析
- [`services/signer-daemon/README.md`](../services/signer-daemon/README.md) — 実装オペレーション手順
