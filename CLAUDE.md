# 定期調査の手順（advisories ブランチ）

このブランチは vuln-watch（main ブランチの Rust CLI）の `kind = "advisory"` ソースが読む勧告置き場です。
あなたの仕事は、CVE 単体では見えにくい「このソフトは今すぐ更新すべき」という横断的な勧告を見つけ、
`advisories/<年>/<id>.toml` に記録して PR を出すことです。

拾いたいのは次のような話です。

- 共通部品・ランタイム（Chromium / Electron / OpenSSL / glibc / log4j / curl / zlib など）の問題で、多数の製品が更新を必要としている
- 証明書・CA・署名鍵の漏えいや失効（例: 2026-10 の eMudhra 中間 CA 鍵の漏えいで Electron 製アプリ、Go のバイナリ、certifi、ca-certificates の更新が必要になった件）
- サプライチェーン侵害（改ざんされたパッケージ・リリース・拡張機能）
- 実際に悪用が始まり、ベンダーが更新を強く求めている事例

単一の CVE で、既に CISA KEV や GitHub Advisory Database に載っていて横断的な話がないものは書きません（vuln-watch が別ソースで拾います）。

## 手順

1. `advisories/` の active な勧告と `watch-hints.txt`（関心のあるソフト）を読む。
2. 過去 48 時間の動きを検索する（最大 15 回）。候補ごとに一次情報を実際に開いて確認する。
3. 既存の勧告と同じ話題なら新規作成せず、重要な変化（重大度・対象・対策）があるときだけ既存ファイルの `revision` を上げて `updated` を更新する。終息したら `status = "resolved"`、誤りだったら `status = "withdrawn"`。
4. 新規は 1 回 3 件まで。該当がなければ何も変更せず終わる（それが普通）。
5. `python3 scripts/validate.py --online <変更したファイル>` を実行し、エラーがなくなるまで直す。
6. `advisories` ブランチから `advisory/<日付>` ブランチを切って push し、`advisories` ブランチ宛てに PR を作る。PR 本文には各勧告の要点と、確度の根拠を 1 行ずつ書く。自分でマージしない。

## 形式

`examples/VWA-2026-0101-example.toml` を見本にする。ファイル名は `id` と同じ。`id` は `VWA-<年>-<月日>-<slug>`（例 `VWA-2026-1025-emudhra-ca`）で、作成後は変えない。

## 必ず守ること

- `references` には実際に開いた URL だけを書く。`quote` はそのページの本文から文字どおり写す（CI がページ本文に含まれるか検証する）。
- primary は一次情報（ベンダー公式の勧告・リリースノート・ブログ、CISA / JPCERT / 各国 CERT、NVD / cve.org、GitHub Advisory）。ニュースやブログは secondary。
- 修正版のバージョン、CVE 番号、影響製品は出典に書いてあるものだけ。推測で埋めない。
- 知らない名前や通称だけの話は、一次情報で正体を確認できるまで `confidence = "confirmed"` にしない。
- primary がなければ `confidence = "unverified"`、`severity` は `medium` 以下。
- `actions`（対策）は出典の推奨策を優先し、独自の提案には先頭に「（独自提案）」と書く。
- `deb` は Ubuntu のパッケージ名と修正版を出典（USN など）で確認できたときだけ書き、`release` にコードネームを付ける。
- `expires` は既定で 30 日後、最大 90 日後。
- サーバー構成など、関心ソフト以外の環境情報をこのブランチに書かない（公開リポジトリです）。
