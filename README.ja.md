# vuln-watch

[English](README.md)

## 目次

- [情報源](#情報源)
- [判定ルール](#判定ルール)
  - [インストール済みパッケージとの照合](#インストール済みパッケージとの照合)
- [取りこぼし対策](#取りこぼし対策)
- [セットアップ](#セットアップ)
  - [Discord](#1-discord)
  - [インストール](#2-インストール)
  - [設定](#3-設定)
  - [起動](#4-起動)
- [使い方](#使い方)
- [運用](#運用)
- [開発](#開発)
  - [リリース手順](#リリース手順)
- [ライセンス](#ライセンス)

脆弱性情報を 2 分おきに取得し、自分に関係するものを Discord の DM で通知します。対象は、悪用が確認された CVE、依存パッケージのアドバイザリ、ホストにインストール済みのパッケージに対する Ubuntu のパッチです。それ以外は 1 日 1 回のダイジェストにまとめます。

Rust 製のシングルバイナリで、systemd timer から起動します。状態は SQLite に保存します。

```
systemd timer (2分) ─▶ vuln-watch run
                         ├─ CISA KEV            悪用確認済み
                         ├─ GitHub Advisory DB  パッケージ単位のアドバイザリ
                         ├─ CVE List            新規 CVE
                         ├─ Ubuntu USN          パッチ公開（dpkg と照合）
                         └─ RSS / Atom          oss-security、リリース
                                │
                       新着のみ（既読管理・ETag）
                                │
                       ルール ─┬─▶ 即時        → Discord DM
                               └─▶ ダイジェスト → 毎日 8:00
```

## 情報源

| kind | 情報源 | 遅延 |
|---|---|---|
| `kev` | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | ポーリング間隔 |
| `ghsa` | [GitHub Advisory Database](https://github.com/advisories)（reviewed） | ポーリング間隔 |
| `cvelist` | [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) | 約 7 分の同期 + ポーリング間隔 |
| `usn` | [Ubuntu Security Notices](https://ubuntu.com/security/notices)（JSON API） | ポーリング間隔 |
| `feed` | 任意の RSS/Atom（例: [oss-security](https://seclists.org/oss-sec/)） | ポーリング間隔 |
| `advisory` | Claude の定期調査が GitHub のブランチに書く勧告（[詳細](#claude-の定期調査による勧告)） | 調査の間隔 + ポーリング間隔 |

oss-security には、CVE レコードより先に報告が出ることがよくあります。

## 判定ルール

| 条件 | 結果 |
|---|---|
| CISA KEV に掲載 | 即時 |
| インストール済みパッケージが USN の修正版より古い | 即時 |
| カーネルの USN で修正版はインストール済みだが、実行中のカーネルが古い（再起動待ち） | 即時 |
| ウォッチ対象に強く一致（パッケージ・製品・タイトル）し、CVSS ≥ 7.0 またはスコアなし | 即時 |
| ウォッチ対象に強く一致し、CVSS < 7.0 | ダイジェスト |
| ウォッチ対象の語が説明文にだけ出現 | ダイジェスト（要確認） |
| インストール済みだが修正版を適用済み（USN） | ダイジェスト（または無視） |
| ウォッチ対象外で CVSS ≥ 9.0 | ダイジェスト |
| それ以外 | 無視 |

- `urgent = false` のウォッチ対象は、一致してもダイジェストにだけ入ります。
- 複数のウォッチ対象が一致したときは、設定の順番に関係なく、`urgent = true` の強い一致 → `urgent = false` の強い一致 → 本文のみの一致の順で優先されます。下の勧告でも同じです。
- ダイジェストは、ウォッチ対象やインストール済みパッケージに一致したものを先に並べ、CVSS だけで入ったものは別の見出しの下にまとめます。
- タイトルに製品名がない場合は、通知に対象の製品名を添えます。
- 通知には、どのフィールドのどの語で一致したかを表示します。
- 複数の情報源から届いた同じ CVE は 1 回だけ通知します。後から KEV に載った場合は改めて通知します。
- REJECTED の CVE と withdrawn の GHSA は除外します。
- 初回実行では、各情報源の既存分を記録するだけで通知しません。
- 情報源の取得失敗が続くと警告を送り、復旧も通知します。
- 1 回の実行で送る即時通知は `max_urgent_per_run` 件までで、超過分はダイジェストに回します。

しきい値・除外語・ウォッチリストは [`config.example.toml`](config.example.toml) で設定します。

### インストール済みパッケージとの照合

`[installed] enabled = true` にすると、USN を `/var/lib/dpkg/status` と照合します。バージョンは dpkg と同じ規則で比較します。dpkg の状態は毎回読み直すので、`apt upgrade` を実行すればすぐに適用済みとして扱われます。リリース名は `/etc/os-release` から取得します。インストールされていないパッケージの USN は、ウォッチリストに一致していても無視します。

カーネルの修正は再起動するまで有効になりません。パッケージがインストール済みのカーネルの USN では、実行中のカーネル（`uname -r`、例: `6.8.0-145-generic`）も比較します。その `linux-image-<release>` パッケージが同じフレーバーの修正版より古ければ、適用済みではなく「再起動待ち」として即時通知します。修正版のカーネルイメージがまだインストールされていなければ「未適用」として即時通知します。HWE と `virtual` のメタパッケージは `generic` フレーバーとして扱います。dpkg で管理されていないカーネル（自前ビルド・コンテナ）は比較しません。検出した実行中のカーネルは `vuln-watch doctor` で確認できます。

### Claude の定期調査による勧告

CVE が付かないまま多くの製品に「今すぐ更新」が必要になる問題があります（例: CA の鍵の漏えいで、Electron 製アプリ・Go のバイナリ・`ca-certificates` が信頼を外す必要がある）。こうした勧告を、Claude の定期調査が対策と出典付きで GitHub のブランチ（既定ではこのリポジトリの `advisories` ブランチ）の `advisories/` 以下に 1 件 1 ファイルの TOML として書きます。`kind = "advisory"` はそのブランチを GitHub API で読み、前回から変わったファイルだけを取得します。`GITHUB_TOKEN` があれば使います。

| 条件 | 結果 |
|---|---|
| 勧告の `deb` パッケージがインストール済みで修正版より古い | 即時 |
| それ以外で severity が `low` | ダイジェスト |
| 一致したのが `urgent = false` のウォッチだけ | ダイジェスト |
| それ以外（ウォッチ一致の有無を問わない） | 即時 |

- 勧告は件数が少なく毎回手でマージするので、原則即時です。一致したウォッチやインストール済みパッケージがあれば理由欄に出します。
- `confidence = "unverified"` の勧告と、`primary` の出典がない勧告は即時通知しません。
- `expires` を過ぎた勧告、`status` が `resolved` / `withdrawn` の勧告は読み飛ばします。
- `revision` が上がると再通知します。それ以外の修正では通知しません。
- 通知には「Claude 調査」と確度を必ず載せます。即時通知には対策と出典を、ダイジェストには対策と勧告ファイルへのリンク（出典はファイル内）を載せます。対応の前に出典を確認してください。

## 取りこぼし対策

- 即時通知は、カーソルや ETag を確定する前に outbox に保存します。Discord に送れなかった分は次の実行で再送します。Discord が内容を不正として拒否した通知はテキストのみで送り直すため、後続の通知を止めません。
- ダイジェストはメッセージを 1 通送るごとにその分をキューから消すため、途中で失敗しても送信済みの分を重複して送りません。失敗した場合は、次の `run`（5 分以上経過後）が残りを「（再送）」の見出しで送り直します。再送の失敗はログに残すだけで、即時通知を止めません。
- `run` は同時に 1 つしか動きません。タイマーの `run` の実行中に手動で `sudo vuln-watch run` を実行した場合は何もせず終了し（終了コード 0、stderr に 1 行表示）、同じ即時通知が二重に送られることはありません。タイムアウトで強制終了された `run` が後続の実行を止めるのは最大 6 分です。
- GitHub Advisory は `updated` 順に取得し、前回の位置までページを遡ります。公開から時間が経って reviewed になったものも拾えます。遡りは 20 ページ（2,000 件）で打ち切ります（長い停止や GitHub による一括更新の後など）。届かなかった範囲は後続の実行で古い順に 1 回最大 5 ページずつ読みます。API のレート制限の残りが 30 回以下のときは読まず、`GITHUB_TOKEN` なしでも通常の巡回の分を残します。読んだものは通常どおりルールと重複排除を通します。未読の範囲が残っている間は `vuln-watch doctor` が警告します。
- 新しい CVE ID はキューに積み、`cvelist_max_records` 件ずつ処理します。同期の取りこぼしは経過時間（`GITHUB_TOKEN` 設定時はコミット履歴も）で検知し、約 30 日分の `deltaLog.json` から補完します。`deltaLog.json` を読めない場合は `delta.json` にフォールバックし、取りこぼした同期分の CVE が抜けている可能性を警告ログに出します。CVE レコードの取得に失敗した場合は毎回の実行で再試行し、10 回失敗**かつ**キューに入って 48 時間経ってから諦めます。諦めた CVE は黙って捨てず、「レコード取得に失敗（48時間）」と cve.org へのリンクを付けてダイジェストに載せます。1 回の実行でレコード取得がすべて失敗した場合（HTTP 404 を除く）はソースの失敗として数え、通常のソース失敗アラートが出ます。キュー内の ID は保持されます。失敗が続くレコードは他のキュー内レコードの後に試すため、新しい CVE の処理を遅らせません。
- USN は前回の位置までページを遡ります。
- RSS は最新の数件しか配信されないため、長時間停止すると RSS の情報源では取りこぼすことがあります。`HEARTBEAT_URL` を設定すると、実行が止まったことに気づけます。
- 取得に失敗し続けるソースは `alert_after_failures` 回連続で失敗した時点で通知します。取得は成功するのに新しい項目が `stale_after_hours`（`[[source]]` ごと。既定は `cvelist` 12、`ghsa` 72、`usn` 168、`kev` 720、`feed` / `advisory` 0 = 無効）時間届かないソースは「新しい項目がありません」と一度だけ通知し、新しい項目が届いたら「新しい項目が届きました」と通知します。API のフィールド名の変更やフィードの移転など、黙って壊れたソースに気づくためのものです。USN の `notices` と cvelist の delta の `new` は必須フィールドとして扱い、形式が変わったら空として読まずに取得失敗にします。

## セットアップ

### 1. Discord

DM で受け取る場合（既定）:

1. [Discord Developer Portal](https://discord.com/developers/applications) でアプリケーションを作成し、**Bot** でトークンを発行して控えます。
2. **OAuth2 → URL Generator** で `bot` スコープを選び（権限は不要）、自分が参加しているサーバーに Bot を招待します。Bot は、サーバーを共有しているユーザーにしか DM を送れません。
3. Discord の開発者モードを有効にし、自分の名前を右クリックしてユーザー ID をコピーします。

チャンネルで受け取る場合は、`discord.mode = "webhook"` と `DISCORD_WEBHOOK_URL` を設定します。

### 2. インストール

x86_64 / aarch64 の Linux（systemd、glibc 2.35 以降。Ubuntu 22.04 以降、Debian 12 以降など）で次を実行します。

```bash
curl -fsSL https://raw.githubusercontent.com/Matuyuhi/vuln-watch/main/install.sh | sudo bash
```

マシンに合った最新の[リリース](https://github.com/Matuyuhi/vuln-watch/releases)をダウンロードして `SHA256SUMS` で検証し、`/usr/local/bin/vuln-watch` と systemd ユニットを配置します。`/etc/vuln-watch/{config.toml,env}` がなければ作成します。バージョンを指定する場合は `bash` の後ろに `-s -- --version 1.2.0` を付けます。

<details>
<summary>リリースのアーカイブから手動で入れる</summary>

```bash
VERSION=1.2.0                                   # リリースページで確認
NAME=vuln-watch-v$VERSION-$(uname -m)-unknown-linux-gnu
curl -fsSLO https://github.com/Matuyuhi/vuln-watch/releases/download/v$VERSION/$NAME.tar.gz
curl -fsSLO https://github.com/Matuyuhi/vuln-watch/releases/download/v$VERSION/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify $NAME.tar.gz --repo Matuyuhi/vuln-watch   # 任意: ビルド来歴の検証
tar -xzf $NAME.tar.gz
sudo ./$NAME/deploy/install.sh
```

</details>

<details>
<summary>ソースからビルドする</summary>

Rust ツールチェーンが必要です。

```bash
git clone https://github.com/Matuyuhi/vuln-watch.git
cd vuln-watch
sudo ./deploy/install.sh
```

</details>

### 3. 設定

`/etc/vuln-watch/env`（権限 600）:

| 変数 | |
|---|---|
| `DISCORD_BOT_TOKEN` | DM 送信に必須 |
| `DISCORD_USER_ID` | 送信先。`discord.user_id` より優先 |
| `DISCORD_WEBHOOK_URL` | Webhook 送信に必須 |
| `GITHUB_TOKEN` | 推奨。権限なしの fine-grained token で十分です。API 制限が 60 → 5,000 回/時になり、CVE List を CDN ではなく API から読むため最大 5 分速くなります。`https://api.github.com` にだけ送ります。`ghsa` / `advisory` の `url`（や次ページのリンク）が別のホストのときはトークンなしで読み、実行ごとに 1 回警告します。 |
| `HEARTBEAT_URL` | 任意。実行成功ごとに ping します（healthchecks.io など） |

`/etc/vuln-watch/config.toml` でウォッチリストと情報源を調整します。ウォッチリストは `vuln-watch watch` でも編集できます（[使い方](#使い方)を参照）。情報源の `url` は `https://` で始める必要があります（`http://` を使えるのは `kind = "feed"` だけです）。

### 4. 起動

```bash
sudo vuln-watch doctor

sudo vuln-watch test-notify

sudo systemctl enable --now vuln-watch-run.timer vuln-watch-digest.timer
sudo journalctl -u 'vuln-watch@*' -f
```

ダイジェストの送信時刻は `deploy/systemd/vuln-watch-digest.timer` で設定します（8:00 Asia/Tokyo）。

## 使い方

```
vuln-watch [--config PATH] [--state-dir DIR] <COMMAND>

  run [--dry-run] [--limit N] [--strict]   全情報源を 1 回取得
  digest [--dry-run]                       ダイジェストを送信
  test-notify                              テスト通知を送信
  check-config                             設定と認証情報を検証
  doctor [--offline]                       インストール状態を診断（root で実行）
  upgrade [--check] [--version V] [--pre]  最新リリースに更新（root で実行）
  watch list                               ウォッチリストを表示
  watch add NAME [-k WORD] [-p PKG]...     ウォッチを追加（root で実行）
  watch edit NAME [-k ...] [--rm-keyword ...]  ウォッチを変更（root で実行）
  watch remove NAME                        ウォッチを削除（root で実行）
```

`--state-dir` の既定値は `$STATE_DIRECTORY` です（systemd では `/var/lib/vuln-watch`）。

インストール済みのホストでは、シェルから実行した `run`・`digest`・`test-notify`・`check-config` は systemd のサービスとして動きます。`sudo` を付けると、vuln-watch が `vuln-watch@.service` と同じ設定で `systemd-run` 経由で自分自身を実行し直します。そのため `/etc/vuln-watch/env` の認証情報を使い、タイマーと同じ state を共有しつつ、出力と終了コードはそのまま端末に返ります（`sudo vuln-watch digest`、`sudo vuln-watch run --strict` など）。`sudo` なしでは案内を出して止まります。ただし認証情報も state も使わない `run --dry-run` はそのまま動きます。別の state ディレクトリでローカルに実行したい場合は `--state-dir` を指定してください。

`vuln-watch watch` は config.toml の `[[watch]]` をその場で書き換えます。コメントや書式は残ります。書き込む前にサービスと同じ検証を通し、存在しない情報源・空の値・同名のエントリはエラーにします（重複したキーワードや極端に短いキーワードは警告のみ）。`add` / `edit` には `-k/--keyword`・`-p/--package`・`-s/--source`（複数指定可）と `--urgent` / `--no-urgent` を、`edit` にはさらに `--rm-keyword`・`--rm-package`・`--rm-source` を指定できます。名前は大文字小文字を区別しません。`--dry-run` を付けると書き込まずに結果だけ表示し、書き込んだ場合は直前の内容を `config.toml.bak` に残します。変更は次回のタイマー実行から反映され、再起動は不要です。`watch list` と `--dry-run` は `sudo` なしで動きます。

```bash
sudo vuln-watch watch add PHP -k php -p php/php-src
sudo vuln-watch watch edit php -k laravel --no-urgent
sudo vuln-watch watch remove PHP
```

`--dry-run` は送信せずに判定結果を表示し、状態も保存しません:

```bash
cargo run -- --config config.example.toml run --dry-run --limit 5
```

dpkg のない環境では `installed.enabled = false` にしてください。

## 運用

- **診断**: `sudo vuln-watch doctor` でインストール状態を項目ごとに ok / warn / FAIL で表示します。PATH 上で先に見つかる古い `vuln-watch`、新しいリリースの有無、パースできなくなった設定、`/etc/vuln-watch/env` の認証情報の不足や例のままの値、systemd が無視する行や使われない変数、パーミッション、unit ファイルと `daemon-reload` の要否、タイマーが有効か、直近の実行が成功したか、連続して失敗しているソース、各ソースに最後に新しい項目が届いた時刻（`stale_after_hours` を超えていれば警告）、未送信の緊急通知、中断された upgrade の残骸を確認します。Discord には何も送りません。FAIL があれば終了コード 1 で終わり、`--offline` でリリース確認を省きます。インストール後や upgrade 後に実行してください。
- **更新**: `sudo vuln-watch upgrade` で最新リリースを `install.sh` と同じ手順で入れ直します（`--check` は確認のみ、`--version 1.2.0` でバージョン指定、`--pre` でプレリリースも対象）。設定と状態はそのまま残ります。`config.example.toml` の変更は [CHANGELOG.md](CHANGELOG.md) で確認してください。ソースから入れた場合は `git pull && sudo ./deploy/install.sh`。
- **サンドボックス**: ユニットは `DynamicUser`、`ProtectSystem=strict`、syscall フィルタを使います。プロセスができるのは外向き通信と状態ディレクトリへの書き込みだけです。
- **アンインストール**:

  ```bash
  sudo systemctl disable --now vuln-watch-run.timer vuln-watch-digest.timer
  sudo rm /etc/systemd/system/vuln-watch* /usr/local/bin/vuln-watch
  sudo rm -r /etc/vuln-watch /var/lib/private/vuln-watch
  ```

## 開発

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
```

CI ワークフロー:

- [CI](.github/workflows/ci.yml): fmt、clippy、テスト。
- [Live smoke test](.github/workflows/smoke.yml): 週 1 回、実際の情報源に対して dry-run を実行し、上流のフォーマット変更を検知します。
- [Dependencies](.github/workflows/deps.yml): [cargo-deny](deny.toml) を毎日実行します（RustSec、ライセンス、禁止クレート、取得元）。依存の更新 PR は Dependabot が週 1 回作成します。
- [CodeQL](.github/workflows/codeql.yml): Rust コードとワークフローの静的解析。push・PR ごとと週 1 回実行し、結果は *Security → Code scanning* に表示されます。
- [Release](.github/workflows/release.yml): リリースを作成・公開します（下記）。

### リリース手順

リリース作業はすべて GitHub Actions 上で行います。

1. 変更をマージするたびに [CHANGELOG.md](CHANGELOG.md) の `## [Unreleased]` に追記します。
2. `main` で *Actions → Release → Run workflow* を開き、バージョン（例: `0.2.0`）を入力して実行します。`0.2.0-rc.1` のようにサフィックス付きのバージョンはプレリリースとして公開されます。
3. ワークフローが `Cargo.toml`/`Cargo.lock` のバージョン更新、CHANGELOG の日付付け、fmt/clippy/テストを行い、`release: v0.2.0` コミットと `v0.2.0` タグを `main` に push します。続けて x86_64 と aarch64 をビルド・動作確認し、アーカイブを `SHA256SUMS`・ビルド来歴の attestation・CHANGELOG の該当セクション（リリースノート）とともに公開します。

*dry run* にチェックを入れると、push と公開以外をすべて実行し、アーカイブを実行結果の artifact として残します。dry run は `main` 以外のブランチでも実行できます。

`main` にブランチ保護をかけている場合は、GitHub Actions が push できるように許可してください（ruleset のバイパス対象に追加）。許可がないと push ステップで失敗します。

## ライセンス

[MIT](LICENSE)
