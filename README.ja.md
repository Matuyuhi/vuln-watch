# vuln-watch

[English](README.md)

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

oss-security には、CVE レコードより先に報告が出ることがよくあります。

## 判定ルール

| 条件 | 結果 |
|---|---|
| CISA KEV に掲載 | 即時 |
| インストール済みパッケージが USN の修正版より古い | 即時 |
| ウォッチ対象に強く一致（パッケージ・製品・タイトル）し、CVSS ≥ 7.0 またはスコアなし | 即時 |
| ウォッチ対象に強く一致し、CVSS < 7.0 | ダイジェスト |
| ウォッチ対象の語が説明文にだけ出現 | ダイジェスト（要確認） |
| インストール済みだが修正版を適用済み（USN） | ダイジェスト（または無視） |
| ウォッチ対象外で CVSS ≥ 9.0 | ダイジェスト |
| それ以外 | 無視 |

- `urgent = false` のウォッチ対象は、一致してもダイジェストにだけ入ります。
- 通知には、どのフィールドのどの語で一致したかを表示します。
- 複数の情報源から届いた同じ CVE は 1 回だけ通知します。後から KEV に載った場合は改めて通知します。
- REJECTED の CVE と withdrawn の GHSA は除外します。
- 初回実行では、各情報源の既存分を記録するだけで通知しません。
- 情報源の取得失敗が続くと警告を送り、復旧も通知します。
- 1 回の実行で送る即時通知は `max_urgent_per_run` 件までで、超過分はダイジェストに回します。

しきい値・除外語・ウォッチリストは [`config.example.toml`](config.example.toml) で設定します。

### インストール済みパッケージとの照合

`[installed] enabled = true` にすると、USN を `/var/lib/dpkg/status` と照合します。バージョンは dpkg と同じ規則で比較します。dpkg の状態は毎回読み直すので、`apt upgrade` を実行すればすぐに適用済みとして扱われます。リリース名は `/etc/os-release` から取得します。インストールされていないパッケージの USN は、ウォッチリストに一致していても無視します。

## 取りこぼし対策

- 即時通知は、カーソルや ETag を確定する前に outbox に保存します。Discord に送れなかった分は次の実行で再送します。
- GitHub Advisory は `updated` 順に取得し、前回の位置までページを遡ります。公開から時間が経って reviewed になったものも拾えます。
- 新しい CVE ID はキューに積み、`cvelist_max_records` 件ずつ処理します。同期の取りこぼしは経過時間（`GITHUB_TOKEN` 設定時はコミット履歴も）で検知し、約 30 日分の `deltaLog.json` から補完します。
- USN は前回の位置までページを遡ります。
- RSS は最新の数件しか配信されないため、長時間停止すると RSS の情報源では取りこぼすことがあります。`HEARTBEAT_URL` を設定すると、実行が止まったことに気づけます。

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
| `GITHUB_TOKEN` | 推奨。権限なしの fine-grained token で十分です。API 制限が 60 → 5,000 回/時になり、CVE List を CDN ではなく API から読むため最大 5 分速くなります。 |
| `HEARTBEAT_URL` | 任意。実行成功ごとに ping します（healthchecks.io など） |

`/etc/vuln-watch/config.toml` でウォッチリストと情報源を調整します。

### 4. 起動

```bash
sudo vuln-watch doctor

sudo systemctl start vuln-watch@test-notify.service

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
```

`--state-dir` の既定値は `$STATE_DIRECTORY` です（systemd では `/var/lib/vuln-watch`）。

`--dry-run` は送信せずに判定結果を表示し、状態も保存しません:

```bash
cargo run -- --config config.example.toml run --dry-run --limit 5
```

dpkg のない環境では `installed.enabled = false` にしてください。

## 運用

- **診断**: `sudo vuln-watch doctor` でインストール状態を項目ごとに ok / warn / FAIL で表示します。PATH 上で先に見つかる古い `vuln-watch`、新しいリリースの有無、パースできなくなった設定、`/etc/vuln-watch/env` の認証情報の不足や例のままの値とパーミッション、unit ファイルと `daemon-reload` の要否、タイマーが有効か、直近の実行が成功したか、連続して失敗しているソース、未送信の緊急通知、中断された upgrade の残骸を確認します。Discord には何も送りません。FAIL があれば終了コード 1 で終わり、`--offline` でリリース確認を省きます。インストール後や upgrade 後に実行してください。
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
