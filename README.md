# vuln-watch

脆弱性やセキュリティパッチの公開を**できるだけ早く・正確に**検知して、Discord の DM に通知する個人用ツールです。
VPS 上で systemd timer により 2 分おきに起動する、Rust 製のシングルバイナリです。

```
systemd timer (2分) ──▶ vuln-watch run
                          ├─ CISA KEV        （悪用確認済み）
                          ├─ GitHub Advisory （パッケージ単位）
                          ├─ CVE List        （CVE 公開そのもの・数分遅延）
                          ├─ Ubuntu USN      （パッチ公開 × インストール済みパッケージ照合）
                          └─ RSS/Atom        （oss-security, リリース…）
                               │
                     新着だけ抽出（SQLite で既読管理・ETag で差分取得）
                               │
                     ルール判定 ──▶ 即時: Discord DM
                               └──▶ ダイジェスト: 毎朝 8:00 にまとめて送信
```

## 通知の判定

| 条件 | 判定 |
|---|---|
| CISA KEV に掲載（実際に悪用が確認された） | **即時** |
| ウォッチ対象に**強く一致**（パッケージ名・製品名・タイトル）で、CVSS ≥ 7.0 またはスコア未付与 | **即時** |
| ウォッチ対象に強く一致したが、CVSS < 7.0 | ダイジェスト |
| ウォッチ対象の名前が**本文にだけ**出てくる（誤検知の可能性あり） | ダイジェスト（※要確認） |
| ウォッチ対象外で CVSS ≥ 9.0 | ダイジェスト |
| それ以外 | 通知しない |

ほかにも、次のように動きます。
- 通知には「どのフィールドの、どのキーワードで一致したか」が表示されるので、自分に関係あるかをすぐ判断できます
- 同じ CVE が複数のソースから届いても、通知は 1 回だけです。ダイジェスト扱いだったものが後から KEV に載った場合などは、即時通知に**格上げ**します
- 取り下げられた CVE（REJECTED）や撤回された GHSA（withdrawn）は無視します
- 各ソースは初回起動時に既存分を「既読」として記録するだけで、通知はしません（大量通知を防ぐため）
- あるソースの取得が連続して失敗すると ⚠️ 警告を送り、復旧すると ✅ を送ります
- 1 回の実行で送る即時通知には上限があり（既定 10 件）、超えた分はダイジェストに回します

### サーバーのパッケージとの照合（`[installed]`）

`installed.enabled = true` にすると、Ubuntu Security Notices を VPS に**実際に入っているパッケージ**（`/var/lib/dpkg/status`）と照合します。照合結果は次のように扱います。

| 照合結果 | 判定 |
|---|---|
| インストール済みで、バージョンが修正版より古い | **即時**（例：`zlib1g 1:1.3…2.2 → 1:1.3…2.3`） |
| インストール済みで、修正版が適用済み | ダイジェスト（`already_fixed = "ignore"` で通知なし） |
| このサーバーには入っていない | 通知しない |

バージョンは dpkg と同じ規則で比較します。dpkg の状態は毎回読み直すので、`apt upgrade` の後は自動的に「適用済み」として扱われます。リリース名（noble など）は `/etc/os-release` から自動で取得します。

しきい値・除外語・ウォッチリストは `config.toml` で変更できます（[config.example.toml](config.example.toml) を参照）。

### 取りこぼし対策

- **通知の永続化**：即時通知は送信前に DB のキュー（outbox）に保存します。Discord が落ちていても失われず、次の実行で再送します
- **GitHub Advisory**：`updated` 順に取得し、前回の位置までページを遡ります（停止中に 100 件を超えても、後から reviewed になった勧告も拾います）
- **CVE List**：新しい CVE ID はまずキューに積み、1 回あたり `cvelist_max_records` 件ずつ処理します（上限を超えても捨てません）。同期の取りこぼしは、前回実行からの経過時間と、GitHub のコミット数（トークン設定時）で検知し、`deltaLog.json`（約 30 日分）から補完します。個別レコードの取得失敗は次回に再試行します
- **KEV の格上げ**：すでに即時通知した CVE でも、後から KEV（悪用確認）に載ったら改めて通知します
- **Ubuntu USN**：RSS ではなく JSON API を使い、前回の位置までページを遡ります
- **既知の限界**：oss-security やリリースフィードなどの RSS は直近の数十件しか配信されないため、VPS が長時間止まっていた間の分は取りこぼす可能性があります（KEV・GitHub Advisory・CVE List・USN は遡って補完します）

### 速さについて

| ソース | 検知までの目安 |
|---|---|
| CVE List | 公開から約 7 分＋ポーリング間隔。`GITHUB_TOKEN` があれば CDN キャッシュ（最大 5 分）を通さず API で取得します |
| GitHub Advisory | 公開＋ポーリング間隔 |
| CISA KEV / RSS | 公開＋ポーリング間隔（ETag を使うので、高頻度で取得しても負荷はわずかです） |
| oss-security | CVE が採番される前の一次報告が最初に出ることが多いソースです |

## セットアップ

### 1. Discord Bot を用意する（DM で受け取る場合）

1. [Discord Developer Portal](https://discord.com/developers/applications) で New Application を作成し、Bot タブで **Reset Token** を押してトークンを控えます
2. OAuth2 → URL Generator で scope `bot` を選び（権限は不要）、生成された URL から**自分のサーバー**に Bot を招待します
   - Bot が DM を送るには、送り先のユーザーと同じサーバーにいる必要があります
3. Discord の設定 → 詳細設定 → 開発者モードを ON にし、自分のアイコンを右クリック →「ユーザー ID をコピー」で ID を控えます

DM ではなくチャンネルで受け取りたい場合は、`discord.mode = "webhook"` にして `DISCORD_WEBHOOK_URL` を設定します。

### 2. インストール

```bash
git clone https://github.com/Matuyuhi/vuln-watch.git
cd vuln-watch
sudo ./deploy/install.sh            # cargo でビルドしてインストール
# あるいは Releases のバイナリを使う場合:
# sudo ./deploy/install.sh ./vuln-watch
```

install.sh は次のものを配置します。
- `/usr/local/bin/vuln-watch`
- `/etc/vuln-watch/config.toml`（すでにあれば上書きしません）
- `/etc/vuln-watch/env`（権限 600、すでにあれば上書きしません）
- systemd のユニットファイル

### 3. 設定

```bash
sudo vi /etc/vuln-watch/env          # DISCORD_BOT_TOKEN, DISCORD_USER_ID, GITHUB_TOKEN
sudo vi /etc/vuln-watch/config.toml  # ウォッチリストを自分の環境に合わせる
```

`GITHUB_TOKEN` は**権限なしの fine-grained token** で十分なので、設定を強く推奨します。設定するとレート制限が 60/h から 5000/h に緩和され、CVE List の取得も速くなります。

### 4. 動作確認と起動

```bash
sudo systemctl start vuln-watch@check-config.service
journalctl -u vuln-watch@check-config -n 40     # 設定と認証情報を確認

sudo systemctl start vuln-watch@test-notify.service   # テスト DM が届くか確認

sudo systemctl enable --now vuln-watch-run.timer vuln-watch-digest.timer
journalctl -u 'vuln-watch@*' -f
```

ローカルで実データの取り込みを試すだけなら、次のコマンドで送信も状態の保存もせずに動作を確認できます。

```bash
cargo run -- --config config.example.toml run --dry-run --limit 5
```

## コマンド

```
vuln-watch [--config PATH] [--state-dir DIR] <COMMAND>
  run [--dry-run] [--limit N] [--strict]   全ソースを 1 回巡回（timer から実行）
  digest [--dry-run]                       ダイジェストを送信
  test-notify                              テスト通知
  check-config                             設定の検証
```

`--state-dir` を省略した場合は `$STATE_DIRECTORY` を使います（systemd が `/var/lib/vuln-watch` を渡します）。

## 運用メモ

- **死活監視**：VPS ごと止まると通知も止まります。`HEARTBEAT_URL` に healthchecks.io などの URL を設定すると、実行が成功するたびに ping します。`digest_send_empty = true` にしておけば、毎朝の DM が生存確認も兼ねます
- **ハードニング**：`DynamicUser`、`ProtectSystem=strict`、syscall フィルタなどで、外向き HTTPS と状態ディレクトリ以外には触れないように制限しています
- **更新**：`git pull && sudo ./deploy/install.sh` で更新できます。設定ファイルは上書きしません
- **フォーマット変更の検知**：週 1 回、GitHub Actions が実データに対して dry-run を実行し（[Live smoke test](.github/workflows/smoke.yml)）、上流 API の仕様変更に気づけるようにしています
- **依存関係スキャン**：[cargo-deny](deny.toml) で RustSec の脆弱性・ライセンス・禁止クレート（OpenSSL 系）・取得元を、PR と毎日の定期実行でチェックしています（[Dependencies](.github/workflows/deps.yml)）。ローカルでは `cargo deny check` で実行できます。依存の更新 PR は Dependabot が週 1 回作ります
- **アンインストール**

  ```bash
  sudo systemctl disable --now vuln-watch-run.timer vuln-watch-digest.timer
  sudo rm /etc/systemd/system/vuln-watch* /usr/local/bin/vuln-watch
  sudo rm -r /etc/vuln-watch /var/lib/private/vuln-watch
  ```

## ライセンス

MIT
