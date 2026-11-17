# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `require_watch = true` on a `kind = "advisory"` source notifies only Claude advisories that match a `[[watch]]` entry, or that list a `deb` package installed here and older than its fixed version. Others are ignored ("ウォッチ不一致"), also with `mode = "urgent"`. Default `false` (every advisory, as before). Other kinds reject the setting.
- `exclude = [...]` on a `[[watch]]` entry: these terms are blanked out (whole-word, case-insensitive) of the product, package, title and description text before the entry's keywords are matched, so the `nginx` keyword no longer strong-matches `Kubernetes ingress-nginx` or `Nginx UI` and sends them as urgent DMs; an item that also names plain `nginx` still matches. Exact `packages` matches are not affected; Claude advisories use the same matching. Empty terms are rejected. `vuln-watch watch add/edit --exclude WORD`, `watch edit --rm-exclude WORD`, and a new EXCLUDE column in `watch list`. `config.example.toml` sets `exclude = ["ingress-nginx", "nginx-ui", "nginx ui", "nginx proxy manager"]` on the `nginx` entry.

### Changed

- Urgent items over `max_urgent_per_run` are no longer moved to the digest (which waits for the 08:00 timer, up to ~24 hours). They are sent in the same run as one compact list message, "⚠️ 即時通知の上限（N件/回）を超えた残りM件", with the digest line format (id and link, product, title, score, reason), split into several messages under Discord limits when needed. Listed items count as notified urgently. If a list message fails transiently, its items stay in the outbox for the next run; if Discord rejects it, its items go to the digest as before (with `digest = false`, they stay in the outbox and are sent one by one by later runs), with one notice. The old "残りN件はダイジェストに回しました" notice is gone. `max_urgent_per_run` still caps the individual urgent messages per run.

### Security

- `vuln-watch doctor` printed up to 40 characters of a line of `/etc/vuln-watch/env` that has no `=`, so a token pasted on its own line (e.g. a 40-character `ghp_…` GitHub token in full, or the start of a Discord bot token) appeared in its output. Such a line is now reported by line number only ("not KEY=value; systemd ignores it (a token pasted on its own line?)"). Text from it is shown only when it is a `[section]` header or starts with a variable name vuln-watch reads (`GITHUB_TOKEN: x`). Lines with `=` still show only the part before `=`, with the same hints as before.
- The heartbeat URL must start with `https://`. `runtime.heartbeat_url` in `config.toml` with another scheme fails config validation (the error shows only the scheme, never the URL). A `HEARTBEAT_URL` that is not `https://` is not pinged; `run` logs a warning and `vuln-watch doctor` reports it as a failure. Over `http://`, the token in the URL was sent in clear text on every run.
- `runtime.heartbeat_url` in `config.toml` (world-readable, so the service user can read it) is discouraged: `run` logs one warning per run and `vuln-watch doctor` warns, advising to move it to `HEARTBEAT_URL` in `/etc/vuln-watch/env` (mode 600). It still works. Anyone who knows the URL can keep the heartbeat green while vuln-watch is not running. `config.example.toml` no longer suggests setting it there.
- Urgent DMs now escape text that comes from sources (CVE / GHSA titles and descriptions, feed titles, product names, field values such as GHSA fixed versions) before it goes into the message content, the embed description and the embed fields, as the digest and the plain-text fallback already did. A crafted title, description or product name could otherwise show a masked link (`[text](https://…)`) whose visible text is not its target. The embed title is not rendered as Markdown and is unchanged. The `出典` links of Claude advisories still work: they are rebuilt from an escaped title and a validated URL.
- Item URLs are validated before they are used as the embed link, in the plain-text fallback and in the digest: only `http`/`https` URLs without credentials are accepted, in normalized form (`<`, `>`, quotes and whitespace percent-encoded), so a feed `<link>` cannot close the digest link early and inject Markdown. Items without a valid URL are shown without a link.
- The "source failing" DM put the error text (for an HTTP error, the first 300 characters of the remote response body) in a ``` code block as is. A body containing ``` closed the block early, and the rest rendered as Discord Markdown, so a feed host or anyone on the path of an `http://` feed could show a masked link in a DM from the bot. Backticks in the error are now broken up with a zero-width space so the block can't be closed from inside, and when the text is cut the closing fence is still added. The URL, the HTTP status and the body text are still shown.
- cvelist: a delta entry whose `cveId` is not `CVE-YYYY-NNNN…` (ASCII digits) is now skipped with a warning. Before, a non-ASCII id without `githubLink` (e.g. `CVE-2026-é12`) panicked while building the record URL, which stopped the whole run (no outbox flush, no later sources, no "source failing" DM) on every run while the entry stayed in `deltaLog.json` (up to ~30 days). The cursor still moves past such a delta and its valid CVEs are processed. Building the record URL no longer panics on any input, and a `githubLink` that is not `http(s)://` is ignored in favour of the standard record URL.

### Fixed

- A digest line with a very long feed GUID, title or reason (or many Markdown characters) was cut at 600 characters, which could drop its link, score and reason. Each field is now bounded on its own instead (id 80, title 90, severity 20, reason 120, actions 150 characters; a link longer than 300 characters is left out), and the line is no longer cut as a whole.
- `vuln-watch doctor` read a quoted value in `/etc/vuln-watch/env` (`KEY="value"` or `KEY='value'`) with its quotes, unlike systemd, so it could misjudge the credentials. It now removes the quotes as systemd does; a quoted empty value counts as unset.

## [1.2.0] - 2026-11-03

### Added

- `[rules] require_remedy = true` sends an urgent message only when a fix or mitigation is published: a GHSA with a patched version, a USN, a KEV entry with a required action, or a Claude advisory with actions or fixed versions. Other items that would be urgent are ignored ("対処未公開") without being marked as notified, so the same CVE is sent when a source with the fix arrives, and the same advisory is decided again when it is updated with a fix. Sources with `mode = "urgent"` are not affected. Default `false`.
- `[rules] digest = false` turns the digest off: items that would go to it are ignored ("ダイジェスト無効"), urgent messages over `max_urgent_per_run` stay in the outbox for the next run, and a cvelist record given up after 48 hours is only logged. `vuln-watch digest` and the digest retry in `run` send nothing. Default `true`.

### Fixed

- When several `[[watch]]` entries matched the same item, the first one in the config decided, so an earlier `urgent = false` entry (e.g. Chrome with keyword `chromium`) sent an item that a later `urgent = true` entry matched by exact package name (e.g. Electron) to the digest instead of an urgent DM. `vuln-watch watch add` appends entries at the end, so new urgent entries were always affected. The match is now chosen by rank, whatever the order: a strong match from an `urgent = true` entry, then a strong match from an `urgent = false` entry, then a description-only match. `watch_urgent_cvss` still applies to the chosen match. Claude advisories use the same rule; a description-only match from an urgent entry no longer outranks a strong match from a digest-only entry there.
- `rust-version` in `Cargo.toml` is now `1.89`, the oldest Rust that builds the locked dependencies (`uuid` 1.29 needs 1.89; `sha2` 0.11 needs 1.88). It said `1.82`, so a source install with Rust 1.82–1.88 failed in `cargo build --locked` without warning. CI has a new `msrv` job that runs `cargo check --locked --all-targets` with the version read from `Cargo.toml`, so a dependency bump that needs a newer Rust fails CI. The README states the minimum for source builds.

### Security

- Minor revisions

## [1.1.4] - 2026-10-28

### Added

- Alert when a source keeps succeeding but returns nothing new for too long. Each `[[source]]` takes `stale_after_hours` (default: `cvelist` 12, `ghsa` 72, `usn` 168, `kev` 720, `feed` / `advisory` 0 = off). When it is exceeded, one "⚠️ ソース `name` から N時間、新しい項目がありません（取得は成功）" message is sent; the next new item sends "✅ ソース `name` に新しい項目が届きました。". The time of the last new item is kept in `lastnew:<name>` (set on bootstrap and whenever a fetch returns an unseen item; existing installs start counting at the first run after the upgrade, without an alert). Nothing is sent in `--dry-run`.
- `vuln-watch doctor` shows when each source last returned something new and warns when it is over `stale_after_hours`.

### Changed

- The USN `notices` field and the cvelist delta `new` field are now required. If the format changes, the fetch fails and the usual source failure alert fires, instead of every page silently reading as empty.

### Fixed

- cvelist no longer drops a CVE silently when its record download keeps failing. Previously a record was removed from the queue after 10 failed runs (about 20 minutes), with only a log line and no failure alert, so a short outage or rate limiting on `raw.githubusercontent.com` could lose a critical CVE. A record is now given up only after 10 failed runs **and** 48 hours in the queue, and is then listed in the digest ("レコード取得に失敗（48時間）" with a cve.org link) and marked seen. When every record download in a run fails with an error other than HTTP 404, the fetch fails so the usual source failure alert fires; the attempts and the delta cursor are still saved and the ids stay queued. Records that keep failing are tried after the other queued ones, so they never hold back newer CVEs.
- GitHub advisories (`kind = "ghsa"`) are no longer skipped when a catch-up walk stops at its 20-page limit (2,000 advisories, e.g. after several days of downtime or a bulk update by GitHub). Previously the cursor moved to the newest advisory anyway, so those updated between the old position and the oldest one read were never read and only a log line remained. The unread range is now stored (`ghsa:<name>:backfill`, committed after the items are queued) and read on later runs in ascending `updated` order, up to 5 pages per run while more than 30 GitHub API requests remain in the rate-limit window, so normal polling keeps its quota without `GITHUB_TOKEN`; a second limit hit widens the range. Backfilled advisories go through the usual seen / rules / de-duplication path. `vuln-watch doctor` warns while a range is unread. Bootstrap and `--dry-run` still read one page and never store a range.

### Security

- `GITHUB_TOKEN` is now sent only to `https://api.github.com`. Previously `ghsa` and `advisory` sources added it to every request, so an `http://` or mirror `url`, a typo in the host, or a `rel="next"` link to another host sent the token in clear text or to a third party. Such requests now go without it and log one warning per run (`<source>: GITHUB_TOKEN not sent to <origin> (only https://api.github.com)`; the token is never logged). An `advisory` source pointed at a GitHub Enterprise API base no longer sends the token.
- `check-config` (and every command that loads the config) now rejects a `url` that does not start with `https://` for `kev`, `ghsa`, `cvelist`, `usn` and `advisory` sources. `feed` sources may still use `http://`.

## [1.1.3] - 2026-10-25

### Changed

- Advisories (`kind = "advisory"`) are now urgent by default, whether or not they match a watch entry or an installed package. Only advisories with severity `low` (unless an installed `deb` package of theirs is outdated), those whose only match is a watch entry with `urgent = false`, and unverified ones go to the digest. Previously only an outdated installed package or a strong watch match with severity `high`/`critical` was urgent, so a confirmed cross-cutting advisory such as a CA key compromise waited for the morning digest.

## [1.1.2] - 2026-10-25

### Added

- New source `kind = "advisory"`: advisories written by a scheduled Claude research run as TOML files under `advisories/` of a GitHub branch (default: the `advisories` branch of `Matuyuhi/vuln-watch`; set `url` and `branch` to use another). Meant for cross-cutting "update this now" cases without a CVE, such as compromised CA keys. Only changed files are downloaded. An advisory is urgent when one of its `deb` packages is installed and outdated, or when it strongly matches a watch entry with severity `high`/`critical` and confidence `likely`/`confirmed`; everything else goes to the digest, and `unverified` advisories or those without a primary source are never urgent. Expired, resolved and withdrawn advisories are skipped; a new `revision` is notified again. Messages are labelled `Claude 調査` with the confidence; urgent messages list the actions and sources, digest lines the actions and a link to the advisory file. `mode = "urgent"` / `"digest"` on the source still never makes an unverified advisory urgent.

## [1.1.1] - 2026-10-25

### Fixed

- A manual `sudo vuln-watch run` that overlaps the timer's run is skipped (exit code 0, with a line on stderr) instead of running alongside it, which could send the same urgent message twice, exceed `max_urgent_per_run`, or send a source failure alert twice. `run` now holds a `run:lock` lease in `state.db` (6 minutes, renewed after each source and before each send; a run killed by the unit's `TimeoutStartSec` blocks later runs for at most that long); a run whose lease expired and was taken by another run stops before sending. `--dry-run` takes no lock. Run and digest leases are released only by the process that holds them.

## [1.1.0] - 2026-10-24

### Changed

- Digest lines and urgent messages name the affected product when the title does not (CVE titles from CNAs often omit it), e.g. `` `Acme Forum` Path traversal in post media ``.
- The digest lists items that match a watch entry or an installed package first, under "関係あり". Items picked up only by their CVSS score follow under "その他の高 CVSS" without the repeated "CVSS x ≥ y" reason.
- The "vuln-watch" footer is no longer added to Discord embeds.

### Fixed

- A kernel USN whose fix is installed but not running yet (no reboot since `apt upgrade` / unattended-upgrades) is now urgent with `インストール済み・再起動待ち: 実行中 <running> → <fixed>`, instead of being reported as patched. The running kernel is read with `uname -r` and compared through its `linux-image-<release>` package; kernels unknown to dpkg keep the previous behaviour. If the fixed kernel image is not installed at all (only other packages of the USN are), it is urgent as `未適用` instead. HWE (`linux-image-generic-hwe-22.04`) and `virtual` metapackages are matched to `generic` kernels. `vuln-watch doctor` shows the running kernel.
- A digest that fails part way no longer resends the messages already delivered: entries are removed from the queue as each message is sent.
- A failed digest is retried by the next `run` (at least 5 minutes after the failure) instead of waiting for the next day's 08:00 timer. The resent digest is headed "📋 脆弱性ダイジェスト（再送）". A failed retry is logged and does not affect urgent delivery or the exit code of `run`.

## [1.0.3] - 2026-10-24

### Fixed

- An urgent message that Discord refuses (HTTP 400/413, e.g. a feed link it does not accept as an embed URL) is resent as plain text instead of failing every run and holding up the urgent messages queued after it.
- cvelist catch-up parses `deltaLog.json` (~33 MB) straight into its entries, cutting peak memory from about 143 MB to 36 MB (the unit has `MemoryMax=256M`).
- If reading `deltaLog.json` fails, cvelist logs a warning and falls back to `delta.json` instead of failing the source and retrying the catch-up on every run. CVEs that only appeared in the missed syncs may be skipped in that case.

### Security

- Network errors for the Discord webhook and the heartbeat URL no longer include the URL (it embeds a secret token) in logs or journal output.
- HTTP response bodies are capped at 64 MiB so a hostile or broken feed cannot exhaust memory.

## [1.0.2] - 2026-10-24

### Added

- `vuln-watch watch list | add | edit | remove` shows and edits the watch list in config.toml, keeping comments and formatting. The result is validated before it is written, the previous file is kept as `config.toml.bak`, and `--dry-run` prints the change without writing.

## [1.0.1] - 2026-10-24

### Changed

- On an installed host, `sudo vuln-watch run`, `digest`, `test-notify` and `check-config` from a shell now run as the systemd service via `systemd-run` (same sandbox, `/etc/vuln-watch/env` and state as the timers), with output and exit code in the terminal, instead of stopping with a pointer to `systemctl start`. Without root they ask for `sudo`; `run --dry-run` still runs locally.

## [1.0.0] - 2026-10-24

### Added

- `vuln-watch doctor` diagnoses an installation: binaries on PATH, release, config, credentials in `/etc/vuln-watch/env`, systemd units and timers, failing sources and undelivered messages.
- `vuln-watch doctor` points out lines of `/etc/vuln-watch/env` that systemd ignores (not `KEY=value`, config.toml settings such as `discord.mode`) and variables vuln-watch does not read.

### Changed

- On a host with `/etc/vuln-watch/env`, `run`, `digest` and `test-notify` started from a shell (no `--state-dir`, outside systemd) stop with a pointer to `systemctl start vuln-watch@<command>.service` instead of failing on missing credentials and using `./state`.

## [1.0.0-rc.2] - 2026-10-24

### Added

- `install.sh` for one-line installs: `curl -fsSL https://raw.githubusercontent.com/Matuyuhi/vuln-watch/main/install.sh | sudo bash`.
- `vuln-watch upgrade` updates to the latest GitHub release (`--check`, `--version`, `--pre`, `--force`).

### Changed

- `deploy/install.sh` prints a short summary instead of the setup steps when updating an existing install.

## [1.0.0-rc.1] - 2026-10-24

### Added

- Poll CISA KEV, GitHub Security Advisories, the CVE List, Ubuntu Security Notices and RSS/Atom feeds, and notify Discord by DM or webhook.
- Urgent / digest / ignore classification against a watch list, with CVSS thresholds.
- Match Ubuntu Security Notices against packages installed on the host (dpkg version ordering).
- Outbox for urgent messages, cursor and ETag tracking, and backfill so notifications are not lost across downtime.
- systemd units (`vuln-watch@.service`, run and digest timers) and `deploy/install.sh`.
- Release archives for x86_64 and aarch64 Linux with SHA256 checksums and build provenance attestations.

[Unreleased]: https://github.com/Matuyuhi/vuln-watch/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/Matuyuhi/vuln-watch/compare/v1.1.4...v1.2.0
[1.1.4]: https://github.com/Matuyuhi/vuln-watch/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/Matuyuhi/vuln-watch/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/Matuyuhi/vuln-watch/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/Matuyuhi/vuln-watch/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Matuyuhi/vuln-watch/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/Matuyuhi/vuln-watch/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Matuyuhi/vuln-watch/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Matuyuhi/vuln-watch/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Matuyuhi/vuln-watch/compare/v1.0.0-rc.2...v1.0.0
[1.0.0-rc.2]: https://github.com/Matuyuhi/vuln-watch/compare/v1.0.0-rc.1...v1.0.0-rc.2
[1.0.0-rc.1]: https://github.com/Matuyuhi/vuln-watch/releases/tag/v1.0.0-rc.1
