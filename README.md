# vuln-watch

[日本語](README.ja.md)

## Table of Contents

- [Sources](#sources)
- [Rules](#rules)
  - [Installed packages](#installed-packages)
- [Reliability](#reliability)
- [Setup](#setup)
  - [Discord](#1-discord)
  - [Install](#2-install)
  - [Configure](#3-configure)
  - [Start](#4-start)
- [Usage](#usage)
- [Operations](#operations)
- [Development](#development)
  - [Releasing](#releasing)
- [License](#license)

Polls vulnerability sources every two minutes and sends a Discord DM when something affects you: an exploited CVE, an advisory for a package you depend on, or an Ubuntu patch for a package installed on the host. Everything else is batched into a daily digest.

Single Rust binary, run by a systemd timer. State is kept in SQLite.

```
systemd timer (2 min) ─▶ vuln-watch run
                           ├─ CISA KEV            exploited in the wild
                           ├─ GitHub Advisory DB  package advisories
                           ├─ CVE List            new CVE records
                           ├─ Ubuntu USN          patches, matched against dpkg
                           └─ RSS / Atom          oss-security, release feeds
                                  │
                         new items only (seen-set, ETag)
                                  │
                         rules ─┬─▶ urgent  → Discord DM
                                └─▶ digest  → daily at 08:00
```

## Sources

| Kind | Source | Latency |
|---|---|---|
| `kev` | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | poll interval |
| `ghsa` | [GitHub Advisory Database](https://github.com/advisories) (reviewed) | poll interval |
| `cvelist` | [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) | ~7 min sync + poll interval |
| `usn` | [Ubuntu Security Notices](https://ubuntu.com/security/notices) (JSON API) | poll interval |
| `feed` | Any RSS/Atom feed, e.g. [oss-security](https://seclists.org/oss-sec/) | poll interval |
| `advisory` | Advisories written by a scheduled Claude research run, read from a GitHub branch ([details](#claude-advisories)) | research schedule + poll interval |

oss-security often carries a disclosure before a CVE record exists.

## Rules

| Condition | Result |
|---|---|
| Listed in CISA KEV | urgent |
| Installed package older than the fixed version in a USN | urgent |
| Kernel USN already installed, but the running kernel is older (reboot pending) | urgent |
| Strong watch match (package, product or title) with CVSS ≥ 7.0 or no score | urgent |
| Strong watch match with CVSS < 7.0 | digest |
| Watch term found only in the description | digest, flagged for review |
| USN for an installed package that is already patched | digest (or ignored) |
| No watch match, CVSS ≥ 9.0 | digest |
| Anything else | ignored |

- Watch entries with `urgent = false` only go to the digest.
- The digest lists items that match a watch entry or an installed package first; items included only for their CVSS score follow under a separate heading.
- Messages name the affected product when the title does not.
- Each notification shows which field and term matched.
- A CVE reported by several sources is notified once. If it later enters KEV, it is notified again.
- Rejected CVEs and withdrawn GHSAs are skipped.
- On the first run each source records existing items without notifying.
- A source failing repeatedly triggers a warning; recovery is reported too.
- At most `max_urgent_per_run` urgent messages per run; the rest go to the digest.

Thresholds, exclusions and the watch list are set in [`config.example.toml`](config.example.toml).

### Installed packages

With `[installed] enabled = true`, USN entries are compared with `/var/lib/dpkg/status` using dpkg version ordering. The file is re-read on every run, so a package counts as patched as soon as `apt upgrade` has run. The release codename is read from `/etc/os-release`. A USN for a package that is not installed is ignored, even if it matches the watch list.

A kernel fix only takes effect after a reboot. For a kernel USN whose packages are installed, the running kernel (`uname -r`, e.g. `6.8.0-145-generic`) is also compared: if its `linux-image-<release>` package is older than the fixed version for the same flavour, the notice is urgent with `再起動待ち` (reboot pending) instead of patched; if no fixed kernel image is installed yet, it is urgent as not applied (`未適用`). HWE and `virtual` metapackages count for the `generic` flavour. A running kernel that dpkg does not know (custom kernel, container) is not compared. `vuln-watch doctor` shows the running kernel it detected.

### Claude advisories

Some problems never get a CVE but still mean "update this now" for many products, e.g. compromised CA keys that Electron apps, Go binaries and `ca-certificates` must drop. A scheduled Claude research run writes such advisories, with the actions to take and their sources, as one TOML file each under `advisories/` of a GitHub branch (by default the `advisories` branch of this repository). `kind = "advisory"` reads that branch through the GitHub API; only files whose blob changed since the last run are downloaded, and `GITHUB_TOKEN` is used when set.

| Condition | Result |
|---|---|
| A `deb` package of the advisory is installed and older than its fixed version | urgent |
| Otherwise, severity `low` | digest |
| Only match is a watch entry with `urgent = false` | digest |
| Anything else, with or without a watch match | urgent |

- Advisories are few and each one is merged by hand, so they are urgent by default. The reason shows the matching watch entry or installed package, if any.
- Advisories with `confidence = "unverified"`, or without a `primary` reference, are never urgent.
- Advisories past `expires`, and those with `status = "resolved"` or `"withdrawn"`, are skipped.
- A new `revision` of an advisory is notified again; other edits are not.
- Every message is labelled `Claude 調査` with its confidence. Urgent messages list the actions and sources; digest lines show the actions and link to the advisory file, which lists the sources. Check the sources before acting.

## Reliability

- Urgent messages go into an outbox before cursors and ETags are committed. If Discord is unreachable, they are retried on the next run. A message Discord refuses as invalid is resent as plain text, so it cannot block the ones queued after it.
- The digest removes items from its queue as each message is sent, so a failure part way never resends what was already delivered. If the digest fails, the next `run` (at least 5 minutes later) resends the remaining items with a "（再送）" header; a failed retry is only logged and does not hold up urgent messages.
- Only one `run` works at a time. A manual `sudo vuln-watch run` started while the timer's run is in progress is skipped (exit code 0, one line on stderr), so the same urgent message is never sent twice. A run killed by the unit timeout blocks later runs for at most 6 minutes.
- GitHub advisories are read in `updated` order and paged back to the last position, so advisories reviewed long after publication are not missed. A catch-up walk stops after 20 pages (2,000 advisories, e.g. after long downtime or a bulk update by GitHub); the range it could not reach is then read on later runs, oldest first, up to 5 pages per run while more than 30 API requests remain in the rate-limit window (so polling keeps working without `GITHUB_TOKEN`), and goes through the usual rules and de-duplication. `vuln-watch doctor` warns while such a range is still unread.
- New CVE ids are queued and processed in batches of `cvelist_max_records`. A missed sync (detected from elapsed time, or from commit history when `GITHUB_TOKEN` is set) is filled from `deltaLog.json`, which covers about 30 days. If that file cannot be read, the source falls back to `delta.json` and logs a warning that CVEs from the missed syncs may be skipped.
- USN is paged back to the last seen notice.
- Plain RSS feeds only expose their latest entries; long downtime can drop items from those feeds. Set `HEARTBEAT_URL` to be alerted when runs stop.
- A source that fails is reported after `alert_after_failures` failures in a row. A source whose fetches succeed but return nothing new for `stale_after_hours` (per `[[source]]`; default `cvelist` 12, `ghsa` 72, `usn` 168, `kev` 720, `feed` / `advisory` 0 = off) is reported once with "新しい項目がありません", and again with "新しい項目が届きました" when new items arrive. This catches a source that breaks silently, such as an API field rename or a feed that moved. The USN `notices` field and the cvelist delta `new` field are required, so a format change there fails loudly instead of reading as empty.

## Setup

### 1. Discord

DM delivery (default):

1. Create an application in the [Discord Developer Portal](https://discord.com/developers/applications). Under **Bot**, reset and copy the token.
2. Under **OAuth2 → URL Generator**, select the `bot` scope (no permissions) and invite the bot to a server you are in. Bots can only DM users they share a server with.
3. Enable Developer Mode in Discord, right-click your name and copy your user ID.

Channel delivery: set `discord.mode = "webhook"` and `DISCORD_WEBHOOK_URL`.

### 2. Install

On x86_64 / aarch64 Linux with systemd (glibc 2.35 or later, e.g. Ubuntu 22.04+, Debian 12+):

```bash
curl -fsSL https://raw.githubusercontent.com/Matuyuhi/vuln-watch/main/install.sh | sudo bash
```

This downloads the latest [release](https://github.com/Matuyuhi/vuln-watch/releases) for the machine, checks it against `SHA256SUMS`, and installs `/usr/local/bin/vuln-watch`, the systemd units, and `/etc/vuln-watch/{config.toml,env}` if they do not exist yet. To pick a version, append `-s -- --version 1.2.0` to `bash`.

<details>
<summary>Manual install from a release archive</summary>

```bash
VERSION=1.2.0                                   # see the releases page
NAME=vuln-watch-v$VERSION-$(uname -m)-unknown-linux-gnu
curl -fsSLO https://github.com/Matuyuhi/vuln-watch/releases/download/v$VERSION/$NAME.tar.gz
curl -fsSLO https://github.com/Matuyuhi/vuln-watch/releases/download/v$VERSION/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify $NAME.tar.gz --repo Matuyuhi/vuln-watch   # optional, build provenance
tar -xzf $NAME.tar.gz
sudo ./$NAME/deploy/install.sh
```

</details>

<details>
<summary>Build from source</summary>

Requires a Rust toolchain.

```bash
git clone https://github.com/Matuyuhi/vuln-watch.git
cd vuln-watch
sudo ./deploy/install.sh
```

</details>

### 3. Configure

`/etc/vuln-watch/env` (mode 600):

| Variable | |
|---|---|
| `DISCORD_BOT_TOKEN` | required for DM delivery |
| `DISCORD_USER_ID` | recipient; overrides `discord.user_id` |
| `DISCORD_WEBHOOK_URL` | required for webhook delivery |
| `GITHUB_TOKEN` | recommended; a fine-grained token with no permissions is enough. Raises the API limit from 60 to 5,000 requests/hour and reads the CVE List through the API instead of the CDN (up to 5 min faster). Only sent to `https://api.github.com`: a `ghsa` / `advisory` `url` (or a `next` page link) on another host is read without it, with one warning per run. |
| `HEARTBEAT_URL` | optional; pinged after every successful run (e.g. healthchecks.io) |

`/etc/vuln-watch/config.toml`: adjust the watch list and sources. The watch list can also be edited with `vuln-watch watch` (see [Usage](#usage)). A source `url` must start with `https://` (only `kind = "feed"` may use `http://`).

### 4. Start

```bash
sudo vuln-watch doctor

sudo vuln-watch test-notify

sudo systemctl enable --now vuln-watch-run.timer vuln-watch-digest.timer
sudo journalctl -u 'vuln-watch@*' -f
```

The digest time is set in `deploy/systemd/vuln-watch-digest.timer` (08:00 Asia/Tokyo).

## Usage

```
vuln-watch [--config PATH] [--state-dir DIR] <COMMAND>

  run [--dry-run] [--limit N] [--strict]   poll all sources once
  digest [--dry-run]                       send the queued digest
  test-notify                              send a test message
  check-config                             validate config and credentials
  doctor [--offline]                       diagnose the installation (as root)
  upgrade [--check] [--version V] [--pre]  update to the latest release (as root)
  watch list                               show the watch list
  watch add NAME [-k WORD] [-p PKG]...     add a watch entry (as root)
  watch edit NAME [-k ...] [--rm-keyword ...]  change a watch entry (as root)
  watch remove NAME                        remove a watch entry (as root)
```

`--state-dir` defaults to `$STATE_DIRECTORY` (`/var/lib/vuln-watch` under systemd).

On an installed host, `run`, `digest`, `test-notify` and `check-config` started from a shell run as the systemd service: with `sudo`, vuln-watch re-runs itself through `systemd-run` with the settings of `vuln-watch@.service`, so it gets the credentials from `/etc/vuln-watch/env` and shares state with the timers, while the output and exit code stay in your terminal (`sudo vuln-watch digest`, `sudo vuln-watch run --strict`). Without `sudo` they stop with a hint, except `run --dry-run`, which needs neither. Pass `--state-dir` to run locally against a separate state directory instead.

`vuln-watch watch` edits the `[[watch]]` entries of config.toml in place, keeping comments and formatting, and writes nothing unless the result passes the same validation as the service (unknown sources, empty values, duplicate names are rejected; repeated or very short keywords get a warning). `add` / `edit` take `-k/--keyword`, `-p/--package`, `-s/--source` (repeatable) and `--urgent` / `--no-urgent`; `edit` also takes `--rm-keyword`, `--rm-package` and `--rm-source`. Names match case-insensitively. `--dry-run` prints the result without writing; otherwise the previous file is kept as `config.toml.bak`. Changes apply from the next timer run, no restart needed. `watch list` and `--dry-run` work without `sudo`.

```bash
sudo vuln-watch watch add PHP -k php -p php/php-src
sudo vuln-watch watch edit php -k laravel --no-urgent
sudo vuln-watch watch remove PHP
```

`--dry-run` prints decisions instead of sending and keeps no state:

```bash
cargo run -- --config config.example.toml run --dry-run --limit 5
```

Set `installed.enabled = false` on machines without dpkg.

## Operations

- **Diagnose**: `sudo vuln-watch doctor` checks the installation and prints ok / warn / FAIL per item: a stale `vuln-watch` earlier on PATH, a newer release, a config that no longer parses, missing or example credentials in `/etc/vuln-watch/env`, lines in it that systemd ignores or that vuln-watch does not read, and its permissions, unit files and `daemon-reload`, whether the timers are enabled and the last run succeeded, sources failing repeatedly, when each source last returned something new (warning when it is over `stale_after_hours`), undelivered urgent messages, and leftovers of an interrupted upgrade. It sends nothing to Discord and exits with 1 when something fails; `--offline` skips the release check. Run it after installing or upgrading.
- **Update**: `sudo vuln-watch upgrade` installs the latest release the same way as `install.sh` (`--check` only reports, `--version 1.2.0` picks a version, `--pre` includes pre-releases). Config and state are kept; check [CHANGELOG.md](CHANGELOG.md) for changes to `config.example.toml`. From source: `git pull && sudo ./deploy/install.sh`.
- **Sandbox**: the unit uses `DynamicUser`, `ProtectSystem=strict` and a syscall filter; the process can only make outbound connections and write its state directory.
- **Uninstall**:

  ```bash
  sudo systemctl disable --now vuln-watch-run.timer vuln-watch-digest.timer
  sudo rm /etc/systemd/system/vuln-watch* /usr/local/bin/vuln-watch
  sudo rm -r /etc/vuln-watch /var/lib/private/vuln-watch
  ```

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
```

CI workflows:

- [CI](.github/workflows/ci.yml): fmt, clippy, tests.
- [Live smoke test](.github/workflows/smoke.yml): weekly dry run against the real sources, to catch upstream format changes.
- [Dependencies](.github/workflows/deps.yml): daily [cargo-deny](deny.toml) check (RustSec, licenses, banned crates, sources). Dependabot opens update PRs weekly.
- [CodeQL](.github/workflows/codeql.yml): static analysis of the Rust code and the workflows on every push and PR, plus weekly. Results are under *Security → Code scanning*.
- [Release](.github/workflows/release.yml): cuts and publishes a release (see below).

### Releasing

Releases are made entirely from GitHub Actions.

1. List the changes under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) as they are merged.
2. Open *Actions → Release → Run workflow* on `main` and enter the version (e.g. `0.2.0`). Versions with a suffix such as `0.2.0-rc.1` are published as pre-releases.
3. The workflow bumps `Cargo.toml`/`Cargo.lock`, dates the changelog, runs fmt/clippy/tests, pushes a `release: v0.2.0` commit to `main` with the `v0.2.0` tag, builds and smoke-tests the x86_64 and aarch64 binaries, and publishes the archives with `SHA256SUMS`, a build provenance attestation, and the changelog section as release notes.

Check *dry run* to do everything except pushing and publishing; the archives are attached to the run as artifacts. Dry runs also work on branches other than `main`.

If `main` is protected, allow GitHub Actions to push to it (add it to the bypass list of the ruleset), or the push step fails.

## License

[MIT](LICENSE)
