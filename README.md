# vuln-watch

[日本語](README.ja.md)

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

oss-security often carries a disclosure before a CVE record exists.

## Rules

| Condition | Result |
|---|---|
| Listed in CISA KEV | urgent |
| Installed package older than the fixed version in a USN | urgent |
| Strong watch match (package, product or title) with CVSS ≥ 7.0 or no score | urgent |
| Strong watch match with CVSS < 7.0 | digest |
| Watch term found only in the description | digest, flagged for review |
| USN for an installed package that is already patched | digest (or ignored) |
| No watch match, CVSS ≥ 9.0 | digest |
| Anything else | ignored |

- Watch entries with `urgent = false` only go to the digest.
- Each notification shows which field and term matched.
- A CVE reported by several sources is notified once. If it later enters KEV, it is notified again.
- Rejected CVEs and withdrawn GHSAs are skipped.
- On the first run each source records existing items without notifying.
- A source failing repeatedly triggers a warning; recovery is reported too.
- At most `max_urgent_per_run` urgent messages per run; the rest go to the digest.

Thresholds, exclusions and the watch list are set in [`config.example.toml`](config.example.toml).

### Installed packages

With `[installed] enabled = true`, USN entries are compared with `/var/lib/dpkg/status` using dpkg version ordering. The file is re-read on every run, so a package counts as patched as soon as `apt upgrade` has run. The release codename is read from `/etc/os-release`. A USN for a package that is not installed is ignored, even if it matches the watch list.

## Reliability

- Urgent messages go into an outbox before cursors and ETags are committed. If Discord is unreachable, they are retried on the next run.
- GitHub advisories are read in `updated` order and paged back to the last position, so advisories reviewed long after publication are not missed.
- New CVE ids are queued and processed in batches of `cvelist_max_records`. A missed sync (detected from elapsed time, or from commit history when `GITHUB_TOKEN` is set) is filled from `deltaLog.json`, which covers about 30 days.
- USN is paged back to the last seen notice.
- Plain RSS feeds only expose their latest entries; long downtime can drop items from those feeds. Set `HEARTBEAT_URL` to be alerted when runs stop.

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
| `GITHUB_TOKEN` | recommended; a fine-grained token with no permissions is enough. Raises the API limit from 60 to 5,000 requests/hour and reads the CVE List through the API instead of the CDN (up to 5 min faster). |
| `HEARTBEAT_URL` | optional; pinged after every successful run (e.g. healthchecks.io) |

`/etc/vuln-watch/config.toml`: adjust the watch list and sources.

### 4. Start

```bash
sudo vuln-watch doctor

sudo systemctl start vuln-watch@test-notify.service

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
```

`--state-dir` defaults to `$STATE_DIRECTORY` (`/var/lib/vuln-watch` under systemd).

`--dry-run` prints decisions instead of sending and keeps no state:

```bash
cargo run -- --config config.example.toml run --dry-run --limit 5
```

Set `installed.enabled = false` on machines without dpkg.

## Operations

- **Diagnose**: `sudo vuln-watch doctor` checks the installation and prints ok / warn / FAIL per item: a stale `vuln-watch` earlier on PATH, a newer release, a config that no longer parses, missing or example credentials in `/etc/vuln-watch/env` and its permissions, unit files and `daemon-reload`, whether the timers are enabled and the last run succeeded, sources failing repeatedly, undelivered urgent messages, and leftovers of an interrupted upgrade. It sends nothing to Discord and exits with 1 when something fails; `--offline` skips the release check. Run it after installing or upgrading.
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
