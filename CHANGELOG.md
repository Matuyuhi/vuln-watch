# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/Matuyuhi/vuln-watch/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/Matuyuhi/vuln-watch/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Matuyuhi/vuln-watch/compare/v1.0.0-rc.2...v1.0.0
[1.0.0-rc.2]: https://github.com/Matuyuhi/vuln-watch/compare/v1.0.0-rc.1...v1.0.0-rc.2
[1.0.0-rc.1]: https://github.com/Matuyuhi/vuln-watch/releases/tag/v1.0.0-rc.1
