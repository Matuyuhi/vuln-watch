# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Poll CISA KEV, GitHub Security Advisories, the CVE List, Ubuntu Security Notices and RSS/Atom feeds, and notify Discord by DM or webhook.
- Urgent / digest / ignore classification against a watch list, with CVSS thresholds.
- Match Ubuntu Security Notices against packages installed on the host (dpkg version ordering).
- Outbox for urgent messages, cursor and ETag tracking, and backfill so notifications are not lost across downtime.
- systemd units (`vuln-watch@.service`, run and digest timers) and `deploy/install.sh`.
- Release archives for x86_64 and aarch64 Linux with SHA256 checksums and build provenance attestations.

[Unreleased]: https://github.com/Matuyuhi/vuln-watch/commits/main
