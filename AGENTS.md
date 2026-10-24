# AGENTS.md

This file provides guidance to coding agents (Claude Code, Codex, etc.) when working with code in this repository.

## Commands

CI (`.github/workflows/ci.yml`) runs exactly these; all must pass:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check            # daily in deps.yml: RustSec, licenses, banned crates
```

- Single test: `cargo test <name_substring>` (e.g. `cargo test strong_match_wins_over_earlier_weak_match`). Tests are inline `#[cfg(test)] mod tests` per module; there is no `tests/` directory.
- Local end-to-end without sending or persisting anything: `cargo run -- --config config.example.toml run --dry-run --limit 5`. This hits the real sources over the network. Set `installed.enabled = false` on machines without dpkg (e.g. macOS).
- When `/etc/vuln-watch/env` exists, systemd is running and `--state-dir` is the default, `run` / `digest` / `test-notify` / `check-config` re-run themselves under `systemd-run` with the [Service] settings of `vuln-watch@.service` (`src/delegate.rs`); they need root, except `run --dry-run`. Never open the production state.db as root: files it creates would be unwritable for the DynamicUser.

## Architecture

Single synchronous binary (blocking `reqwest`, no async runtime) invoked every 2 minutes by a systemd timer; each invocation is one pass, all state in SQLite (`src/db.rs`).

Flow of `run` (`src/app.rs`):

1. `sources::fetch` dispatches on `SourceKind` to `src/sources/{kev,ghsa,cvelist,usn,feed}.rs`. Each returns `Fetched { items, commit }`: normalized `model::Item`s plus kv pairs (cursors, ETags) that must only be persisted after the items are handled.
2. First run of a source (`init:<name>` kv missing) is a bootstrap: items are marked seen and nothing is notified.
3. Each unseen item goes through `rules::evaluate_with` → `Decision { level: Ignore | Digest | Urgent, reason }`.
4. Urgent items are written to the `outbox` table, digest items to `digest_queue`; then `fetched.commit` is written. `flush_outbox` sends urgent messages afterwards (capped by `max_urgent_per_run`, overflow to digest). This ordering is the delivery guarantee — don't commit cursors before enqueueing.
5. Per-source failure counters (`fail:<name>`, `failalert:<name>` kv) drive the "source failing / recovered" messages.

De-duplication keys (`src/model.rs`): `dedupe_key` is the CVE id when known, otherwise `source:id`; `alert_key` adds `#kev` so a CVE that later enters KEV is notified again. The `alerted` table stores the highest level already sent per key.

`pending` table holds discovered-but-unprocessed work (e.g. CVE ids from cvelist awaiting record fetch, processed in batches of `cvelist_max_records`).

Other modules:

- `config.rs` — TOML schema; `config.example.toml` is the reference and is what the smoke test runs against.
- `installed.rs` — parses `/var/lib/dpkg/status` and `/etc/os-release`, dpkg version ordering for USN matching. Re-read every run.
- `discord.rs` — message formatting and delivery (bot DM or webhook). User-facing message text is Japanese.
- `doctor.rs` / `upgrade.rs` — run without loading the config (handled before `Config::load` in `main.rs`) so they work when the config is broken. `upgrade` mirrors `install.sh` (release download + `SHA256SUMS` check).
- `deploy/` — systemd units (`vuln-watch@.service` is a template: `vuln-watch@run`, `@digest`, `@test-notify`), `install.sh` for source installs. Root `install.sh` is the curl installer for releases.

## Conventions

- User-facing changes update `README.md`, `README.ja.md` (keep both in sync) and `CHANGELOG.md` under `## [Unreleased]` in the same change.
- Commit messages: Conventional Commits (`feat:`, `fix:`, `feat(doctor):`, `docs:`).
- Releases are cut only via the Release workflow (Actions → Release → Run workflow); it bumps the version (`scripts/bump-version.sh`), dates the changelog and tags. Don't bump `Cargo.toml` versions by hand.
- The weekly smoke workflow parses `[source]`-prefixed lines from `run --dry-run` stdout; keep that output format stable.
