# vuln-watch advisories

This orphan branch holds advisories written by a scheduled Claude research run. It shares no history with `main`. [vuln-watch](https://github.com/Matuyuhi/vuln-watch) reads it with:

```toml
[[source]]
kind = "advisory"
name = "claude-advisories"
# url = "https://github.com/Matuyuhi/vuln-watch"   # default
# branch = "advisories"                           # default
```

See "Claude advisories" in the main README for how advisories are matched and notified.

## Layout

| Path | Contents |
|---|---|
| `advisories/<year>/<id>.toml` | One advisory per file; the file name equals `id` |
| `examples/` | Format reference, not read by vuln-watch |
| `CLAUDE.md` | Research procedure and rules for the scheduled run (Japanese) |
| `watch-hints.txt` | Software to prioritise during research |
| `scripts/validate.py` | Format checks, and with `--online` reference URL / quote / CVE checks |

## Flow

1. The scheduled run opens a pull request against `advisories` with new or revised files.
2. `Validate advisories` checks the format of every file and, for the changed ones, that each reference answers, each quote appears on its page and each CVE exists.
3. A maintainer reviews and merges. vuln-watch only sees merged advisories.

## Format

See [`examples/VWA-2026-0101-example.toml`](examples/VWA-2026-0101-example.toml). Required: `id`, `revision`, `status`, `published`, `expires`, `severity`, `confidence`, `title`, `summary`, `references`. A new `revision` is notified again; `resolved` / `withdrawn` and expired advisories are skipped.
