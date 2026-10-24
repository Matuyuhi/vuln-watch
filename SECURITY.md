# Security Policy

## Supported versions

Security fixes are made on `main` and shipped in the next release. Only the latest release is supported.

| Version | Supported |
|---|---|
| [latest release](https://github.com/Matuyuhi/vuln-watch/releases/latest) | yes |
| older releases | no |

## Reporting a vulnerability

Most security problems can be filed as a [public issue](https://github.com/Matuyuhi/vuln-watch/issues/new). Issues are public, so **remove tokens, webhook URLs and user IDs** from anything you paste.

If the problem can be exploited against a running deployment (for example token leakage, code execution, or forging or suppressing notifications), report it privately instead: open the repository's **Security** tab and choose **Report a vulnerability** ([direct link](https://github.com/Matuyuhi/vuln-watch/security/advisories/new)). If you are unsure, report privately.

Include as much of the following as you can:

- the affected version or commit
- a description of the problem and its impact
- steps to reproduce, or a proof of concept
- relevant configuration

This is a personal project maintained in spare time. You can expect:

- an acknowledgement within 7 days
- an initial assessment within 14 days
- a fix or mitigation plan as soon as practical after the issue is confirmed

Fixes are recorded in [CHANGELOG.md](CHANGELOG.md). Privately reported issues are published as a GitHub Security Advisory once a fix is released, and credited to the reporter unless you prefer to stay anonymous.

## Scope

In scope:

- the `vuln-watch` binary and its source code
- `deploy/install.sh` and the systemd units in `deploy/systemd/`
- the release workflow and published release archives

Examples of issues we want to hear about:

- leaking `DISCORD_BOT_TOKEN`, `DISCORD_WEBHOOK_URL` or `GITHUB_TOKEN` (logs, notifications, error messages, state files)
- crafted feed, advisory or CVE content that causes code execution, a crash loop, unbounded memory or disk use, or message injection into Discord (for example mass mentions)
- anything that lets a remote party suppress or forge urgent notifications
- weaknesses in the installer or systemd hardening that grant more privilege than documented

Out of scope:

- vulnerabilities in the upstream data sources (CISA KEV, GitHub Advisory Database, CVE List, Ubuntu USN, RSS feeds) or in Discord — report those to their owners
- incorrect or missing advisory data published by an upstream source
- vulnerabilities in dependencies that do not affect vuln-watch; these are tracked by Dependabot and `cargo deny`
- problems that require an attacker who can already write `/etc/vuln-watch/` or the state directory

## Verifying releases

Release archives come with `SHA256SUMS` and a build provenance attestation. Verify a download before installing it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify vuln-watch-*.tar.gz --repo Matuyuhi/vuln-watch
```

## Keeping your deployment safe

- Keep `/etc/vuln-watch/env` at mode `600`, owned by root.
- Use a fine-grained `GITHUB_TOKEN` with no permissions; vuln-watch only reads public data.
- Give the Discord bot no server permissions; it only needs to send DMs.
- Keep the hardening options in `vuln-watch@.service` when you customise the unit.
