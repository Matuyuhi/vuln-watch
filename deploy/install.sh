#!/usr/bin/env bash
# Install or update vuln-watch on a systemd host.
#   sudo ./deploy/install.sh [path/to/vuln-watch-binary]
# Without an argument, the binary next to deploy/ is used (release archive);
# in a source checkout it is built with `cargo build --release`.
set -euo pipefail

BIN="${1:-}"
[[ -z "$BIN" ]] || BIN=$(realpath "$BIN")

cd "$(dirname "$0")/.."

if [[ $EUID -ne 0 ]]; then
  echo "run as root (sudo)" >&2
  exit 1
fi

if [[ -z "$BIN" && -x ./vuln-watch && ! -f Cargo.toml ]]; then
  BIN=./vuln-watch
elif [[ -z "$BIN" ]]; then
  if [[ -n "${SUDO_USER:-}" ]]; then
    sudo -u "$SUDO_USER" -H bash -lc "cd '$PWD' && cargo build --release --locked"
  else
    cargo build --release --locked
  fi
  BIN=target/release/vuln-watch
fi

previous=""
[[ -x /usr/local/bin/vuln-watch ]] && previous=$(/usr/local/bin/vuln-watch --version 2>/dev/null || echo "vuln-watch (unknown)")

install -Dm755 "$BIN" /usr/local/bin/vuln-watch
echo "installed $(/usr/local/bin/vuln-watch --version)"

install -d -m755 /etc/vuln-watch
if [[ ! -f /etc/vuln-watch/config.toml ]]; then
  install -m644 config.example.toml /etc/vuln-watch/config.toml
  echo "created /etc/vuln-watch/config.toml (edit discord.user_id and the watch list)"
fi
if [[ ! -f /etc/vuln-watch/env ]]; then
  install -m600 deploy/env.example /etc/vuln-watch/env
  echo "created /etc/vuln-watch/env (set DISCORD_BOT_TOKEN etc.)"
fi

install -m644 deploy/systemd/vuln-watch@.service /etc/systemd/system/
install -m644 deploy/systemd/vuln-watch-run.timer /etc/systemd/system/
install -m644 deploy/systemd/vuln-watch-digest.timer /etc/systemd/system/
systemctl daemon-reload

if [[ -n "$previous" ]]; then
  echo "updated from ${previous#vuln-watch }; config in /etc/vuln-watch was kept"
  echo "check the installation with: sudo vuln-watch doctor"
  exit 0
fi

cat <<'EOF'

Installed. Next steps:
  1. edit /etc/vuln-watch/config.toml and /etc/vuln-watch/env
  2. sudo vuln-watch doctor   (the timers stay FAIL until step 4)
  3. sudo systemctl start vuln-watch@test-notify.service   (test DM)
  4. sudo systemctl enable --now vuln-watch-run.timer vuln-watch-digest.timer
  5. sudo vuln-watch doctor   (again, to confirm the timers)
  logs: journalctl -u 'vuln-watch@*' -f
EOF
