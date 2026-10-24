#!/usr/bin/env bash
# Install vuln-watch from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/Matuyuhi/vuln-watch/main/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/Matuyuhi/vuln-watch/main/install.sh | sudo bash -s -- --version 1.0.0
#
# Downloads the archive for this machine, checks it against SHA256SUMS and
# runs the bundled deploy/install.sh. Without --version the latest release is
# installed (the newest pre-release if there is no stable release yet).
# Once installed, update with `sudo vuln-watch upgrade`.
set -euo pipefail

REPO="Matuyuhi/vuln-watch"

die() { echo "error: $*" >&2; exit 1; }

version=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:?--version needs a value}"; shift 2 ;;
    --version=*) version="${1#*=}"; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root: curl -fsSL ... | sudo bash"
[[ "$(uname -s)" == Linux ]] || die "only Linux is supported"
for cmd in curl tar sha256sum systemctl; do
  command -v "$cmd" >/dev/null || die "$cmd is required"
done

case "$(uname -m)" in
  x86_64|amd64) target=x86_64-unknown-linux-gnu ;;
  aarch64|arm64) target=aarch64-unknown-linux-gnu ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

api() {
  curl -fsSL -H "Accept: application/vnd.github+json" \
    ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
    "https://api.github.com/repos/$REPO/$1"
}
first_tag() { sed -n 's/^ *"tag_name": *"\([^"]*\)".*/\1/p' | head -n1; }

if [[ -n "$version" ]]; then
  tag="v${version#v}"
else
  tag=$(api releases/latest 2>/dev/null | first_tag || true)
  if [[ -z "$tag" ]]; then
    tag=$(api "releases?per_page=1" | first_tag)
    [[ -n "$tag" ]] && echo "no stable release yet; installing pre-release $tag"
  fi
  [[ -n "$tag" ]] || die "could not find a release of $REPO"
fi

name="vuln-watch-$tag-$target"
base="https://github.com/$REPO/releases/download/$tag"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

echo "downloading $name.tar.gz"
curl -fsSL -o "$name.tar.gz" "$base/$name.tar.gz" || die "no $target archive for $tag"
curl -fsSL -o SHA256SUMS "$base/SHA256SUMS"
grep -F " $name.tar.gz" SHA256SUMS | sha256sum --check --quiet - || die "checksum mismatch for $name.tar.gz"

tar -xzf "$name.tar.gz"
"./$name/deploy/install.sh"
