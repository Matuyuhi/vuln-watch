#!/usr/bin/env bash
# Prepare the files for a release; used by the Release workflow.
#   scripts/bump-version.sh 0.2.0
# Sets the version in Cargo.toml / Cargo.lock and turns "## [Unreleased]" in
# CHANGELOG.md into "## [0.2.0] - <today>" (scripts/changelog-release.py). A
# final release also takes in the sections of its pre-releases (0.2.0-rc.*), so
# its notes cover everything since the previous final release. Does not commit
# or tag.
set -euo pipefail

cd "$(dirname "$0")/.."

die() { echo "error: $*" >&2; exit 1; }

version="${1:?usage: $0 VERSION}"
version="${version#v}"
tag="v$version"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "not a semver version: $version"
! git rev-parse -q --verify "refs/tags/$tag" >/dev/null || die "tag $tag already exists"

current=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
[[ -n "$current" ]] || die "could not read the current version from Cargo.toml"

# CHANGELOG first: it fails when there is nothing to release.
# A final release is compared with the previous final release, a pre-release
# with the latest tag of any kind.
if [[ "$version" == *-* ]]; then
  prev_tag=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)
else
  prev_tag=$(git describe --tags --abbrev=0 --match 'v*' --exclude 'v*-*' 2>/dev/null || true)
fi
repo_url=$(sed -n 's/^repository = "\(.*\)"/\1/p' Cargo.toml)
python3 scripts/changelog-release.py "$version" "$(date -u +%F)" "$repo_url" "$prev_tag"

# Version in Cargo.toml / Cargo.lock
if [[ "$current" != "$version" ]]; then
  sed -i -e "0,/^version = \"$current\"/s//version = \"$version\"/" Cargo.toml
  cargo update --workspace --quiet
fi

echo "prepared $tag (was $current)"
