#!/usr/bin/env bash
# Prepare the files for a release; used by the Release workflow.
#   scripts/bump-version.sh 0.2.0
# Sets the version in Cargo.toml / Cargo.lock and turns "## [Unreleased]" in
# CHANGELOG.md into "## [0.2.0] - <today>". Does not commit or tag.
set -euo pipefail

cd "$(dirname "$0")/.."

die() { echo "error: $*" >&2; exit 1; }

version="${1:?usage: $0 VERSION}"
version="${version#v}"
tag="v$version"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "not a semver version: $version"
! git rev-parse -q --verify "refs/tags/$tag" >/dev/null || die "tag $tag already exists"
grep -q '^## \[Unreleased\]' CHANGELOG.md || die 'CHANGELOG.md has no "## [Unreleased]" section'
scripts/changelog-section.sh Unreleased >/dev/null || die 'nothing listed under "## [Unreleased]" in CHANGELOG.md'

current=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
[[ -n "$current" ]] || die "could not read the current version from Cargo.toml"

# Version in Cargo.toml / Cargo.lock
if [[ "$current" != "$version" ]]; then
  sed -i -e "0,/^version = \"$current\"/s//version = \"$version\"/" Cargo.toml
  cargo update --workspace --quiet
fi

# CHANGELOG: rename Unreleased, open a new empty one, update compare links
date=$(date -u +%F)
repo_url=$(sed -n 's/^repository = "\(.*\)"/\1/p' Cargo.toml)
prev_tag=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)
awk -v v="$version" -v d="$date" -v url="$repo_url" -v tag="$tag" -v prev="$prev_tag" '
  /^## \[Unreleased\]/ { print "## [Unreleased]\n\n## [" v "] - " d; next }
  /^\[Unreleased\]: / {
    print "[Unreleased]: " url "/compare/" tag "...HEAD"
    if (prev != "") print "[" v "]: " url "/compare/" prev "..." tag
    else            print "[" v "]: " url "/releases/tag/" tag
    next
  }
  { print }
' CHANGELOG.md > CHANGELOG.md.tmp && mv CHANGELOG.md.tmp CHANGELOG.md

echo "prepared $tag (was $current)"
