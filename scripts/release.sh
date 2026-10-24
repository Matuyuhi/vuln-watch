#!/usr/bin/env bash
# Cut a release: bump the version, date the changelog, commit and tag.
#   scripts/release.sh 0.2.0          # prepare commit + tag locally
#   scripts/release.sh 0.2.0 --push   # and push them (starts the Release workflow)
#
# Before running, list the changes under "## [Unreleased]" in CHANGELOG.md.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() { echo "usage: $0 VERSION [--push]" >&2; exit 2; }

version="${1:-}"
[[ -n "$version" ]] || usage
version="${version#v}"
push=false
case "${2:-}" in
  "") ;;
  --push) push=true ;;
  *) usage ;;
esac

die() { echo "error: $*" >&2; exit 1; }

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "not a semver version: $version"
tag="v$version"

branch=$(git symbolic-ref --short HEAD)
[[ "$branch" == main ]] || die "releases are cut from main (on $branch)"
[[ -z "$(git status --porcelain)" ]] || die "working tree is not clean"
git fetch --quiet origin main --tags
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]] || die "main is not in sync with origin/main"
! git rev-parse -q --verify "refs/tags/$tag" >/dev/null || die "tag $tag already exists"

grep -q '^## \[Unreleased\]' CHANGELOG.md || die 'CHANGELOG.md has no "## [Unreleased]" section'
scripts/changelog-section.sh Unreleased >/dev/null || die 'nothing listed under "## [Unreleased]" in CHANGELOG.md'

current=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
[[ -n "$current" ]] || die "could not read the current version from Cargo.toml"

# Version in Cargo.toml / Cargo.lock
if [[ "$current" != "$version" ]]; then
  sed -i.bak -e "0,/^version = \"$current\"/s//version = \"$version\"/" Cargo.toml && rm Cargo.toml.bak
  cargo update --offline --workspace --quiet
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

cargo build --locked --quiet
cargo test --locked --quiet

git add Cargo.toml Cargo.lock CHANGELOG.md
git commit --quiet -m "release: $tag"
git tag -a "$tag" -m "$tag"
echo "created commit and tag $tag"

if $push; then
  git push --atomic origin main "$tag"
  echo "pushed; follow the Release workflow at $repo_url/actions/workflows/release.yml"
else
  echo "review with: git show $tag"
  echo "publish with: git push --atomic origin main $tag"
fi
