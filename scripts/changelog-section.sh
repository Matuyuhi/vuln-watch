#!/usr/bin/env bash
# Print the body of one version's section from CHANGELOG.md.
#   scripts/changelog-section.sh 0.2.0
# Fails if the section is missing or empty.
set -euo pipefail

version="${1:?usage: $0 VERSION}"
changelog="$(dirname "$0")/../CHANGELOG.md"

body=$(awk -v v="$version" '
  /^## / {
    if (found) exit
    if ($2 == "[" v "]" || $2 == v) { found = 1; next }
  }
  /^\[[^]]+\]: / { exit }
  found
' "$changelog" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')

if [[ -z "$body" ]]; then
  echo "CHANGELOG.md has no entries for $version" >&2
  exit 1
fi
printf '%s\n' "$body"
