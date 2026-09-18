#!/usr/bin/env bash
# CI guard: the bundled presets/adapters must name the same bernstein tag
# as data/bernstein_tag.txt (the version the Worker reports).
set -euo pipefail
cd "$(dirname "$0")/.."
tag=$(tr -d '[:space:]' < data/bernstein_tag.txt)
for f in data/presets.json data/adapters.json; do
  got=$(node -e "process.stdout.write(require('./$f').bernstein_version)")
  if [ "$got" != "$tag" ]; then
    echo "check-data-tag: $f names $got, data/bernstein_tag.txt says $tag" >&2
    exit 1
  fi
done
echo "check-data-tag: ok ($tag)"
