#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/built/trust-record-verify" >&2
  exit 1
fi
src=$(cd "$1" && pwd)
if [[ ! -f "$src/dist/index.js" ]]; then
  echo 'Missing dist/index.js; build the source checkout first.' >&2
  exit 1
fi
source_root=$(git -C "$src" rev-parse --show-toplevel)
if [[ -n "$(git -C "$source_root" status --porcelain --untracked-files=all)" ]]; then
  echo 'Source tree is dirty; use a clean built checkout.' >&2
  exit 1
fi
for name in LICENSE NOTICE; do
  if [[ ! -r "$source_root/$name" || ! -f "$source_root/$name" ]]; then
    echo "Missing upstream legal file: $name" >&2
    exit 1
  fi
done
commit=$(git -C "$src" rev-parse HEAD)
commit_date=$(git -C "$src" show -s --format=%cs HEAD)
metadata=$(node --input-type=module - "$src/package.json" <<'NODE'
import { readFileSync } from 'node:fs';
const pkg = JSON.parse(readFileSync(process.argv[2], 'utf8'));
if (typeof pkg.name !== 'string' || typeof pkg.version !== 'string' || pkg.license !== 'Apache-2.0') {
  throw new Error('Expected package name, version and Apache-2.0 license');
}
console.log(`Package: ${pkg.name}\nVersion: ${pkg.version}\nPackage license: ${pkg.license}`);
NODE
)
shopt -s nullglob
files=("$src"/dist/*.js "$src"/dist/*.d.ts "$src/dist/generated/validators.js" "$src/dist/generated/validators.d.ts")
for file in "${files[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "Missing built file: $file" >&2
    exit 1
  fi
done
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dest="$repo_root/vendor/trust-record-verify"
mkdir -p "$dest/generated"
cp "$source_root/LICENSE" "$source_root/NOTICE" "$dest/"
for file in "${files[@]}"; do
  cp "$file" "$dest/${file#"$src/dist/"}"
done
cat > "$dest/SOURCE.md" <<SOURCE
# Vendored trust-record-verify

Upstream: https://github.com/agentrust-io/trace-spec — trust-record-verify/
Commit: $commit
Commit date: $commit_date
$metadata

Repository-root LICENSE and NOTICE are retained verbatim; see those files for
the upstream licensing scope and attribution. The package license above is
from trust-record-verify/package.json.

Built output; regenerate with \`scripts/vendor-trust-record-verify.sh\`; do not edit
SOURCE
