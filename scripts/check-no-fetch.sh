#!/usr/bin/env bash
# CI guard: this Worker must never call out. Fails the build if src/
# contains a call to fetch(), eval(), or `new Function`.
#
# The Workers module-worker entrypoint is itself a method named `fetch`
# (`async fetch(request, env, ctx) {...}`) — that declaration is excluded,
# every other occurrence of `fetch(` is a real outbound call and fails.
set -euo pipefail
cd "$(dirname "$0")/.."

violations=$(grep -rnE 'fetch\(|eval\(|new[[:space:]]+Function[[:space:]]*\(' src --include='*.ts' \
  | grep -v 'async fetch(' \
  || true)

if [ -n "$violations" ]; then
  echo "check-no-fetch: forbidden call found in src/ (this Worker must never call out):" >&2
  printf '%s\n' "$violations" >&2
  exit 1
fi

echo "check-no-fetch: ok"
