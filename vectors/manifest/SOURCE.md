# Agent Manifest conformance vectors

| File | Upstream | Commit | Date |
|---|---|---|---|
| `level0-software-only.json` | https://github.com/agentrust-io/agent-manifest — `examples/level0-software-only.json` | `802975a83e0c3880dcacd1db60d3442c75511cac` | 2026-09-24 |
| `level1-tpm-attested.json` | https://github.com/agentrust-io/agent-manifest — `examples/level1-tpm-attested.json` | `802975a83e0c3880dcacd1db60d3442c75511cac` | 2026-09-24 |

These are the upstream example manifests, vendored verbatim. The upstream
repository does not ship COSE-signed variants; these are the unsigned JSON
payloads that a COSE envelope wraps. Tests that need a signed envelope use
the reference implementation to produce one on the fly.
