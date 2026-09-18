# TRACE conformance vectors

| Directory | Upstream | Commit | Date |
|---|---|---|---|
| `delegation-link/` | https://github.com/agentrust-io/trace-spec — `examples/delegation-link/*.json` (24 files, names kept) | `0ec045311754c7c057d3a42cb102ac6f15019fe5` | 2026-09-18 |
| `bernstein/` | https://github.com/sipyourdrink-ltd/bernstein — `tests/fixtures/trust-record-vectors/*-trust-record.json` (5 files) | `97f9ffa7452a5b1e95baf1dc39c7cb2f3c158364` | 2026-09-10 |

Only the JSON records are vendored. The signing key that produced the
bernstein fixtures stays upstream; every check here uses the public key each
record carries in `cnf.jwk`.
