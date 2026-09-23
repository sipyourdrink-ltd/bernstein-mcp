# Worked examples: `verify_trace_record` and `verify_delegation_chain`

Four requests and the responses they produced, committed so the run can be repeated as-is.

| Case | Tool | Input | Verdict |
|---|---|---|---|
| a | `verify_trace_record` | `a-valid-record.json` — the single-execution vector from the Bernstein repository | `valid` |
| b | `verify_trace_record` | `b-tampered-signature-record.json` — the same record with one character of `signature` changed | `invalid`, `failing_check: signature` |
| c | `verify_delegation_chain` | `c-parent-record.json` + `c-child-record.json` with `c-context.json` (the parent's `cnf.jwk` as the trusted root; the child's credential registered with its window) | `verified`, depth 1 |
| d | `verify_delegation_chain` | the same two records, no context | `provenance-invalid`: `credential_unknown`, `root_key_untrusted` |

Tested against bernstein-mcp `14700e0420d139ef050228d902c0b580303b0ee0` with the trace-spec schema vendored at
`a7df1fce9265ce5b1643f05b02ad2122baee6097` (`vendor/SOURCE.md`). Case (a) was also sent to the hosted endpoint,
`https://mcp.bernstein.run/mcp`, and returned the same verdict, digest and check list byte for byte.

## Running them

```bash
npm run dev                      # wrangler dev; the port is printed
curl -s -X POST http://localhost:8787/mcp \
  -H "content-type: application/json" -H "accept: application/json, text/event-stream" \
  --data-binary @examples/trace-verifier/a-request.json
```

`*-request.json` are complete JSON-RPC `tools/call` bodies. `build-requests.mjs` regenerates them from the record
files, so a new vector only needs the record dropped next to it.

## What the responses show

- (a) the digest `sha256:62e4a015…` is computed over the whole record, signature included, and matches the digest the
  integrations listing cites for this vector.
- (b) every check before `signature` still passes; the failure detail names the key the verifier used:
  "EdDSA signature does not verify over the canonical record with the cnf.jwk key". The digest changes because the
  tampered byte is inside the record.
- (c) the walk finds the leaf on its own (the one record no other record names as parent) and reports depth 1.
- (d) with no context, every root is untrusted and every credential unknown by construction; the first broken link is
  the child's `delegation.credential_id`.

## Age is not checked

None of the checks compares a record's `iat` with the clock. `iat` appears in the summary only; the schema bounds it
below by a fixed floor; and a delegation credential's `[not_before, not_after]` window is judged against the hop's own
`iat`, never against `now`, which the tool accepts and documents as inert. Whether a record is too old is the relying
party's policy, applied outside this tool.
