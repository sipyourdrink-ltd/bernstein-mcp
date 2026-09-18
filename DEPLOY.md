# Deploy, verify, roll back

## Credentials

`wrangler deploy` needs `CLOUDFLARE_API_TOKEN` with Workers Scripts:Edit,
Workers Tail:Read and Account Settings:Read on the account, Workers Routes:Edit
on the `bernstein.run` zone, and User Details:Read. CI takes it from the
repository secret of the same name.

## Deploy

```bash
npm ci
npm test
CLOUDFLARE_API_TOKEN=… npx wrangler deploy
```

DNS: `mcp.bernstein.run` is a proxied `AAAA 100::` placeholder; the Worker
route serves everything on that hostname.

## Verify

```bash
curl -s https://mcp.bernstein.run/healthz
# {"ok":true,"version":"v3.19.2"}

curl -s https://mcp.bernstein.run/mcp \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# result.tools lists verify_receipt, explain_receipt, verify_chain, …
```

## Roll back

```bash
CLOUDFLARE_API_TOKEN=… npx wrangler rollback
```

## Refresh the bundled data

`data/bernstein_tag.txt` names the bernstein release the Worker mirrors.
`scripts/bundle_data.py` and `scripts/gen_vectors.py` run against a checkout
of that tag in `.bernstein-src/` (git-ignored) and rewrite `data/*.json` and
`vectors/*.json`. CI checks that the bundled files name the same tag.
