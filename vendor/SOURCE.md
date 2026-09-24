# Vendored files

| File | Upstream | Commit | Date |
|---|---|---|---|
| `trace-claim.json` | https://github.com/agentrust-io/trace-spec — `schema/trace-claim.json` | `a7df1fce9265ce5b1643f05b02ad2122baee6097` | 2026-09-20 |
| `agent-manifest.schema.json` | https://github.com/agentrust-io/agent-manifest — `python/src/agent_manifest/models.py` (Manifest.model_json_schema()) | `802975a83e0c3880dcacd1db60d3442c75511cac` | 2026-09-24 |

The schema is bundled into the Worker and evaluated with a pure JSON Schema
interpreter; nothing is fetched at runtime. Refresh by copying the file from
the upstream commit and updating this table.
