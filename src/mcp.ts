import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import adaptersJson from "../data/adapters.json";
import bernsteinTagRaw from "../data/bernstein_tag.txt";
import presetsJson from "../data/presets.json";
import { MAX_BODY_BYTES, MAX_CHAIN_ENTRIES } from "./limits.js";
import { explainReceipt } from "./verify/explain.js";
import { fromParsed, type JsonValue } from "./verify/pyjson.js";
import { verifyReceiptBounded } from "./verify/bounded.js";
import { CHECK_ORDER, verifyChain } from "./verify/receipt.js";

export const BERNSTEIN_VERSION = bernsteinTagRaw.trim();

const PRESETS = presetsJson.presets as Record<string, Record<string, unknown>>;
const PRESET_NAMES = Object.keys(PRESETS).sort();
const ADAPTERS = adaptersJson.adapters as { name: string; binary: string; module: string }[];

/**
 * Builds one McpServer per request (stateless mode — see src/index.ts).
 * Logs exactly one line on `initialize`: {evt, client, client_version}.
 * Nothing else is logged (no IP, no body, no receipt contents).
 */
export function createServer(): McpServer {
  const server = new McpServer({
    name: "bernstein",
    version: BERNSTEIN_VERSION,
  });

  server.server.oninitialized = () => {
    const clientInfo = server.server.getClientVersion();
    console.log(
      JSON.stringify({
        evt: "mcp.initialize",
        client: clientInfo?.name,
        client_version: clientInfo?.version,
      }),
    );
  };

  registerTools(server);
  return server;
}

function reply<T extends Record<string, unknown>>(structuredContent: T) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(structuredContent) }],
    structuredContent,
  };
}

const checkSchema = z.object({
  name: z.enum(CHECK_ORDER),
  outcome: z.enum(["ok", "fail", "unverifiable", "skipped"]),
  detail: z.string(),
});

const verdictSchema = z.enum(["valid", "invalid", "unverifiable"]);

const receiptInput = {
  receipt: z
    .union([z.string(), z.record(z.string(), z.unknown())])
    .describe(
      "The run receipt: pass the file contents as a string for byte-exact verification, or the parsed object.",
    ),
};

export function registerTools(server: McpServer): void {
  server.registerTool(
    "server_info",
    {
      title: "Server info",
      description: "Identity, version, and request limits for this MCP server.",
      outputSchema: {
        name: z.string(),
        version: z.string(),
        limits: z.object({
          max_body_bytes: z.number().int().positive(),
          max_chain_entries: z.number().int().positive(),
        }),
      },
    },
    async () =>
      reply({
        name: "bernstein",
        version: BERNSTEIN_VERSION,
        limits: { max_body_bytes: MAX_BODY_BYTES, max_chain_entries: MAX_CHAIN_ENTRIES },
      }),
  );

  server.registerTool(
    "verify_receipt",
    {
      title: "Verify a run receipt",
      description:
        "Recompute every hash chain a bernstein run receipt embeds (journal, lineage spine, optional audit range), " +
        "rebuild the signed subject from the recomputed heads, and check the Ed25519 signature with the key the " +
        "receipt carries. Needs no secret and reads nothing but the receipt. Returns the verdict, the first failing " +
        "check, and one line per check.",
      inputSchema: receiptInput,
      outputSchema: {
        verdict: verdictSchema,
        failing_check: z.enum(CHECK_ORDER).nullable(),
        divergent_step: z.number().int().nullable(),
        receipt_sha256: z.string(),
        checks: z.array(checkSchema),
        summary: z
          .object({
            run_id: z.string(),
            schema_version: z.string(),
            hash_profile: z.string(),
            journal_events: z.number().int(),
            spine_entries: z.number().int(),
            audit_events: z.number().int().nullable(),
            key_id: z.string(),
          })
          .nullable(),
        verify_url: z.string().nullable(),
        note: z.string().nullable(),
      },
    },
    async ({ receipt }) => {
      const v = await verifyReceiptBounded(receipt);
      const lossy = v.input_form === "object" && v.verdict === "invalid" && v.failing_check !== "signature";
      return reply({
        verdict: v.verdict,
        failing_check: v.failing_check,
        divergent_step: v.divergent_step,
        receipt_sha256: v.receipt_sha256,
        checks: v.checks,
        summary: v.summary,
        verify_url: v.summary ? `https://mcp.bernstein.run/verify/${v.receipt_sha256}` : null,
        note: lossy
          ? "Passed as a parsed object: number spelling (1 vs 1.0, -0.0) is lost. If the file verifies locally, pass its contents as a string."
          : null,
      });
    },
  );

  server.registerTool(
    "explain_receipt",
    {
      title: "Explain a run receipt",
      description:
        "Verify a run receipt and narrate the result in plain language: what the run recorded, which chains " +
        "recomputed, where the first divergence is, and what an auditor can and cannot conclude without the " +
        "producing install's keys.",
      inputSchema: receiptInput,
      outputSchema: {
        verdict: verdictSchema,
        explanation: z.string(),
        receipt_sha256: z.string(),
      },
    },
    async ({ receipt }) => {
      const v = await verifyReceiptBounded(receipt);
      return reply({ verdict: v.verdict, explanation: explainReceipt(v), receipt_sha256: v.receipt_sha256 });
    },
  );

  server.registerTool(
    "verify_chain",
    {
      title: "Verify a hash chain",
      description:
        "Walk a list of bernstein chain rows and recompute every link: journal rows (event_hash), lineage spine " +
        "entries (entry_hash) or audit events (prev_hmac linkage). The row kind is detected from the fields, or " +
        "pass `kind` explicitly. Reports the first divergent index. Rows arrive parsed, so a float spelled 1.0 " +
        "or -0.0 in the original file cannot be told apart from an integer; verify_receipt with the file contents " +
        "as a string is exact.",
      inputSchema: {
        entries: z.array(z.record(z.string(), z.unknown())).max(MAX_CHAIN_ENTRIES).describe("Rows in chain order, oldest first."),
        kind: z.enum(["journal", "spine", "audit_linkage"]).optional(),
      },
      outputSchema: {
        kind: z.enum(["journal", "spine", "audit_linkage"]),
        intact: z.boolean(),
        entries: z.number().int(),
        head: z.string(),
        divergent_index: z.number().int().nullable(),
        detail: z.string(),
      },
    },
    async ({ entries, kind }) => {
      const rows = fromParsed(entries) as JsonValue[];
      return reply({ ...verifyChain(rows, kind) });
    },
  );

  server.registerTool(
    "list_presets",
    {
      title: "List compliance presets",
      description: `The compliance presets bernstein ${BERNSTEIN_VERSION} ships, with the switches each one turns on.`,
      outputSchema: {
        bernstein_version: z.string(),
        presets: z.array(z.object({ name: z.string(), enabled: z.array(z.string()) })),
      },
    },
    async () =>
      reply({
        bernstein_version: BERNSTEIN_VERSION,
        presets: PRESET_NAMES.map((name) => ({
          name,
          enabled: Object.entries(PRESETS[name])
            .filter(([, v]) => v === true)
            .map(([k]) => k)
            .sort(),
        })),
      }),
  );

  server.registerTool(
    "get_preset",
    {
      title: "Get a compliance preset",
      description: `Every field of one compliance preset as bernstein ${BERNSTEIN_VERSION} resolves it.`,
      inputSchema: { name: z.enum(PRESET_NAMES as [string, ...string[]]) },
      outputSchema: {
        bernstein_version: z.string(),
        name: z.string(),
        config: z.record(z.string(), z.unknown()),
      },
    },
    async ({ name }) => reply({ bernstein_version: BERNSTEIN_VERSION, name, config: PRESETS[name] }),
  );

  server.registerTool(
    "list_adapters",
    {
      title: "List agent adapters",
      description: `The agent adapters bundled with bernstein ${BERNSTEIN_VERSION}: adapter name, the binary it drives, the module that implements it.`,
      outputSchema: {
        bernstein_version: z.string(),
        adapters: z.array(z.object({ name: z.string(), binary: z.string(), module: z.string() })),
      },
    },
    async () => reply({ bernstein_version: BERNSTEIN_VERSION, adapters: ADAPTERS }),
  );
}
