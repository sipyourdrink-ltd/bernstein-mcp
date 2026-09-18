import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import adaptersJson from "../data/adapters.json";
import bernsteinTagRaw from "../data/bernstein_tag.txt";
import presetsJson from "../data/presets.json";
import { MAX_BODY_BYTES, MAX_CHAIN_ENTRIES } from "./limits.js";
import { explainReceipt } from "./verify/explain.js";
import { fromParsed, type JsonValue } from "./verify/pyjson.js";
import { verifyReceiptBounded } from "./verify/bounded.js";
import { CHECK_ORDER, parseChainText, producerFamily, verifyChain, type ChainVerification } from "./verify/receipt.js";
import { KEYS_PATH, signVerdict, VERIFIER_URL, type Signer } from "./verify/attest.js";

export const BERNSTEIN_VERSION = bernsteinTagRaw.trim();

const PRESETS = presetsJson.presets as Record<string, Record<string, unknown>>;
const PRESET_NAMES = Object.keys(PRESETS).sort();
const ADAPTERS = adaptersJson.adapters as { name: string; binary: string; module: string }[];

/** What one request did, for the request log line (src/index.ts). */
export interface RequestTrace {
  tool?: string;
  verdict?: string;
  producer?: "bernstein" | "bernstein-attest" | "other";
}

export interface ServerOptions {
  /** This deployment's verdict-signing key; null → verdicts go out unsigned. */
  signer: Signer | null;
  /** Filled in by the tool handlers; the caller logs it. */
  trace?: RequestTrace;
}

/**
 * Builds one McpServer per request (stateless mode — see src/index.ts).
 * Nothing is logged here: the request log line is written by the Worker
 * entry point from the parsed JSON-RPC envelope plus `opts.trace`.
 */
export function createServer(opts: ServerOptions = { signer: null }): McpServer {
  const server = new McpServer({
    name: "bernstein",
    version: BERNSTEIN_VERSION,
  });
  registerTools(server, opts);
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

function chainRefused(kind: ChainVerification["kind"] | undefined, entries: number, detail: string): ChainVerification {
  return { kind: kind ?? "journal", intact: false, entries, head: "", divergent_index: null, detail };
}

export function registerTools(server: McpServer, opts: ServerOptions = { signer: null }): void {
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
        verdict_key: z
          .object({ kty: z.string(), crv: z.string(), x: z.string(), kid: z.string(), use: z.string(), alg: z.string() })
          .nullable()
          .describe("Public Ed25519 JWK this deployment signs verdicts with; also at keys_url."),
        keys_url: z.string(),
      },
    },
    async () =>
      reply({
        name: "bernstein",
        version: BERNSTEIN_VERSION,
        limits: { max_body_bytes: MAX_BODY_BYTES, max_chain_entries: MAX_CHAIN_ENTRIES },
        verdict_key: opts.signer?.publicJwk ?? null,
        keys_url: `${VERIFIER_URL}${KEYS_PATH}`,
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
        "check, one line per check, and the same verdict as a DSSE envelope signed by this verifier's Ed25519 key " +
        "(public key at keys_url) so the outcome can be kept and re-checked offline.",
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
            producer: z.string().nullable(),
            tool_calls: z.number().int().nullable(),
          })
          .nullable(),
        verify_url: z.string().nullable(),
        signed_verdict: z
          .object({
            payloadType: z.string(),
            payload: z.string(),
            signatures: z.array(z.object({ keyid: z.string(), sig: z.string() })),
          })
          .nullable()
          .describe("DSSE envelope over the verdict statement (JCS JSON in payload), Ed25519 over the DSSE PAE."),
        keys_url: z.string(),
        note: z.string().nullable(),
      },
    },
    async ({ receipt }) => {
      const v = await verifyReceiptBounded(receipt);
      if (opts.trace) {
        opts.trace.verdict = v.verdict;
        if (v.summary) opts.trace.producer = producerFamily(v.summary.producer);
      }
      const lossy = v.input_form === "object" && v.verdict === "invalid" && v.failing_check !== "signature";
      const signed = opts.signer ? await signVerdict(v, opts.signer, BERNSTEIN_VERSION) : null;
      return reply({
        verdict: v.verdict,
        failing_check: v.failing_check,
        divergent_step: v.divergent_step,
        receipt_sha256: v.receipt_sha256,
        checks: v.checks,
        summary: v.summary,
        verify_url: v.summary ? `${VERIFIER_URL}/verify/${v.receipt_sha256}` : null,
        signed_verdict: signed,
        keys_url: `${VERIFIER_URL}${KEYS_PATH}`,
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
      if (opts.trace) {
        opts.trace.verdict = v.verdict;
        if (v.summary) opts.trace.producer = producerFamily(v.summary.producer);
      }
      return reply({ verdict: v.verdict, explanation: explainReceipt(v), receipt_sha256: v.receipt_sha256 });
    },
  );

  server.registerTool(
    "verify_chain",
    {
      title: "Verify a hash chain",
      description:
        "Walk bernstein chain rows and recompute every link: journal rows (event_hash), lineage spine entries " +
        "(entry_hash) or audit events (prev_hmac linkage). The row kind is detected from the fields, or pass " +
        "`kind` explicitly. Reports the first divergent index. Pass `entries` as the file text (a JSON array or " +
        "one row per line, as journal.jsonl is written) for byte-exact hashing; a parsed array also works, but " +
        "then a float spelled 1.0 or -0.0 in the file cannot be told apart from an integer.",
      inputSchema: {
        entries: z
          .union([z.array(z.record(z.string(), z.unknown())).max(MAX_CHAIN_ENTRIES), z.string().max(MAX_BODY_BYTES)])
          .describe("Rows in chain order, oldest first: a JSON array, or the raw text of the file."),
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
      let rows: JsonValue[];
      if (typeof entries === "string") {
        const parsed = parseChainText(entries);
        if (!parsed.ok) return reply({ ...chainRefused(kind, 0, parsed.detail) });
        if (parsed.rows.length > MAX_CHAIN_ENTRIES) {
          return reply({ ...chainRefused(kind, parsed.rows.length, `more than ${MAX_CHAIN_ENTRIES} rows; run bernstein verify locally`) });
        }
        rows = parsed.rows;
      } else {
        rows = fromParsed(entries) as JsonValue[];
      }
      const out = verifyChain(rows, kind);
      if (opts.trace) opts.trace.verdict = out.intact ? "intact" : "broken";
      return reply({ ...out });
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
