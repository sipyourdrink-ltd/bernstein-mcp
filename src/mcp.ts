import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import adaptersJson from "../data/adapters.json";
import bernsteinTagRaw from "../data/bernstein_tag.txt";
import presetsJson from "../data/presets.json";
import { MAX_BODY_BYTES, MAX_CHAIN_ENTRIES, MAX_TRACE_RECORDS } from "./limits.js";
import { explainReceipt } from "./verify/explain.js";
import { fromParsed, type JsonValue, type JsonObject } from "./verify/pyjson.js";
import { verifyReceiptBounded } from "./verify/bounded.js";
import { CHECK_ORDER, parseChainText, producerFamily, verifyChain, type ChainVerification } from "./verify/receipt.js";
import { KEYS_PATH, signVerdict, VERIFIER_URL, type Signer } from "./verify/attest.js";
import { verifyTraceRecord, TRACE_CHECK_ORDER } from "./verify/trace/record.js";
import { verifyAgentManifest, MANIFEST_CHECK_ORDER } from "./verify/manifest/verify.js";
import { verifyDelegationChain, CODE_DETAIL, type ChainContext } from "./verify/trace/chain.js";
import { explainTraceMapping } from "./verify/trace/mapping.js";
import { parseJson } from "./verify/pyjson.js";

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

const traceRecordInput = z
  .union([z.string().max(MAX_BODY_BYTES), z.record(z.string(), z.unknown())])
  .describe("A TRACE v0.2 Trust Record: the file contents as a string, or the parsed object.");

const traceChecksSchema = z.array(
  z.object({
    name: z.enum(TRACE_CHECK_ORDER),
    outcome: z.enum(["ok", "fail", "unverifiable", "skipped"]),
    detail: z.string(),
  }),
);

const chainContextSchema = z
  .object({
    leaf: z.string().optional().describe("Digest of the record under appraisal (`sha256:<hex>`); absent → the record no other record names as parent."),
    now: z.number().optional().describe("Carried for completeness; credential windows are judged at each hop's own iat."),
    max_depth: z.number().int().nonnegative().optional().describe("Default 8."),
    supported_digest_algorithms: z.array(z.string()).optional().describe('Default ["sha256"]; "sha384" is also computed.'),
    data_class_lattice: z.array(z.string()).optional().describe("Least to most sensitive; classes outside it are not compared. Default []."),
    trusted_root_keys: z.array(z.record(z.string(), z.unknown())).optional().describe("Public JWKs; identity is (kty, crv, x, y). Default [] → the root is untrusted."),
    credentials: z
      .record(z.string(), z.object({ issuer: z.string(), holder: z.string(), not_before: z.number().int(), not_after: z.number().int() }))
      .optional()
      .describe("credential_id → {issuer, holder, not_before, not_after}. Default {} → every hop's credential is unknown."),
  })
  .optional();

function chainUnverifiable(code: string, detail: string) {
  return {
    classification: "unverifiable" as const,
    codes: [code],
    failures: [] as string[],
    warnings: [code],
    depth: 0,
    walk: [] as { record_sha256: string; subject: string; depth: number; delegation: { parent_record_hash: string; credential_id: string } | null; codes: string[] }[],
    first_broken_link: { record_sha256: "", code, detail },
    note: null as string | null,
  };
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
          max_trace_records: z.number().int().positive(),
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
        limits: { max_body_bytes: MAX_BODY_BYTES, max_chain_entries: MAX_CHAIN_ENTRIES, max_trace_records: MAX_TRACE_RECORDS },
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
        try {
          rows = fromParsed(entries) as JsonValue[];
        } catch (exc) {
          return reply({ ...chainRefused(kind, entries.length, `rows are not representable as JSON: ${(exc as Error).message}`) });
        }
      }
      const out = verifyChain(rows, kind);
      if (opts.trace) opts.trace.verdict = out.intact ? "intact" : "broken";
      return reply({ ...out });
    },
  );

  server.registerTool(
    "verify_trace_record",
    {
      title: "Verify a TRACE Trust Record",
      description:
        "TRACE v0.2 conformance checks on one Trust Record, stateless, no account: schema (vendored trace-claim.json), " +
        "profile, subject URI, software-only runtime rule, policy digest, public-only confirmation key, the embedded " +
        "signature (EdDSA, ES256 or ES384 with the key in cnf.jwk), appraisal, delegation link shape and references. " +
        "Nothing is fetched: resolvers are checked as URIs only. `record_sha256` is the RFC 8785 digest of the complete " +
        "record, signature included — the value a child hop puts in delegation.parent_record_hash.",
      inputSchema: { record: traceRecordInput },
      outputSchema: {
        verdict: verdictSchema,
        failing_check: z.enum(TRACE_CHECK_ORDER).nullable(),
        record_sha256: z.string(),
        checks: traceChecksSchema,
        summary: z
          .object({
            subject: z.string(),
            eat_profile: z.string(),
            iat: z.number().int(),
            model_id: z.string(),
            provider: z.string(),
            data_class: z.string(),
            key_thumbprint: z.string(),
            has_delegation: z.boolean(),
            references: z.number().int(),
            tool_calls: z.number().int().nullable(),
          })
          .nullable(),
        note: z.string().nullable(),
      },
    },
    async ({ record }) => {
      const v = await verifyTraceRecord(record);
      if (opts.trace) opts.trace.verdict = v.verdict;
      return reply({
        verdict: v.verdict,
        failing_check: v.failing_check,
        record_sha256: v.record_sha256,
        checks: v.checks,
        summary: v.summary,
        note: v.note,
      });
    },
  );

  server.registerTool(
    "verify_agent_manifest",
    {
      title: "Verify an Agent Manifest",
      description:
        "Agent Manifest v0.2 conformance checks on one manifest, stateless, no account: schema (vendored agent-manifest.schema.json), " +
        "profile context, version, canonicalization, COSE envelope signature (Ed25519, key identified by kid in the protected header; ML-DSA-65 is reported unverifiable). " +
        "Optionally checks that a TRACE Trust Record cites this manifest by digest. Nothing is fetched; resolvers are checked as URIs only. " +
        "The manifest hash is sha256 over the COSE payload bytes (or RFC 8785 canonical JSON for object input).",
      inputSchema: {
        manifest: z
          .union([z.string().max(MAX_BODY_BYTES), z.record(z.string(), z.unknown())])
          .describe("The agent manifest: COSE envelope as base64 string, or the parsed JSON object (payload)."),
        trustRecord: z
          .record(z.string(), z.unknown())
          .optional()
          .describe("Optional TRACE v0.2 Trust Record to check if it cites this manifest (references[].rel == 'agent-manifest')."),
      },
      outputSchema: {
        verdict: z.enum(["valid", "invalid", "unverifiable"]),
        failing_check: z.enum(MANIFEST_CHECK_ORDER).nullable(),
        manifest_sha256: z.string(),
        checks: z.array(
          z.object({
            name: z.enum(MANIFEST_CHECK_ORDER),
            outcome: z.enum(["ok", "fail", "unverifiable", "skipped"]),
            detail: z.string(),
          }),
        ),
        summary: z
          .object({
            manifest_id: z.string(),
            agent_id: z.string(),
            version: z.string(),
            issued_at: z.string(),
            expires_at: z.string(),
            issuer: z.string(),
            crypto_profile: z.string(),
            manifest_hash: z.string(),
            key_kind: z.string(),
            key_kid: z.string(),
          })
          .nullable(),
        note: z.string().nullable(),
      },
    },
    async ({ manifest, trustRecord }) => {
      // manifest is string | Record<string, unknown> from the zod schema
      // verifyAgentManifest accepts Uint8Array | string | JsonObject
      const v = await verifyAgentManifest(manifest as string | Uint8Array | JsonObject, trustRecord as JsonObject | undefined);
      if (opts.trace) opts.trace.verdict = v.verdict;
      return reply({
        verdict: v.verdict,
        failing_check: v.failing_check,
        manifest_sha256: v.manifest_sha256,
        checks: v.checks,
        summary: v.summary,
        note: v.note,
      });
    },
  );

  server.registerTool(
    "verify_delegation_chain",
    {
      title: "Verify a TRACE delegation chain",
      description:
        "TRACE v0.2 delegation-chain conformance, stateless, no account: index every Trust Record by the RFC 8785 " +
        "digest of its complete form, start at the leaf, follow delegation.parent_record_hash to the root, and check " +
        "each hop's signature, the root key against `trusted_root_keys`, the depth bound, the link's digest algorithm, " +
        "the credential (registered, issuer = parent subject, holder = record subject, window at the hop's own iat) " +
        "and data_class narrowing under `data_class_lattice`. Classification: provenance-invalid outranks " +
        "authorization-invalid; an unread link is unverifiable, not broken. Pass `records` as a JSON array or as " +
        "file text (one record per line or a JSON array).",
      inputSchema: {
        records: z
          .union([z.array(z.union([z.string(), z.record(z.string(), z.unknown())])), z.string().max(MAX_BODY_BYTES)])
          .describe("The record set in any order: a JSON array of records (objects or strings), or the raw text of a file."),
        context: chainContextSchema,
      },
      outputSchema: {
        classification: z.enum(["verified", "provenance-invalid", "authorization-invalid", "unverifiable"]),
        codes: z.array(z.string()),
        failures: z.array(z.string()),
        warnings: z.array(z.string()),
        depth: z.number().int(),
        walk: z.array(
          z.object({
            record_sha256: z.string(),
            subject: z.string(),
            depth: z.number().int(),
            delegation: z.object({ parent_record_hash: z.string(), credential_id: z.string() }).nullable(),
            codes: z.array(z.string()),
          }),
        ),
        first_broken_link: z.object({ record_sha256: z.string(), code: z.string(), detail: z.string() }).nullable(),
        note: z.string().nullable(),
      },
    },
    async ({ records, context }) => {
      let rows: JsonValue[];
      if (typeof records === "string") {
        const parsed = parseChainText(records);
        if (!parsed.ok) return reply(chainUnverifiable("records_unparseable", parsed.detail));
        rows = parsed.rows;
      } else {
        rows = [];
        for (const r of records) {
          try {
            rows.push(typeof r === "string" ? parseJson(r) : fromParsed(r));
          } catch (exc) {
            return reply(chainUnverifiable("records_unparseable", `record ${rows.length} is not valid JSON: ${(exc as Error).message}`));
          }
        }
      }
      if (rows.length > MAX_TRACE_RECORDS) return reply(chainUnverifiable("too_many_records", CODE_DETAIL["too_many_records"]));
      const out = await verifyDelegationChain(rows, (context ?? {}) as ChainContext);
      if (opts.trace) opts.trace.verdict = out.classification;
      return reply({ ...out });
    },
  );

  server.registerTool(
    "explain_trace_mapping",
    {
      title: "Explain the bernstein → TRACE mapping",
      description:
        "How a bernstein run maps onto a TRACE v0.2 Trust Record: one row per claim with the journal field it is " +
        "sourced from and the rule that derives it. Pass a run receipt to fill in the rows its embedded journal can " +
        "answer (subject, iat, model, data_class, policy digest, tool transcript) alongside the receipt's own verdict.",
      inputSchema: {
        receipt: z
          .union([z.string(), z.record(z.string(), z.unknown())])
          .optional()
          .describe("Optional run receipt: the file contents as a string, or the parsed object."),
      },
      outputSchema: {
        mapping: z.array(z.object({ claim: z.string(), source: z.string(), rule: z.string(), value: z.string().nullable() })),
        markdown: z.string(),
        verdict: verdictSchema.nullable(),
        receipt_sha256: z.string().nullable(),
      },
    },
    async ({ receipt }) => {
      const out = await explainTraceMapping(receipt);
      if (opts.trace && out.verdict) opts.trace.verdict = out.verdict;
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
