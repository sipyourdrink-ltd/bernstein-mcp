// How a bernstein run maps onto a TRACE v0.2 Trust Record.
//
// The table mirrors the producer, bernstein's
// `core/observability/trust_record.py`: one row per claim, the journal
// field it is sourced from, and the rule that derives it. Given a run
// receipt, the rows the embedded journal can answer are filled from it —
// the same last-wins folds and the same transcript digest the emitter
// computes — so an operator can see what the record for that run would
// carry before it is minted.

import { sha256Hex } from "../chains.js";
import { fromParsed, jcs, parseJson, utf8, JsonNumber, type JsonObject, type JsonValue } from "../pyjson.js";
import { verifyReceiptBounded, type ReceiptInput } from "../bounded.js";
import { type Verdict } from "../receipt.js";
import { isObject } from "./keys.js";
import { TRACE_PROFILE } from "./record.js";

export const TRACE_VERIFIER_URI = "https://bernstein.run/trace/verifier";
export const DEFAULT_DATA_CLASS = "confidential";
export const ALL_ZERO_MEASUREMENT = "sha256:" + "0".repeat(64);
const RELEASE_PAGE = "https://github.com/sipyourdrink-ltd/bernstein/releases";

export interface MappingRow {
  claim: string;
  source: string;
  rule: string;
  value: string | null;
}

export const MAPPING_CLAIMS = [
  "eat_profile",
  "iat",
  "subject",
  "model",
  "runtime",
  "policy.bundle_hash",
  "policy.enforcement_mode",
  "data_class",
  "tool_transcript",
  "build_provenance",
  "appraisal",
  "cnf.jwk",
  "delegation",
  "references",
  "signature",
] as const;

const TABLE: readonly [claim: (typeof MAPPING_CLAIMS)[number], source: string, rule: string][] = [
  ["eat_profile", "constant", TRACE_PROFILE],
  ["iat", "journal: last event `ts`", "rounded to whole seconds; equals `appraisal.timestamp`"],
  ["subject", "`run_id` + `exec_id`", "`spiffe://bernstein.run/run/<run_id>/exec/<exec_id>`; the run aggregate carries `spiffe://bernstein.run/run/<run_id>`"],
  ["model", "journal: last event carrying `model_id` (+ `model_provider`, optional `model_version`)", "required; a mid-run switch shows the last model"],
  ["runtime", "constant", `{platform: "software-only", measurement: "${ALL_ZERO_MEASUREMENT}"}`],
  ["policy.bundle_hash", "journal: last `gate_config`", "`sha256:` + hex SHA-256 of the RFC 8785 canonical `gate_config`"],
  ["policy.enforcement_mode", "constant", "`enforce`"],
  ["data_class", "journal: last `data_class`", `\`${DEFAULT_DATA_CLASS}\` when none is declared`],
  [
    "tool_transcript",
    'journal: every `event == "tool_call"`, in order',
    "`hash` = `sha256:` + hex SHA-256 over the RFC 8785 canonical ordered list of payloads (row minus chain fields); `call_count`; always present, also at zero calls",
  ],
  ["build_provenance", "installed package", `\`slsa_level: 0\`; \`digest\` = digest of the installed files; \`provenance_uri\` = ${RELEASE_PAGE}`],
  ["appraisal", "constant + iat", `\`status: "none"\`; \`verifier: ${TRACE_VERIFIER_URI}\`; \`timestamp\` = iat`],
  ["cnf.jwk", "install signing key", "public Ed25519 OKP JWK with `kid`"],
  [
    "delegation",
    "parent hop's signed record",
    "`parent_record_hash` = `sha256:` + hex SHA-256 over the RFC 8785 canonical complete parent record (signature included); `credential_id` caller-supplied; absent on a root",
  ],
  [
    "references",
    "journal: `artifact_produced` events (`artifact_id`, `resolver`, `digest`)",
    'one `{rel: "produced-artifact", id, resolver, digest}` each; omitted when empty; the run aggregate carries `rel: "member-execution"` per execution',
  ],
  ["signature", "install key", "base64url Ed25519 over the RFC 8785 canonical record without `signature`"],
];

/** Journal bookkeeping fields the emitter strips from a tool_call payload. */
const JOURNAL_CHAIN_FIELDS = new Set(["index", "event", "prev_hash", "payload_hash", "event_hash", "ts", "elapsed_s"]);

export interface JournalFacts {
  iat: number | null;
  run_id: string | null;
  model: { provider: string; model_id: string; version?: string } | null;
  data_class: string | null;
  bundle_hash: string | null;
  call_count: number;
  tool_transcript_hash: string;
}

function eventName(row: JsonObject): string {
  const e = row["event"] ?? row["event_type"];
  return typeof e === "string" ? e : "";
}

function last(rows: JsonObject[], key: string): JsonValue | undefined {
  for (let i = rows.length - 1; i >= 0; i--) if (key in rows[i]) return rows[i][key];
  return undefined;
}

/** Python `round()`: half to even. */
export function roundHalfEven(x: number): number {
  const f = Math.floor(x);
  const diff = x - f;
  if (diff < 0.5) return f;
  if (diff > 0.5) return f + 1;
  return f % 2 === 0 ? f : f + 1;
}

/** The folds the emitter performs over journal rows, on the receipt's embedded rows. */
export function journalFacts(rows: JsonObject[]): JournalFacts {
  const ts = rows.length ? rows[rows.length - 1]["ts"] : undefined;
  const iat = ts instanceof JsonNumber ? roundHalfEven(ts.value) : null;
  const runId = last(rows, "run_id");
  const provider = last(rows, "model_provider");
  const modelId = last(rows, "model_id");
  const version = last(rows, "model_version");
  const model =
    typeof provider === "string" && typeof modelId === "string"
      ? { provider, model_id: modelId, ...(typeof version === "string" ? { version } : {}) }
      : null;
  const dataClass = last(rows, "data_class");
  const gate = last(rows, "gate_config");
  const calls: JsonObject[] = [];
  for (const row of rows) {
    if (eventName(row) !== "tool_call") continue;
    const payload: JsonObject = {};
    for (const [k, v] of Object.entries(row)) {
      if (!JOURNAL_CHAIN_FIELDS.has(k)) Object.defineProperty(payload, k, { value: v, enumerable: true, writable: true, configurable: true });
    }
    calls.push(payload);
  }
  return {
    iat,
    run_id: typeof runId === "string" ? runId : null,
    model,
    data_class: typeof dataClass === "string" ? dataClass : null,
    bundle_hash: gate === undefined ? null : "sha256:" + sha256Hex(utf8(jcs(gate))),
    call_count: calls.length,
    tool_transcript_hash: "sha256:" + sha256Hex(utf8(jcs(calls))),
  };
}

export interface TraceMapping {
  mapping: MappingRow[];
  markdown: string;
  verdict: Verdict | null;
  receipt_sha256: string | null;
}

function cell(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function renderMarkdown(rows: MappingRow[]): string {
  const lines = ["| claim | source | rule | value |", "|---|---|---|---|"];
  for (const r of rows) lines.push(`| ${cell(r.claim)} | ${cell(r.source)} | ${cell(r.rule)} | ${r.value === null ? "" : cell(r.value)} |`);
  return lines.join("\n");
}

/** The mapping table, with values filled from `receipt` where its journal can answer. */
export async function explainTraceMapping(receipt: ReceiptInput | undefined): Promise<TraceMapping> {
  const values: Partial<Record<(typeof MAPPING_CLAIMS)[number], string>> = {};
  let verdict: Verdict | null = null;
  let receiptSha256: string | null = null;
  if (receipt !== undefined) {
    const v = await verifyReceiptBounded(receipt);
    verdict = v.verdict;
    receiptSha256 = v.receipt_sha256 || null;
    if (v.summary) {
      let parsed: JsonValue | null = null;
      try {
        parsed = typeof receipt === "string" ? parseJson(receipt) : fromParsed(receipt);
      } catch {
        parsed = null;
      }
      const journal = isObject(parsed) ? parsed["journal"] : undefined;
      const events = isObject(journal) && Array.isArray(journal["events"]) ? (journal["events"] as JsonValue[]).filter(isObject) : [];
      const facts = journalFacts(events);
      const runId = v.summary.run_id;
      values["subject"] = `spiffe://bernstein.run/run/${runId}/exec/${facts.run_id ?? runId}`;
      if (facts.iat !== null) values["iat"] = String(facts.iat);
      if (facts.model) values["model"] = JSON.stringify(facts.model);
      if (facts.data_class !== null) values["data_class"] = facts.data_class;
      if (facts.bundle_hash !== null) values["policy.bundle_hash"] = facts.bundle_hash;
      values["tool_transcript"] = JSON.stringify({ hash: facts.tool_transcript_hash, call_count: facts.call_count });
    }
  }
  const mapping: MappingRow[] = TABLE.map(([claim, source, rule]) => ({ claim, source, rule, value: values[claim] ?? null }));
  return { mapping, markdown: renderMarkdown(mapping), verdict, receipt_sha256: receiptSha256 };
}
