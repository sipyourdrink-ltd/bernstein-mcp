// Seal one journal segment into a bernstein run receipt (schema 1.1.0,
// py-json-v1 profile). Every value the verifier recomputes is computed
// here with the verifier's own functions, so a receipt this writes is
// valid by construction and a single changed byte is not.
import { sha256Hex, sha256HexLarge, spineEntryHash } from "../src/verify/chains.js";
import { JsonNumber, pyDumps, utf8, type JsonObject } from "../src/verify/pyjson.js";
import { PAYLOAD_TYPE, RECEIPT_TYPE, pae } from "../src/verify/receipt.js";
import { type AttestKey, sign } from "./keys.js";
import { type RowInput } from "./rows.js";
import { PRODUCER_NAME, PRODUCER_VERSION } from "./version.js";

export interface TouchedFile { path: string; stepId: string; contentSha256: string | null }
export interface SealInput {
  runId: string; rows: RowInput[]; files: TouchedFile[];
  agent: "claude-code" | "codex"; agentVersion?: string; model: string;
  key: AttestKey; now: number;
}
export interface Sealed { receipt: Record<string, unknown>; text: string; receiptSha256: string }

const SPINE_DOMAIN = "bernstein:lineage:v2";

function spineEntries(input: SealInput): Record<string, unknown>[] {
  let prev = "";
  const out: Record<string, unknown>[] = [];
  for (const f of input.files) {
    const base: JsonObject = {
      v: new JsonNumber("2"),
      prev_hash: prev,
      artifact_path: f.path,
      content_hash: f.contentSha256 ? "sha256:" + f.contentSha256 : "sha256:missing",
      actor: input.agent,
      step_id: f.stepId,
      model: input.model,
      timestamp: new JsonNumber(String(input.now)),
    };
    const entryHash = spineEntryHash(base, SPINE_DOMAIN);
    out.push({ v: 2, prev_hash: prev, artifact_path: f.path, content_hash: base.content_hash, actor: input.agent, step_id: f.stepId, model: input.model, timestamp: input.now, entry_hash: entryHash });
    prev = entryHash;
  }
  return out;
}

export async function buildReceipt(input: SealInput): Promise<Sealed> {
  if (input.rows.length === 0) throw new Error("a receipt needs at least one journal row");
  if (!Number.isInteger(input.now)) throw new TypeError("now must be integer epoch seconds");
  const journalHead = String(input.rows[input.rows.length - 1]["event_hash"]);
  const entries = spineEntries(input);
  const spineHead = entries.length ? String(entries[entries.length - 1]["entry_hash"]) : "";
  const block: JsonObject = {
    journal_event_count: new JsonNumber(String(input.rows.length)),
    journal_head: journalHead,
    run_id: input.runId,
    spine_entry_count: new JsonNumber(String(entries.length)),
    spine_head: spineHead,
  };
  const bindingBytes = utf8(pyDumps(block));
  const subject = sha256Hex(bindingBytes);
  const signature = await sign(input.key, pae(PAYLOAD_TYPE, bindingBytes));
  const producer: Record<string, unknown> = { name: PRODUCER_NAME, version: PRODUCER_VERSION, agent: input.agent };
  if (input.agentVersion) producer["agent_version"] = input.agentVersion;
  const receipt: Record<string, unknown> = {
    receipt_type: RECEIPT_TYPE,
    schema_version: "1.1.0",
    run_id: input.runId,
    created_at: input.now,
    producer,
    journal: { event_count: input.rows.length, events: input.rows, head_hash: journalHead },
    spine: { entry_count: entries.length, entries, head_hash: spineHead },
    subject: { name: `session-receipt-${input.runId}`, digest: { sha256: subject } },
    signing: {
      alg: "EdDSA",
      key_id: input.key.keyId,
      payload_type: PAYLOAD_TYPE,
      public_key_jwk: input.key.publicJwk,
      signature_b64: signature,
    },
  };
  const text = JSON.stringify(receipt, null, 1) + "\n";
  // Same digest the verifier reports: canonical py-json bytes plus "\n".
  const receiptSha256 = await sha256HexLarge(utf8(pyDumps(toCanonical(receipt)) + "\n"));
  return { receipt, text, receiptSha256 };
}

// JSON.parse round-trip gives plain numbers; fromParsed inside pyDumps wraps
// them. Rows carry integers only (rows.ts enforces it), so nothing is lost.
function toCanonical(receipt: Record<string, unknown>): unknown {
  return JSON.parse(JSON.stringify(receipt));
}
