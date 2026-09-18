// Keyless recomputation of the three hash chains a run receipt embeds.
//
// Each function mirrors one walk in the producer (bernstein v3.19.2):
//   journal — `bernstein.core.replay.journal.verify_events`
//   spine   — `bernstein.core.replay.run_receipt._walk_spine_rows`
//   audit   — `bernstein.core.security.audit_multitenant._events_jsonl_bytes`
//             plus the prev_hmac → hmac linkage (the HMAC values themselves
//             need the producing install's key and are reported as such).
//
// Every hash is SHA-256 over bytes the producer wrote with Python's
// json.dumps; see pyjson.ts for why the spelling matters.

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { JsonNumber, pyDumps, utf8, type JsonObject, type JsonValue } from "./pyjson.js";

export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

export function sha256HexOfString(s: string): string {
  return sha256Hex(utf8(s));
}

export interface ChainWalk {
  /** Recomputed head (last row's hash), or the genesis value for no rows. */
  head: string;
  /** 0-based index of the first diverging row, or null for an intact chain. */
  divergentIndex: number | null;
  /** Reason for the divergence, empty for an intact chain. */
  error: string;
  count: number;
}

const JOURNAL_GENESIS = "";
const NON_DETERMINISTIC_FIELDS = new Set(["ts", "elapsed_s", "index", "prev_hash", "payload_hash", "event_hash"]);

function str(v: JsonValue | undefined): string {
  if (v === undefined || v === null) return "";
  if (typeof v === "string") return v;
  if (v instanceof JsonNumber) return v.lexeme;
  if (typeof v === "boolean") return v ? "True" : "False"; // Python str(bool)
  return pyDumps(v);
}

/** `payload_hash` of one journal row: SHA-256 of the timing-excluded payload. */
export function journalPayloadHash(row: JsonObject): string {
  const projected: JsonObject = {};
  for (const [k, v] of Object.entries(row)) {
    if (!NON_DETERMINISTIC_FIELDS.has(k)) {
      Object.defineProperty(projected, k, { value: v, enumerable: true, writable: true, configurable: true });
    }
  }
  Object.defineProperty(projected, "event", {
    value: str(row["event"]),
    enumerable: true,
    writable: true,
    configurable: true,
  });
  return sha256HexOfString(pyDumps(projected));
}

/** `event_hash = H(prev_hash, event_type, payload_hash, index)`. */
export function journalEventHash(prevHash: string, eventType: string, payloadHash: string, index: number): string {
  const preimage = pyDumps({
    prev_hash: prevHash,
    event_type: eventType,
    payload_hash: payloadHash,
    index: new JsonNumber(String(index)),
  });
  return sha256HexOfString(preimage);
}

/** The exact `verify_events` walk over embedded journal rows. */
export function walkJournal(rows: JsonObject[]): ChainWalk {
  let prev = JOURNAL_GENESIS;
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const eventType = str(row["event"]);
    const expected = journalEventHash(prev, eventType, journalPayloadHash(row), i);
    const storedHash = str(row["event_hash"]);
    const storedPrev = str(row["prev_hash"]);
    if (storedPrev !== prev || storedHash !== expected) {
      const reason = storedPrev !== prev ? `step ${i}: prev_hash break` : `step ${i}: event_hash mismatch`;
      return { head: prev, divergentIndex: i, error: reason, count: rows.length };
    }
    prev = storedHash;
  }
  return { head: prev, divergentIndex: null, error: "", count: rows.length };
}

const SPINE_GENESIS = "";
const SPINE_REQUIRED = ["v", "prev_hash", "artifact_path", "content_hash", "actor", "step_id", "model", "timestamp", "entry_hash"];
const SPINE_V2_DOMAIN = "bernstein:lineage:v2";

/** `entry_hash` of one spine entry (`compute_entry_hash`), `sha256:`-prefixed. */
export function spineEntryHash(row: JsonObject, domainPrefix: string): string {
  const fields: JsonObject = {
    prev_hash: str(row["prev_hash"]),
    artifact_path: str(row["artifact_path"]),
    content_hash: str(row["content_hash"]),
    actor: str(row["actor"]),
    step_id: str(row["step_id"]),
    model: str(row["model"]),
    timestamp: spineTimestamp(row["timestamp"]),
  };
  for (const k of ["traceparent", "tracestate", "baggage"]) {
    const v = row[k];
    if (v !== undefined && v !== null) fields[k] = v;
  }
  // ensure_ascii=False here: the producer serialises spine preimages raw.
  const preimage = new Uint8Array([...utf8(domainPrefix), ...utf8(pyDumps(fields, false))]);
  return "sha256:" + sha256Hex(preimage);
}

function spineTimestamp(v: JsonValue | undefined): JsonNumber {
  // Python: int(row["timestamp"]) — accepts ints, integral floats and
  // numeric strings; anything else is "unhashable field types".
  if (v instanceof JsonNumber) {
    if (v.isInteger) return v;
    const f = v.value;
    if (Number.isInteger(f)) return new JsonNumber(String(f));
    return new JsonNumber(String(Math.trunc(f)));
  }
  if (typeof v === "string" && /^\s*[+-]?\d+\s*$/.test(v)) return new JsonNumber(String(Number(v.trim())));
  if (typeof v === "boolean") return new JsonNumber(v ? "1" : "0");
  throw new TypeError("unhashable timestamp");
}

/** The exact `_walk_spine_rows` walk over embedded spine entries. */
export function walkSpine(rows: JsonObject[]): ChainWalk {
  let prev = SPINE_GENESIS;
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const missing = SPINE_REQUIRED.filter((f) => !(f in row)).sort();
    if (missing.length) {
      return { head: prev, divergentIndex: i, error: `spine entry ${i}: missing fields [${missing.map((m) => `'${m}'`).join(", ")}]`, count: rows.length };
    }
    if (str(row["prev_hash"]) !== prev) {
      return { head: prev, divergentIndex: i, error: `spine entry ${i}: prev_hash break`, count: rows.length };
    }
    const v = row["v"];
    const version = v === null || v === undefined ? null : v instanceof JsonNumber ? v.value : NaN;
    if (!(version === null || version === 1 || version === 2)) {
      return { head: prev, divergentIndex: i, error: `spine entry ${i}: unsupported scheme version ${JSON.stringify(v)}`, count: rows.length };
    }
    let expected: string;
    try {
      expected = spineEntryHash(row, version === 2 ? SPINE_V2_DOMAIN : "");
    } catch {
      return { head: prev, divergentIndex: i, error: `spine entry ${i}: unhashable field types`, count: rows.length };
    }
    if (str(row["entry_hash"]) !== expected) {
      return { head: prev, divergentIndex: i, error: `spine entry ${i}: entry_hash mismatch`, count: rows.length };
    }
    prev = str(row["entry_hash"]);
  }
  return { head: prev, divergentIndex: null, error: "", count: rows.length };
}

/** `head_sha256` of an audit range: SHA-256 over canonical JSONL of the events. */
export function auditRangeHead(events: JsonValue[]): string {
  if (events.length === 0) return sha256Hex(new Uint8Array());
  const jsonl = events.map((e) => pyDumps(e)).join("\n") + "\n";
  return sha256HexOfString(jsonl);
}

const AUDIT_GENESIS_HMAC = "0".repeat(64);

/** prev_hmac → hmac linkage of embedded audit events (structure only). */
export function walkAuditLinkage(events: JsonObject[]): ChainWalk {
  let prev = AUDIT_GENESIS_HMAC;
  for (let i = 0; i < events.length; i++) {
    if (str(events[i]["prev_hmac"]) !== prev) {
      return { head: prev, divergentIndex: i, error: `event ${i}: prev_hmac != prior hmac`, count: events.length };
    }
    prev = str(events[i]["hmac"]);
  }
  return { head: prev, divergentIndex: null, error: "", count: events.length };
}
