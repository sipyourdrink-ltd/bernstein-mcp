// Keyless verification of a bernstein run receipt, check by check.
//
// Mirrors `bernstein.core.replay.run_receipt.verify_run_receipt` (v3.19.2)
// but keeps going after the first failure so the caller can name every
// check that passed, failed, or could not be decided. The verdict is
// "invalid" as soon as one check fails, "unverifiable" when the input is
// not a receipt at all, else "valid".
//
// Nothing here reads the network or a key store: the Ed25519 public key is
// the one the receipt embeds (trust-on-first-use), the audit-range HMACs
// need the producing install's key and are reported as unverifiable.

import { auditRangeHead, sha256Hex, sha256HexLarge, sha256HexOfString, walkAuditLinkage, walkJournal, walkSpine } from "./chains.js";
import { JsonNumber, fromParsed, jcs, parseJson, pyDumps, utf8, type JsonObject, type JsonValue } from "./pyjson.js";

export const RECEIPT_TYPE = "https://bernstein.run/attestations/run-receipt/v1";
export const PAYLOAD_TYPE = "application/vnd.bernstein.run-receipt+json";
const SCHEMA_VERSIONS = new Set(["1.0.0", "1.1.0"]);
const HASH_PROFILE_LEGACY = "py-json-v1";
const HASH_PROFILE_JCS_V2 = "jcs-v2";
const EXTENSION_SET_SCHEMA_VERSION = "1.0.0";

export const CHECK_ORDER = [
  "schema",
  "journal_chain",
  "journal_head",
  "spine_chain",
  "spine_head",
  "audit_range_head",
  "audit_range_linkage",
  "audit_range_hmac",
  "subject_binding",
  "signature",
] as const;

export type CheckName = (typeof CHECK_ORDER)[number];
export type Outcome = "ok" | "fail" | "unverifiable" | "skipped";
export type Verdict = "valid" | "invalid" | "unverifiable";

export interface Check {
  name: CheckName;
  outcome: Outcome;
  detail: string;
}

export interface ReceiptSummary {
  run_id: string;
  schema_version: string;
  hash_profile: string;
  journal_events: number;
  spine_entries: number;
  audit_events: number | null;
  key_id: string;
  /** "bernstein-attest 0.2.0 (claude-code)" | "bernstein 4.0.0" | null when the receipt carries no producer block. */
  producer: string | null;
  /** Count of journal events with event === "tool_call"; null when there are none. */
  tool_calls: number | null;
}

/** `producer.name` (+ version, + agent) off the receipt's top-level `producer` block; null when absent or unnamed. */
export function producerLabel(receipt: JsonObject): string | null {
  const p = receipt["producer"];
  if (!p || typeof p !== "object" || Array.isArray(p)) return null;
  const name = (p as JsonObject)["name"];
  if (typeof name !== "string" || !name) return null;
  const version = (p as JsonObject)["version"];
  const agent = (p as JsonObject)["agent"];
  return name + (typeof version === "string" ? ` ${version}` : "") + (typeof agent === "string" ? ` (${agent})` : "");
}

/** Which family a producer label belongs to, read from its prefix only. */
export function producerFamily(label: string | null): "bernstein" | "bernstein-attest" | "other" {
  if (label?.startsWith("bernstein-attest")) return "bernstein-attest";
  if (label?.startsWith("bernstein")) return "bernstein";
  return "other";
}

export interface ReceiptVerification {
  verdict: Verdict;
  failing_check: CheckName | null;
  divergent_step: number | null;
  checks: Check[];
  /** SHA-256 of the receipt's canonical bytes plus "\n" (py-json-v1). */
  receipt_sha256: string;
  summary: ReceiptSummary | null;
  /** Filled once the binding block could be rebuilt. */
  binding: { block: JsonObject; bytes_b64: string; pae_sha256: string } | null;
  /** "string" keeps the producer's number spelling; "object" cannot tell 1 from 1.0. */
  input_form: "string" | "object";
}

function isObject(v: JsonValue | undefined): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof JsonNumber);
}

function asString(v: JsonValue | undefined): string {
  return typeof v === "string" ? v : "";
}

function asInt(v: JsonValue | undefined): number | null {
  return v instanceof JsonNumber && v.isInteger ? v.value : null;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function base64ToBytes(text: string, urlsafe: boolean): Uint8Array {
  let t = urlsafe ? text.replace(/-/g, "+").replace(/_/g, "/") : text;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(t)) throw new Error("not base64");
  t += "=".repeat((4 - (t.length % 4)) % 4);
  const bin = atob(t);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** DSSE pre-authentication encoding: "DSSEv1 <len> <type> <len> <payload>". */
export function pae(payloadType: string, payload: Uint8Array): Uint8Array {
  const head = utf8(`DSSEv1 ${utf8(payloadType).length} ${payloadType} ${payload.length} `);
  const out = new Uint8Array(head.length + payload.length);
  out.set(head, 0);
  out.set(payload, head.length);
  return out;
}

function endpointIdentities(events: JsonObject[]): JsonObject[] {
  const seen = new Set<string>();
  const out: { adapter: string; model: string; base_url: string; profile: string }[] = [];
  for (const e of events) {
    if (e["event"] !== "agent_spawned") continue;
    const adapter = asString(e["endpoint_adapter_name"]);
    if (!adapter) continue;
    const id = {
      adapter,
      model: asString(e["endpoint_model"]),
      base_url: asString(e["endpoint_base_url"]),
      profile: asString(e["endpoint_profile_name"]),
    };
    const key = JSON.stringify([id.adapter, id.model, id.base_url, id.profile]);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(id);
  }
  out.sort((a, b) => {
    for (const k of ["adapter", "model", "base_url", "profile"] as const) {
      if (a[k] < b[k]) return -1;
      if (a[k] > b[k]) return 1;
    }
    return 0;
  });
  return out.map((id) => ({ adapter: id.adapter, model: id.model, base_url: id.base_url, profile: id.profile }));
}

function extensionSetDigest(events: JsonObject[]): string | null {
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i];
    if (e["event"] !== "loaded_extension_set") continue;
    const raw = e["extensions"];
    if (!Array.isArray(raw)) continue;
    if (!raw.every((r) => isObject(r))) continue;
    const payload: JsonObject = { schema_version: EXTENSION_SET_SCHEMA_VERSION, entries: raw };
    return "sha256:" + sha256HexOfString(pyDumps(payload));
  }
  return null;
}

function bindingBytes(block: JsonObject, hashProfile: string): Uint8Array {
  return utf8(hashProfile === HASH_PROFILE_JCS_V2 ? jcs(block) : pyDumps(block));
}

async function ed25519Verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
}

/**
 * Verify a receipt given either its exact bytes (string) or an already
 * parsed object. Bytes are preferred: they keep the producer's number
 * spelling, so `receipt_sha256` is the same value `bernstein` prints.
 */
export async function verifyReceipt(input: string | unknown): Promise<ReceiptVerification> {
  const checks: Check[] = [];
  const add = (name: CheckName, outcome: Outcome, detail = "") => checks.push({ name, outcome, detail });
  const done = (
    partial: Partial<Pick<ReceiptVerification, "divergent_step" | "summary" | "binding">> & { receipt_sha256: string },
  ): ReceiptVerification => {
    const failing = checks.find((c) => c.outcome === "fail");
    const verdict: Verdict = failing
      ? failing.name === "schema"
        ? "unverifiable"
        : "invalid"
      : "valid";
    return {
      verdict,
      failing_check: failing ? failing.name : null,
      divergent_step: partial.divergent_step ?? null,
      checks,
      receipt_sha256: partial.receipt_sha256,
      summary: partial.summary ?? null,
      binding: partial.binding ?? null,
      input_form: typeof input === "string" ? "string" : "object",
    };
  };

  let receipt: JsonValue;
  try {
    receipt = typeof input === "string" ? parseJson(input) : fromParsed(input);
  } catch (exc) {
    add("schema", "fail", `receipt is not valid JSON: ${(exc as Error).message}`);
    return done({ receipt_sha256: sha256HexOfString(typeof input === "string" ? input : "") });
  }
  const receiptSha256 = await sha256HexLarge(utf8(pyDumps(receipt) + "\n"));

  // -- schema ---------------------------------------------------------------
  if (!isObject(receipt)) {
    add("schema", "fail", "receipt is not a JSON object");
    return done({ receipt_sha256: receiptSha256 });
  }
  const runId = asString(receipt["run_id"]);
  const schemaVersion = asString(receipt["schema_version"]);
  const hashProfile = receipt["hash_profile"] === undefined ? HASH_PROFILE_LEGACY : asString(receipt["hash_profile"]);
  const journal = receipt["journal"];
  const spine = receipt["spine"];
  const signing = receipt["signing"];
  const schemaProblem = !runId
    ? "receipt.run_id missing"
    : receipt["receipt_type"] !== RECEIPT_TYPE
      ? `unexpected receipt_type ${JSON.stringify(receipt["receipt_type"] ?? null)}`
      : !SCHEMA_VERSIONS.has(schemaVersion)
        ? `unsupported schema_version ${JSON.stringify(receipt["schema_version"] ?? null)}`
        : hashProfile !== HASH_PROFILE_LEGACY && hashProfile !== HASH_PROFILE_JCS_V2
          ? `unsupported hash_profile ${JSON.stringify(hashProfile)}`
          : !isObject(journal) || !Array.isArray(journal["events"])
            ? "receipt.journal.events missing or not a list"
            : !isObject(spine) || !Array.isArray(spine["entries"])
              ? "receipt.spine.entries missing or not a list"
              : !isObject(signing)
                ? "receipt.signing missing"
                : signing["payload_type"] !== PAYLOAD_TYPE
                  ? `unexpected signing.payload_type ${JSON.stringify(signing["payload_type"] ?? null)}`
                  : !(journal["events"] as JsonValue[]).every(isObject)
                    ? "receipt.journal.events contains a non-object row"
                    : (journal["events"] as JsonValue[]).length === 0
                      ? "receipt.journal.events is empty"
                      : !(spine["entries"] as JsonValue[]).every(isObject)
                        ? "receipt.spine.entries contains a non-object row"
                        : null;
  if (schemaProblem !== null) {
    add("schema", "fail", schemaProblem);
    return done({ receipt_sha256: receiptSha256 });
  }
  add("schema", "ok");
  const journalBlock = journal as JsonObject;
  const spineBlock = spine as JsonObject;
  const signingBlock = signing as JsonObject;
  const events = journalBlock["events"] as JsonObject[];
  const entries = spineBlock["entries"] as JsonObject[];

  // -- journal ----------------------------------------------------------------
  const jw = walkJournal(events);
  let divergentStep: number | null = null;
  if (jw.divergentIndex === null) {
    add("journal_chain", "ok", `${events.length} rows`);
  } else {
    divergentStep = jw.divergentIndex;
    add("journal_chain", "fail", `step ${jw.divergentIndex}: ${jw.error}`);
  }
  const journalHead = asString(events[events.length - 1]["event_hash"]);
  if (journalBlock["head_hash"] === journalHead && asInt(journalBlock["event_count"]) === events.length) {
    add("journal_head", "ok");
  } else {
    add("journal_head", "fail", "head_hash/event_count do not match embedded rows");
  }

  // -- spine ------------------------------------------------------------------
  const sw = walkSpine(entries);
  if (sw.divergentIndex === null) {
    add("spine_chain", "ok", `${entries.length} entries`);
  } else {
    add("spine_chain", "fail", sw.error);
  }
  if (spineBlock["head_hash"] === sw.head && asInt(spineBlock["entry_count"]) === entries.length) {
    add("spine_head", "ok");
  } else {
    add("spine_head", "fail", "head_hash/entry_count do not match embedded entries");
  }

  // -- audit range (opt-in) ---------------------------------------------------
  const audit = receipt["audit_range"];
  let auditHead: string | null = null;
  let auditEvents: JsonObject[] | null = null;
  if (audit === undefined || audit === null) {
    add("audit_range_head", "skipped", "no audit_range block");
    add("audit_range_linkage", "skipped", "no audit_range block");
    add("audit_range_hmac", "skipped", "no audit_range block");
  } else if (!isObject(audit) || !Array.isArray(audit["events"]) || !(audit["events"] as JsonValue[]).every(isObject)) {
    add("audit_range_head", "fail", "receipt.audit_range.events missing or not a list of objects");
    add("audit_range_linkage", "skipped", "audit_range malformed");
    add("audit_range_hmac", "skipped", "audit_range malformed");
  } else {
    auditEvents = audit["events"] as JsonObject[];
    const recomputed = await auditRangeHead(auditEvents);
    if (audit["head_sha256"] === recomputed && asInt(audit["event_count"]) === auditEvents.length) {
      add("audit_range_head", "ok");
    } else {
      add("audit_range_head", "fail", "head_sha256/event_count do not match embedded events");
    }
    auditHead = recomputed;
    const lw = walkAuditLinkage(auditEvents);
    if (lw.divergentIndex !== null) {
      add("audit_range_linkage", "fail", lw.error);
    } else if (audit["head_hmac"] === lw.head) {
      add("audit_range_linkage", "ok", "prev_hmac chain + head_hmac consistent");
    } else {
      add("audit_range_linkage", "fail", "head_hmac != last event hmac");
    }
    add("audit_range_hmac", "unverifiable", "HMAC-SHA256 keyed by the producing install; no key here");
  }

  // -- subject binding, rebuilt from recomputed values only --------------------
  const block: JsonObject = {
    journal_event_count: new JsonNumber(String(events.length)),
    journal_head: journalHead,
    run_id: runId,
    spine_entry_count: new JsonNumber(String(entries.length)),
    spine_head: sw.head,
  };
  if (hashProfile !== HASH_PROFILE_LEGACY) block["hash_profile"] = hashProfile;
  const endpoints = endpointIdentities(events);
  if (endpoints.length > 0) block["endpoints"] = endpoints;
  const extDigest = extensionSetDigest(events);
  if (extDigest !== null) block["extension_set_digest"] = extDigest;
  if (auditHead !== null) {
    const a = audit as JsonObject;
    if (schemaVersion === "1.0.0") {
      block["audit_range_head_sha256"] = auditHead;
    } else {
      if (a["event_count"] !== undefined && a["event_count"] !== null) block["audit_range_event_count"] = a["event_count"];
      if (a["head_hmac"] !== undefined && a["head_hmac"] !== null) block["audit_range_head_hmac"] = a["head_hmac"];
      block["audit_range_head_sha256"] = auditHead;
      if (a["since"] !== undefined && a["since"] !== null) block["audit_range_since"] = a["since"];
      if (a["until"] !== undefined && a["until"] !== null) block["audit_range_until"] = a["until"];
    }
  }
  const bytes = bindingBytes(block, hashProfile);
  const subject = sha256Hex(bytes);
  const subjectBlock = receipt["subject"];
  const digest = isObject(subjectBlock) ? subjectBlock["digest"] : undefined;
  const stated = isObject(digest) ? asString(digest["sha256"]) : "";
  if (stated === subject) {
    add("subject_binding", "ok");
  } else {
    add("subject_binding", "fail", `stated ${stated.slice(0, 16)} != recomputed ${subject.slice(0, 16)}`);
  }
  const preimage = pae(PAYLOAD_TYPE, bytes);
  const binding = { block, bytes_b64: bytesToBase64(bytes), pae_sha256: sha256Hex(preimage) };

  // -- signature ----------------------------------------------------------------
  const jwk = signingBlock["public_key_jwk"];
  let keyId = "";
  if (!isObject(jwk)) {
    add("signature", "fail", "receipt.signing.public_key_jwk missing or not an object");
  } else if (jwk["kty"] !== "OKP" || jwk["crv"] !== "Ed25519" || typeof jwk["x"] !== "string") {
    add("signature", "fail", "embedded JWK is not an OKP/Ed25519 key");
  } else if (typeof signingBlock["signature_b64"] !== "string") {
    add("signature", "fail", "receipt.signing.signature_b64 missing");
  } else {
    keyId = asString(jwk["kid"]) || asString(signingBlock["key_id"]);
    try {
      const pub = base64ToBytes(jwk["x"], true);
      if (pub.length !== 32) throw new Error(`Ed25519 public key must be 32 bytes (got ${pub.length})`);
      const sig = base64ToBytes(signingBlock["signature_b64"], false);
      if (sig.length !== 64) throw new Error(`Ed25519 signature must be 64 bytes (got ${sig.length})`);
      const ok = await ed25519Verify(pub, sig, preimage);
      if (ok) {
        add("signature", "ok", "Ed25519 over DSSE PAE(binding) with embedded JWK (trust-on-first-use)");
      } else {
        add("signature", "fail", "Ed25519 signature does not verify over the recomputed binding");
      }
    } catch (exc) {
      add("signature", "fail", `signature material unusable: ${(exc as Error).message}`);
    }
  }

  return done({
    receipt_sha256: receiptSha256,
    divergent_step: divergentStep,
    binding,
    summary: {
      run_id: runId,
      schema_version: schemaVersion,
      hash_profile: hashProfile,
      journal_events: events.length,
      spine_entries: entries.length,
      audit_events: auditEvents ? auditEvents.length : null,
      key_id: keyId,
      producer: producerLabel(receipt),
      tool_calls: (() => {
        const n = events.filter((e) => e && typeof e === "object" && (e as JsonObject)["event"] === "tool_call").length;
        return n > 0 ? n : null;
      })(),
    },
  });
}

export type ChainKind = "journal" | "spine" | "audit_linkage";

export interface ChainVerification {
  kind: ChainKind;
  intact: boolean;
  entries: number;
  head: string;
  divergent_index: number | null;
  detail: string;
}

/**
 * Rows given as text: a JSON array, or one JSON object per line (JSONL, the
 * on-disk shape of a journal or spine). Parsing here keeps every number's
 * spelling, so the hashes recompute exactly as the producer wrote them.
 */
export function parseChainText(text: string): { ok: true; rows: JsonValue[] } | { ok: false; detail: string } {
  const trimmed = text.trim();
  if (trimmed === "") return { ok: true, rows: [] };
  if (trimmed.startsWith("[")) {
    try {
      const v = parseJson(trimmed);
      return Array.isArray(v) ? { ok: true, rows: v } : { ok: false, detail: "text is not a JSON array" };
    } catch (e) {
      return { ok: false, detail: `text is not valid JSON: ${(e as Error).message}` };
    }
  }
  const rows: JsonValue[] = [];
  const lines = trimmed.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === "") continue;
    try {
      rows.push(parseJson(line));
    } catch (e) {
      return { ok: false, detail: `line ${i + 1} is not valid JSON: ${(e as Error).message}` };
    }
  }
  return { ok: true, rows };
}

/** Detect the row shape and walk it: journal rows, spine entries, or audit events. */
export function verifyChain(entries: JsonValue[], kind?: ChainKind): ChainVerification {
  if (!entries.every(isObject)) {
    return { kind: kind ?? "journal", intact: false, entries: entries.length, head: "", divergent_index: null, detail: "every entry must be a JSON object" };
  }
  const rows = entries as JsonObject[];
  const detected: ChainKind | null =
    kind ??
    (rows.length === 0
      ? null
      : "event_hash" in rows[0]
        ? "journal"
        : "entry_hash" in rows[0]
          ? "spine"
          : "hmac" in rows[0] || "prev_hmac" in rows[0]
            ? "audit_linkage"
            : null);
  if (detected === null) {
    return { kind: "journal", intact: false, entries: rows.length, head: "", divergent_index: null, detail: "cannot tell the row kind: expected event_hash (journal), entry_hash (spine) or hmac (audit) fields" };
  }
  const walk = detected === "journal" ? walkJournal(rows) : detected === "spine" ? walkSpine(rows) : walkAuditLinkage(rows);
  const intact = walk.divergentIndex === null;
  const detail = intact
    ? detected === "audit_linkage"
      ? "prev_hmac linkage intact; HMAC values need the producing install's key"
      : `${rows.length} ${detected} rows recompute to the stored hashes`
    : walk.error;
  return { kind: detected, intact, entries: rows.length, head: walk.head, divergent_index: walk.divergentIndex, detail };
}
