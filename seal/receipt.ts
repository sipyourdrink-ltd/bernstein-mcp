// A page receipt: one bernstein run receipt (schema 1.1.0) whose only
// artifact is the HTML the reader was just served. The journal holds one
// `page_served` row, the spine one entry with the body's sha256, and the
// binding is signed with the seal key. Everything the verifier recomputes is
// computed here with the verifier's own functions, so the receipt is valid
// by construction and a single changed byte of the page is not.
import { journalEventHash, journalPayloadHash, sha256Hex, sha256HexLarge, spineEntryHash } from "../src/verify/chains.js";
import { JsonNumber, compareCodePoints, pyDumps, utf8, type JsonObject } from "../src/verify/pyjson.js";
import { PAYLOAD_TYPE, RECEIPT_TYPE, bytesToBase64, pae } from "../src/verify/receipt.js";
import { jwkThumbprint } from "../src/verify/attest.js";

export const SEAL_PRODUCER = "bernstein-page-seal";
export const SEAL_VERSION = "0.1.0";
const SPINE_DOMAIN = "bernstein:lineage:v2";

export interface SealKey {
  privateKey: CryptoKey;
  publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string; kid: string; alg: "EdDSA" };
  keyId: string;
}

/** Import the private Ed25519 JWK held in the PAGE_SEAL_KEY secret; malformed → null. */
export async function importSealKey(secret: string | undefined): Promise<SealKey | null> {
  if (!secret) return null;
  try {
    const jwk = JSON.parse(secret) as { kty?: string; crv?: string; x?: string; d?: string };
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || typeof jwk.d !== "string") return null;
    const privateKey = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d }, { name: "Ed25519" }, false, ["sign"]);
    return {
      privateKey,
      publicJwk: { kty: "OKP", crv: "Ed25519", x: jwk.x, kid: jwkThumbprint(jwk.x), alg: "EdDSA" },
      keyId: "bernstein-seal-" + sha256Hex(utf8(jwk.x)).slice(0, 8),
    };
  } catch {
    return null;
  }
}

export interface PageSealInput {
  url: URL;
  body: Uint8Array;
  now: number;
  key: SealKey;
}

export interface PageReceipt {
  receipt: Record<string, unknown>;
  text: string;
  receiptSha256: string;
  contentSha256: string;
}

type Row = Record<string, string | number | boolean>;

function toJsonObject(row: Row): JsonObject {
  const out: JsonObject = {};
  for (const [k, v] of Object.entries(row)) out[k] = typeof v === "number" ? new JsonNumber(String(v)) : v;
  return out;
}

function sortedRow(row: Row): Row {
  const out: Row = {};
  for (const k of Object.keys(row).sort(compareCodePoints)) out[k] = row[k];
  return out;
}

export async function buildPageReceipt(input: PageSealInput): Promise<PageReceipt> {
  if (!Number.isInteger(input.now)) throw new TypeError("now must be integer epoch seconds");
  const contentSha256 = await sha256HexLarge(input.body);
  const path = input.url.pathname;
  const artifact = `${input.url.origin}${path}`;

  const payload: Row = {
    event: "page_served",
    host: input.url.host,
    path,
    content_sha256: contentSha256,
    bytes: input.body.length,
    served_at: input.now,
  };
  const payloadHash = journalPayloadHash(toJsonObject(payload));
  const eventHash = journalEventHash("", "page_served", payloadHash, 0);
  const row = sortedRow({ ...payload, index: 0, prev_hash: "", payload_hash: payloadHash, event_hash: eventHash });

  const entryBase: JsonObject = {
    v: new JsonNumber("2"),
    prev_hash: "",
    artifact_path: artifact,
    content_hash: "sha256:" + contentSha256,
    actor: SEAL_PRODUCER,
    step_id: "serve",
    model: "",
    timestamp: new JsonNumber(String(input.now)),
  };
  const entryHash = spineEntryHash(entryBase, SPINE_DOMAIN);
  const entry = { v: 2, prev_hash: "", artifact_path: artifact, content_hash: entryBase.content_hash, actor: SEAL_PRODUCER, step_id: "serve", model: "", timestamp: input.now, entry_hash: entryHash };

  const runId = "page-" + contentSha256.slice(0, 12);
  const block: JsonObject = {
    journal_event_count: new JsonNumber("1"),
    journal_head: eventHash,
    run_id: runId,
    spine_entry_count: new JsonNumber("1"),
    spine_head: entryHash,
  };
  const bindingBytes = utf8(pyDumps(block));
  const subject = sha256Hex(bindingBytes);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, input.key.privateKey, pae(PAYLOAD_TYPE, bindingBytes) as BufferSource));

  const receipt: Record<string, unknown> = {
    receipt_type: RECEIPT_TYPE,
    schema_version: "1.1.0",
    run_id: runId,
    created_at: input.now,
    producer: { name: SEAL_PRODUCER, version: SEAL_VERSION },
    journal: { event_count: 1, events: [row], head_hash: eventHash },
    spine: { entry_count: 1, entries: [entry], head_hash: entryHash },
    subject: { name: `page-receipt-${input.url.host}${path}`, digest: { sha256: subject } },
    signing: {
      alg: "EdDSA",
      key_id: input.key.keyId,
      payload_type: PAYLOAD_TYPE,
      public_key_jwk: input.key.publicJwk,
      signature_b64: bytesToBase64(sig),
    },
  };
  const text = JSON.stringify(receipt);
  const receiptSha256 = await sha256HexLarge(utf8(pyDumps(JSON.parse(text)) + "\n"));
  return { receipt, text, receiptSha256, contentSha256 };
}

export function base64Url(text: string): string {
  return bytesToBase64(utf8(text)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
