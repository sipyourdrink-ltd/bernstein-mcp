// Journal rows in the shape `bernstein.core.replay.journal` writes them,
// hashed the way src/verify/chains.ts walks them. Values are flat: strings,
// integers and booleans only — a session never needs more, and it keeps
// every row a single JSON line with an unambiguous canonical form.
import { journalEventHash, journalPayloadHash } from "../src/verify/chains.js";
import { JsonNumber, compareCodePoints, type JsonObject } from "../src/verify/pyjson.js";

export type RowInput = Record<string, string | number | boolean>;
export interface ChainHead { index: number; prev_hash: string }
export const GENESIS: ChainHead = { index: 0, prev_hash: "" };

export function sortedRow(input: RowInput): RowInput {
  const out: RowInput = {};
  for (const k of Object.keys(input).sort(compareCodePoints)) out[k] = input[k];
  return out;
}

export function toJsonObject(row: RowInput): JsonObject {
  const out: JsonObject = {};
  for (const [k, v] of Object.entries(row)) {
    if (typeof v === "number") {
      if (!Number.isInteger(v)) throw new TypeError(`row field ${k} must be an integer`);
      out[k] = new JsonNumber(String(v));
    } else if (typeof v === "string" || typeof v === "boolean") {
      out[k] = v;
    } else {
      throw new TypeError(`row field ${k} has an unsupported value`);
    }
  }
  return out;
}

export function hashRow(input: RowInput, head: ChainHead): { row: RowInput; head: ChainHead } {
  const payloadHash = journalPayloadHash(toJsonObject(input));
  const eventType = String(input["event"] ?? "");
  const eventHash = journalEventHash(head.prev_hash, eventType, payloadHash, head.index);
  const row = sortedRow({ ...input, index: head.index, prev_hash: head.prev_hash, payload_hash: payloadHash, event_hash: eventHash });
  return { row, head: { index: head.index + 1, prev_hash: eventHash } };
}
