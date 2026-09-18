// The vendored TRACE v0.2 schema (vendor/trace-claim.json), evaluated by a
// pure JSON Schema interpreter: no eval, no fetch, no remote $ref.

import { Validator, type Schema } from "@cfworker/json-schema";
import schemaJson from "../../../vendor/trace-claim.json";
import { JsonNumber, type JsonValue } from "../pyjson.js";

export interface SchemaError {
  /** JSON Pointer of the failing instance location, "#" for the root. */
  path: string;
  message: string;
}

export interface SchemaResult {
  ok: boolean;
  errors: SchemaError[];
}

let validator: Validator | null = null;

function getValidator(): Validator {
  if (!validator) validator = new Validator(schemaJson as unknown as Schema, "2020-12", false);
  return validator;
}

/** Turns the lexeme-preserving tree back into plain JSON values for the validator. */
export function toPlain(value: JsonValue | unknown): unknown {
  if (value instanceof JsonNumber) return value.value;
  if (Array.isArray(value)) return value.map(toPlain);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      Object.defineProperty(out, k, { value: toPlain(v), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  return value;
}

/**
 * Validates one record. Errors come back most specific first: the
 * interpreter reports every enclosing keyword too, and the deepest
 * instance location is the one that names the actual defect.
 */
export function validateTraceRecord(value: JsonValue | unknown): SchemaResult {
  const result = getValidator().validate(toPlain(value));
  if (result.valid) return { ok: true, errors: [] };
  const errors = result.errors
    .map((e, i) => ({ path: e.instanceLocation, message: e.error, i }))
    .sort((a, b) => b.path.length - a.path.length || a.i - b.i)
    .map(({ path, message }) => ({ path, message }));
  return { ok: false, errors };
}
