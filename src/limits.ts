// Body-size, JSON-depth, and response-header guards shared by every route.
// Nothing here calls out (no fetch/eval/new Function) — see
// scripts/check-no-fetch.sh, wired into `npm test`.

/** Hard cap on request body size. */
export const MAX_BODY_BYTES = 1_048_576; // 1 MiB

/** Hard cap on receipt/chain rows the verifier walks. */
export const MAX_CHAIN_ENTRIES = 2_000;

/** Hard cap on Trust Records one delegation-chain call walks. */
export const MAX_TRACE_RECORDS = 64;

/** Max JSON nesting depth accepted on any request body. */
export const MAX_JSON_DEPTH = 32;

export type BodyReadResult =
  | { ok: true; text: string }
  | { ok: false; status: 413 };

/**
 * Reads a request body up to `maxBytes`, rejecting before parsing.
 *
 * Two layers: a `content-length` pre-check (rejects without touching the
 * body at all when the client is honest about size), and a streamed byte
 * count as a backstop for chunked/absent content-length. Either one tripping
 * returns 413 — callers must not fall through to JSON.parse afterwards.
 */
export async function readBodyWithLimit(
  request: Request,
  maxBytes: number = MAX_BODY_BYTES,
): Promise<BodyReadResult> {
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    const declaredBytes = Number(declared);
    if (Number.isFinite(declaredBytes) && declaredBytes > maxBytes) {
      return { ok: false, status: 413 };
    }
  }

  if (!request.body) {
    return { ok: true, text: "" };
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value && value.byteLength > 0) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return { ok: false, status: 413 };
      }
      chunks.push(value);
    }
  }

  const buf = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buf.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, text: new TextDecoder("utf-8").decode(buf) };
}

export type ParsedJsonResult =
  | { ok: true; value: unknown }
  | { ok: false; reason: "parse_error" | "depth_exceeded" };

/**
 * Parses JSON text and rejects anything nested deeper than `maxDepth`.
 * Never throws: a malformed body or a pathologically deep one both come
 * back as a typed failure so the caller can answer with a JSON-RPC error
 * instead of a 500.
 */
export function parseJsonWithDepthLimit(
  text: string,
  maxDepth: number = MAX_JSON_DEPTH,
): ParsedJsonResult {
  let value: unknown;
  try {
    value = text.length === 0 ? null : JSON.parse(text);
  } catch {
    return { ok: false, reason: "parse_error" };
  }
  if (exceedsDepth(value, maxDepth)) {
    return { ok: false, reason: "depth_exceeded" };
  }
  return { ok: true, value };
}

// Bails out the instant `depth` passes `maxDepth`, before recursing into
// children — so an adversarially deep single-branch structure only ever
// recurses to `maxDepth + 1` frames, regardless of how deep it actually goes.
function exceedsDepth(value: unknown, maxDepth: number, depth = 0): boolean {
  if (depth > maxDepth) return true;
  if (value === null || typeof value !== "object") return false;
  const children = Array.isArray(value)
    ? value
    : Object.values(value as Record<string, unknown>);
  for (const child of children) {
    if (exceedsDepth(child, maxDepth, depth + 1)) return true;
  }
  return false;
}

export interface JsonRpcErrorBody {
  jsonrpc: "2.0";
  id: string | number | null;
  error: { code: number; message: string };
}

// Reserved server-error range per the JSON-RPC 2.0 spec (-32000..-32099).
export const JSON_RPC_PARSE_ERROR = -32700;
export const JSON_RPC_REQUEST_TOO_LARGE = -32001;

export function jsonRpcError(
  id: string | number | null,
  code: number,
  message: string,
): JsonRpcErrorBody {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

/** Applies the response headers every route on this Worker must send. */
export function withStandardHeaders(response: Response): Response {
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("X-Content-Type-Options", "nosniff");
  return response;
}
