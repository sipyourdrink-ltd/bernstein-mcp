// Canonical JSON exactly as the receipt producer writes it.
//
// A run receipt's hashes are computed by Python's `json.dumps(obj,
// sort_keys=True, separators=(",", ":"))`. Reproducing those bytes from
// JavaScript needs three things `JSON.stringify` does not give:
//
//   1. Number lexemes. JSON.parse turns `1.0` into the number 1, and Python
//      would write that back as `1.0` (it was a float) — so the receipt text
//      is parsed here with a reader that keeps every number's original
//      spelling, and numbers are re-emitted the way Python's `repr` would
//      (`1.0`, `1e-05`, `1e+16`, `-0.0`, `123456789.125`).
//   2. Key order by Unicode code point (Python `str` comparison), not by
//      UTF-16 code unit (what `Object.keys().sort()` gives).
//   3. Python's escaping: with `ensure_ascii=True` (the default, used for
//      receipts, journal rows and the binding block) every character outside
//      0x20–0x7E becomes `\uXXXX` (astral characters as a surrogate pair);
//      with `ensure_ascii=False` (spine entries) only `"`, `\` and
//      controls < 0x20 are escaped.
//
// `jcs()` is the RFC 8785 profile (`hash_profile: "jcs-v2"`): ES6 number
// formatting, UTF-16 key order, raw UTF-8 — which is what JSON.stringify
// already does once keys are sorted.
//
// Nothing here touches the network or evaluates code.

/** A JSON number as it appeared in the source text. */
export class JsonNumber {
  constructor(public readonly lexeme: string) {}
  /** True when Python's `json.loads` would produce an `int` for this lexeme. */
  get isInteger(): boolean {
    return !/[.eE]/.test(this.lexeme);
  }
  /** The JavaScript number (lossy above 2^53 for integers, exact for floats). */
  get value(): number {
    return Number(this.lexeme);
  }
  toJSON(): number {
    return this.value;
  }
}

/** JSON as parsed by `parseJson`: numbers keep their lexeme. */
export type JsonValue =
  | null
  | boolean
  | string
  | JsonNumber
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };

export class JsonParseError extends Error {
  constructor(message: string, public readonly offset: number) {
    super(message);
    this.name = "JsonParseError";
  }
}

/**
 * Strict RFC 8259 parser that preserves number lexemes and enforces a
 * nesting depth. Duplicate keys: last one wins, like Python and JS.
 * Prototype-polluting keys (`__proto__`) are stored as own properties via
 * `Object.defineProperty`, never assigned through the prototype chain.
 */
export function parseJson(text: string, maxDepth = 32): JsonValue {
  let i = 0;
  const n = text.length;

  const fail = (msg: string): never => {
    throw new JsonParseError(msg, i);
  };
  const ws = (): void => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const parseString = (): string => {
    // text[i] === '"'
    i++;
    let out = "";
    let start = i;
    for (;;) {
      if (i >= n) fail("unterminated string");
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        out += text.slice(start, i);
        i++;
        return out;
      }
      if (c === 0x5c) {
        out += text.slice(start, i);
        i++;
        if (i >= n) fail("unterminated escape");
        const e = text[i++];
        switch (e) {
          case '"':
            out += '"';
            break;
          case "\\":
            out += "\\";
            break;
          case "/":
            out += "/";
            break;
          case "b":
            out += "\b";
            break;
          case "f":
            out += "\f";
            break;
          case "n":
            out += "\n";
            break;
          case "r":
            out += "\r";
            break;
          case "t":
            out += "\t";
            break;
          case "u": {
            const hex = text.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("bad \\u escape");
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default:
            fail("bad escape");
        }
        start = i;
        continue;
      }
      if (c < 0x20) fail("control character in string");
      i++;
    }
  };

  const parseNumber = (): JsonNumber => {
    const start = i;
    if (text[i] === "-") i++;
    if (i >= n) fail("bad number");
    if (text[i] === "0") {
      i++;
    } else if (text[i] >= "1" && text[i] <= "9") {
      while (i < n && text[i] >= "0" && text[i] <= "9") i++;
    } else {
      fail("bad number");
    }
    if (text[i] === ".") {
      i++;
      if (!(text[i] >= "0" && text[i] <= "9")) fail("bad fraction");
      while (i < n && text[i] >= "0" && text[i] <= "9") i++;
    }
    if (text[i] === "e" || text[i] === "E") {
      i++;
      if (text[i] === "+" || text[i] === "-") i++;
      if (!(text[i] >= "0" && text[i] <= "9")) fail("bad exponent");
      while (i < n && text[i] >= "0" && text[i] <= "9") i++;
    }
    return new JsonNumber(text.slice(start, i));
  };

  const parseValue = (depth: number): JsonValue => {
    if (depth > maxDepth) fail("nesting too deep");
    ws();
    if (i >= n) fail("unexpected end");
    const c = text[i];
    if (c === "{") {
      i++;
      const obj: JsonObject = {};
      ws();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail("expected string key");
        const key = parseString();
        ws();
        if (text[i] !== ":") fail("expected ':'");
        i++;
        const val = parseValue(depth + 1);
        Object.defineProperty(obj, key, {
          value: val,
          enumerable: true,
          writable: true,
          configurable: true,
        });
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return obj;
        }
        fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++;
      const arr: JsonValue[] = [];
      ws();
      if (text[i] === "]") {
        i++;
        return arr;
      }
      for (;;) {
        arr.push(parseValue(depth + 1));
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return arr;
        }
        fail("expected ',' or ']'");
      }
    }
    if (c === '"') return parseString();
    if (c === "t" && text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (c === "f" && text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (c === "n" && text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    if (c === "-" || (c >= "0" && c <= "9")) return parseNumber();
    return fail("unexpected token");
  };

  const value = parseValue(0);
  ws();
  if (i !== n) fail("trailing characters");
  return value;
}

/**
 * Wraps an already-parsed JavaScript value (e.g. a tool argument the MCP
 * transport decoded) into the lexeme-preserving shape. Integer-valued
 * numbers are treated as Python `int` — the one thing a parsed object
 * cannot tell apart from a float written as `1.0`.
 */
export function fromParsed(value: unknown): JsonValue {
  if (value === null || value === undefined) return null;
  if (typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite number");
    return new JsonNumber(Number.isInteger(value) ? String(value) : pyFloatRepr(value));
  }
  if (value instanceof JsonNumber) return value;
  if (Array.isArray(value)) return value.map(fromParsed);
  if (typeof value === "object") {
    const out: JsonObject = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      Object.defineProperty(out, k, {
        value: fromParsed(v),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  }
  throw new TypeError(`unsupported value of type ${typeof value}`);
}

/** Python `repr(float)` for a finite double. */
export function pyFloatRepr(x: number): string {
  if (Object.is(x, -0)) return "-0.0";
  if (!Number.isFinite(x)) return x > 0 ? "Infinity" : x < 0 ? "-Infinity" : "NaN";
  // Shortest round-trip digits, the same set Python's repr uses.
  const m = /^(-?)(\d)(?:\.(\d+))?e([+-]\d+)$/.exec(x.toExponential());
  if (!m) throw new Error(`unexpected exponential form for ${x}`);
  const sign = m[1];
  const digits = m[2] + (m[3] ?? "");
  const exp = Number(m[4]);
  if (exp >= -4 && exp <= 15) {
    if (exp >= 0) {
      const intPart = digits.slice(0, exp + 1).padEnd(exp + 1, "0");
      const frac = digits.slice(exp + 1);
      return `${sign}${intPart}.${frac || "0"}`;
    }
    return `${sign}0.${"0".repeat(-exp - 1)}${digits}`;
  }
  const mantissa = m[3] ? `${m[2]}.${m[3]}` : m[2];
  const expAbs = String(Math.abs(exp)).padStart(2, "0");
  return `${sign}${mantissa}e${exp < 0 ? "-" : "+"}${expAbs}`;
}

/** Python `json.dumps` spelling of a number parsed from `lexeme`. */
export function pyNumber(num: JsonNumber): string {
  if (num.isInteger) {
    // Python int: the digits themselves (arbitrary precision), "-0" → "0".
    return num.lexeme === "-0" ? "0" : num.lexeme;
  }
  return pyFloatRepr(Number(num.lexeme));
}

/** Python `str` ordering: by Unicode code point. */
export function compareCodePoints(a: string, b: string): number {
  const la = a.length;
  const lb = b.length;
  let i = 0;
  let j = 0;
  while (i < la && j < lb) {
    const ca = a.codePointAt(i) as number;
    const cb = b.codePointAt(j) as number;
    if (ca !== cb) return ca < cb ? -1 : 1;
    i += ca > 0xffff ? 2 : 1;
    j += cb > 0xffff ? 2 : 1;
  }
  return la - i === lb - j ? 0 : la - i < lb - j ? -1 : 1;
}

const SHORT_ESCAPES: Record<number, string> = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
};

function hex4(c: number): string {
  return "\\u" + c.toString(16).padStart(4, "0");
}

/** Python `json.dumps` string encoding for either `ensure_ascii` setting. */
export function pyString(s: string, ensureAscii: boolean): string {
  let out = '"';
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    let esc: string | undefined;
    if (c in SHORT_ESCAPES) esc = SHORT_ESCAPES[c];
    else if (c < 0x20) esc = hex4(c);
    else if (ensureAscii && c > 0x7e) esc = hex4(c); // surrogate halves fall out naturally
    if (esc !== undefined) {
      out += s.slice(start, i) + esc;
      start = i + 1;
    }
  }
  return out + s.slice(start) + '"';
}

/**
 * `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=…)`.
 * Accepts the lexeme-preserving tree; plain JS values are wrapped first.
 */
export function pyDumps(value: unknown, ensureAscii = true): string {
  const v = value instanceof JsonNumber || isJsonTree(value) ? (value as JsonValue) : fromParsed(value);
  return dumpValue(v, ensureAscii);
}

function isJsonTree(value: unknown): boolean {
  // Cheap structural check: objects/arrays produced by parseJson/fromParsed
  // only ever contain JsonNumber for numbers. A raw JS number means "not
  // yet wrapped".
  if (value === null || typeof value !== "object") return typeof value !== "number";
  if (value instanceof JsonNumber) return true;
  const children = Array.isArray(value) ? value : Object.values(value as object);
  return children.every(isJsonTree);
}

function dumpValue(v: JsonValue, ensureAscii: boolean): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "string") return pyString(v, ensureAscii);
  if (v instanceof JsonNumber) return pyNumber(v);
  if (Array.isArray(v)) return "[" + v.map((x) => dumpValue(x, ensureAscii)).join(",") + "]";
  const keys = Object.keys(v).sort(compareCodePoints);
  return "{" + keys.map((k) => pyString(k, ensureAscii) + ":" + dumpValue(v[k], ensureAscii)).join(",") + "}";
}

/** RFC 8785 (JCS) serialization of the same tree. */
export function jcs(value: JsonValue): string {
  return jcsValue(value);
}

function jcsValue(v: JsonValue): string {
  if (v === null || typeof v === "boolean") return String(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (v instanceof JsonNumber) {
    if (v.isInteger) {
      const n = Number(v.lexeme);
      // JCS numbers are IEEE doubles serialized per ES6; integers beyond
      // 2^53 lose precision there too, so this matches an ES6 serializer.
      return JSON.stringify(n);
    }
    return JSON.stringify(v.value);
  }
  if (Array.isArray(v)) return "[" + v.map(jcsValue).join(",") + "]";
  const keys = Object.keys(v).sort(); // UTF-16 code unit order, per RFC 8785
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcsValue(v[k])).join(",") + "}";
}

/**
 * The same serialization with object keys sorted by Unicode code point
 * instead of UTF-16 code unit. NOT RFC 8785: the two orders differ only
 * when a key contains a character outside the Basic Multilingual Plane,
 * and this variant exists so a verifier can name that divergence in a
 * diagnostic. Never used for a verdict.
 */
export function jcsCodePointOrder(value: JsonValue): string {
  return jcsValueOrdered(value, compareCodePoints);
}

function jcsValueOrdered(v: JsonValue, cmp: (a: string, b: string) => number): string {
  if (v === null || typeof v === "boolean") return String(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (v instanceof JsonNumber) return jcsValue(v);
  if (Array.isArray(v)) return "[" + v.map((x) => jcsValueOrdered(x, cmp)).join(",") + "]";
  const keys = Object.keys(v).sort(cmp);
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcsValueOrdered(v[k], cmp)).join(",") + "}";
}

/** UTF-8 bytes of a string (lone surrogates become U+FFFD, as TextEncoder does). */
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
