/**
 * RFC 8785 JSON Canonicalization Scheme, with the integer bound of section 3.2.2.
 *
 * Section 3.2.2 fixes the signature pre-image as the RFC 8785 form of the record.
 * The rules implemented here:
 *
 * - Object members are sorted by the UTF-16 code units of their names
 *   (RFC 8785 section 3.2.3). JavaScript string comparison is exactly that order.
 * - No whitespace between tokens.
 * - Strings are emitted as UTF-8 with only U+0022, U+005C and U+0000 to U+001F
 *   escaped, using the short forms for backspace, tab, line feed, form feed and
 *   carriage return and lowercase `\u00xx` otherwise (RFC 8785 section 3.2.2.2).
 * - Numbers use the ECMAScript Number-to-String form (RFC 8785 section
 *   3.2.2.3), which is what `String(number)` produces; negative zero becomes `0`.
 *
 * Refused, each as `canonicalization_failed`:
 *
 * - an integer outside -9007199254740991 to 9007199254740991, which section
 *   3.2.2 raises from RFC 8785's SHOULD to a MUST;
 * - NaN and the infinities, which have no JSON form;
 * - a string or member name holding an unpaired surrogate, which has no UTF-8
 *   form (RFC 8785 section 3.1 requires I-JSON input, RFC 7493 section 2.1);
 * - anything that is not JSON data: `undefined`, functions, symbols, bigints,
 *   class instances, array holes, cyclic structures, and an object with a
 *   symbol-keyed member, which `Object.keys` would silently leave out.
 */
/** The widest integer range section 3.2.2 lets a canonicalized object carry. */
export declare const JCS_SAFE_INTEGER = 9007199254740991;
/** The RFC 8785 text of *value*. */
export declare function canonicalJson(value: unknown): string;
/** The RFC 8785 bytes of *value*: the UTF-8 encoding of `canonicalJson(value)`. */
export declare function canonicalize(value: unknown): Uint8Array;
