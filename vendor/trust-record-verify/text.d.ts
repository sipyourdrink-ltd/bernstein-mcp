/** String helpers shared by the canonicalizer, the schema validator and the verifier. */
/** UTF-8 bytes of a string already known to be well formed. */
export declare function utf8(value: string): Uint8Array;
/**
 * Offset of the first unpaired surrogate in *value*, or -1.
 *
 * A JavaScript string is a sequence of UTF-16 code units and may hold a lone
 * surrogate, which has no UTF-8 encoding. `TextEncoder` would silently replace
 * it with U+FFFD, so two different strings would produce the same bytes.
 */
export declare function unpairedSurrogateAt(value: string): number;
/**
 * Number of Unicode code points in *value*, counting a lone surrogate as one.
 *
 * JSON Schema measures string length in code points, not UTF-16 code units, so
 * `minLength` and `maxLength` need this rather than `.length`.
 */
export declare function codePointLength(value: string): number;
/** Compare two strings by Unicode code point, the order Python uses for `str`. */
export declare function compareCodePoints(a: string, b: string): number;
/**
 * Compare two strings without an early exit on the first differing code unit.
 *
 * Code units rather than UTF-8 bytes: encoding first would map every lone
 * surrogate to U+FFFD and make distinct strings compare equal. The length is
 * not hidden, as with any constant-time comparison of variable-length input.
 */
export declare function timingSafeEqual(a: string, b: string): boolean;
/**
 * True for an object written as `{...}` or made by `Object.create(null)`, in any
 * realm, and for nothing else: its prototype is null, or it is a realm's
 * `Object.prototype`, which has no prototype of its own and whose own
 * `constructor` is that realm's `Object`. An array, a `Date`, a class instance,
 * `Object.create({})` and `Object.create(Object.create(null))` are each refused;
 * the last has a null-prototype prototype, which is not `Object.prototype`.
 */
export declare function isPlainObject(value: unknown): value is Record<string, unknown>;
/** True for a `Uint8Array` of any realm, Node's `Buffer` included, and nothing else. */
export declare function isUint8Array(value: unknown): value is Uint8Array;
/** True for a `Set` of any realm and nothing else. */
export declare function isSet(value: unknown): value is ReadonlySet<unknown>;
/** Own-property read, so an inherited member never stands in for an absent one. */
export declare function own(object: Record<string, unknown>, key: string): unknown;
