/**
 * base64url without padding (RFC 4648 section 5), decoded strictly.
 *
 * Section 3.2.2 carries an embedded signature as "base64url, no padding", and
 * RFC 7515 section 2 defines the same form for JWK members. A value is accepted
 * only in that form: characters from the URL-safe alphabet, no `=` padding, no
 * whitespace, a length that is not 1 more than a multiple of 4, and unused
 * trailing bits set to zero (RFC 4648 section 3.5). The last rule makes the
 * encoding canonical, so one byte string has exactly one accepted spelling.
 */
/** Why a value was refused, or `null` for a well-formed value. */
export declare function base64urlProblem(value: unknown): string | null;
/** Decode *value*, or return `null` when it is not canonical unpadded base64url. */
export declare function decodeBase64url(value: unknown): Uint8Array | null;
/** Encode *bytes* as unpadded base64url. */
export declare function encodeBase64url(bytes: Uint8Array): string;
