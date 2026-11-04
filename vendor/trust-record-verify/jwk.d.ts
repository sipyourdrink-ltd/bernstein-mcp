/**
 * RFC 7638 JWK Thumbprints, and the identifiers a revocation source may list a key under.
 */
/**
 * The RFC 7638 thumbprint of *jwk*: base64url SHA-256 of the required members,
 * serialized with RFC 8785 (their names are ASCII, so that is the member order
 * RFC 7638 section 3.3 specifies).
 *
 * Refuses, as `jwk_invalid`, a value that is not an object, an unknown `kty`,
 * and a required member that is absent, empty or not a string.
 */
export declare function jwkThumbprint(jwk: unknown): Promise<string>;
/**
 * Every identifier a revocation store or statement may list *jwk* under: its
 * thumbprint first, then its `kid` when that is a non-empty string different
 * from the thumbprint. Matching either one revokes the key (section 3.2.3).
 */
export declare function keyIdentifiers(jwk: unknown): Promise<string[]>;
