/**
 * WebCrypto access. Nothing here reaches the network or any module outside the
 * platform: the verifier runs wherever `globalThis.crypto.subtle` exists, which
 * covers current browsers, Node.js 20 and later, Deno, Bun and edge workers.
 */
/** A short, never-throwing description of an untrusted value for an error message. */
export declare function show(value: unknown): string;
export declare function digest(algorithm: "SHA-256" | "SHA-384", data: Uint8Array): Promise<Uint8Array>;
export declare function hex(bytes: Uint8Array): string;
/**
 * Import an Ed25519 public key from a JWK, refusing every other key type.
 *
 * `role` selects which failure codes a refusal carries, so the caller learns
 * whether the trusted key or the record's own `cnf.jwk` was at fault. The
 * checks and their order follow the reference: `kty`, then `crv`, then the
 * presence of `x`, then its encoding, then its length.
 */
export declare function importEd25519(jwk: unknown, role: "trusted_key" | "cnf_key" | "bundle_key"): Promise<CryptoKey>;
/** Ed25519 verification. Any refusal by the platform counts as a signature that does not verify. */
export declare function verifyEd25519(key: CryptoKey, signature: Uint8Array, message: Uint8Array): Promise<boolean>;
