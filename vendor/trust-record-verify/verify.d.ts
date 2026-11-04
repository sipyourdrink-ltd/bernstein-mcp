/**
 * `verifyRecord`: verification of a TRACE v0.2 Trust Record with an embedded signature.
 *
 * The checks run in this order, and the first one that fails is the one reported.
 * The order is the Python reference's (`agentrust_trace.verify_record`), so two
 * implementations report the same failure for the same input; where the
 * specification requires a check, the section is named.
 *
 *    1. Options: `invalid_argument` for a malformed option (caller data, not record data).
 *    2. The record is a JSON object: `record_not_object`.
 *    3. Profile, before any cryptographic work. A v0.2 verifier MUST require
 *       `tag:agentrust-io.com,2026:trace-v0.2` and MUST reject the v0.1 identifier
 *       (spec/trace-v0.2.md, "Changes from v0.1"): `profile_missing`,
 *       `profile_superseded`, `profile_unsupported`.
 *    4. The embedded signature is present and decodes as canonical unpadded
 *       base64url (section 3.2.2): `signature_missing`, `signature_malformed`.
 *       Ahead of the schema, as in the reference, so a padded signature or one
 *       in the standard alphabet is reported as the encoding fault it is. The
 *       empty string decodes, to no bytes, and is left to the schema's pattern.
 *    5. The record conforms to the schema: `schema_invalid`, with the location.
 *    6. A trusted key: the caller's, or `cnf.jwk` only when `allowEmbeddedKey` is
 *       set, and it is an Ed25519 key: `trusted_key_missing`,
 *       `trusted_key_unsupported`, `trusted_key_malformed`.
 *    7. Revocation (section 3.2.3), keyed on the trusted key and never on the
 *       record's own `cnf.jwk`: a caller-supplied store, then a bundle.
 *       `key_revoked`, `revocation_unavailable`; any other bundle defect is
 *       reported in the result, not thrown.
 *    8. The confirmation key: `cnf.jwk` is an Ed25519 key with the same RFC 7638
 *       thumbprint as the trusted key, because the binding is a signature made
 *       by the key in `cnf` (section 3.2.2): `cnf_key_unsupported`,
 *       `cnf_key_malformed`, `cnf_key_mismatch`.
 *    9. Freshness (section 3.2.2): `iat_invalid`, `record_in_future` past the
 *       allowed skew, `record_stale` past the maximum age, `nonce_mismatch` when a
 *       challenge nonce was issued.
 *   10. The signature verifies over the RFC 8785 form of the record with
 *       `signature` absent (section 3.2.2): `canonicalization_failed`,
 *       `signature_invalid`.
 */
import { type RevocationCheck } from "./revocation.js";
/** The profile URI this build implements, and the only one `verifyRecord` accepts. */
export declare const TRACE_PROFILE_V0_2 = "tag:agentrust-io.com,2026:trace-v0.2";
/** Every profile this build accepts, reported whole on each result (section 3.3). */
export declare const ACCEPTED_PROFILES: readonly string[];
/**
 * A caller-supplied revocation source: the identifiers of revoked keys, or a
 * lookup returning `true` for a revoked key. An identifier is a key's RFC 7638
 * thumbprint or its `kid`. A lookup that throws, or answers with anything but a
 * boolean, has not answered, and the record is rejected rather than passed.
 */
export type RevocationStore = ReadonlySet<string> | readonly string[] | ((identifier: string) => boolean | Promise<boolean>);
export interface VerifyOptions {
    /** The Ed25519 public key, as a JWK, that the caller trusts to have signed the record. */
    readonly trustedKey?: unknown;
    /**
     * Verify against the record's own `cnf.jwk` when no trusted key is given. That
     * proves the record is internally consistent, not who produced it, and the
     * result reports it as `trustedKeySource: "record"`.
     */
    readonly allowEmbeddedKey?: boolean;
    /** Verification moment in Unix seconds. Defaults to the clock. */
    readonly now?: number;
    /** Maximum record age in seconds. Default 86400 (section 3.2.2); `null` disables the bound. */
    readonly maxAgeSeconds?: number | null;
    /** Tolerated clock skew for `iat` and for a bundle's `issued_at`. Default 300 (section 3.2.2). */
    readonly maxFutureSkewSeconds?: number;
    /** A challenge nonce the record's `runtime.nonce` must echo. */
    readonly expectedNonce?: string;
    readonly revocation?: RevocationStore;
    /**
     * A `TraceRevocationBundle/1.0`, validated here against its schema. Its bundle
     * signature authenticates the statements; a statement's own signature is not
     * checked, and no inclusion entry ID is taken, so a statement naming the trusted
     * key rejects every record that key signed (section 3.2.3's fallback for a record
     * without a usable receipt).
     */
    readonly revocationBundle?: unknown;
    /** JWKs whose signature the caller accepts on a bundle. */
    readonly trustedBundleKeys?: readonly unknown[];
    /** Maximum bundle age in seconds, measured from `issued_at`. Default 86400. */
    readonly maxBundleAgeSeconds?: number;
}
export interface VerificationResult {
    /** The `eat_profile` the record carries, which this verifier accepted. */
    readonly profile: string;
    /** The complete set of profiles this verifier accepts, `ACCEPTED_PROFILES`. */
    readonly acceptedProfiles: readonly string[];
    /** What the revocation check reported. Only `verified` is a revocation check that passed. */
    readonly revocation: RevocationCheck;
    /** RFC 7638 thumbprint of the key the signature was verified against. */
    readonly trustedKeyThumbprint: string;
    /** `caller` for a pinned key, `record` when `allowEmbeddedKey` trusted `cnf.jwk`. */
    readonly trustedKeySource: "caller" | "record";
}
/**
 * Verify a signed TRACE v0.2 Trust Record.
 *
 * Resolves with a `VerificationResult` when the record verifies, and rejects
 * with a `TraceVerificationError` naming the first failed check otherwise. A
 * resolved result still has to be read: its `revocation.outcome` is
 * `no_check_performed` or `unverified_for_revocation` whenever no bundle or store
 * established that the key is unrevoked, and section 3.2.3 forbids treating
 * either as an affirming appraisal.
 */
export declare function verifyRecord(record: unknown, options?: VerifyOptions): Promise<VerificationResult>;
