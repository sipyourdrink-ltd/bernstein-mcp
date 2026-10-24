/**
 * Revocation-bundle consumer for section 3.2.3.
 *
 * Section 3.2.3 separates three states a verifier reports: verified against a
 * bundle valid at T; unverified for revocation, because the bundle cannot ground
 * that answer; and no revocation check performed, because there was no bundle.
 * It forbids reporting either of the last two as an affirming appraisal. Those
 * three states are the three values of `RevocationCheck.outcome`, and nothing
 * here sets or names an appraisal status.
 *
 * The checks run in a fixed order, and the order is part of the result: a bundle
 * that fails a step is not read further, so `cause` names the first thing wrong.
 *
 *   1. Shape, against the bundle schema and the statement schema it refers to.
 *   2. One log per bundle: every statement names the bundle's `log_id`.
 *   3. Who signed the set: an `ed25519` signature by a key the caller trusts,
 *      over the RFC 8785 form of the bundle with `sig` absent.
 *   4. What the set says about this key. A statement naming it rejects the
 *      record, whatever the bundle's age: the statement was authenticated with
 *      the bundle, and section 3.2.3 gives a statement no expiry.
 *   5. Whether the set was issued in the future, beyond the allowed clock skew.
 *   6. Whether the set is still evidence for what it does not say: both the
 *      issuer's `valid_until` and the caller's maximum age hold, the tighter one
 *      governing, inclusive on the valid side.
 *
 * No inclusion entry ID reaches this function, so a statement naming the key
 * applies section 3.2.3's fallback for records without a usable receipt: every
 * record the key signed is rejected. Statement-level signatures are not checked;
 * the bundle signature authenticates the set.
 */
export type RevocationOutcome = "verified" | "unverified_for_revocation" | "no_check_performed";
export type RevocationCause = "bundle_expired" | "bundle_malformed" | "bundle_key_untrusted" | "bundle_signature_invalid" | "bundle_signature_unsupported" | "bundle_issued_in_future";
/**
 * What the revocation check reported, with the facts a second verifier needs to
 * reach the same outcome from retained data alone. `evidence` is plain JSON.
 */
export interface RevocationCheck {
    readonly outcome: RevocationOutcome;
    readonly cause: RevocationCause | null;
    readonly evidence: Readonly<Record<string, unknown>>;
}
export declare const NO_CHECK: RevocationCheck;
export interface BundleCheckOptions {
    /** Identifiers of the key the record is verified against: thumbprint first, then `kid`. */
    readonly trustedKeyIdentifiers: readonly string[];
    /** JWKs whose signature the caller accepts on a bundle. */
    readonly trustedBundleKeys: readonly unknown[];
    /** Verification moment, Unix seconds. */
    readonly now: number;
    readonly maxBundleAgeSeconds: number;
    readonly maxFutureSkewSeconds: number;
}
/** The bundle's identity: `sha256:` and the hex SHA-256 of its RFC 8785 form, signature included. */
export declare function bundleDigest(bundle: unknown): Promise<string>;
/**
 * Decide what *bundle* lets a verifier report about the trusted record key.
 *
 * Returns a `RevocationCheck`. Throws `key_revoked` when a statement on the
 * bundle's log names the key, and `invalid_argument` when a trusted bundle key
 * the search reaches has no thumbprint. Every other defect in the bundle is an
 * outcome, not an exception: inability to check is not evidence of a defect.
 */
export declare function checkRevocationBundle(bundle: unknown, options: BundleCheckOptions): Promise<RevocationCheck>;
