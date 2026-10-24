/**
 * Failure codes and the single error type every rejection is reported with.
 *
 * Each code names one check. The order in which `verifyRecord` runs its checks
 * is documented beside the function and is the order the Python reference uses,
 * so two implementations report the same first failure for the same input.
 */
export declare const FAILURE_CODES: readonly ["invalid_argument", "crypto_unavailable", "record_not_object", "profile_missing", "profile_superseded", "profile_unsupported", "signature_missing", "signature_malformed", "schema_invalid", "trusted_key_missing", "trusted_key_unsupported", "trusted_key_malformed", "revocation_unavailable", "key_revoked", "cnf_key_unsupported", "cnf_key_malformed", "cnf_key_mismatch", "iat_invalid", "record_in_future", "record_stale", "nonce_mismatch", "canonicalization_failed", "signature_invalid", "jwk_invalid", "delegation_absent", "delegation_algorithm_unsupported", "delegation_parent_mismatch"];
export type FailureCode = (typeof FAILURE_CODES)[number];
/**
 * The only error type this package throws.
 *
 * `code` is stable and meant for programs; `message` is for people and may
 * change. `path` is set for `schema_invalid` and names the location of the
 * reported violation in the form the Python reference prints it: property names
 * and array indexes joined with dots, or `<record>` for the record itself.
 */
export declare class TraceVerificationError extends Error {
    readonly code: FailureCode;
    readonly path: string | undefined;
    constructor(code: FailureCode, message: string, options?: {
        path?: string;
        cause?: unknown;
    });
}
export declare function fail(code: FailureCode, message: string, options?: {
    path?: string;
    cause?: unknown;
}): never;
