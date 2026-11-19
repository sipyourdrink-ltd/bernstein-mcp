/**
 * Citation-resolution consumer for `verifyRecord` (spec section 3.1.2).
 *
 * A Trust Record cites objects outside itself at `appraisal.policy_ref`,
 * `runtime.rim_uri` and `model.aibom_uri`. This module records, per surface,
 * whether a caller-supplied resolver produced bytes for the cited URI and what
 * those bytes hashed to. It records resolvability and nothing else:
 *
 * - It asserts no binding (held open by agentrust-io/trace-spec#280 and #190).
 * - It never reads `references[]` (section 3.1.2 rule 3).
 * - The resolver is caller-supplied only, never selected or configured from the record.
 * - `transparency` is deferred (coordinated in agentrust-io/trace-tests#92; spec
 *   section 7 open question 3) and reported as `not_attempted` with `surface_deferred`.
 * - It runs last in `verifyRecord`, after signature verification and every check
 *   that can reject, so an unauthenticated record never drives resolution.
 * - It imports no network or platform library.
 */
/** What the resolver did for one cited surface. */
export type CitationOutcome = "resolved" | "unresolvable" | "not_attempted";
/** Why a surface reports anything other than `resolved`. */
export type CitationCause = "no_resolver" | "field_absent" | "surface_deferred" | "resolver_raised" | "resolver_returned_non_bytes";
/**
 * What the resolver did for one surface, and the facts a second run needs.
 * `evidence` is JSON-serializable by construction.
 */
export interface CitationCheck {
    readonly outcome: CitationOutcome;
    readonly cause: CitationCause | null;
    readonly evidence: Readonly<Record<string, unknown>>;
}
/** Caller-supplied citation resolver returning the cited object's bytes. */
export type CitationResolver = (uri: string) => Uint8Array | Promise<Uint8Array>;
/**
 * The citation surfaces, in report order. The second element is the deferral
 * reason for a surface this module does not consume, or `null` for one it does.
 */
export declare const SURFACES: readonly (readonly [string, string | null])[];
/** Extract an exception's class/type name without leaking message text. */
export declare function exceptionName(err: unknown): string;
/** Describe a non-bytes / invalid value's runtime type without leaking content. */
export declare function typeName(value: unknown): string;
/**
 * Report, per surface in `SURFACES` order, whether the cited URI resolved.
 *
 * Throws `TraceVerificationError` with `record_not_object` when `record` is not a
 * plain JSON object, or `invalid_argument` when `resolver` is neither a function,
 * `null`, nor `undefined`. Every resolver failure or non-bytes return value is
 * recorded as `unresolvable` rather than thrown.
 */
export declare function checkCitations(record: unknown, resolver?: CitationResolver | null): Promise<Readonly<Record<string, CitationCheck>>>;
