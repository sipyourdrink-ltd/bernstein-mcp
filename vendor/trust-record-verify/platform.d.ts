/**
 * Platform-measurement consumer for `verifyRecord` (the platform-measurement row
 * of agentrust-io/trace-spec#279, raised in agentrust-io/trace-spec#431).
 *
 * A Trust Record carries `runtime.platform` and `runtime.measurement`. This module
 * records what a caller-supplied appraiser reported about the measurement the
 * record carries, per layer, and nothing else:
 *
 * - Every layer outcome is the appraiser's report, carried as reported.
 * - The appraiser is caller-supplied only, never selected from the record.
 * - The appraiser receives a deep copy of `record.runtime` and cannot mutate the record.
 * - A report whose `measurement` differs from `runtime.measurement` is rejected with
 *   `appraisal_rejected` and cause `measurement_mismatch`.
 * - `not_attempted` is distinct from `appraised`; no outcome or layer outcome is a
 *   pass-like value or an `appraisal.status`.
 * - It runs last in `verifyRecord`, after signature verification and every check
 *   that can reject.
 */
/** What happened to the measurement as a whole. */
export type PlatformOutcome = "appraised" | "appraisal_rejected" | "not_attempted";
/** Why the measurement reports anything other than `appraised`. */
export type PlatformCause = "no_appraiser" | "field_absent" | "appraiser_raised" | "appraiser_returned_invalid" | "measurement_mismatch";
/** What the appraiser reported for one layer. */
export type LayerOutcome = "established" | "not_established";
/** Why a layer is `not_established`. */
export type LayerCause = "layer_not_measured" | "measured_not_appraised" | "evidence_spans_multiple_boots";
/** The statuses an appraiser may report for a layer. */
export type LayerStatus = "established" | LayerCause;
/**
 * The statuses an appraiser may report for a layer: `established`, or one of the
 * `LayerCause` values, which the module records as `not_established` with that cause.
 */
export declare const LAYER_STATUSES: readonly LayerStatus[];
/** The appraiser's report for one layer. */
export interface LayerCheck {
    readonly outcome: LayerOutcome;
    readonly cause: LayerCause | null;
}
/**
 * What the appraiser reported about `runtime.measurement`.
 *
 * `layers` is keyed by the appraiser's own layer names and is empty unless
 * `outcome` is `appraised`. `evidence` is JSON-serializable by construction.
 */
export interface PlatformMeasurementCheck {
    readonly outcome: PlatformOutcome;
    readonly cause: PlatformCause | null;
    readonly evidence: Readonly<Record<string, unknown>>;
    readonly layers: Readonly<Record<string, LayerCheck>>;
}
/** Caller-supplied platform measurement appraiser. */
export type PlatformAppraiser = (runtime: Record<string, unknown>) => unknown | Promise<unknown>;
/** What a result reports when no appraiser was supplied. */
export declare const NOT_ATTEMPTED: PlatformMeasurementCheck;
/**
 * Record what `appraiser` reported about the record's `runtime.measurement`.
 *
 * Throws `TraceVerificationError` with `record_not_object` when `record` is not a
 * plain JSON object, or `invalid_argument` when `appraiser` is neither a function,
 * `null`, nor `undefined`. Every appraiser exception, malformed report, or
 * measurement mismatch is recorded as `appraisal_rejected` rather than thrown.
 */
export declare function checkPlatformMeasurement(record: unknown, appraiser?: PlatformAppraiser | null): Promise<PlatformMeasurementCheck>;
