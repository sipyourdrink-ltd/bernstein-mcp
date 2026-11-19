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
import { exceptionName, typeName } from "./citation.js";
import { fail } from "./errors.js";
import { compareCodePoints, isPlainObject, own } from "./text.js";
/**
 * The statuses an appraiser may report for a layer: `established`, or one of the
 * `LayerCause` values, which the module records as `not_established` with that cause.
 */
export const LAYER_STATUSES = Object.freeze([
    "established",
    "layer_not_measured",
    "measured_not_appraised",
    "evidence_spans_multiple_boots",
]);
/** What a result reports when no appraiser was supplied. */
export const NOT_ATTEMPTED = Object.freeze({
    outcome: "not_attempted",
    cause: "no_appraiser",
    evidence: Object.freeze({}),
    layers: Object.freeze({}),
});
const FIELD_ABSENT = Object.freeze({
    outcome: "not_attempted",
    cause: "field_absent",
    evidence: Object.freeze({}),
    layers: Object.freeze({}),
});
function rejected(cause, evidence) {
    return Object.freeze({
        outcome: "appraisal_rejected",
        cause,
        evidence: Object.freeze(evidence),
        layers: Object.freeze({}),
    });
}
function cloneValue(value, seen) {
    if (Array.isArray(value)) {
        if (seen.has(value)) {
            return seen.get(value);
        }
        const copy = [];
        seen.set(value, copy);
        for (const item of value) {
            copy.push(cloneValue(item, seen));
        }
        return copy;
    }
    if (isPlainObject(value)) {
        if (seen.has(value)) {
            return seen.get(value);
        }
        const copy = {};
        seen.set(value, copy);
        for (const key of Object.keys(value)) {
            // Assignment would invoke Object.prototype's legacy __proto__ setter.
            Object.defineProperty(copy, key, {
                value: cloneValue(own(value, key), seen),
                enumerable: true,
                writable: true,
                configurable: true,
            });
        }
        return copy;
    }
    return value;
}
/**
 * Record what `appraiser` reported about the record's `runtime.measurement`.
 *
 * Throws `TraceVerificationError` with `record_not_object` when `record` is not a
 * plain JSON object, or `invalid_argument` when `appraiser` is neither a function,
 * `null`, nor `undefined`. Every appraiser exception, malformed report, or
 * measurement mismatch is recorded as `appraisal_rejected` rather than thrown.
 */
export async function checkPlatformMeasurement(record, appraiser) {
    if (!isPlainObject(record)) {
        fail("record_not_object", "a Trust Record is a JSON object");
    }
    if (appraiser !== undefined && appraiser !== null && typeof appraiser !== "function") {
        fail("invalid_argument", "platformAppraiser must be a function or null");
    }
    if (appraiser === undefined || appraiser === null) {
        return NOT_ATTEMPTED;
    }
    const runtime = own(record, "runtime");
    if (!isPlainObject(runtime)) {
        return FIELD_ABSENT;
    }
    const measurement = own(runtime, "measurement");
    if (typeof measurement !== "string" || measurement === "") {
        return FIELD_ABSENT;
    }
    const runtimeCopy = cloneValue(runtime, new WeakMap());
    let report;
    try {
        report = await appraiser(runtimeCopy);
    }
    catch (err) {
        return rejected("appraiser_raised", {
            measurement,
            exception: exceptionName(err),
        });
    }
    if (!isPlainObject(report)) {
        return rejected("appraiser_returned_invalid", {
            measurement,
            member: "report",
            returned: typeName(report),
        });
    }
    const reportMembers = Object.keys(report).sort(compareCodePoints);
    if (reportMembers.length !== 2 ||
        reportMembers[0] !== "layers" ||
        reportMembers[1] !== "measurement") {
        return rejected("appraiser_returned_invalid", {
            measurement,
            member: "report",
            members: Object.freeze(reportMembers),
        });
    }
    const appraised = own(report, "measurement");
    if (appraised !== measurement) {
        return rejected("measurement_mismatch", {
            measurement,
            appraised: typeof appraised === "string" ? appraised : typeName(appraised),
        });
    }
    const layers = own(report, "layers");
    if (!isPlainObject(layers)) {
        return rejected("appraiser_returned_invalid", {
            measurement,
            member: "layers",
            returned: typeName(layers),
        });
    }
    const layerNames = Object.keys(layers);
    if (layerNames.length === 0) {
        return rejected("appraiser_returned_invalid", {
            measurement,
            member: "layers",
            returned: "empty",
        });
    }
    const checks = {};
    for (const name of layerNames) {
        if (name === "") {
            return rejected("appraiser_returned_invalid", {
                measurement,
                member: "layer name",
                returned: "empty string",
            });
        }
        const status = own(layers, name);
        if (typeof status !== "string" || !LAYER_STATUSES.includes(status)) {
            return rejected("appraiser_returned_invalid", {
                measurement,
                member: "layer status",
                layer: name,
                returned: typeof status === "string" ? status : typeName(status),
            });
        }
        Object.defineProperty(checks, name, {
            value: Object.freeze(status === "established"
                ? { outcome: "established", cause: null }
                : { outcome: "not_established", cause: status }),
            enumerable: true,
        });
    }
    return Object.freeze({
        outcome: "appraised",
        cause: null,
        evidence: Object.freeze({ measurement, layers: layerNames.length }),
        layers: Object.freeze(checks),
    });
}
