#!/usr/bin/env python3
"""Golden-vector generator for the run-receipt verifier.

Runs against the pinned bernstein source tree checked out at
``../.bernstein-src`` (tag v3.19.2) and writes ``../vectors/*.json``.

    cd .bernstein-src \
      && uv run python ../scripts/gen_vectors.py

Every vector is byte-deterministic: fixed Ed25519 seed (RFC 8032 signatures
are deterministic), fixed HMAC key for the opt-in audit range, and a frozen
audit clock. Journal wall-clock fields (``ts`` / ``elapsed_s``) never enter
a receipt, so the journal needs no clock freeze.

Vector schema::

    {
      "name": str,
      "input": <run receipt dict, exactly what verify_run_receipt parses>,
      "expected": {
        "verdict": "valid" | "invalid" | "unverifiable",
        "failing_check": <check name> | null,
        "checks": [{"name", "outcome": "ok"|"fail"|"unverifiable"|"skipped", "detail"}],
        "python_status": <verify_run_receipt().status>,
        "python_errors": [...],
        "divergent_step": int | null
      },
      "canonical": {
        "receipt_sha256":          sha256 over canonical JSON of input + "\n" (== RunReceipt.sha256)
        "receipt_canonical_sha256": sha256 over canonical JSON of input (no newline)
        "binding_block":           the exact dict that is signed (rebuilt from recomputed heads)
        "binding_bytes_b64":       canonical bytes of binding_block (py-json-v1 profile)
        "binding_bytes_sha256":    == input.subject.digest.sha256 for a valid receipt
        "pae_sha256":              sha256 of the DSSE PAE that the Ed25519 signature covers
        "journal_rows":            [{"index", "payload_hash", "event_hash"}] per embedded row
        "spine_rows":              [{"index", "entry_hash"}] per embedded entry
      },
      "notes": str
    }

``checks`` is the ordered check list a secret-less verifier runs. The
``audit_range_hmac`` check is always ``unverifiable`` because it needs the
producing install's HMAC key; every other check is keyless.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SRC = ROOT / ".bernstein-src"
OUT = ROOT / "vectors"

import bernstein  # noqa: E402

_loaded_from = Path(bernstein.__file__).resolve()
if SRC.resolve() not in _loaded_from.parents:
    sys.exit(f"refusing: bernstein imported from {_loaded_from}, expected under {SRC}")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import bernstein.core.security.audit as audit_mod  # noqa: E402
from bernstein.core.lineage.spine import LineageSpine  # noqa: E402
from bernstein.core.replay.journal import EventJournal, verify_events  # noqa: E402
from bernstein.core.replay.run_receipt import (  # noqa: E402
    RUN_RECEIPT_PAYLOAD_TYPE,
    _binding_block,
    _canonical_json_bytes,
    _extract_endpoint_identities,
    _walk_spine_rows,
    build_run_receipt,
    verify_run_receipt,
)
from bernstein.core.security.audit import AuditLog  # noqa: E402
from bernstein.core.security.audit_dsse import pae  # noqa: E402
from bernstein.core.security.audit_multitenant import _events_jsonl_bytes  # noqa: E402
from bernstein.core.security.lineage_kms import FileBasedKMSAdapter  # noqa: E402
from bernstein.core.security.loaded_extension_set import extension_set_digest_from_events  # noqa: E402

SIGN_SEED = b"mcp-spike-v3.19.2-2026-09-18-xyz"  # 32 bytes, fixed so signatures are reproducible
assert len(SIGN_SEED) == 32
HMAC_KEY = b"golden-vector-hmac-key-not-secret"  # build-time only; never needed to verify
KID = "bernstein-mcp-golden-2026-09-18"
AUDIT_SINCE = "2026-01-01T00:00:00.000000Z"
AUDIT_UNTIL = "2026-01-02T00:00:00.000000Z"


# ---------------------------------------------------------------------------
# Deterministic clock for the audit log (the only wall-clock that enters a receipt)
# ---------------------------------------------------------------------------


class _FrozenDatetime(datetime):
    _tick = 0

    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        cls._tick += 1
        return datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC).replace(second=cls._tick % 60, minute=cls._tick // 60)


audit_mod.datetime = _FrozenDatetime  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Run seeding
# ---------------------------------------------------------------------------


def _write_key(path: Path) -> None:
    key = Ed25519PrivateKey.from_private_bytes(SIGN_SEED)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _public_pem() -> str:
    key = Ed25519PrivateKey.from_private_bytes(SIGN_SEED)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def _seed_run(sdd: Path, run_id: str, n_journal: int, n_spine: int, *, stress_payloads: bool) -> None:
    journal = EventJournal(run_id=run_id, sdd_dir=sdd)
    journal.record("run_started", run_id=run_id, plan="plan.md")
    body = n_journal - 2
    for i in range(body):
        kind = i % 5
        if kind == 0:
            journal.record("task_claimed", task_id=f"T-{i}", role="backend", attempt=i % 3)
        elif kind == 1:
            journal.record(
                "dispatch_knob_selection",
                task_id=f"T-{i}",
                run_id=run_id,
                effort="medium",
                lane="fast",
                cache_strategy="ephemeral",
                rate_multiplier=1.0 if not stress_payloads else [1.0, 0.5, 1e-05, 1e16, 2.5, 1e21, -0.0, 123456789.125][i % 8],
                resolved=True,
                reason="default",
            )
        elif kind == 2:
            data: dict[str, Any] = {"task_id": f"T-{i}", "status": "ok", "files": [f"src/m{i}.py"]}
            if stress_payloads:
                data["summary"] = ["тест", "🚀 emoji", "tab\tnl\n", 'quote"back\\', " sep", "ascii"][i % 6]
                data["nested"] = {"z": None, "a": [True, False, {"b": i}], "é": "ünïcode"}
            journal.record("task_completed", **data)
        elif kind == 3:
            journal.record("agent_spawned", task_id=f"T-{i}", endpoint_adapter_name="claude", endpoint_model="m1",
                           endpoint_base_url="", endpoint_profile_name="")
        else:
            journal.record("message", task_id=f"T-{i}", body=f"note {i}")
    journal.record("run_completed", run_id=run_id, ticks=n_journal)

    spine = LineageSpine(sdd / "lineage", run_id=run_id, hmac_key=HMAC_KEY)
    for i in range(n_spine):
        path = f"src/mod_{i}.py" if not (stress_payloads and i == 0) else "src/юникод_🚀.py"
        spine.record(
            artifact_path=path,
            content=f"# artefact {i}\n".encode(),
            actor="backend" if i % 2 == 0 else "qa",
            step_id=f"T-{i}",
            model="m1",
            timestamp=1000 + i,
        )


def _seed_audit(sdd: Path) -> None:
    audit_dir = sdd / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    log = AuditLog(audit_dir, key=HMAC_KEY)
    log.log("task.created", "alice", "task", "T-1", {"role": "backend"})
    log.log("task.completed", "alice", "task", "T-1", {"status": "ok", "note": "юникод"})


def _build(tmp: Path, name: str, n_journal: int, n_spine: int, *, audit: bool, stress: bool) -> dict[str, Any]:
    sdd = tmp / name / ".sdd"
    run_id = f"golden-{name}"
    _seed_run(sdd, run_id, n_journal, n_spine, stress_payloads=stress)
    key_path = tmp / name / "sign.pem"
    _write_key(key_path)
    kms = FileBasedKMSAdapter(key_path, kid=KID)
    kwargs: dict[str, Any] = {}
    if audit:
        _seed_audit(sdd)
        kwargs = dict(include_audit_range=True, audit_hmac_key=HMAC_KEY, audit_since=AUDIT_SINCE, audit_until=AUDIT_UNTIL)
    built = build_run_receipt(run_id, sdd, kms, write=False, **kwargs)
    return json.loads(built.receipt_bytes)


# ---------------------------------------------------------------------------
# Secret-less check list (mirrors verify_run_receipt order, adds the audit linkage split)
# ---------------------------------------------------------------------------

CHECK_ORDER = [
    "schema",
    "journal_chain",
    "journal_head",
    "spine_chain",
    "spine_head",
    "audit_range_head",
    "audit_range_linkage",
    "audit_range_hmac",
    "subject_binding",
    "signature",
]


def _checks_for(receipt: dict[str, Any]) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Run the keyless checks one by one so a vector names the first failure precisely."""
    checks: list[dict[str, str]] = []
    canonical: dict[str, Any] = {}

    def add(name: str, outcome: str, detail: str = "") -> None:
        checks.append({"name": name, "outcome": outcome, "detail": detail})

    # schema
    try:
        events = receipt["journal"]["events"]
        entries = receipt["spine"]["entries"]
        signing = receipt["signing"]
        assert isinstance(events, list) and events and isinstance(entries, list) and isinstance(signing, dict)
        add("schema", "ok")
    except Exception as exc:  # noqa: BLE001
        add("schema", "fail", f"{type(exc).__name__}: {exc}")
        return checks, canonical

    # journal
    jr = verify_events(events)
    if jr.chain_consistent:
        add("journal_chain", "ok", f"{len(events)} rows")
    else:
        add("journal_chain", "fail", f"step {jr.divergent_index}: {'; '.join(jr.errors)}")
    journal_head = str(events[-1].get("event_hash", ""))
    if receipt["journal"].get("head_hash") == journal_head and receipt["journal"].get("event_count") == len(events):
        add("journal_head", "ok")
    else:
        add("journal_head", "fail", "head_hash/event_count do not match embedded rows")

    # spine
    spine_head, div, err = _walk_spine_rows(entries)
    if div is None:
        add("spine_chain", "ok", f"{len(entries)} entries")
    else:
        add("spine_chain", "fail", err)
    if receipt["spine"].get("head_hash") == spine_head and receipt["spine"].get("entry_count") == len(entries):
        add("spine_head", "ok")
    else:
        add("spine_head", "fail", "head_hash/entry_count do not match embedded entries")

    # audit range (opt-in)
    audit = receipt.get("audit_range")
    audit_head = None
    if audit is None:
        add("audit_range_head", "skipped", "no audit_range block")
        add("audit_range_linkage", "skipped", "no audit_range block")
        add("audit_range_hmac", "skipped", "no audit_range block")
    else:
        aev = audit["events"]
        recomputed = hashlib.sha256(_events_jsonl_bytes(aev)).hexdigest()
        if audit.get("head_sha256") == recomputed and audit.get("event_count") == len(aev):
            add("audit_range_head", "ok")
        else:
            add("audit_range_head", "fail", "head_sha256/event_count do not match embedded events")
        audit_head = recomputed
        prev = "0" * 64
        link_ok = True
        for i, e in enumerate(aev):
            if e.get("prev_hmac") != prev:
                link_ok = False
                add("audit_range_linkage", "fail", f"event {i}: prev_hmac != prior hmac")
                break
            prev = str(e.get("hmac", ""))
        if link_ok:
            if audit.get("head_hmac") == prev:
                add("audit_range_linkage", "ok", "prev_hmac chain + head_hmac consistent")
            else:
                add("audit_range_linkage", "fail", "head_hmac != last event hmac")
        add("audit_range_hmac", "unverifiable", "HMAC-SHA256 keyed by the producing install; no key here")

    # subject binding (rebuilt from recomputed values, exactly like verify_run_receipt)
    schema_version = str(receipt.get("schema_version"))
    hash_profile = str(receipt.get("hash_profile", "py-json-v1"))
    ep = _extract_endpoint_identities(events)
    binding = _binding_block(
        run_id=str(receipt.get("run_id", "")),
        journal_head=journal_head,
        journal_count=len(events),
        spine_head=spine_head,
        spine_count=len(entries),
        audit_head_sha256=audit_head,
        endpoint_identities=ep or None,
        extension_set_digest=extension_set_digest_from_events(events),
        audit_since=audit.get("since") if audit else None,
        audit_until=audit.get("until") if audit else None,
        audit_event_count=audit.get("event_count") if audit else None,
        audit_head_hmac=audit.get("head_hmac") if audit else None,
        schema_version=schema_version,
        hash_profile=hash_profile,
    )
    binding_bytes = _canonical_json_bytes(binding)
    subject = hashlib.sha256(binding_bytes).hexdigest()
    stated = str(receipt.get("subject", {}).get("digest", {}).get("sha256", ""))
    if stated == subject:
        add("subject_binding", "ok")
    else:
        add("subject_binding", "fail", f"stated {stated[:16]} != recomputed {subject[:16]}")

    preimage = pae(RUN_RECEIPT_PAYLOAD_TYPE, binding_bytes)
    canonical.update(
        {
            "binding_block": binding,
            "binding_bytes_b64": base64.b64encode(binding_bytes).decode("ascii"),
            "binding_bytes_sha256": subject,
            "pae_sha256": hashlib.sha256(preimage).hexdigest(),
            "journal_rows": [
                {"index": i, "payload_hash": r.get("payload_hash"), "event_hash": r.get("event_hash")}
                for i, r in enumerate(events)
            ],
            "spine_rows": [{"index": i, "entry_hash": r.get("entry_hash")} for i, r in enumerate(entries)],
        }
    )

    # signature
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        jwk = signing["public_key_jwk"]
        x = jwk["x"]
        raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
        pub = Ed25519PublicKey.from_public_bytes(raw)
        sig = base64.b64decode(signing["signature_b64"], validate=True)
        pub.verify(sig, preimage)
        add("signature", "ok", "Ed25519 over DSSE PAE(binding) with embedded JWK (trust-on-first-use)")
    except InvalidSignature:
        add("signature", "fail", "Ed25519 signature does not verify over the recomputed binding")
    except Exception as exc:  # noqa: BLE001
        add("signature", "fail", f"{type(exc).__name__}: {exc}")
    return checks, canonical


def _expected(receipt: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    checks, canonical = _checks_for(receipt)
    failing = next((c["name"] for c in checks if c["outcome"] == "fail"), None)
    verdict = "invalid" if failing else "valid"
    py = verify_run_receipt(_canonical_json_bytes(receipt) + b"\n")
    if (py.ok and verdict != "valid") or (not py.ok and verdict != "invalid"):
        raise SystemExit(f"check list disagrees with verify_run_receipt: {verdict} vs {py.status} {py.errors}")
    expected = {
        "verdict": verdict,
        "failing_check": failing,
        "checks": checks,
        "python_status": py.status,
        "python_errors": list(py.errors),
        "divergent_step": py.divergent_step,
    }
    canonical["receipt_canonical_sha256"] = hashlib.sha256(_canonical_json_bytes(receipt)).hexdigest()
    canonical["receipt_sha256"] = hashlib.sha256(_canonical_json_bytes(receipt) + b"\n").hexdigest()
    return expected, canonical


def _emit(name: str, receipt: dict[str, Any], notes: str) -> None:
    expected, canonical = _expected(receipt)
    doc = {"name": name, "input": receipt, "expected": expected, "canonical": canonical, "notes": notes}
    path = OUT / f"{name}.json"
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=False) + "\n", encoding="utf-8")
    size = len(_canonical_json_bytes(receipt))
    print(f"{name:32s} verdict={expected['verdict']:8s} failing={expected['failing_check']!s:20s} "
          f"journal={len(receipt['journal']['events'])} spine={len(receipt['spine']['entries'])} "
          f"receipt_bytes={size}")


# ---------------------------------------------------------------------------
# Corruptions (all derived from the 100-row vector)
# ---------------------------------------------------------------------------


def _corrupt_entry(r: dict[str, Any]) -> dict[str, Any]:
    r = copy.deepcopy(r)
    row = r["journal"]["events"][len(r["journal"]["events"]) // 2]
    # flip a decision-payload field; chain fields left as recorded
    key = next(k for k in row if k not in {"event", "index", "prev_hash", "payload_hash", "event_hash"})
    row[key] = f"{row[key]}-tampered" if isinstance(row[key], str) else 424242
    return r


def _corrupt_linkage(r: dict[str, Any]) -> dict[str, Any]:
    r = copy.deepcopy(r)
    row = r["journal"]["events"][10]
    row["prev_hash"] = "0" * 64
    return r


def _corrupt_signature(r: dict[str, Any]) -> dict[str, Any]:
    r = copy.deepcopy(r)
    sig = bytearray(base64.b64decode(r["signing"]["signature_b64"]))
    sig[0] ^= 0x01
    r["signing"]["signature_b64"] = base64.b64encode(bytes(sig)).decode("ascii")
    return r


def _corrupt_reorder(r: dict[str, Any]) -> dict[str, Any]:
    r = copy.deepcopy(r)
    ev = r["journal"]["events"]
    ev[20], ev[21] = ev[21], ev[20]
    return r


def _corrupt_truncate(r: dict[str, Any]) -> dict[str, Any]:
    r = copy.deepcopy(r)
    # drop the last journal row but leave head_hash / event_count as signed
    r["journal"]["events"].pop()
    return r


# ---------------------------------------------------------------------------
# CPU timing
# ---------------------------------------------------------------------------


def _time_verify(receipt: dict[str, Any], runs: int = 3) -> dict[str, Any]:
    raw = _canonical_json_bytes(receipt) + b"\n"
    total: list[float] = []
    parse: list[float] = []
    journal: list[float] = []
    for _ in range(runs):
        t0 = time.perf_counter()
        res = verify_run_receipt(raw)
        total.append(time.perf_counter() - t0)
        assert res.ok, res.errors
        t0 = time.perf_counter()
        doc = json.loads(raw)
        parse.append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        verify_events(doc["journal"]["events"])
        journal.append(time.perf_counter() - t0)
    return {
        "runs": runs,
        "receipt_bytes": len(raw),
        "journal_events": len(receipt["journal"]["events"]),
        "spine_entries": len(receipt["spine"]["entries"]),
        "verify_total_ms": [round(t * 1000, 2) for t in total],
        "verify_total_median_ms": round(statistics.median(total) * 1000, 2),
        "json_parse_median_ms": round(statistics.median(parse) * 1000, 2),
        "journal_walk_median_ms": round(statistics.median(journal) * 1000, 2),
        "ed25519_verifications": 1,
        "sha256_calls_approx": 2 * len(receipt["journal"]["events"]) + len(receipt["spine"]["entries"]) + 2,
    }


def main() -> None:
    import tempfile

    OUT.mkdir(parents=True, exist_ok=True)
    for stale in OUT.glob("*.json"):
        stale.unlink()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        short = _build(tmp, "short", 3, 2, audit=True, stress=False)
        hundred = _build(tmp, "100", 100, 10, audit=False, stress=True)
        big = _build(tmp, "10000", 10_000, 100, audit=False, stress=False)

    pub = _public_pem()
    common = (
        "Signed with a fixed Ed25519 seed (kid %s); the public key is embedded in "
        "input.signing.public_key_jwk and duplicated as PEM in notes_public_key_pem. "
        "Verification needs no secret: journal + spine heads recompute from the embedded rows, "
        "the subject binding is rebuilt from recomputed heads, then one Ed25519 verify over "
        "DSSE PAE('application/vnd.bernstein.run-receipt+json', binding_bytes)." % KID
    )
    _emit("valid-short-with-audit-range", short,
          common + " Includes the opt-in audit_range: head_sha256 and prev_hmac linkage are keyless, "
          "the HMAC values themselves are unverifiable without the install key.")
    _emit("valid-100-stress-canonicalization", hundred,
          common + " Payloads carry non-ASCII strings, control chars, U+2028, nested objects, null/bool, "
          "and floats (1.0, 0.5, 1e-05, 1e16, 2.5, 1e21, -0.0, 123456789.125) so a port must reproduce "
          "Python json.dumps(sort_keys=True, separators=(',',':')) with ensure_ascii=True and float repr.")
    _emit("valid-10000", big, common + " 10 000 journal rows + 100 spine entries; CPU benchmark input.")
    _emit("invalid-entry-tampered", _corrupt_entry(hundred),
          "Decision payload of journal row 50 mutated; payload_hash no longer recomputes.")
    _emit("invalid-linkage-break", _corrupt_linkage(hundred),
          "prev_hash of journal row 10 replaced by zeros; chain link breaks at step 10.")
    _emit("invalid-bad-signature", _corrupt_signature(hundred),
          "First byte of signature_b64 flipped; every hash recomputes, only the Ed25519 check fails.")
    _emit("invalid-reordered", _corrupt_reorder(hundred),
          "Journal rows 20 and 21 swapped; prev_hash link breaks at step 20.")
    _emit("invalid-truncated", _corrupt_truncate(hundred),
          "Last journal row dropped while head_hash/event_count stay as signed; prefix chains cleanly, head mismatch.")

    (OUT / "public_key.pem").write_text(pub, encoding="utf-8")
    timing = _time_verify(big)
    (OUT / "cpu_timing.json").write_text(json.dumps(timing, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(timing, indent=1))


if __name__ == "__main__":
    main()
