#!/usr/bin/env python3
"""Bundle the compliance presets and adapter catalogue into data/*.json.

Runs against the pinned bernstein source in .bernstein-src/ so the Worker
ships exactly the tables the tagged release resolves, with no host paths,
no detection status, nothing environment-dependent.

    .bernstein-src/.venv/bin/python scripts/bundle_data.py
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / ".bernstein-src" / "src"
sys.path.insert(0, str(SRC))

from bernstein.cli.commands.adapter_cmd import _enumerate_adapters  # noqa: E402
from bernstein.core.security.compliance import ComplianceConfig, CompliancePreset  # noqa: E402

TAG = (ROOT / "data" / "bernstein_tag.txt").read_text().strip()


def _jsonable(value: object) -> object:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v) for v in sorted(value, key=str) if not isinstance(value, (list, tuple))] or [
            _jsonable(v) for v in value
        ]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in sorted(value.items())}
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "value") and not isinstance(value, (str, int, float, bool)):
        return _jsonable(value.value)  # enums
    return value


def presets() -> dict[str, object]:
    out: dict[str, object] = {}
    for preset in CompliancePreset:
        cfg = ComplianceConfig.from_preset(preset)
        out[preset.value] = _jsonable(cfg)
    return {"bernstein_version": TAG, "presets": out}


def adapters() -> dict[str, object]:
    rows = []
    for row in _enumerate_adapters():
        # `source` is a host path into the pinned checkout; keep only the
        # dotted module name so the bundle carries no local paths.
        source = str(row.get("source") or "")
        module = source.split("/src/", 1)[1] if "/src/" in source else source
        module = module.removesuffix(".py").replace("/", ".")
        rows.append({"name": row["name"], "binary": row.get("binary") or "", "module": module})
    rows.sort(key=lambda r: r["name"])
    return {"bernstein_version": TAG, "adapters": rows}


def main() -> None:
    data = ROOT / "data"
    for name, payload in (("presets.json", presets()), ("adapters.json", adapters())):
        text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        (data / name).write_text(text)
        print(f"wrote data/{name}")


if __name__ == "__main__":
    main()
