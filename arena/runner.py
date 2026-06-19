"""Run an adapter across the corpus and persist normalized results."""

from __future__ import annotations

import dataclasses
import json
import time
from pathlib import Path

from .adapters import get_adapter
from .schema import REPO_ROOT, Sample, iter_samples

RESULTS_DIR = REPO_ROOT / "results"


def run(
    adapter_name: str,
    config: dict[str, str] | None = None,
    ecosystem: str | None = None,
) -> Path:
    adapter = get_adapter(adapter_name, config)
    if not adapter.available():
        raise RuntimeError(
            f"adapter '{adapter_name}' is not available in this environment "
            f"(missing tool or required --config)."
        )

    samples = iter_samples(ecosystem)
    if not samples:
        raise RuntimeError("no samples found in corpus/")

    records = []
    for sample in samples:
        result = adapter.scan(sample)
        records.append(dataclasses.asdict(result))
        status = "ERROR" if result.error else ("FLAG" if result.flagged else "ok")
        print(f"  [{status:>5}] {sample.id}")

    RESULTS_DIR.mkdir(exist_ok=True)
    run_id = time.strftime("%Y%m%d-%H%M%S")
    out = RESULTS_DIR / f"{adapter_name}-{run_id}.json"
    out.write_text(
        json.dumps(
            {"adapter": adapter_name, "config": config or {}, "results": records},
            indent=2,
        ),
        encoding="utf-8",
    )
    return out


def latest_results(adapter_name: str) -> Path | None:
    if not RESULTS_DIR.is_dir():
        return None
    runs = sorted(RESULTS_DIR.glob(f"{adapter_name}-*.json"))
    return runs[-1] if runs else None
