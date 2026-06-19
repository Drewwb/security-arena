"""Score a results file against corpus ground truth.

Detection is evaluated as binary classification at the sample level:
malicious samples that get flagged are true positives; benign decoys that get
flagged are false positives. We also break recall down per technique and per
ecosystem, which is where scanners actually differ.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .schema import iter_samples


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def score(results_file: Path) -> dict:
    payload = json.loads(results_file.read_text(encoding="utf-8"))
    flagged = {r["sample_id"]: r for r in payload["results"]}
    samples = {s.id: s for s in iter_samples()}

    overall = Metrics()
    by_technique: dict[str, Metrics] = defaultdict(Metrics)
    by_ecosystem: dict[str, Metrics] = defaultdict(Metrics)
    errors: list[str] = []

    for sid, sample in samples.items():
        result = flagged.get(sid)
        if result is None:
            errors.append(f"{sid}: no result (not scanned)")
            continue
        if result.get("error"):
            errors.append(f"{sid}: scan error: {result['error']}")

        is_flagged = bool(result.get("flagged"))
        buckets = [overall, by_technique[sample.technique], by_ecosystem[sample.ecosystem]]
        for m in buckets:
            if sample.malicious and is_flagged:
                m.tp += 1
            elif sample.malicious and not is_flagged:
                m.fn += 1
            elif not sample.malicious and is_flagged:
                m.fp += 1
            else:
                m.tn += 1

    return {
        "adapter": payload.get("adapter"),
        "overall": overall,
        "by_technique": dict(by_technique),
        "by_ecosystem": dict(by_ecosystem),
        "errors": errors,
    }


def format_report(report: dict) -> str:
    o: Metrics = report["overall"]
    lines = []
    lines.append(f"Scorecard - adapter: {report['adapter']}")
    lines.append("=" * 56)
    lines.append(
        f"Overall   TP={o.tp} FP={o.fp} FN={o.fn} TN={o.tn}   "
        f"(n={o.total})"
    )
    lines.append(
        f"          precision={o.precision:.2f}  recall={o.recall:.2f}  f1={o.f1:.2f}"
    )
    lines.append("")
    lines.append(f"{'Technique':<28}{'recall':>8}{'TP':>5}{'FN':>5}{'FP':>5}")
    lines.append("-" * 56)
    for tech, m in sorted(report["by_technique"].items()):
        lines.append(f"{tech:<28}{m.recall:>8.2f}{m.tp:>5}{m.fn:>5}{m.fp:>5}")
    lines.append("")
    lines.append(f"{'Ecosystem':<28}{'recall':>8}{'prec':>8}")
    lines.append("-" * 56)
    for eco, m in sorted(report["by_ecosystem"].items()):
        lines.append(f"{eco:<28}{m.recall:>8.2f}{m.precision:>8.2f}")
    if report["errors"]:
        lines.append("")
        lines.append("Notes:")
        for e in report["errors"]:
            lines.append(f"  - {e}")
    return "\n".join(lines)
