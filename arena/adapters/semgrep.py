"""Example CLI adapter: Semgrep.

Demonstrates the typical pattern — run a scanner CLI that emits JSON, then map its
output onto the normalized ScanResult. Requires `semgrep` on PATH. By default it uses
Semgrep's registry "auto" config; point it at custom rules with:

    python -m arena run --adapter semgrep --config rules=p/supply-chain
"""

from __future__ import annotations

import json
import shutil
import subprocess

from ..schema import Sample
from .base import Adapter, ScanResult


class SemgrepAdapter(Adapter):
    name = "semgrep"

    def available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(self, sample: Sample) -> ScanResult:
        rules = self.config.get("rules", "auto")
        cmd = [
            "semgrep",
            "--config", rules,
            "--json",
            "--quiet",
            "--metrics", "off",
            str(sample.package_dir),
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=180, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ScanResult(sample_id=sample.id, flagged=False, error=str(exc))

        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            return ScanResult(
                sample_id=sample.id, flagged=False,
                error=f"could not parse semgrep output: {exc}",
                raw=proc.stdout,
            )

        results = payload.get("results", [])
        findings = [
            {
                "type": r.get("check_id", "unknown"),
                "severity": r.get("extra", {}).get("severity", "INFO"),
                "path": r.get("path"),
                "line": r.get("start", {}).get("line"),
            }
            for r in results
        ]
        return ScanResult(
            sample_id=sample.id,
            flagged=len(results) > 0,
            score=min(1.0, len(results) / 3.0),
            findings=findings,
            raw=payload,
        )
