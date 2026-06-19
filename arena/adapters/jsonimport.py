"""Zero-coupling adapter: ingest findings your scanner produced out-of-band.

You run your scanner however you like, export results as JSON keyed by sample id, then:

    python -m arena run --adapter jsonimport --config findings=path/to/findings.json

Expected JSON shape (a flat object keyed by sample id):

    {
      "npm-typosquat-001": {"flagged": true,  "score": 0.9,
                            "findings": [{"type": "typosquatting"}]},
      "npm-benign-postinstall-001": {"flagged": false, "score": 0.1}
    }

Only `flagged` is required per entry. Missing samples are treated as not-flagged.
This path runs nothing automatically, which sidesteps any tool-ToS concerns about
automated execution.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..schema import Sample
from .base import Adapter, ScanResult


class JsonImportAdapter(Adapter):
    name = "jsonimport"

    def __init__(self, config=None):
        super().__init__(config)
        self._data: dict | None = None

    def _load(self) -> dict:
        if self._data is not None:
            return self._data
        path = self.config.get("findings")
        if not path:
            raise ValueError(
                "jsonimport requires --config findings=<path/to/findings.json>"
            )
        self._data = json.loads(Path(path).read_text(encoding="utf-8"))
        return self._data

    def available(self) -> bool:
        return bool(self.config.get("findings"))

    def scan(self, sample: Sample) -> ScanResult:
        try:
            data = self._load()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return ScanResult(sample_id=sample.id, flagged=False, error=str(exc))

        entry = data.get(sample.id, {})
        return ScanResult(
            sample_id=sample.id,
            flagged=bool(entry.get("flagged", False)),
            score=float(entry.get("score", 0.0)),
            findings=entry.get("findings", []),
            raw=entry,
        )
