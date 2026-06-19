"""Manifest schema, loading, and validation for corpus samples."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import CANARY

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "corpus"
TAXONOMY_FILE = REPO_ROOT / "taxonomy" / "techniques.yaml"

VALID_ECOSYSTEMS = {"npm", "pypi"}
REQUIRED_FIELDS = {"id", "ecosystem", "name", "malicious", "technique", "description"}


@dataclass
class Sample:
    """A single corpus sample, loaded from its manifest.yaml."""

    id: str
    ecosystem: str
    name: str          # the (fake) package name as it would be published
    malicious: bool
    technique: str
    description: str
    path: Path         # directory containing the sample
    version: str = "0.0.0"
    severity: str = "medium"
    expected_findings: list[dict[str, Any]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    canary: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def package_dir(self) -> Path:
        """Directory holding the actual package files a scanner should inspect."""
        pkg = self.path / "package"
        return pkg if pkg.is_dir() else self.path


def load_taxonomy() -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(TAXONOMY_FILE.read_text(encoding="utf-8"))
    return {t["id"]: t for t in data.get("techniques", [])}


def load_sample(manifest_path: Path) -> Sample:
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    known = {f.name for f in dataclasses.fields(Sample)} - {"path", "raw"}
    kwargs = {k: v for k, v in data.items() if k in known}
    return Sample(path=manifest_path.parent, raw=data, **kwargs)


def iter_samples(ecosystem: str | None = None) -> list[Sample]:
    samples: list[Sample] = []
    for manifest in sorted(CORPUS_DIR.glob("*/*/manifest.yaml")):
        sample = load_sample(manifest)
        if ecosystem and sample.ecosystem != ecosystem:
            continue
        samples.append(sample)
    return samples


def validate_sample(sample: Sample, taxonomy: dict[str, dict[str, Any]]) -> list[str]:
    """Return a list of human-readable validation errors (empty == valid)."""
    errors: list[str] = []
    missing = REQUIRED_FIELDS - set(sample.raw.keys())
    if missing:
        errors.append(f"missing required fields: {', '.join(sorted(missing))}")

    if sample.ecosystem not in VALID_ECOSYSTEMS:
        errors.append(f"unknown ecosystem '{sample.ecosystem}'")

    if sample.technique and sample.technique not in taxonomy:
        errors.append(f"technique '{sample.technique}' not in taxonomy")

    if not isinstance(sample.malicious, bool):
        errors.append("'malicious' must be a boolean")

    # Directory id should match the manifest id for predictable addressing.
    if sample.id and sample.path.name != sample.id:
        errors.append(f"directory '{sample.path.name}' does not match id '{sample.id}'")

    # Safety invariant: every malicious sample must carry the canary marker somewhere
    # in its files so it is always identifiable as an inert test fixture.
    if sample.malicious and not _contains_canary(sample):
        errors.append(f"malicious sample missing '{CANARY}' marker in its files")

    # Inverse: benign decoys should be labeled with a benign technique.
    if not sample.malicious and not sample.technique.startswith("benign"):
        errors.append("benign sample should use a 'benign-*' technique id")

    return errors


def _contains_canary(sample: Sample) -> bool:
    for path in sample.path.rglob("*"):
        if not path.is_file():
            continue
        try:
            if CANARY in path.read_text(encoding="utf-8", errors="ignore"):
                return True
        except OSError:
            continue
    return False
