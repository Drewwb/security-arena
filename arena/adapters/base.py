"""Adapter contract. One adapter == one scanner integration."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..schema import Sample


@dataclass
class ScanResult:
    """Normalized result of running a scanner against a single sample."""

    sample_id: str
    flagged: bool                       # did the scanner consider this sample risky?
    score: float = 0.0                  # optional 0..1 risk score, if the scanner gives one
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None            # set if the scan failed to run
    raw: Any = None                     # raw scanner output, for debugging


class Adapter(ABC):
    """Base class for scanner adapters.

    Subclasses live in this package and are auto-discovered by their `name`.
    Implement `available()` (is the scanner usable right now?) and `scan()`.
    """

    #: short identifier used on the CLI, e.g. `--adapter semgrep`
    name: str = "base"

    def __init__(self, config: dict[str, str] | None = None) -> None:
        self.config = config or {}

    def available(self) -> bool:
        """Return True if this scanner can run in the current environment."""
        return True

    @abstractmethod
    def scan(self, sample: Sample) -> ScanResult:
        """Run the scanner against one sample and return a normalized result."""
        raise NotImplementedError
