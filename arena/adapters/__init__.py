"""Adapter registry — discovers Adapter subclasses defined in this package."""

from __future__ import annotations

import importlib
import pkgutil

from .base import Adapter, ScanResult

__all__ = ["Adapter", "ScanResult", "get_adapter", "available_adapters"]


def _load_all() -> dict[str, type[Adapter]]:
    registry: dict[str, type[Adapter]] = {}
    for mod in pkgutil.iter_modules(__path__):
        if mod.name == "base":
            continue
        module = importlib.import_module(f"{__name__}.{mod.name}")
        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and issubclass(obj, Adapter)
                and obj is not Adapter
            ):
                registry[obj.name] = obj
    return registry


def available_adapters() -> dict[str, type[Adapter]]:
    return _load_all()


def get_adapter(name: str, config: dict[str, str] | None = None) -> Adapter:
    registry = _load_all()
    if name not in registry:
        known = ", ".join(sorted(registry)) or "(none)"
        raise KeyError(f"unknown adapter '{name}'. Available: {known}")
    return registry[name](config=config)
