"""Recursive, JSON-safe serialization for dataclass-based model objects.

Every model in :mod:`requesttrace.models` is a frozen/plain dataclass. Rather
than hand-writing ``to_dict``/``to_json`` on each one, this module provides a
single recursive converter so serialization behavior (enum -> value,
datetime -> ISO 8601, dataclass -> dict, nested collections) stays
consistent everywhere it is used: JSON reports, baseline files and golden
tests.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
from enum import Enum
from typing import Any


def to_json_safe(value: Any) -> Any:
    """Recursively convert a model value into plain JSON-serializable data."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: to_json_safe(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, (list, tuple, set)):
        return [to_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_json_safe(item) for key, item in value.items()}
    return value


def dataclass_to_dict(instance: Any) -> dict[str, Any]:
    """Convert a single dataclass instance into a JSON-safe dict."""
    return to_json_safe(instance)


def dump_json(value: Any, *, indent: int | None = 2) -> str:
    """Serialize a model value (or plain data) to a deterministic JSON string."""
    return json.dumps(to_json_safe(value), indent=indent, sort_keys=False)


def utc_now() -> dt.datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return dt.datetime.now(dt.timezone.utc)
