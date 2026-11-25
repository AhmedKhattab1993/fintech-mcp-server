"""Canonical JSON serialization and SHA-256 helpers."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any


def _default(obj: Any) -> Any:
    if isinstance(obj, Decimal):
        return format(obj, "f")
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def canonical_json(payload: Any) -> bytes:
    """Deterministic UTF-8 JSON encoding used for proposal and audit hashing."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_default,
    ).encode("utf-8")


def sha256_hex(payload: Any) -> str:
    """Compute SHA-256 hex digest over canonical JSON."""
    return hashlib.sha256(canonical_json(payload)).hexdigest()
