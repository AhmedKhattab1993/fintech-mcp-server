"""Tamper-evident SHA-256 hash-chained and Ed25519-signed append-only audit log."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from fintech_mcp.canonical import canonical_json, sha256_hex

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditVerification:
    ok: bool
    entries_verified: int
    head_hash: str
    error: str | None = None


class SignedAuditLog:
    """Append-only JSONL ledger written before any state-mutating broker call."""

    def __init__(
        self,
        path: Path,
        signing_key: Ed25519PrivateKey,
        verify_key: Ed25519PublicKey | None = None,
    ) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._signing_key = signing_key
        self._verify_key = verify_key or signing_key.public_key()

    def _read_entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(json.loads(line))
        return entries

    def append(
        self, event: str, actor: str, data: dict[str, Any], now_utc: datetime
    ) -> dict[str, Any]:
        entries = self._read_entries()
        seq = len(entries) + 1
        prev_hash = entries[-1]["entry_hash"] if entries else GENESIS_HASH
        body = {
            "seq": seq,
            "ts": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event": event,
            "actor": actor,
            "prev_hash": prev_hash,
            "data": data,
        }
        entry_hash = sha256_hex(body)
        sig = self._signing_key.sign(canonical_json({**body, "entry_hash": entry_hash})).hex()
        record = {**body, "entry_hash": entry_hash, "sig": sig}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def verify(self) -> AuditVerification:
        entries = self._read_entries()
        expected_prev = GENESIS_HASH
        for idx, rec in enumerate(entries, start=1):
            if rec.get("seq") != idx:
                return AuditVerification(
                    False, idx - 1, expected_prev, f"Sequence gap at entry {idx}"
                )
            if rec.get("prev_hash") != expected_prev:
                return AuditVerification(
                    False, idx - 1, expected_prev, f"Broken prev_hash at entry {idx}"
                )

            body = {
                "seq": rec["seq"],
                "ts": rec["ts"],
                "event": rec["event"],
                "actor": rec["actor"],
                "prev_hash": rec["prev_hash"],
                "data": rec["data"],
            }
            computed = sha256_hex(body)
            if computed != rec.get("entry_hash"):
                return AuditVerification(
                    False, idx - 1, expected_prev, f"Tampered payload at entry {idx}"
                )

            try:
                sig_bytes = bytes.fromhex(rec["sig"])
                self._verify_key.verify(sig_bytes, canonical_json({**body, "entry_hash": computed}))
            except (KeyError, ValueError, InvalidSignature):
                return AuditVerification(
                    False, idx - 1, expected_prev, f"Invalid Ed25519 signature at entry {idx}"
                )

            expected_prev = computed

        return AuditVerification(True, len(entries), expected_prev)
