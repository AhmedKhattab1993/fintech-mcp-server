"""Out-of-band Ed25519 human confirmation gate.

The MCP server holds ONLY the reviewer's public key and exposes NO tool to sign approvals.
Only an authenticated human reviewer on a separate operator channel can unlock execution
of a specific SHA-256 proposal_hash before its TTL expires.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from fintech_mcp.canonical import canonical_json
from fintech_mcp.schemas import ApprovalRecord, OrderProposal, SignedApproval


class ApprovalGateError(PermissionError):
    """Non-bypassable execution denial with explicit machine-readable reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def sign_approval(
    private_key: Ed25519PrivateKey,
    proposal_hash: str,
    approver_id: str,
    decision: str,
    now_utc: datetime,
    note: str = "",
) -> SignedApproval:
    """Helper used strictly by the out-of-band operator UI/CLI (never exposed as an MCP tool)."""
    record = ApprovalRecord(
        proposal_hash=proposal_hash,
        decision="approve" if decision == "approve" else "reject",
        approver_id=approver_id,
        decided_at_utc=now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        note=note,
    )
    sig = private_key.sign(canonical_json(record.model_dump(mode="json"))).hex()
    return SignedApproval(record=record, signature_hex=sig)


class ApprovalGate:
    """Stores immutable proposals and verifies signed human approvals prior to routing."""

    def __init__(self, reviewer_public_key: Ed25519PublicKey) -> None:
        self._reviewer_public_key = reviewer_public_key
        self._proposals: dict[str, OrderProposal] = {}
        self._approvals: dict[str, SignedApproval] = {}
        self._executed_hashes: set[str] = set()

    def register_proposal(self, proposal: OrderProposal) -> None:
        self._proposals[proposal.proposal_hash] = proposal

    def record_signed_approval(self, signed: SignedApproval) -> None:
        """Out-of-band operator channel submits a signed decision."""
        self._verify_signature(signed)
        self._approvals[signed.record.proposal_hash] = signed

    def _verify_signature(self, signed: SignedApproval) -> None:
        try:
            self._reviewer_public_key.verify(
                bytes.fromhex(signed.signature_hex),
                canonical_json(signed.record.model_dump(mode="json")),
            )
        except (ValueError, InvalidSignature) as exc:
            raise ApprovalGateError(
                "invalid_approval_signature",
                "Ed25519 approval signature failed verification against trusted reviewer key",
            ) from exc

    def authorize_execution(
        self,
        proposal_hash: str,
        current_price: Decimal,
        max_price_drift_bps: Decimal,
        now_utc: datetime,
    ) -> tuple[OrderProposal, SignedApproval]:
        proposal = self._proposals.get(proposal_hash)
        if proposal is None:
            raise ApprovalGateError(
                "unknown_proposal",
                f"No deterministic proposal found for hash '{proposal_hash}'",
            )
        if not proposal.all_checks_passed:
            raise ApprovalGateError(
                "risk_checks_failed",
                "Proposal failed deterministic pre-trade risk checks and cannot be executed",
            )
        if proposal_hash in self._executed_hashes:
            raise ApprovalGateError(
                "proposal_already_executed",
                "Proposal hash has already been executed (replay denied)",
            )

        expires_at = datetime.strptime(proposal.expires_at_utc, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        )
        now_aware = now_utc if now_utc.tzinfo else now_utc.replace(tzinfo=UTC)
        if now_aware > expires_at:
            raise ApprovalGateError(
                "proposal_expired",
                f"Proposal expired at {proposal.expires_at_utc}; recompute risk proposal",
            )

        signed = self._approvals.get(proposal_hash)
        if signed is None:
            raise ApprovalGateError(
                "approval_required",
                "Execution denied: awaiting signed human approval on operator channel",
            )
        self._verify_signature(signed)
        if signed.record.decision != "approve":
            raise ApprovalGateError(
                "approval_rejected",
                f"Proposal was explicitly rejected by reviewer '{signed.record.approver_id}'",
            )

        drift_bps = (
            abs(current_price - proposal.reference_price) / proposal.reference_price
        ) * Decimal("10000")
        if drift_bps > max_price_drift_bps:
            raise ApprovalGateError(
                "price_drift_exceeded",
                (
                    f"Live quote drifted {drift_bps:.1f} bps from proposal price "
                    f"(max {max_price_drift_bps} bps)"
                ),
            )

        return proposal, signed

    def mark_executed(self, proposal_hash: str) -> None:
        self._executed_hashes.add(proposal_hash)
