"""Stdio JSON-RPC 2.0 transport for local MCP clients (Claude Desktop, Cursor, eval harnesses)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fintech_mcp.audit import SignedAuditLog
from fintech_mcp.auth import OAuth21Verifier
from fintech_mcp.broker import SandboxBrokerAdapter
from fintech_mcp.gate import ApprovalGate
from fintech_mcp.router import FinancialMCPRouter
from fintech_mcp.schemas import Scope


def main() -> None:
    state_dir = Path(os.environ.get("FINTECH_MCP_STATE_DIR", ".state"))
    verifier = OAuth21Verifier(
        signing_secret=os.environ.get(
            "FINTECH_MCP_JWT_SECRET", "sandbox-only-dev-secret-replace-with-jwks"
        ),
        issuer="https://auth.example-broker.test",
        resource_audience="https://mcp.example-broker.test",
    )
    token = os.environ.get("FINTECH_MCP_BEARER_TOKEN") or verifier.issue_token(
        subject="local-sandbox-user",
        scopes=[Scope.PORTFOLIO_READ, Scope.MARKET_READ, Scope.ORDERS_PROPOSE],
        account_ids=["acct_alpha_01"],
    )
    principal = verifier.verify_token(token)

    reviewer_key = Ed25519PrivateKey.generate()
    audit_key = Ed25519PrivateKey.generate()
    router = FinancialMCPRouter(
        broker=SandboxBrokerAdapter(),
        gate=ApprovalGate(reviewer_public_key=reviewer_key.public_key()),
        audit_log=SignedAuditLog(path=state_dir / "audit.jsonl", signing_key=audit_key),
    )

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        req = json.loads(line)
        resp = router.handle_jsonrpc(principal, req)
        sys.stdout.write(json.dumps(resp, sort_keys=True) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
