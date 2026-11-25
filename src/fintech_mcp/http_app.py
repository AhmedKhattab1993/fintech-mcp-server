"""FastAPI Streamable HTTP MCP transport with OAuth 2.1 + RFC 9728 Protected Resource metadata."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Header, HTTPException, Request

from fintech_mcp.audit import SignedAuditLog
from fintech_mcp.auth import AuthError, OAuth21Verifier
from fintech_mcp.broker import SandboxBrokerAdapter
from fintech_mcp.gate import ApprovalGate
from fintech_mcp.router import FinancialMCPRouter


def create_app(
    verifier: OAuth21Verifier,
    router: FinancialMCPRouter,
    authorization_server: str = "https://auth.example-broker.test",
) -> FastAPI:
    app = FastAPI(title="Fintech MCP Server Blueprint", version="0.1.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/oauth-protected-resource")
    def oauth_protected_resource() -> dict[str, Any]:
        """RFC 9728 metadata so MCP clients discover OAuth 2.1 issuer and required scopes."""
        return {
            "resource": verifier.resource_audience,
            "authorization_servers": [authorization_server],
            "scopes_supported": [
                "portfolio:read",
                "market:read",
                "orders:propose",
                "orders:execute",
            ],
            "bearer_methods_supported": ["header"],
        }

    @app.post("/mcp")
    async def mcp_endpoint(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        try:
            principal = verifier.verify_bearer(authorization)
        except AuthError as err:
            raise HTTPException(
                status_code=err.status_code,
                detail={"error": err.code, "message": err.message},
                headers={
                    "WWW-Authenticate": (
                        f'Bearer resource_metadata="{verifier.resource_audience}'
                        '/.well-known/oauth-protected-resource"'
                    )
                },
            ) from err

        body = await request.json()
        return router.handle_jsonrpc(principal, body)

    return app


def create_demo_app(
    state_dir: Path = Path(".state"),
) -> tuple[FastAPI, OAuth21Verifier, ApprovalGate, Ed25519PrivateKey]:
    """Build a runnable local instance with ephemeral Ed25519 keys for sandbox development."""
    verifier = OAuth21Verifier(
        signing_secret="sandbox-only-dev-secret-replace-with-jwks",
        issuer="https://auth.example-broker.test",
        resource_audience="https://mcp.example-broker.test",
    )
    reviewer_key = Ed25519PrivateKey.generate()
    audit_key = Ed25519PrivateKey.generate()
    broker = SandboxBrokerAdapter()
    gate = ApprovalGate(reviewer_public_key=reviewer_key.public_key())
    audit_log = SignedAuditLog(path=state_dir / "audit.jsonl", signing_key=audit_key)
    router = FinancialMCPRouter(broker=broker, gate=gate, audit_log=audit_log)
    app = create_app(verifier=verifier, router=router)
    return app, verifier, gate, reviewer_key
