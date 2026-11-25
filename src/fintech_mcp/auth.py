"""OAuth 2.1 bearer-token verification, RFC 8707 resource binding, and per-account scoping."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

from fintech_mcp.schemas import Scope


class AuthError(PermissionError):
    """Structured OAuth 2.1 authorization error."""

    def __init__(self, code: str, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[Scope]
    account_ids: frozenset[str]
    audience: str
    expires_at: int

    def require_scope(self, scope: Scope) -> None:
        if scope not in self.scopes:
            raise AuthError(
                code="insufficient_scope",
                message=f"Token missing required OAuth scope '{scope.value}'",
                status_code=403,
            )

    def require_account(self, account_id: str) -> None:
        if account_id not in self.account_ids:
            raise AuthError(
                code="account_access_denied",
                message=f"Principal '{self.subject}' is not authorized for account '{account_id}'",
                status_code=403,
            )


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


class OAuth21Verifier:
    """Validates HS256 JWTs bound to an RFC 8707 MCP resource audience.

    In production, swap the HMAC verification key for your IdP's JWKS / RS256 / ES256 keys
    while keeping identical audience, issuer, scope, and account-ownership checks.
    """

    def __init__(self, signing_secret: str, issuer: str, resource_audience: str) -> None:
        if len(signing_secret) < 16:
            raise ValueError("signing_secret must be at least 16 characters")
        self._secret = signing_secret.encode("utf-8")
        self.issuer = issuer
        self.resource_audience = resource_audience

    def issue_token(
        self,
        subject: str,
        scopes: list[Scope] | set[Scope],
        account_ids: list[str] | set[str],
        ttl_seconds: int = 900,
        now: int | None = None,
        audience: str | None = None,
    ) -> str:
        issued_at = int(time.time()) if now is None else now
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience or self.resource_audience,
            "iat": issued_at,
            "exp": issued_at + ttl_seconds,
            "scope": " ".join(sorted(s.value for s in scopes)),
            "account_ids": sorted(account_ids),
        }
        h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{h_b64}.{p_b64}".encode("ascii")
        sig = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"

    def verify_bearer(self, authorization_header: str | None, now: int | None = None) -> Principal:
        if not authorization_header:
            raise AuthError("missing_token", "Missing Authorization bearer token", 401)
        parts = authorization_header.strip().split(" ")
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
            raise AuthError("malformed_token", "Authorization header must use Bearer scheme", 401)
        return self.verify_token(parts[1], now=now)

    def verify_token(self, token: str, now: int | None = None) -> Principal:
        segments = token.split(".")
        if len(segments) != 3:
            raise AuthError("invalid_token", "Malformed JWT token", 401)
        h_b64, p_b64, s_b64 = segments
        try:
            header = json.loads(_b64url_decode(h_b64))
            payload = json.loads(_b64url_decode(p_b64))
            provided_sig = _b64url_decode(s_b64)
        except Exception as exc:
            raise AuthError("invalid_token", "Unable to decode JWT segments", 401) from exc

        if header.get("alg") != "HS256":
            raise AuthError("unsupported_alg", "Unsupported JWT signing algorithm", 401)

        expected_sig = hmac.new(
            self._secret, f"{h_b64}.{p_b64}".encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(provided_sig, expected_sig):
            raise AuthError("invalid_signature", "JWT signature verification failed", 401)

        current = int(time.time()) if now is None else now
        if payload.get("iss") != self.issuer:
            raise AuthError("invalid_issuer", "Token issuer mismatch", 401)
        if payload.get("aud") != self.resource_audience:
            raise AuthError(
                "invalid_audience",
                "Token audience does not match this MCP resource (RFC 8707)",
                401,
            )
        exp = payload.get("exp")
        if not isinstance(exp, int) or exp <= current:
            raise AuthError("token_expired", "Bearer token has expired", 401)

        raw_scopes = str(payload.get("scope", "")).split()
        valid_scopes: set[Scope] = set()
        for raw in raw_scopes:
            try:
                valid_scopes.add(Scope(raw))
            except ValueError:
                continue

        account_ids = payload.get("account_ids")
        if not isinstance(account_ids, list) or not all(isinstance(a, str) for a in account_ids):
            raise AuthError("invalid_claims", "Missing or invalid account_ids claim", 401)

        return Principal(
            subject=str(payload.get("sub", "")),
            scopes=frozenset(valid_scopes),
            account_ids=frozenset(account_ids),
            audience=str(payload["aud"]),
            expires_at=exp,
        )
