"""Automated unit & integration tests for Fintech MCP Server blueprint."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from fintech_mcp.audit import SignedAuditLog
from fintech_mcp.auth import AuthError, OAuth21Verifier
from fintech_mcp.broker import SandboxBrokerAdapter
from fintech_mcp.gate import ApprovalGate, sign_approval
from fintech_mcp.http_app import create_app
from fintech_mcp.risk import RiskPolicy
from fintech_mcp.router import FinancialMCPRouter
from fintech_mcp.schemas import Scope


class MutableClock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now = self.now + timedelta(seconds=seconds)


@pytest.fixture()
def env(tmp_path: Path):
    clock = MutableClock(datetime(2026, 11, 25, 15, 0, 0, tzinfo=UTC))
    verifier = OAuth21Verifier(
        signing_secret="test-signing-secret-at-least-32-bytes",
        issuer="https://auth.example-broker.test",
        resource_audience="https://mcp.example-broker.test",
    )
    reviewer_key = Ed25519PrivateKey.generate()
    attacker_key = Ed25519PrivateKey.generate()
    audit_key = Ed25519PrivateKey.generate()

    broker = SandboxBrokerAdapter()
    gate = ApprovalGate(reviewer_public_key=reviewer_key.public_key())
    audit_log = SignedAuditLog(path=tmp_path / "audit.jsonl", signing_key=audit_key)
    router = FinancialMCPRouter(
        broker=broker,
        gate=gate,
        audit_log=audit_log,
        policy=RiskPolicy(),
        clock=clock,
    )
    app = create_app(verifier=verifier, router=router)
    client = TestClient(app)
    return {
        "clock": clock,
        "verifier": verifier,
        "reviewer_key": reviewer_key,
        "attacker_key": attacker_key,
        "broker": broker,
        "gate": gate,
        "audit_log": audit_log,
        "router": router,
        "client": client,
        "audit_path": tmp_path / "audit.jsonl",
    }


def _rpc(client: TestClient, token: str, method: str, params: dict | None = None) -> dict:
    resp = client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {token}"},
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
    )
    assert resp.status_code == 200
    return resp.json()["result"]


def test_rfc9728_protected_resource_metadata(env):
    resp = env["client"].get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource"] == "https://mcp.example-broker.test"
    assert "orders:execute" in body["scopes_supported"]


def test_oauth_rejects_missing_expired_and_wrong_audience_tokens(env):
    client = env["client"]
    verifier = env["verifier"]

    # Missing bearer header -> 401 with WWW-Authenticate resource_metadata challenge
    r0 = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r0.status_code == 401
    assert "resource_metadata=" in r0.headers["www-authenticate"]

    # Wrong RFC 8707 audience -> 401
    wrong_aud = verifier.issue_token(
        subject="u1",
        scopes=[Scope.PORTFOLIO_READ],
        account_ids=["acct_alpha_01"],
        audience="https://other-api.example.test",
    )
    r1 = client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {wrong_aud}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert r1.status_code == 401
    assert r1.json()["detail"]["error"] == "invalid_audience"

    # Expired token -> AuthError
    expired = verifier.issue_token(
        subject="u1",
        scopes=[Scope.PORTFOLIO_READ],
        account_ids=["acct_alpha_01"],
        ttl_seconds=10,
        now=1000,
    )
    with pytest.raises(AuthError) as exc_info:
        verifier.verify_token(expired, now=2000)
    assert exc_info.value.code == "token_expired"


def test_tools_list_filters_by_oauth_scope(env):
    token = env["verifier"].issue_token(
        subject="readonly-analyst",
        scopes=[Scope.PORTFOLIO_READ, Scope.MARKET_READ],
        account_ids=["acct_alpha_01"],
    )
    res = _rpc(env["client"], token, "tools/list")
    names = {t["name"] for t in res["tools"]}
    assert names == {
        "get_account_balances",
        "get_positions",
        "get_market_quote",
        "verify_audit_log",
    }
    assert "execute_approved_order" not in names


def test_cross_account_idor_is_blocked_and_audited(env):
    token = env["verifier"].issue_token(
        subject="user-alpha",
        scopes=[Scope.PORTFOLIO_READ],
        account_ids=["acct_alpha_01"],
    )
    res = _rpc(
        env["client"],
        token,
        "tools/call",
        {"name": "get_account_balances", "arguments": {"account_id": "acct_beta_02"}},
    )
    assert res["isError"] is True
    assert res["structuredContent"]["error"] == "account_access_denied"
    assert env["audit_log"].verify().entries_verified == 1


def test_pydantic_rejects_extra_fields_and_invalid_symbols(env):
    token = env["verifier"].issue_token(
        subject="trader-1",
        scopes=[Scope.ORDERS_PROPOSE],
        account_ids=["acct_alpha_01"],
    )
    # Prompt-injected extra field attempting to inject an arbitrary dollar amount or bypass flag
    res = _rpc(
        env["client"],
        token,
        "tools/call",
        {
            "name": "evaluate_order_risk",
            "arguments": {
                "account_id": "acct_alpha_01",
                "symbol": "AAPL",
                "side": "BUY",
                "quantity": "10",
                "rationale": "Add small AAPL slice",
                "bypass_approval": True,
            },
        },
    )
    assert res["isError"] is True
    assert res["structuredContent"]["error"] == "validation_error"


def test_deterministic_risk_checks_reject_concentration_and_notional_breaches(env):
    token = env["verifier"].issue_token(
        subject="trader-1",
        scopes=[Scope.ORDERS_PROPOSE, Scope.ORDERS_EXECUTE],
        account_ids=["acct_alpha_01"],
    )
    # 1,500 shares of AAPL @ $228.50 = $342,750 -> breaches $250k order ceiling and 15% weight cap
    res = _rpc(
        env["client"],
        token,
        "tools/call",
        {
            "name": "evaluate_order_risk",
            "arguments": {
                "account_id": "acct_alpha_01",
                "symbol": "AAPL",
                "side": "BUY",
                "quantity": "1500",
                "order_type": "MARKET",
                "rationale": "Oversized AAPL purchase",
            },
        },
    )
    assert res["isError"] is False
    proposal = res["structuredContent"]
    assert proposal["status"] == "REJECTED_BY_RISK"
    assert proposal["all_checks_passed"] is False
    failed = {c["name"] for c in proposal["checks"] if not c["passed"]}
    assert "order_notional_ceiling" in failed
    assert "single_name_concentration" in failed

    # Even if someone signs it, execution MUST still be denied because risk checks failed
    signed = sign_approval(
        env["reviewer_key"],
        proposal["proposal_hash"],
        approver_id="pm@desk.test",
        decision="approve",
        now_utc=env["clock"](),
    )
    env["gate"].record_signed_approval(signed)
    exec_res = _rpc(
        env["client"],
        token,
        "tools/call",
        {
            "name": "execute_approved_order",
            "arguments": {
                "proposal_hash": proposal["proposal_hash"],
                "idempotency_key": "idem-risk-fail-01",
            },
        },
    )
    assert exec_res["isError"] is True
    assert exec_res["structuredContent"]["error"] == "risk_checks_failed"


def test_full_propose_deny_approve_execute_replay_and_audit_flow(env):
    token = env["verifier"].issue_token(
        subject="pm-agent",
        scopes=[
            Scope.PORTFOLIO_READ,
            Scope.MARKET_READ,
            Scope.ORDERS_PROPOSE,
            Scope.ORDERS_EXECUTE,
        ],
        account_ids=["acct_alpha_01"],
    )
    # 1. Compute deterministic proposal (200 shares NVDA @ $142.00 = $28,400.00)
    prop_res = _rpc(
        env["client"],
        token,
        "tools/call",
        {
            "name": "evaluate_order_risk",
            "arguments": {
                "account_id": "acct_alpha_01",
                "symbol": "NVDA",
                "side": "BUY",
                "quantity": "200",
                "order_type": "MARKET",
                "rationale": "Initiate starter NVDA position within 15% single-name cap",
            },
        },
    )
    assert prop_res["isError"] is False
    proposal = prop_res["structuredContent"]
    assert proposal["status"] == "READY_FOR_APPROVAL"
    assert Decimal(proposal["estimated_notional"]) == Decimal("28400.00")
    phash = proposal["proposal_hash"]

    # 2. Attempt execution BEFORE human approval -> DENIED
    denied = _rpc(
        env["client"],
        token,
        "tools/call",
        {
            "name": "execute_approved_order",
            "arguments": {"proposal_hash": phash, "idempotency_key": "idem-0001"},
        },
    )
    assert denied["isError"] is True
    assert denied["structuredContent"]["error"] == "approval_required"

    # 3. Forged signature from untrusted key -> DENIED
    forged = sign_approval(
        env["attacker_key"], phash, "attacker@evil.test", "approve", env["clock"]()
    )
    with pytest.raises(PermissionError):
        env["gate"].record_signed_approval(forged)

    # 4. Legitimate human signs out-of-band -> execution succeeds
    signed = sign_approval(
        env["reviewer_key"], phash, "pm@desk.test", "approve", env["clock"](), "LGTM"
    )
    env["gate"].record_signed_approval(signed)
    executed = _rpc(
        env["client"],
        token,
        "tools/call",
        {
            "name": "execute_approved_order",
            "arguments": {"proposal_hash": phash, "idempotency_key": "idem-0001"},
        },
    )
    assert executed["isError"] is False
    receipt = executed["structuredContent"]["receipt"]
    assert receipt["status"] == "FILLED"
    assert Decimal(receipt["notional"]) == Decimal("28400.00")

    # 5. Replay of same proposal_hash -> DENIED
    replay = _rpc(
        env["client"],
        token,
        "tools/call",
        {
            "name": "execute_approved_order",
            "arguments": {"proposal_hash": phash, "idempotency_key": "idem-0002"},
        },
    )
    assert replay["isError"] is True
    assert replay["structuredContent"]["error"] == "proposal_already_executed"

    # 6. Audit chain verifies cleanly
    audit_ok = _rpc(
        env["client"], token, "tools/call", {"name": "verify_audit_log", "arguments": {}}
    )
    assert audit_ok["structuredContent"]["ok"] is True
    assert audit_ok["structuredContent"]["entries_verified"] >= 4

    # 7. Mutate one digit in audit.jsonl -> tamper detection fires immediately
    lines = env["audit_path"].read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[-1])
    tampered["data"]["quantity"] = "9999"
    lines[-1] = json.dumps(tampered, sort_keys=True)
    env["audit_path"].write_text("\n".join(lines) + "\n", encoding="utf-8")

    audit_bad = _rpc(
        env["client"], token, "tools/call", {"name": "verify_audit_log", "arguments": {}}
    )
    assert audit_bad["structuredContent"]["ok"] is False
    assert "Tampered payload" in audit_bad["structuredContent"]["error"]


def test_stale_ttl_and_price_drift_deny_execution(env):
    token = env["verifier"].issue_token(
        subject="pm-agent",
        scopes=[Scope.ORDERS_PROPOSE, Scope.ORDERS_EXECUTE],
        account_ids=["acct_alpha_01"],
    )
    # Price drift > 50 bps denies execution even when approved
    p1 = _rpc(
        env["client"],
        token,
        "tools/call",
        {
            "name": "evaluate_order_risk",
            "arguments": {
                "account_id": "acct_alpha_01",
                "symbol": "NVDA",
                "side": "BUY",
                "quantity": "100",
                "order_type": "MARKET",
                "rationale": "Check drift guard",
            },
        },
    )["structuredContent"]
    env["gate"].record_signed_approval(
        sign_approval(
            env["reviewer_key"], p1["proposal_hash"], "pm@desk.test", "approve", env["clock"]()
        )
    )
    env["broker"].set_quote_price("NVDA", Decimal("145.00"))  # +211 bps drift
    drift_res = _rpc(
        env["client"],
        token,
        "tools/call",
        {
            "name": "execute_approved_order",
            "arguments": {"proposal_hash": p1["proposal_hash"], "idempotency_key": "idem-drift"},
        },
    )
    assert drift_res["isError"] is True
    assert drift_res["structuredContent"]["error"] == "price_drift_exceeded"

    # Expired TTL (>15 min) denies execution
    env["broker"].set_quote_price("NVDA", Decimal("141.95"))
    p2 = _rpc(
        env["client"],
        token,
        "tools/call",
        {
            "name": "evaluate_order_risk",
            "arguments": {
                "account_id": "acct_alpha_01",
                "symbol": "NVDA",
                "side": "BUY",
                "quantity": "100",
                "order_type": "MARKET",
                "rationale": "Check TTL guard",
            },
        },
    )["structuredContent"]
    env["gate"].record_signed_approval(
        sign_approval(
            env["reviewer_key"], p2["proposal_hash"], "pm@desk.test", "approve", env["clock"]()
        )
    )
    env["clock"].advance(901)
    exp_res = _rpc(
        env["client"],
        token,
        "tools/call",
        {
            "name": "execute_approved_order",
            "arguments": {"proposal_hash": p2["proposal_hash"], "idempotency_key": "idem-ttl"},
        },
    )
    assert exp_res["isError"] is True
    assert exp_res["structuredContent"]["error"] == "proposal_expired"
