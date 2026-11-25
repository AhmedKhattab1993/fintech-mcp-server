"""MCP tool router enforcing OAuth 2.1 scopes, typed contracts, risk checks, and audit logging."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ValidationError

from fintech_mcp.audit import SignedAuditLog
from fintech_mcp.auth import AuthError, Principal
from fintech_mcp.broker import BrokerAdapter
from fintech_mcp.gate import ApprovalGate, ApprovalGateError
from fintech_mcp.risk import RiskPolicy, evaluate_order_proposal
from fintech_mcp.schemas import (
    EvaluateOrderRiskInput,
    ExecuteApprovedOrderInput,
    GetBalancesInput,
    GetPositionsInput,
    GetQuoteInput,
    Scope,
    VerifyAuditLogInput,
)

MCP_PROTOCOL_VERSION = "2025-06-18"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    required_scope: Scope
    input_model: type[BaseModel]


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="get_account_balances",
        description="Read cash, buying power, and NAV for an authorized brokerage account.",
        required_scope=Scope.PORTFOLIO_READ,
        input_model=GetBalancesInput,
    ),
    ToolSpec(
        name="get_positions",
        description="Read current holdings, market values, and portfolio weights (Decimal exact).",
        required_scope=Scope.PORTFOLIO_READ,
        input_model=GetPositionsInput,
    ),
    ToolSpec(
        name="get_market_quote",
        description="Read latest bid/ask/last market quote for an equity or ETF symbol.",
        required_scope=Scope.MARKET_READ,
        input_model=GetQuoteInput,
    ),
    ToolSpec(
        name="evaluate_order_risk",
        description=(
            "Compute deterministic Decimal sizing, post-trade concentration, and pre-trade risk "
            "checks for an order intent. Emits an immutable SHA-256 proposal_hash; never executes."
        ),
        required_scope=Scope.ORDERS_PROPOSE,
        input_model=EvaluateOrderRiskInput,
    ),
    ToolSpec(
        name="execute_approved_order",
        description=(
            "Route a previously computed proposal_hash to the broker ONLY after an authenticated "
            "human reviewer signs approval on the separate operator channel."
        ),
        required_scope=Scope.ORDERS_EXECUTE,
        input_model=ExecuteApprovedOrderInput,
    ),
    ToolSpec(
        name="verify_audit_log",
        description="Verify the SHA-256 hash chain and Ed25519 signatures across the audit log.",
        required_scope=Scope.PORTFOLIO_READ,
        input_model=VerifyAuditLogInput,
    ),
)

TOOL_INDEX: dict[str, ToolSpec] = {spec.name: spec for spec in TOOL_SPECS}


class FinancialMCPRouter:
    """Transport-agnostic JSON-RPC 2.0 MCP router (used by both HTTP and stdio servers)."""

    def __init__(
        self,
        broker: BrokerAdapter,
        gate: ApprovalGate,
        audit_log: SignedAuditLog,
        policy: RiskPolicy | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.broker = broker
        self.gate = gate
        self.audit_log = audit_log
        self.policy = policy or RiskPolicy()
        self.clock = clock or (lambda: datetime.now(UTC))

    def list_tools(self, principal: Principal) -> list[dict[str, Any]]:
        """Advertise only tools permitted by the caller's OAuth 2.1 scopes."""
        tools: list[dict[str, Any]] = []
        for spec in TOOL_SPECS:
            if spec.required_scope in principal.scopes:
                tools.append(
                    {
                        "name": spec.name,
                        "description": spec.description,
                        "inputSchema": spec.input_model.model_json_schema(),
                        "annotations": {
                            "requiredScope": spec.required_scope.value,
                            "readOnlyHint": spec.name
                            in (
                                "get_account_balances",
                                "get_positions",
                                "get_market_quote",
                                "verify_audit_log",
                            ),
                            "destructiveHint": spec.name == "execute_approved_order",
                        },
                    }
                )
        return tools

    def call_tool(
        self, principal: Principal, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        spec = TOOL_INDEX.get(name)
        if spec is None:
            return self._tool_error("unknown_tool", f"Tool '{name}' does not exist")

        try:
            principal.require_scope(spec.required_scope)
            parsed = spec.input_model.model_validate(arguments or {})
        except AuthError as err:
            self.audit_log.append(
                event="tool.denied",
                actor=principal.subject,
                data={"tool": name, "code": err.code, "message": err.message},
                now_utc=self.clock(),
            )
            return self._tool_error(err.code, err.message)
        except ValidationError as err:
            return self._tool_error("validation_error", str(err))

        now = self.clock()
        try:
            if isinstance(parsed, GetBalancesInput):
                principal.require_account(parsed.account_id)
                result = self.broker.get_balances(parsed.account_id).model_dump(mode="json")
            elif isinstance(parsed, GetPositionsInput):
                principal.require_account(parsed.account_id)
                positions = self.broker.get_positions(parsed.account_id, limit=parsed.limit)
                result = {
                    "account_id": parsed.account_id,
                    "count": len(positions),
                    "positions": [p.model_dump(mode="json") for p in positions],
                }
            elif isinstance(parsed, GetQuoteInput):
                result = self.broker.get_quote(parsed.symbol).model_dump(mode="json")
            elif isinstance(parsed, EvaluateOrderRiskInput):
                principal.require_account(parsed.account_id)
                bal = self.broker.get_balances(parsed.account_id)
                pos = self.broker.get_positions(parsed.account_id)
                quote = self.broker.get_quote(parsed.symbol)
                proposal = evaluate_order_proposal(
                    intent=parsed,
                    balances=bal,
                    positions=pos,
                    quote=quote,
                    policy=self.policy,
                    now_utc=now,
                )
                self.gate.register_proposal(proposal)
                self.audit_log.append(
                    event="order.proposed",
                    actor=principal.subject,
                    data={
                        "account_id": proposal.account_id,
                        "proposal_hash": proposal.proposal_hash,
                        "symbol": proposal.symbol,
                        "side": proposal.side.value,
                        "quantity": str(proposal.quantity),
                        "estimated_notional": str(proposal.estimated_notional),
                        "all_checks_passed": proposal.all_checks_passed,
                    },
                    now_utc=now,
                )
                result = proposal.model_dump(mode="json")
            elif isinstance(parsed, ExecuteApprovedOrderInput):
                # Look up proposal first via gate to enforce account ownership and approval
                proposal_preview = self.gate._proposals.get(parsed.proposal_hash)
                if proposal_preview is not None:
                    principal.require_account(proposal_preview.account_id)
                current_px = (
                    self.broker.get_quote(proposal_preview.symbol).last
                    if proposal_preview is not None
                    else None
                )
                proposal, signed = self.gate.authorize_execution(
                    proposal_hash=parsed.proposal_hash,
                    current_price=current_px or proposal_preview.reference_price,  # type: ignore[union-attr]
                    max_price_drift_bps=self.policy.max_price_drift_bps,
                    now_utc=now,
                )
                principal.require_account(proposal.account_id)
                # Write tamper-evident audit entry BEFORE routing to broker
                audit_rec = self.audit_log.append(
                    event="order.execution_authorized",
                    actor=principal.subject,
                    data={
                        "proposal_hash": proposal.proposal_hash,
                        "account_id": proposal.account_id,
                        "symbol": proposal.symbol,
                        "side": proposal.side.value,
                        "quantity": str(proposal.quantity),
                        "approver_id": signed.record.approver_id,
                        "approval_sig": signed.signature_hex,
                        "idempotency_key": parsed.idempotency_key,
                    },
                    now_utc=now,
                )
                verification = self.audit_log.verify()
                if not verification.ok:
                    raise ApprovalGateError(
                        "audit_chain_invalid", verification.error or "Audit chain failed"
                    )

                receipt = self.broker.submit_order(proposal, parsed.idempotency_key, now_utc=now)
                self.gate.mark_executed(proposal.proposal_hash)
                result = {
                    "receipt": receipt.model_dump(mode="json"),
                    "audit_entry_hash": audit_rec["entry_hash"],
                    "audit_seq": audit_rec["seq"],
                }
            elif isinstance(parsed, VerifyAuditLogInput):
                ver = self.audit_log.verify()
                result = {
                    "ok": ver.ok,
                    "entries_verified": ver.entries_verified,
                    "head_hash": ver.head_hash,
                    "error": ver.error,
                }
            else:
                return self._tool_error("unhandled_tool", f"No handler for '{name}'")
        except AuthError as err:
            self.audit_log.append(
                event="tool.denied",
                actor=principal.subject,
                data={"tool": name, "code": err.code, "message": err.message},
                now_utc=now,
            )
            return self._tool_error(err.code, err.message)
        except ApprovalGateError as err:
            self.audit_log.append(
                event="order.execution_denied",
                actor=principal.subject,
                data={"tool": name, "code": err.code, "message": err.message},
                now_utc=now,
            )
            return self._tool_error(err.code, err.message)
        except KeyError as err:
            return self._tool_error("not_found", str(err).strip("'"))

        return {
            "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
            "structuredContent": result,
            "isError": False,
        }

    def handle_jsonrpc(self, principal: Principal, request: dict[str, Any]) -> dict[str, Any]:
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "fintech-mcp-server", "version": "0.1.0"},
                },
            }
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.list_tools(principal)}}
        if method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments") or {}
            res = self.call_tool(principal, tool_name, tool_args)
            return {"jsonrpc": "2.0", "id": req_id, "result": res}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    @staticmethod
    def _tool_error(code: str, message: str) -> dict[str, Any]:
        payload = {"error": code, "message": message}
        return {
            "content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}],
            "structuredContent": payload,
            "isError": True,
        }
