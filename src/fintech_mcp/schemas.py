"""Typed Pydantic v2 contracts for every financial MCP tool and risk check."""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Scope(StrEnum):
    PORTFOLIO_READ = "portfolio:read"
    MARKET_READ = "market:read"
    ORDERS_PROPOSE = "orders:propose"
    ORDERS_EXECUTE = "orders:execute"


class Side(StrEnum):
    BUY = "BUY"
    SELL = "SELL"


class OrderType(StrEnum):
    MARKET = "MARKET"
    LIMIT = "LIMIT"


class GetBalancesInput(StrictModel):
    account_id: str = Field(min_length=3, max_length=64)


class GetPositionsInput(StrictModel):
    account_id: str = Field(min_length=3, max_length=64)
    limit: int = Field(default=50, ge=1, le=100, description="Token-budget pagination cap")


class GetQuoteInput(StrictModel):
    symbol: str = Field(min_length=1, max_length=12)

    @field_validator("symbol")
    @classmethod
    def normalize_symbol(cls, value: str) -> str:
        sym = value.strip().upper()
        if not sym.isalnum():
            raise ValueError("symbol must be alphanumeric")
        return sym


class EvaluateOrderRiskInput(StrictModel):
    """Intent passed by the LLM; all dollar amounts and weights are computed server-side."""

    account_id: str = Field(min_length=3, max_length=64)
    symbol: str = Field(min_length=1, max_length=12)
    side: Side
    quantity: Decimal = Field(gt=Decimal("0"), description="Share quantity (exact decimal)")
    order_type: OrderType = OrderType.LIMIT
    limit_price: Decimal | None = Field(default=None, gt=Decimal("0"))
    rationale: str = Field(min_length=4, max_length=500)

    @field_validator("symbol")
    @classmethod
    def normalize_symbol(cls, value: str) -> str:
        sym = value.strip().upper()
        if not sym.isalnum():
            raise ValueError("symbol must be alphanumeric")
        return sym


class ExecuteApprovedOrderInput(StrictModel):
    """Execution only accepts an immutable proposal_hash + signed human approval."""

    proposal_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    idempotency_key: str = Field(min_length=8, max_length=128)


class VerifyAuditLogInput(StrictModel):
    pass


class BalanceSnapshot(StrictModel):
    account_id: str
    currency: str = "USD"
    cash: Decimal
    buying_power: Decimal
    nav: Decimal


class Position(StrictModel):
    symbol: str
    quantity: Decimal
    avg_cost: Decimal
    market_price: Decimal
    market_value: Decimal
    weight_pct: Decimal


class MarketQuote(StrictModel):
    symbol: str
    bid: Decimal
    ask: Decimal
    last: Decimal
    as_of_utc: str


class RiskCheckResult(StrictModel):
    name: str
    passed: bool
    observed: str
    limit: str
    detail: str


class OrderProposal(StrictModel):
    proposal_hash: str
    account_id: str
    symbol: str
    side: Side
    quantity: Decimal
    order_type: OrderType
    reference_price: Decimal
    estimated_notional: Decimal
    post_trade_weight_pct: Decimal
    snapshot_hash: str
    created_at_utc: str
    expires_at_utc: str
    all_checks_passed: bool
    checks: list[RiskCheckResult]
    status: Literal["READY_FOR_APPROVAL", "REJECTED_BY_RISK"]


class ApprovalRecord(StrictModel):
    proposal_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    decision: Literal["approve", "reject"]
    approver_id: str = Field(min_length=3, max_length=128)
    decided_at_utc: str
    note: str = Field(default="", max_length=300)


class SignedApproval(StrictModel):
    record: ApprovalRecord
    signature_hex: str = Field(pattern=r"^[a-f0-9]{128}$")


class BrokerOrderReceipt(StrictModel):
    broker_order_id: str
    idempotency_key: str
    proposal_hash: str
    account_id: str
    symbol: str
    side: Side
    quantity: Decimal
    fill_price: Decimal
    notional: Decimal
    status: Literal["FILLED", "REJECTED"]
    executed_at_utc: str
