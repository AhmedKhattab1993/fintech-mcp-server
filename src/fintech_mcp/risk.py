"""Deterministic Decimal pre-trade risk engine and immutable proposal hashing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal

from fintech_mcp.canonical import sha256_hex
from fintech_mcp.schemas import (
    BalanceSnapshot,
    EvaluateOrderRiskInput,
    MarketQuote,
    OrderProposal,
    OrderType,
    Position,
    RiskCheckResult,
    Side,
)

MONEY_QUANT = Decimal("0.01")
PCT_QUANT = Decimal("0.01")


@dataclass(frozen=True)
class RiskPolicy:
    max_order_notional_usd: Decimal = Decimal("250000.00")
    max_single_name_weight_pct: Decimal = Decimal("15.00")
    allowed_symbols: frozenset[str] = frozenset(
        {"AAPL", "MSFT", "NVDA", "SPY", "QQQ", "TLT", "IEF"}
    )
    proposal_ttl_seconds: int = 900
    max_price_drift_bps: Decimal = Decimal("50")  # 0.50%


def compute_snapshot_hash(
    balances: BalanceSnapshot,
    positions: list[Position],
    quote: MarketQuote,
) -> str:
    payload = {
        "account_id": balances.account_id,
        "cash": balances.cash,
        "nav": balances.nav,
        "positions": [
            {"symbol": p.symbol, "qty": p.quantity, "mv": p.market_value}
            for p in sorted(positions, key=lambda x: x.symbol)
        ],
        "quote": {"symbol": quote.symbol, "last": quote.last, "as_of": quote.as_of_utc},
    }
    return sha256_hex(payload)


def evaluate_order_proposal(
    intent: EvaluateOrderRiskInput,
    balances: BalanceSnapshot,
    positions: list[Position],
    quote: MarketQuote,
    policy: RiskPolicy,
    now_utc: datetime,
) -> OrderProposal:
    """Compute exact notional, post-trade concentration, and deterministic risk checks."""
    if intent.order_type == OrderType.LIMIT and intent.limit_price is not None:
        ref_price = intent.limit_price.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    else:
        ref_price = (quote.ask if intent.side == Side.BUY else quote.bid).quantize(
            MONEY_QUANT, rounding=ROUND_HALF_UP
        )

    notional = (intent.quantity * ref_price).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    existing = next((p for p in positions if p.symbol == intent.symbol), None)
    current_qty = existing.quantity if existing else Decimal("0")
    current_val = existing.market_value if existing else Decimal("0.00")

    if intent.side == Side.BUY:
        post_val = current_val + notional
    else:
        post_val = max(Decimal("0.00"), current_val - notional)

    post_weight_pct = (
        ((post_val / balances.nav) * Decimal("100")).quantize(PCT_QUANT, rounding=ROUND_HALF_UP)
        if balances.nav > Decimal("0")
        else Decimal("100.00")
    )

    checks: list[RiskCheckResult] = []

    # 1. Allowed universe check
    allowed = intent.symbol in policy.allowed_symbols
    checks.append(
        RiskCheckResult(
            name="allowed_instrument",
            passed=allowed,
            observed=intent.symbol,
            limit="policy whitelist",
            detail="Symbol permitted by desk universe"
            if allowed
            else "Symbol not in approved universe",
        )
    )

    # 2. Max single-order notional ceiling
    within_ceiling = notional <= policy.max_order_notional_usd
    checks.append(
        RiskCheckResult(
            name="order_notional_ceiling",
            passed=within_ceiling,
            observed=f"${notional:,.2f}",
            limit=f"${policy.max_order_notional_usd:,.2f}",
            detail="Within hard order notional ceiling"
            if within_ceiling
            else "Exceeds max single-order ceiling",
        )
    )

    # 3. Buying power / short-sale guard
    if intent.side == Side.BUY:
        funded = notional <= balances.buying_power
        checks.append(
            RiskCheckResult(
                name="buying_power",
                passed=funded,
                observed=f"${notional:,.2f}",
                limit=f"${balances.buying_power:,.2f}",
                detail="Sufficient buying power"
                if funded
                else "Insufficient buying power for BUY order",
            )
        )
    else:
        has_shares = intent.quantity <= current_qty
        checks.append(
            RiskCheckResult(
                name="long_only_inventory",
                passed=has_shares,
                observed=f"{intent.quantity} shares",
                limit=f"{current_qty} held",
                detail="Sell covered by existing inventory"
                if has_shares
                else "Short selling disabled; exceeds held shares",
            )
        )

    # 4. Post-trade single-name concentration limit
    within_weight = post_weight_pct <= policy.max_single_name_weight_pct
    checks.append(
        RiskCheckResult(
            name="single_name_concentration",
            passed=within_weight,
            observed=f"{post_weight_pct}%",
            limit=f"{policy.max_single_name_weight_pct}%",
            detail="Post-trade exposure within single-name cap"
            if within_weight
            else "Post-trade weight breaches single-name concentration cap",
        )
    )

    all_passed = all(c.passed for c in checks)
    snapshot_hash = compute_snapshot_hash(balances, positions, quote)
    created_at = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at = (now_utc + timedelta(seconds=policy.proposal_ttl_seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    hash_payload = {
        "account_id": intent.account_id,
        "symbol": intent.symbol,
        "side": intent.side.value,
        "quantity": intent.quantity,
        "order_type": intent.order_type.value,
        "reference_price": ref_price,
        "estimated_notional": notional,
        "snapshot_hash": snapshot_hash,
        "created_at_utc": created_at,
        "expires_at_utc": expires_at,
    }
    proposal_hash = sha256_hex(hash_payload)

    return OrderProposal(
        proposal_hash=proposal_hash,
        account_id=intent.account_id,
        symbol=intent.symbol,
        side=intent.side,
        quantity=intent.quantity,
        order_type=intent.order_type,
        reference_price=ref_price,
        estimated_notional=notional,
        post_trade_weight_pct=post_weight_pct,
        snapshot_hash=snapshot_hash,
        created_at_utc=created_at,
        expires_at_utc=expires_at,
        all_checks_passed=all_passed,
        checks=checks,
        status="READY_FOR_APPROVAL" if all_passed else "REJECTED_BY_RISK",
    )
