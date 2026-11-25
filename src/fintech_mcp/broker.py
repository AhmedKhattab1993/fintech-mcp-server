"""Broker adapter protocol and deterministic in-memory sandbox implementation."""

from __future__ import annotations

from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Protocol

from fintech_mcp.schemas import (
    BalanceSnapshot,
    BrokerOrderReceipt,
    MarketQuote,
    OrderProposal,
    Position,
    Side,
)

MONEY_QUANT = Decimal("0.01")
PCT_QUANT = Decimal("0.01")


class BrokerAdapter(Protocol):
    def get_balances(self, account_id: str) -> BalanceSnapshot: ...
    def get_positions(self, account_id: str, limit: int = 50) -> list[Position]: ...
    def get_quote(self, symbol: str) -> MarketQuote: ...
    def submit_order(
        self, proposal: OrderProposal, idempotency_key: str, now_utc: datetime
    ) -> BrokerOrderReceipt: ...


class SandboxBrokerAdapter:
    """Deterministic sandbox broker mimicking IBKR/Alpaca REST accounts and quotes."""

    def __init__(self) -> None:
        self._cash: dict[str, Decimal] = {
            "acct_alpha_01": Decimal("420000.00"),
            "acct_beta_02": Decimal("180000.00"),
        }
        self._holdings: dict[str, dict[str, tuple[Decimal, Decimal]]] = {
            "acct_alpha_01": {
                "AAPL": (Decimal("1000"), Decimal("210.50")),
                "MSFT": (Decimal("600"), Decimal("415.00")),
                "SPY": (Decimal("2500"), Decimal("550.00")),
                "TLT": (Decimal("4000"), Decimal("92.00")),
            },
            "acct_beta_02": {
                "QQQ": (Decimal("900"), Decimal("480.00")),
                "IEF": (Decimal("2000"), Decimal("95.00")),
            },
        }
        self._quotes: dict[str, MarketQuote] = {
            "AAPL": MarketQuote(
                symbol="AAPL",
                bid=Decimal("228.40"),
                ask=Decimal("228.50"),
                last=Decimal("228.45"),
                as_of_utc="2026-11-25T15:00:00Z",
            ),
            "MSFT": MarketQuote(
                symbol="MSFT",
                bid=Decimal("432.10"),
                ask=Decimal("432.30"),
                last=Decimal("432.20"),
                as_of_utc="2026-11-25T15:00:00Z",
            ),
            "NVDA": MarketQuote(
                symbol="NVDA",
                bid=Decimal("141.90"),
                ask=Decimal("142.00"),
                last=Decimal("141.95"),
                as_of_utc="2026-11-25T15:00:00Z",
            ),
            "SPY": MarketQuote(
                symbol="SPY",
                bid=Decimal("598.10"),
                ask=Decimal("598.20"),
                last=Decimal("598.15"),
                as_of_utc="2026-11-25T15:00:00Z",
            ),
            "QQQ": MarketQuote(
                symbol="QQQ",
                bid=Decimal("512.00"),
                ask=Decimal("512.10"),
                last=Decimal("512.05"),
                as_of_utc="2026-11-25T15:00:00Z",
            ),
            "TLT": MarketQuote(
                symbol="TLT",
                bid=Decimal("91.40"),
                ask=Decimal("91.50"),
                last=Decimal("91.45"),
                as_of_utc="2026-11-25T15:00:00Z",
            ),
            "IEF": MarketQuote(
                symbol="IEF",
                bid=Decimal("94.10"),
                ask=Decimal("94.20"),
                last=Decimal("94.15"),
                as_of_utc="2026-11-25T15:00:00Z",
            ),
        }
        self._receipts_by_idempotency: dict[str, BrokerOrderReceipt] = {}
        self._seq = 1000

    def set_quote_price(self, symbol: str, last: Decimal) -> None:
        q = self._quotes[symbol]
        self._quotes[symbol] = MarketQuote(
            symbol=symbol,
            bid=(last - Decimal("0.05")).quantize(MONEY_QUANT),
            ask=(last + Decimal("0.05")).quantize(MONEY_QUANT),
            last=last.quantize(MONEY_QUANT),
            as_of_utc=q.as_of_utc,
        )

    def get_quote(self, symbol: str) -> MarketQuote:
        sym = symbol.upper()
        if sym not in self._quotes:
            raise KeyError(f"Unknown symbol '{sym}'")
        return self._quotes[sym]

    def get_balances(self, account_id: str) -> BalanceSnapshot:
        if account_id not in self._cash:
            raise KeyError(f"Unknown account '{account_id}'")
        cash = self._cash[account_id]
        equity = Decimal("0.00")
        for sym, (qty, _) in self._holdings.get(account_id, {}).items():
            equity += (qty * self._quotes[sym].last).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
        nav = (cash + equity).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
        return BalanceSnapshot(account_id=account_id, cash=cash, buying_power=cash, nav=nav)

    def get_positions(self, account_id: str, limit: int = 50) -> list[Position]:
        bal = self.get_balances(account_id)
        positions: list[Position] = []
        for sym in sorted(self._holdings.get(account_id, {}))[:limit]:
            qty, avg_cost = self._holdings[account_id][sym]
            if qty == Decimal("0"):
                continue
            px = self._quotes[sym].last
            mv = (qty * px).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
            wt = ((mv / bal.nav) * Decimal("100")).quantize(PCT_QUANT, rounding=ROUND_HALF_UP)
            positions.append(
                Position(
                    symbol=sym,
                    quantity=qty,
                    avg_cost=avg_cost,
                    market_price=px,
                    market_value=mv,
                    weight_pct=wt,
                )
            )
        return positions

    def submit_order(
        self, proposal: OrderProposal, idempotency_key: str, now_utc: datetime
    ) -> BrokerOrderReceipt:
        if idempotency_key in self._receipts_by_idempotency:
            return self._receipts_by_idempotency[idempotency_key]

        quote = self.get_quote(proposal.symbol)
        fill_px = quote.ask if proposal.side == Side.BUY else quote.bid
        notional = (proposal.quantity * fill_px).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

        holdings = self._holdings.setdefault(proposal.account_id, {})
        cur_qty, cur_avg = holdings.get(proposal.symbol, (Decimal("0"), fill_px))

        if proposal.side == Side.BUY:
            new_qty = cur_qty + proposal.quantity
            new_avg = (((cur_qty * cur_avg) + notional) / new_qty).quantize(
                MONEY_QUANT, rounding=ROUND_HALF_UP
            )
            holdings[proposal.symbol] = (new_qty, new_avg)
            self._cash[proposal.account_id] = (self._cash[proposal.account_id] - notional).quantize(
                MONEY_QUANT
            )
        else:
            new_qty = cur_qty - proposal.quantity
            holdings[proposal.symbol] = (new_qty, cur_avg)
            self._cash[proposal.account_id] = (self._cash[proposal.account_id] + notional).quantize(
                MONEY_QUANT
            )

        self._seq += 1
        receipt = BrokerOrderReceipt(
            broker_order_id=f"SBX-{self._seq}",
            idempotency_key=idempotency_key,
            proposal_hash=proposal.proposal_hash,
            account_id=proposal.account_id,
            symbol=proposal.symbol,
            side=proposal.side,
            quantity=proposal.quantity,
            fill_price=fill_px,
            notional=notional,
            status="FILLED",
            executed_at_utc=now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        self._receipts_by_idempotency[idempotency_key] = receipt
        return receipt
