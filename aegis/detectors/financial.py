"""Money controls: limits, beneficiary verification, bank-detail-change fraud, anomalies, refunds."""
from __future__ import annotations

import re

from ..models import Decision, Signal
from ..sandbox.world import ToolError, to_amount
from .base import Context, inr


def financial(ctx: Context) -> list[Signal]:
    tool = ctx.call.tool
    if tool not in ("payments.transfer", "payments.refund"):
        return []
    args = ctx.args
    try:
        amount = to_amount(args.get("amount"))
    except ToolError:
        return [Signal("financial", 0.6, "Payment amount is missing or invalid", "high", Decision.ESCALATE)]
    agent_name = ctx.agent_name
    limits = ctx.policy.limits(ctx.call.agent_id, tool)
    signals: list[Signal] = []

    hard_max, auto_max, daily_max = limits.get("hard_max"), limits.get("auto_approve_max"), limits.get("daily_max")
    if hard_max is not None and amount > hard_max:
        signals.append(Signal("financial", 0.9, f"{inr(amount)} exceeds {agent_name}'s hard limit of {inr(hard_max)}",
                              "critical", Decision.BLOCK, ["LLM06"], {"amount": amount, "hard_max": hard_max}))
    elif auto_max is not None and amount > auto_max:
        signals.append(Signal("financial", 0.45,
                              f"{inr(amount)} is above the {inr(auto_max)} auto-approve limit - needs human sign-off",
                              "medium", Decision.ESCALATE, ["LLM06"], {"amount": amount, "auto_approve_max": auto_max}))
    if daily_max is not None and ctx.agent and ctx.agent.spend_today + amount > daily_max:
        signals.append(Signal("financial", 0.5,
                              f"Daily limit: {inr(ctx.agent.spend_today + amount)} would exceed {inr(daily_max)} today",
                              "high", Decision.ESCALATE, ["LLM06"]))

    if tool == "payments.transfer":
        signals += _beneficiary_checks(ctx, amount)
    else:
        signals += _refund_checks(ctx, amount)
    return signals


_IFSC = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")


def _beneficiary_checks(ctx: Context, amount: float) -> list[Signal]:
    world, args = ctx.world, ctx.args
    raw = str(args.get("to_account") or "").strip()
    account = re.sub(r"[\s-]", "", raw)
    ifsc_raw = str(args.get("ifsc") or "").strip().upper()
    # Hallucination guard: garbled parameters on an irreversible payment must never run.
    if not (account.isdigit() and 9 <= len(account) <= 18):
        hint = " - that is an IFSC code; the agent mixed up the fields" if _IFSC.match(raw.upper()) else ""
        return [Signal("financial", 0.85, f"Malformed beneficiary account '{raw}' (expected 9-18 digits){hint}",
                       "high", Decision.BLOCK, ["ASI02"], {"to_account": raw})]
    if not ifsc_raw:
        return [Signal("financial", 0.45, "IFSC code missing - the bank cannot route this payment safely", "medium",
                       Decision.ESCALATE, ["ASI02"])]
    if not _IFSC.match(ifsc_raw):
        return [Signal("financial", 0.8, f"Malformed IFSC code '{ifsc_raw}'", "high", Decision.BLOCK, ["ASI02"])]
    vendor = world.vendor_by_account(account)
    signals: list[Signal] = []
    if vendor is None:
        named = world.vendor_by_name(str(args.get("beneficiary_name") or ""))
        if named:
            signals.append(Signal(
                "financial", 0.7,
                f"Bank details changed: '{named['name']}' is on file with a/c …{named['account'][-4:]}, "
                f"but this payment goes to a/c …{account[-4:]} (invoice-redirection fraud pattern)",
                "high", None, ["ASI01"], {"vendor": named["id"], "account_on_file": named["account"],
                                          "account_requested": account}))
        else:
            signals.append(Signal("financial", 0.5,
                                  f"New beneficiary: a/c …{account[-4:] or '????'} is not in the vendor master",
                                  "high", None, ["ASI02"], {"account": account}))
        return signals
    ifsc = str(args.get("ifsc") or "").strip().upper()
    if ifsc and ifsc != vendor["ifsc"]:
        signals.append(Signal("financial", 0.4, f"IFSC {ifsc} does not match the vendor master ({vendor['ifsc']})",
                              "medium", None, ["ASI01"]))
    avg = world.vendor_average(vendor["id"])
    if avg and amount > 3 * avg:
        signals.append(Signal("financial", 0.35,
                              f"{inr(amount)} is {amount / avg:.1f}x {vendor['name']}'s average payment ({inr(avg)})",
                              "medium", None, [], {"vendor_average": round(avg)}))
    memo = str(args.get("memo") or "").strip().lower()
    if memo:
        dup = next((t for t in world.transfers if t["memo"].strip().lower() == memo and t["account"] == account), None)
        if dup:
            signals.append(Signal("financial", 0.7, f"Duplicate payment: '{args.get('memo')}' was already paid "
                                                    f"(UTR {dup['ref']})", "high", Decision.BLOCK, ["ASI02"]))
    return signals


def _refund_checks(ctx: Context, amount: float) -> list[Signal]:
    order_id = str(ctx.args.get("order_id") or "")
    order = ctx.world.order(order_id)
    if order is None:
        return [Signal("financial", 0.6, f"Order '{order_id}' does not exist", "high", Decision.BLOCK, ["ASI02"])]
    signals = []
    if order["refunded"]:
        signals.append(Signal("financial", 0.7, f"{order['id']} was already refunded - duplicate refund", "high",
                              Decision.BLOCK, ["ASI02"]))
    if amount > order["amount"]:
        signals.append(Signal("financial", 0.7,
                              f"Refund {inr(amount)} exceeds the order value of {inr(order['amount'])}", "high",
                              Decision.BLOCK, ["ASI02"]))
    return signals
