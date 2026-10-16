"""Lookalike / typo-squatted domains in recipients and URLs (phishing and BEC infrastructure)."""
from __future__ import annotations

from ..models import Decision, Signal
from ..textscan import domain_of, lookalike_of
from .base import Context, recipients


def trusted_domains(ctx: Context) -> list[str]:
    return sorted(set(ctx.policy.trusted_domains) | {domain_of(v["email"]) for v in ctx.world.vendors()})


def lookalike(ctx: Context) -> list[Signal]:
    tool = ctx.call.tool
    if tool == "email.send":
        targets = recipients(ctx.args.get("to"))
    elif tool == "web.fetch":
        targets = [str(ctx.args.get("url") or "")]
    else:
        return []
    trusted = trusted_domains(ctx)
    signals = []
    for target in targets:
        domain = domain_of(target)
        imitated = lookalike_of(domain, trusted)
        if imitated:
            signals.append(Signal("lookalike", 0.65, f"'{domain}' imitates the trusted domain '{imitated}'", "high",
                                  Decision.ESCALATE, ["ASI09"], {"domain": domain, "imitates": imitated}))
    return signals
