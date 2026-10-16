"""Who is acting, and are they allowed to use this tool at all? (least privilege + kill switch)"""
from __future__ import annotations

from ..models import Decision, Signal
from .base import TIER_BASE, Context


def identity(ctx: Context) -> list[Signal]:
    call = ctx.call
    if ctx.kill_switch:
        return [Signal("identity", 1.0, "Global kill switch engaged - every agent action is frozen",
                       "critical", Decision.BLOCK, ["ASI10"], {"kill_switch": True})]
    if ctx.agent is None:
        return [Signal("identity", 1.0, f"Unknown agent '{call.agent_id}' - no identity is registered with AEGIS",
                       "critical", Decision.BLOCK, ["ASI03"])]
    if ctx.agent.status != "active":
        return [Signal("identity", 1.0,
                       f"{ctx.agent.name} is {ctx.agent.status} ({ctx.agent.status_reason or 'by an operator'}) "
                       "- its actions are suspended", "critical", Decision.BLOCK, ["ASI10"],
                       {"suspended": True})]
    signals: list[Signal] = []
    if ctx.spec is None:
        effect = Decision(ctx.policy.enforcement.get("unknown_tools", "block"))
        signals.append(Signal("identity", 0.9 if effect == Decision.BLOCK else 0.6,
                              f"Unknown tool '{call.tool}' is not in the AEGIS tool catalogue", "high", effect,
                              ["ASI02"]))
        return signals
    if call.tool not in ctx.agent.tools:
        signals.append(Signal(
            "identity", 0.95,
            f"Privilege violation: {ctx.agent.name} ({ctx.agent.role}) is not authorised to use {call.tool}",
            "critical", Decision.BLOCK, ["ASI03", "LLM06"], {"allowed_tools": ctx.agent.tools}))
    spec = ctx.spec
    signals.append(Signal("baseline", TIER_BASE.get(spec.tier, 0.05),
                          f"{spec.tier}-tier {'irreversible ' if not spec.reversible else ''}{spec.side_effect} action",
                          "info", evidence={"tier": spec.tier, "reversible": spec.reversible}))
    return signals
