"""Circuit breaker: runaway loops, bursts and quota abuse (OWASP ASI08 cascading failures / ASI10 rogue agents)."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..models import Decision, Signal
from .base import Context


def fingerprint(tool: str, args: dict[str, Any]) -> str:
    digest = hashlib.sha1(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()[:12]
    return f"{tool}|{digest}"


def velocity(ctx: Context) -> list[Signal]:
    agent = ctx.agent
    if agent is None:
        return []
    cb = ctx.policy.breaker
    now, tool = ctx.now, ctx.call.tool
    signals: list[Signal] = []

    window, max_calls = cb.get("rate_window_seconds", 10), cb.get("max_calls", 25)
    burst = sum(1 for t, _ in agent.recent_calls if now - t <= window) + 1
    if burst > max_calls:
        signals.append(Signal("velocity", 0.85, f"Rate anomaly: {burst} actions in {window}s (limit {max_calls})",
                              "high", Decision.BLOCK, ["ASI08", "ASI10"], {"calls": burst, "window_s": window}))

    fp = fingerprint(tool, ctx.args)
    dup_window, max_dup = cb.get("duplicate_window_seconds", 60), cb.get("max_duplicates", 3)
    repeats = sum(1 for t, f in agent.recent_calls if f == fp and now - t <= dup_window) + 1
    if repeats > max_dup:
        signals.append(Signal("velocity", 0.8,
                              f"Loop detected: the identical {tool} call was attempted {repeats}x in {dup_window}s",
                              "high", Decision.BLOCK, ["ASI08"], {"repeats": repeats}))

    quota = ctx.policy.limits(agent.id, tool).get("max_per_hour")
    if quota:
        used = sum(1 for t, f in agent.recent_calls if f.startswith(tool + "|") and now - t <= 3600) + 1
        if used > quota:
            signals.append(Signal("velocity", 0.5, f"Hourly quota: {used} {tool} calls this hour (limit {quota})",
                                  "medium", Decision.ESCALATE, ["ASI08"]))
    return signals
