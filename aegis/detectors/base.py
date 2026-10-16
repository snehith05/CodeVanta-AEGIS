"""Shared context handed to every detector."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..models import AgentState, Session, ToolCall
from ..policy import Policy
from ..sandbox.tools import ToolSpec

if TYPE_CHECKING:
    from ..sandbox.world import World

TIER_BASE = {"low": 0.02, "medium": 0.05, "high": 0.1, "critical": 0.15}


@dataclass
class Context:
    call: ToolCall
    spec: ToolSpec | None
    agent: AgentState | None
    session: Session
    policy: Policy
    world: "World"
    kill_switch: bool
    now: float

    @property
    def args(self) -> dict[str, Any]:
        return self.call.args

    @property
    def agent_name(self) -> str:
        return self.agent.name if self.agent else self.call.agent_id


def recipients(value: Any) -> list[str]:
    return [a.strip() for a in re.split(r"[,;]", str(value or "")) if a.strip()]


def inr(amount: float) -> str:
    """Format rupees the Indian way: 4,85,000."""
    n = int(round(amount))
    s = str(abs(n))
    if len(s) > 3:
        head, tail = s[:-3], s[-3:]
        head = ",".join([head[max(0, i - 2):i] for i in range(len(head), 0, -2)][::-1])
        s = head + "," + tail
    return ("-" if n < 0 else "") + "₹" + s
