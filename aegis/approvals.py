"""Human-in-the-loop approval queue. Unanswered requests expire as denials (fail-closed)."""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Approval:
    id: str
    action_id: str
    agent_id: str
    tool: str
    args: dict[str, Any]
    risk: int
    reason: str
    signals: list[dict[str, Any]]
    created: float
    expires: float
    status: str = "pending"  # pending | approved | denied | expired
    decided_by: str | None = None
    note: str = ""
    decided_at: float | None = None
    future: asyncio.Future | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "action_id": self.action_id, "agent_id": self.agent_id, "tool": self.tool,
            "args": self.args, "risk": self.risk, "reason": self.reason, "signals": self.signals,
            "created": self.created, "expires": self.expires, "status": self.status,
            "decided_by": self.decided_by, "note": self.note, "decided_at": self.decided_at,
        }


class ApprovalQueue:
    def __init__(self) -> None:
        self.items: dict[str, Approval] = {}

    def create(self, action_id: str, agent_id: str, tool: str, args: dict[str, Any], risk: int, reason: str,
               signals: list[dict[str, Any]], timeout: float) -> Approval:
        now = time.time()
        approval = Approval(id="apr_" + uuid.uuid4().hex[:8], action_id=action_id, agent_id=agent_id, tool=tool,
                            args=args, risk=risk, reason=reason, signals=signals, created=now, expires=now + timeout)
        try:
            approval.future = asyncio.get_running_loop().create_future()
        except RuntimeError:
            approval.future = None
        self.items[approval.id] = approval
        return approval

    def decide(self, approval_id: str, approve: bool, by: str, note: str = "") -> Approval:
        approval = self.items.get(approval_id)
        if approval is None:
            raise KeyError(approval_id)
        if approval.status != "pending":
            return approval
        approval.status = "approved" if approve else "denied"
        approval.decided_by = by
        approval.note = note
        approval.decided_at = time.time()
        if approval.future and not approval.future.done():
            approval.future.set_result(approval.status)
        return approval

    async def wait(self, approval_id: str) -> Approval:
        approval = self.items[approval_id]
        if approval.status != "pending" or approval.future is None:
            return approval
        remaining = max(0.0, approval.expires - time.time())
        try:
            await asyncio.wait_for(asyncio.shield(approval.future), timeout=remaining)
        except asyncio.TimeoutError:
            if approval.status == "pending":
                approval.status = "expired"
                approval.decided_by = "aegis (timeout)"
                approval.decided_at = time.time()
        return approval

    def pending(self) -> list[Approval]:
        return [a for a in self.items.values() if a.status == "pending"]

    def recent(self, n: int = 20) -> list[Approval]:
        return sorted(self.items.values(), key=lambda a: a.created, reverse=True)[:n]
