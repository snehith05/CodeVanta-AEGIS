"""Core data types shared by the gateway, the detectors and the API."""
from __future__ import annotations

import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    """What AEGIS does with an action, from most to least permissive."""

    ALLOW = "allow"          # run it
    FLAG = "flag"            # run it, but raise an alert for a human to review later
    REDACT = "redact"        # run it with sensitive data masked out of the arguments
    ESCALATE = "escalate"    # hold it until a human approves (fail-closed on timeout)
    BLOCK = "block"          # never run it

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Decision.ALLOW: 0, Decision.FLAG: 1, Decision.REDACT: 2, Decision.ESCALATE: 3, Decision.BLOCK: 4}


def strictest(*decisions: Decision | None) -> Decision:
    present = [d for d in decisions if d is not None]
    return max(present, key=lambda d: d.rank) if present else Decision.ALLOW


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class Signal:
    """One detector's opinion about an action.

    ``score`` (0..1) feeds the combined risk score. ``hard`` is a decision the
    detector insists on regardless of score - e.g. RBAC violations always block.
    """

    detector: str
    score: float
    reason: str
    severity: str = "medium"
    hard: Decision | None = None
    tags: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    redacted_args: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "score": round(self.score, 3),
            "reason": self.reason,
            "severity": self.severity,
            "hard": self.hard.value if self.hard else None,
            "tags": self.tags,
            "evidence": self.evidence,
        }


@dataclass
class ToolCall:
    agent_id: str
    tool: str
    args: dict[str, Any]
    session_id: str
    origin: str = "api"  # scenario | playground | sdk | api
    id: str = field(default_factory=lambda: "act_" + uuid.uuid4().hex[:10])
    ts: float = field(default_factory=time.time)


@dataclass
class Verdict:
    decision: Decision
    risk: int  # 0..100
    reason: str
    signals: list[Signal]
    latency_ms: float
    args: dict[str, Any]  # the arguments that will actually run (masked when REDACT)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "risk": self.risk,
            "reason": self.reason,
            "latency_ms": round(self.latency_ms, 3),
            "signals": [s.to_dict() for s in self.signals],
        }


@dataclass
class ActionRecord:
    """Everything AEGIS knows about one intercepted action, for the dashboard and API."""

    call: ToolCall
    verdict: Verdict
    status: str  # executed | blocked | pending | denied | expired | error
    enforced: bool = True  # False in monitor (shadow) mode
    output: Any = None
    output_preview: str = ""
    post_signals: list[Signal] = field(default_factory=list)
    approval_id: str | None = None
    decided_by: str | None = None
    ledger_seq: int | None = None
    ledger_hash: str | None = None
    narration: str = ""

    def to_dict(self, include_output: bool = False) -> dict[str, Any]:
        d = {
            "id": self.call.id,
            "ts": self.call.ts,
            "agent_id": self.call.agent_id,
            "session_id": self.call.session_id,
            "origin": self.call.origin,
            "tool": self.call.tool,
            "args": self.call.args,
            "effective_args": self.verdict.args,
            "status": self.status,
            "enforced": self.enforced,
            "output_preview": self.output_preview,
            "post_signals": [s.to_dict() for s in self.post_signals],
            "approval_id": self.approval_id,
            "decided_by": self.decided_by,
            "ledger_seq": self.ledger_seq,
            "ledger_hash": self.ledger_hash,
            "narration": self.narration,
            **self.verdict.to_dict(),
        }
        if include_output:
            d["output"] = self.output
        return d


@dataclass
class TaintEntry:
    """A value that entered the agent's context from a source AEGIS does not trust."""

    value: str
    source_tool: str
    source_ref: str
    source_label: str
    injected: bool
    action_id: str


@dataclass
class Session:
    """One agent task. Provenance and intent are tracked per session."""

    id: str
    agent_id: str
    task: str
    started: float = field(default_factory=time.time)
    taint: dict[str, TaintEntry] = field(default_factory=dict)
    trusted_values: set[str] = field(default_factory=set)
    trusted_texts: list[str] = field(default_factory=list)
    untrusted_texts: list[dict[str, Any]] = field(default_factory=list)
    injection_sources: list[dict[str, Any]] = field(default_factory=list)
    scope: set[str] = field(default_factory=set)
    read_only: bool = False

    @property
    def compromised(self) -> bool:
        return bool(self.injection_sources)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "task": self.task,
            "started": self.started,
            "scope": sorted(self.scope),
            "read_only": self.read_only,
            "tainted_values": len(self.taint),
            "injection_sources": self.injection_sources,
            "compromised": self.compromised,
        }


@dataclass
class AgentState:
    id: str
    name: str
    role: str
    owner: str
    description: str
    tools: list[str]
    limits: dict[str, Any]
    color: str = "#d4a537"
    status: str = "active"  # active | paused | quarantined
    status_reason: str = ""
    trust: float = 100.0
    counts: dict[str, int] = field(default_factory=lambda: {d.value: 0 for d in Decision})
    last_seen: float | None = None
    recent_calls: deque = field(default_factory=lambda: deque(maxlen=500))   # (ts, fingerprint)
    recent_blocks: deque = field(default_factory=lambda: deque(maxlen=100))  # ts
    spend_today: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "owner": self.owner,
            "description": self.description,
            "tools": self.tools,
            "limits": self.limits,
            "color": self.color,
            "status": self.status,
            "status_reason": self.status_reason,
            "trust": round(self.trust, 1),
            "counts": self.counts,
            "last_seen": self.last_seen,
            "spend_today": self.spend_today,
        }
