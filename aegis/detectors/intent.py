"""Intent drift: is this action plausibly part of the task the human actually gave?

Goal hijacking (OWASP ASI01) shows up as an agent suddenly doing something its task
never asked for - a "summarise the tickets" job that starts sending email, a
"fetch prices" job that starts running shell commands.
"""
from __future__ import annotations

import re

from ..models import Decision, Signal
from ..textscan import is_internal
from .base import Context, recipients

SCOPE_WORDS: dict[str, list[str]] = {
    "finance": ["pay", "payment", "invoice", "refund", "vendor", "transfer", "salary", "reimburse", "bill", "settle",
                "gst", "remit"],
    "support": ["ticket", "complaint", "resolve", "support", "charged", "issue"],
    "crm": ["customer", "client", "lead", "crm", "contact"],
    "comms": ["email", "mail", "inbox", "reply", "notify", "inform", "message", "newsletter", "offer", "campaign",
              "outreach", "send"],
    "data": ["database", "db", "table", "record", "sql", "report", "logs", "data", "backup", "migrate", "order"],
    "files": ["file", "folder", "disk", "space", "log", "export", "archive", "price list", "csv"],
    "system": ["server", "disk", "space", "deploy", "restart", "shell", "maintenance", "cleanup", "clean up"],
    "web": ["website", "web", "url", "online", "internet", "price", "research", "browse", "fetch"],
    "identity": ["access", "permission", "role", "onboard", "offboard", "login"],
}
EXPAND = {"support": {"crm", "comms"}, "comms": {"crm"}, "finance": {"comms"}, "system": {"files"}, "data": {"files"}}
READ_VERBS = ["summarize", "summarise", "list", "check", "review", "find", "show", "analyse", "analyze", "count",
              "how many", "what", "look up", "report on", "tell me", "status", "investigate", "fetch", "get", "read"]
WRITE_VERBS = ["pay", "send", "email", "reply", "delete", "remove", "clean", "update", "refund", "transfer", "write",
               "create", "grant", "process", "resolve", "run", "fix", "free up", "drop", "post", "notify", "change",
               "set", "move", "archive", "approve", "book", "cancel", "upload", "share"]


def _has(text: str, words: list[str]) -> bool:
    return any(re.search(rf"\b{re.escape(w)}(e?s|ed|ing)?\b", text) for w in words)


def infer_scope(task: str) -> tuple[set[str], bool]:
    t = (task or "").lower()
    if not t.strip():
        return set(), False
    scope = {cat for cat, words in SCOPE_WORDS.items() if _has(t, words)}
    for cat in list(scope):
        scope |= EXPAND.get(cat, set())
    read_only = _has(t, READ_VERBS) and not _has(t, WRITE_VERBS)
    return scope, read_only


def intent(ctx: Context) -> list[Signal]:
    s, spec = ctx.session, ctx.spec
    if spec is None or not s.task:
        return []
    if ctx.call.tool == "email.send":
        to = recipients(ctx.args.get("to"))
        if to and all(is_internal(r, ctx.policy.internal_domains) for r in to):
            return []  # reporting back inside the company is always in scope
    short = s.task if len(s.task) <= 70 else s.task[:67] + "..."
    evidence = {"task": s.task, "scope": sorted(s.scope), "category": spec.category, "read_only": s.read_only}
    if spec.side_effect == "write" and s.read_only:
        score = 0.5 + (0.25 if s.compromised else 0.0)
        return [Signal("intent", score,
                       f"Goal drift: the task \"{short}\" is read-only, but the agent attempted {ctx.call.tool}",
                       "high", Decision.ESCALATE, ["ASI01"], evidence)]
    if s.scope and spec.category not in s.scope:
        if spec.side_effect == "read":
            score = 0.15 + (0.15 if s.compromised else 0.0)
        else:
            score = 0.4 + (0.3 if s.compromised else 0.0) + (0.15 if spec.tier == "critical" else 0.0)
        score = min(score, 0.85)
        severity = "high" if score >= 0.5 else "medium" if score >= 0.3 else "low"
        what = "Out of scope" if spec.side_effect == "write" else "Unusual for this task"
        return [Signal("intent", score,
                       f"{what}: {ctx.call.tool} ({spec.category}) isn't part of the task \"{short}\"",
                       severity, None, ["ASI01"], evidence)]
    return []
