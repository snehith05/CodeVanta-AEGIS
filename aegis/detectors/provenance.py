"""Provenance (taint) tracking - the core defence against indirect prompt injection.

When an agent reads untrusted content (emails, tickets, web pages, uploaded files)
AEGIS remembers every actionable value in it: account numbers, IFSC codes, email
addresses, URLs, commands. If a later high-impact action uses one of those values
and nothing trusted (the vendor master, the CRM, the human's own instruction)
vouches for it, the action is treated as attacker-steered. This works no matter
how cleverly the injection is worded, because it follows the data, not the words.
"""
from __future__ import annotations

import re
from typing import Any

from ..models import Decision, Signal, TaintEntry
from ..textscan import EMAIL_RE, domain_of, is_internal, normalize_value, squash
from .base import Context

_TEXTUAL = {"beneficiary_name", "command", "sql", "principal", "path", "url"}


def _trusted_index(ctx: Context) -> set[str]:
    idx = set(ctx.session.trusted_values)
    for v in ctx.world.vendors():
        idx.update({v["account"], v["ifsc"].lower(), v["email"].lower(), domain_of(v["email"]), squash(v["name"])})
    for c in ctx.world.customers():
        idx.update({c["email"], squash(c["name"])})
    idx.update(ctx.policy.trusted_domains)
    return idx


def _parts(param: str, value: Any) -> list[Any]:
    """A recipient list is checked address by address, so one trusted name can't launder another."""
    if isinstance(value, str) and "@" in value and re.search(r"[,;]", value):
        return [p.strip() for p in re.split(r"[,;]", value) if p.strip()]
    return [value]


def _check(ctx: Context, param: str, value: Any, trusted: set[str]) -> tuple[str, TaintEntry] | None:
    s = ctx.session
    forms = normalize_value(value)
    if isinstance(value, str) and EMAIL_RE.fullmatch(value.strip()):
        if is_internal(value, ctx.policy.internal_domains):
            return None
        forms = [value.strip().lower()]  # judge an address by itself, not by its (shared) domain
    if any(f in trusted for f in forms) or (isinstance(value, str) and squash(value) in trusted):
        return None  # corroborated by a trusted source
    hit: tuple[str, TaintEntry] | None = None
    for f in forms:
        entry = s.taint.get(f)
        if entry and (hit is None or entry.injected):
            hit = (f, entry)
    if hit is None and param in _TEXTUAL and isinstance(value, str):
        needle = squash(value)
        if len(needle) >= 8 and not any(needle in t for t in s.trusted_texts):
            for src in reversed(s.untrusted_texts):
                if needle in src["text"]:
                    entry = TaintEntry(needle, src["tool"], src["ref"], src["label"], src["injected"], src["action_id"])
                    if hit is None or entry.injected:
                        hit = (needle, entry)
    return hit


def provenance(ctx: Context) -> list[Signal]:
    spec, s = ctx.spec, ctx.session
    if spec is None or not spec.sinks or not (s.taint or s.untrusted_texts):
        return []
    trusted = _trusted_index(ctx)
    signals: list[Signal] = []
    for param, weight in spec.sinks.items():
        value = ctx.args.get(param)
        if value in (None, "") or weight <= 0:
            continue
        hits = [h for part in _parts(param, value) if (h := _check(ctx, param, part, trusted))]
        if not hits:
            continue
        form, entry = next((h for h in hits if h[1].injected), hits[0])
        shown = str(value) if len(str(value)) <= 60 else str(value)[:57] + "..."
        if entry.injected:
            score, severity = (0.9, "critical") if weight >= 0.4 else (0.5, "high")
            hard = Decision.BLOCK if weight >= 0.5 else None
            reason = (f"'{param}' = {shown} was planted by injected instructions in {entry.source_label}")
        else:
            score, severity, hard = round(weight * 0.6, 2), "medium", None
            reason = f"'{param}' = {shown} came from untrusted content ({entry.source_label}) and nothing trusted vouches for it"
        signals.append(Signal("provenance", score, reason, severity, hard, ["ASI01"], {
            "param": param, "value": str(value), "source": entry.source_label, "source_tool": entry.source_tool,
            "source_action": entry.action_id, "injected": entry.injected}))
    return signals
