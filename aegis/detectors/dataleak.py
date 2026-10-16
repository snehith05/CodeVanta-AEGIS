"""Data-leak guard: decides on *context*, not keywords.

The same Aadhaar number is fine in an email to the person it belongs to (masked),
suspicious in an internal email, and an exfiltration attempt when forty of them
go to a Gmail address. AEGIS works out whose data it is and where it is going.
"""
from __future__ import annotations

import re

from ..models import Decision, Signal
from ..textscan import domain_of, is_internal, redact_text, scan_pii
from .base import Context, recipients

_OUTBOUND_FIELDS = {
    "email.send": ["subject", "body", "attachment_content"],
    "tickets.reply": ["message"],
    "web.fetch": ["url"],
    "files.write": ["content"],
}
_KIND_NAMES = {"aadhaar": "aadhaar", "pan": "pan", "cards": "card", "phones": "phone", "emails": "email"}


def data_leak(ctx: Context) -> list[Signal]:
    tool = ctx.call.tool
    if tool == "db.query":
        return _bulk_read(ctx)
    fields = _OUTBOUND_FIELDS.get(tool)
    if not fields:
        return []
    texts = {f: str(ctx.args.get(f) or "") for f in fields}
    pii = scan_pii("\n".join(texts.values()))
    if not pii.total and not pii.secrets:
        return []

    dest, external = _destination(ctx)
    dp = ctx.policy.data_protection
    bulk = dp.get("bulk_pii_threshold", 5)
    always_mask = set(dp.get("always_mask", ["aadhaar", "card"]))
    people = max(len(pii.aadhaar), len(pii.pan), len(pii.cards))
    evidence = {"found": pii.summary(), "destination": dest, "external": external}
    signals: list[Signal] = []

    if pii.secrets:
        kinds = sorted({name for name, _ in pii.secrets})
        if external:
            signals.append(Signal("data-leak", 0.95, f"Credential leak: {', '.join(kinds)} in outbound {tool} to {dest}",
                                  "critical", Decision.BLOCK, ["LLM02"], evidence))
        else:
            signals.append(Signal("data-leak", 0.45, f"Credentials ({', '.join(kinds)}) masked from an internal message",
                                  "high", Decision.REDACT, ["LLM02"], evidence, _redact(texts, {"secret"})))

    owners = _owners(ctx, pii)
    if external:
        subject_is_recipient = len(owners) == 1 and next(iter(owners)) in {r.lower() for r in recipients(dest)}
        if subject_is_recipient:
            present = {k for k, v in (("aadhaar", pii.aadhaar), ("card", pii.cards)) if v} & always_mask
            if present:
                names = " and ".join({"aadhaar": "Aadhaar", "card": "card number"}[k] for k in sorted(present))
                signals.append(Signal(
                    "data-leak", 0.3,
                    f"Recipient is the data subject - their own details may be sent, but {names} "
                    "is always masked (UIDAI masked-Aadhaar norm)", "medium", Decision.REDACT, ["LLM02", "DPDP"],
                    evidence, _redact(texts, present)))
            else:
                signals.append(Signal("data-leak", 0.05, "Recipient is the data subject - personal details allowed",
                                      "info", None, [], evidence))
        elif people >= bulk or len(pii.phones) >= bulk * 2:
            signals.append(Signal(
                "data-leak", 0.95,
                f"Bulk personal-data exfiltration: {pii.describe()} for {max(people, len(owners))} people to external "
                f"{domain_of(dest) or dest}", "critical", Decision.BLOCK, ["LLM02", "DPDP"], evidence))
        elif len(set(pii.emails) - {r.lower() for r in recipients(dest)}) >= bulk * 2:
            signals.append(Signal(
                "data-leak", 0.85, f"Contact-list exfiltration: {len(pii.emails)} email addresses to {dest}",
                "critical", Decision.BLOCK, ["LLM02", "DPDP"], evidence))
        elif pii.identity_count or pii.phones:
            kinds = {"aadhaar", "pan", "card", "phone"}
            keep = {r.lower() for r in recipients(dest)}
            signals.append(Signal(  # masking removes the risk, so the residual score stays below "escalate"
                "data-leak", 0.4, f"Other people's personal data ({pii.describe()}) in a message to {dest} - masked",
                "high", Decision.REDACT, ["LLM02", "DPDP"], evidence, _redact(texts, kinds, keep)))
    else:
        if people >= bulk:
            signals.append(Signal("data-leak", 0.3,
                                  f"Bulk KYC data ({pii.describe()}) shared internally - check data minimisation",
                                  "medium", None, ["DPDP"], evidence))
        present = {k for k, v in (("aadhaar", pii.aadhaar), ("card", pii.cards)) if v} & always_mask
        if present:
            signals.append(Signal("data-leak", 0.25, f"{', '.join(sorted(present)).title()} masked (always-mask policy)",
                                  "low", Decision.REDACT, ["DPDP"], evidence, _redact(texts, present)))
    return signals


def _destination(ctx: Context) -> tuple[str, bool]:
    tool, args = ctx.call.tool, ctx.args
    internal = ctx.policy.internal_domains
    if tool == "email.send":
        to = str(args.get("to") or "")
        return to, any(not is_internal(r, internal) for r in recipients(to)) or not to
    if tool == "tickets.reply":
        ticket = next((t for t in ctx.world.tickets if t["id"].lower() == str(args.get("ticket_id", "")).lower()), None)
        email = ticket["customer_email"] if ticket else "customer"
        return email, True
    if tool == "web.fetch":
        url = str(args.get("url") or "")
        return url, not is_internal(url, internal)
    if tool == "files.write":
        path = str(args.get("path") or "")
        return path, path.startswith(("/public", "/srv/kudla/public", "s3://", "http"))
    return "", True


def _owners(ctx: Context, pii) -> set[str]:
    """Emails of the customers whose identifiers appear in the text (one lookup table per call)."""
    index = {}
    for c in ctx.world.customers():
        for key in (c["aadhaar"], c["pan"].lower(), c["phone"]):
            index[key] = c["email"]
    return {index[v] for v in (*pii.aadhaar, *(p.lower() for p in pii.pan), *pii.cards, *pii.phones) if v in index}


def _redact(texts: dict[str, str], kinds: set[str], keep: set[str] | None = None) -> dict[str, str]:
    out = {}
    for field, text in texts.items():
        if text:
            new, counts = redact_text(text, kinds, keep)
            if counts:
                out[field] = new
    return out


def _bulk_read(ctx: Context) -> list[Signal]:
    sql = str(ctx.args.get("sql") or "").lower()
    if "customers" not in sql or re.search(r"\bwhere\b", sql):
        return []
    if not re.search(r"\b(aadhaar|pan)\b|select\s+\*", sql):
        return []
    rows = ctx.world.row_count("customers") or 0
    return [Signal("data-leak", 0.25, f"Bulk read of customer KYC data ({rows} rows incl. Aadhaar/PAN)", "medium",
                   None, ["LLM02"], {"rows": rows})]
