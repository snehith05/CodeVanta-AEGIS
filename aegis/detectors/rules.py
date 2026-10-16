"""Organisation-specific rules written in the YAML policy (policy-as-code)."""
from __future__ import annotations

from ..models import Decision, Signal
from ..policy import SEVERITY_SCORE
from .base import Context


def custom_rules(ctx: Context) -> list[Signal]:
    context = {"session_compromised": ctx.session.compromised}
    signals = []
    for rule in ctx.policy.matching_rules(ctx.call.tool, ctx.args, context):
        effect = Decision(rule["effect"])
        severity = rule.get("severity", "medium")
        signals.append(Signal(
            "policy", SEVERITY_SCORE[severity], f"Policy {rule['id']}: {rule['description']}", severity,
            None if effect == Decision.ALLOW else effect, ["POLICY"], {"rule_id": rule["id"]}))
    return signals
