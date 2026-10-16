"""Policy-as-code: load, validate and query the YAML policy."""
from __future__ import annotations

import fnmatch
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from .models import Decision
from .textscan import domain_of, is_internal

IST = timezone(timedelta(hours=5, minutes=30))

VALID_EFFECTS = {d.value for d in Decision}
VALID_OPS = {
    "eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "matches", "not_matches", "contains",
    "not_contains", "domain_in", "domain_not_in", "empty", "not_empty", "internal", "external",
}
VALID_CONTEXT = {"outside_business_hours", "session_compromised"}
SEVERITY_SCORE = {"info": 0.05, "low": 0.2, "medium": 0.35, "high": 0.6, "critical": 0.9}


class PolicyError(ValueError):
    pass


class Policy:
    """A validated policy document. Construct with :meth:`load` or :meth:`from_text`."""

    def __init__(self, data: dict[str, Any], text: str):
        self.data = data
        self.text = text

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        text = Path(path).read_text(encoding="utf-8")
        return cls.from_text(text)

    @classmethod
    def from_text(cls, text: str) -> "Policy":
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyError(f"YAML syntax error: {exc}") from exc
        if not isinstance(data, dict):
            raise PolicyError("Policy must be a YAML mapping")
        errors = validate(data)
        if errors:
            raise PolicyError("; ".join(errors))
        return cls(data, text)

    # ------------------------------------------------------------------ accessors
    @property
    def org(self) -> dict[str, Any]:
        return self.data.get("organisation", {})

    @property
    def internal_domains(self) -> list[str]:
        return [d.lower() for d in self.org.get("internal_domains", [])]

    @property
    def trusted_domains(self) -> list[str]:
        return [d.lower() for d in self.org.get("trusted_domains", [])]

    @property
    def enforcement(self) -> dict[str, Any]:
        return self.data.get("enforcement", {})

    @property
    def mode(self) -> str:
        return self.enforcement.get("mode", "enforce")

    @property
    def thresholds(self) -> dict[str, int]:
        t = self.enforcement.get("thresholds", {})
        return {"flag": t.get("flag", 25), "escalate": t.get("escalate", 55), "block": t.get("block", 80)}

    @property
    def breaker(self) -> dict[str, Any]:
        return self.data.get("circuit_breaker", {})

    @property
    def data_protection(self) -> dict[str, Any]:
        return self.data.get("data_protection", {})

    @property
    def system(self) -> dict[str, Any]:
        return self.data.get("system", {})

    @property
    def agents(self) -> dict[str, dict[str, Any]]:
        return self.data.get("agents", {})

    @property
    def rules(self) -> list[dict[str, Any]]:
        return [r for r in self.data.get("rules", []) if r.get("enabled", True)]

    def agent(self, agent_id: str) -> dict[str, Any] | None:
        return self.agents.get(agent_id)

    def limits(self, agent_id: str, tool: str) -> dict[str, Any]:
        agent = self.agent(agent_id) or {}
        return (agent.get("limits") or {}).get(tool, {})

    def resolve(self, value: Any) -> Any:
        """Expand ``$organisation.blocked_domains`` style references."""
        if isinstance(value, str) and value.startswith("$"):
            node: Any = self.data
            for part in value[1:].split("."):
                node = node.get(part) if isinstance(node, dict) else None
            return node
        return value

    # ------------------------------------------------------------------ custom rules
    def matching_rules(self, tool: str, args: dict[str, Any], context: dict[str, Any]) -> list[dict[str, Any]]:
        hits = []
        for rule in self.rules:
            if not fnmatch.fnmatch(tool, rule["tool"]):
                continue
            if all(self._condition(c, args, context) for c in rule.get("when", [])):
                hits.append(rule)
        return hits

    def _condition(self, cond: dict[str, Any], args: dict[str, Any], context: dict[str, Any]) -> bool:
        if "context" in cond:
            key = cond["context"]
            if key == "outside_business_hours":
                now = context.get("now") or datetime.now(IST)
                return not (9 <= now.hour < 19)
            return bool(context.get(key))
        op = cond["op"]
        actual = args.get(cond["arg"])
        expected = self.resolve(cond.get("value"))
        text = "" if actual is None else str(actual)
        if op == "empty":
            return not text.strip()
        if op == "not_empty":
            return bool(text.strip())
        if op in ("internal", "external"):
            if not text:
                return False
            addresses = [a.strip() for a in re.split(r"[,;]", text) if a.strip()]
            internal = all(is_internal(a, self.internal_domains) for a in addresses)
            return internal if op == "internal" else not internal
        if op in ("domain_in", "domain_not_in"):
            domains = [d.lower() for d in (expected or [])]
            d = domain_of(text)
            inside = any(d == x or d.endswith("." + x) for x in domains)
            return inside if op == "domain_in" else not inside
        if op in ("matches", "not_matches"):
            found = re.search(str(expected), text) is not None
            return found if op == "matches" else not found
        if op in ("contains", "not_contains"):
            found = str(expected).lower() in text.lower()
            return found if op == "contains" else not found
        if op in ("in", "not_in"):
            inside = actual in (expected or [])
            return inside if op == "in" else not inside
        try:
            a, e = float(actual), float(expected)  # numeric comparisons
        except (TypeError, ValueError):
            a, e = text, str(expected)
        return {
            "eq": a == e, "ne": a != e, "gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e,
        }[op]


def validate(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    t = (data.get("enforcement") or {}).get("thresholds") or {}
    if t and not (0 <= t.get("flag", 25) < t.get("escalate", 55) < t.get("block", 80) <= 100):
        errors.append("thresholds must satisfy 0 <= flag < escalate < block <= 100")
    mode = (data.get("enforcement") or {}).get("mode", "enforce")
    if mode not in ("enforce", "monitor"):
        errors.append("enforcement.mode must be 'enforce' or 'monitor'")
    agents = data.get("agents")
    if not isinstance(agents, dict) or not agents:
        errors.append("at least one agent must be defined under 'agents'")
    else:
        for aid, agent in agents.items():
            if not isinstance(agent, dict):
                errors.append(f"agent '{aid}' must be a mapping")
                continue
            if not isinstance(agent.get("tools"), list):
                errors.append(f"agent '{aid}' needs a 'tools' list")
            for tool, lim in (agent.get("limits") or {}).items():
                if not isinstance(lim, dict):
                    errors.append(f"limits for {aid}/{tool} must be a mapping")
    for i, rule in enumerate(data.get("rules") or []):
        rid = rule.get("id", f"#{i + 1}")
        if "tool" not in rule:
            errors.append(f"rule {rid}: missing 'tool'")
        if rule.get("effect") not in VALID_EFFECTS:
            errors.append(f"rule {rid}: effect must be one of {sorted(VALID_EFFECTS)}")
        if rule.get("severity", "medium") not in SEVERITY_SCORE:
            errors.append(f"rule {rid}: unknown severity '{rule.get('severity')}'")
        for cond in rule.get("when") or []:
            if "context" in cond:
                if cond["context"] not in VALID_CONTEXT:
                    errors.append(f"rule {rid}: unknown context '{cond['context']}'")
                continue
            if cond.get("op") not in VALID_OPS:
                errors.append(f"rule {rid}: unknown operator '{cond.get('op')}'")
            if "arg" not in cond:
                errors.append(f"rule {rid}: condition needs 'arg'")
            if cond.get("op") in ("matches", "not_matches"):
                try:
                    re.compile(str(cond.get("value")))
                except re.error as exc:
                    errors.append(f"rule {rid}: bad regex ({exc})")
    return errors
