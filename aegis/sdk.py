"""Guard any Python agent's tools with AEGIS - no dependencies, three lines of code.

    from aegis.sdk import Aegis, ActionBlocked

    aegis = Aegis("finbot", task="Pay this week's vendor invoices")

    @aegis.guard("payments.transfer")
    def transfer(to_account, ifsc, beneficiary_name, amount, memo=""):
        ...  # your real banking code - it only runs if AEGIS allows the call

Works with any framework (LangChain, CrewAI, OpenAI/Claude tool calling, MCP servers):
wrap the function that performs the side effect, and AEGIS decides before it runs.
"""
from __future__ import annotations

import functools
import inspect
import json
import urllib.error
import urllib.request
from typing import Any, Callable


class ActionBlocked(Exception):
    """Raised when AEGIS blocks an action or a human denies it."""

    def __init__(self, decision: dict[str, Any]):
        self.decision = decision
        super().__init__(f"AEGIS {decision.get('status')}: {decision.get('reason')} (risk {decision.get('risk')}/100)")


class Aegis:
    def __init__(self, agent_id: str, task: str = "", url: str = "http://127.0.0.1:8000", timeout: float = 180):
        self.agent_id = agent_id
        self.url = url.rstrip("/")
        self.timeout = timeout  # longer than the approval timeout, so held actions can wait for a human
        self.session_id = self._post("/v1/sessions", {"agent_id": agent_id, "task": task})["id"]

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(self.url + path, data=json.dumps(body, default=str).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"AEGIS rejected the request: {exc.read().decode(errors='replace')}") from exc

    def check(self, tool: str, **args: Any) -> dict[str, Any]:
        """Ask AEGIS for a decision without running anything (waits if a human must approve)."""
        return self._post("/v1/actions", {"agent_id": self.agent_id, "tool": tool, "args": args,
                                          "session_id": self.session_id, "execute": False})

    def report(self, action_id: str, output: Any) -> Any:
        """Hand the tool's output back so AEGIS can scan it for injected instructions and taint its values."""
        return self._post(f"/v1/actions/{action_id}/result", {"output": output})["output"]

    def guard(self, tool: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                decision = self.check(tool, **bound.arguments)
                if decision.get("status") != "allowed":
                    raise ActionBlocked(decision)
                # REDACT decisions come back with sensitive values masked - run with those
                safe = {k: v for k, v in (decision.get("effective_args") or {}).items() if k in sig.parameters}
                result = fn(**{**bound.arguments, **safe})
                return self.report(decision["id"], result)
            return wrapper
        return decorator
