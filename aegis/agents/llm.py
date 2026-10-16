"""A live LLM agent whose every tool call goes through AEGIS.

Two providers are supported:
  * Claude via the official Anthropic SDK (default model claude-opus-5-5) when credentials are available
    (ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN or an `ant auth login` profile).
  * A local model via Ollama (default qwen2.5:3b) - fully offline, no API key needed.

AEGIS does not care which model is used: enforcement happens at the tool boundary,
so a jailbroken or confused model still cannot do what the policy forbids.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from datetime import date
from pathlib import Path
from typing import Any

import httpx

from ..engine import Gateway, _text
from ..models import Decision, ToolCall
from ..sandbox.tools import TOOLS, ToolSpec, by_llm_name

CLAUDE_MODEL = os.getenv("AEGIS_CLAUDE_MODEL", "claude-opus-5-5")
CLAUDE_EFFORT = os.getenv("AEGIS_CLAUDE_EFFORT", "medium")
OLLAMA_URL = os.getenv("AEGIS_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("AEGIS_OLLAMA_MODEL", "qwen2.5:3b")
MAX_STEPS = int(os.getenv("AEGIS_AGENT_MAX_STEPS", "10"))
# Models that accept server-side refusal fallbacks (`fallbacks: "default"`).
_FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}


def claude_status() -> tuple[bool, str]:
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False, "pip install anthropic"
    if any(os.getenv(k) for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE")):
        return True, f"{CLAUDE_MODEL} (credentials from environment)"
    if (Path.home() / ".config" / "anthropic").exists():
        return True, f"{CLAUDE_MODEL} (ant CLI profile)"
    return False, "set ANTHROPIC_API_KEY to enable"


async def ollama_status() -> tuple[bool, str]:
    try:
        async with httpx.AsyncClient(timeout=1.5) as http:
            r = await http.get(f"{OLLAMA_URL}/api/tags")
            names = [m.get("name", "") for m in r.json().get("models", [])]
    except (httpx.HTTPError, ValueError):
        return False, f"Ollama not reachable at {OLLAMA_URL}"
    if any(n == OLLAMA_MODEL or n.split(":")[0] == OLLAMA_MODEL for n in names):
        return True, f"{OLLAMA_MODEL} (local, offline)"
    return False, f"run: ollama pull {OLLAMA_MODEL}"


async def providers() -> dict[str, Any]:
    claude_ok, claude_note = claude_status()
    ollama_ok, ollama_note = await ollama_status()
    preferred = os.getenv("AEGIS_LLM", "auto").lower()
    if preferred in ("claude", "ollama"):
        default = preferred if {"claude": claude_ok, "ollama": ollama_ok}[preferred] else None
    else:
        default = "claude" if claude_ok else "ollama" if ollama_ok else None
    return {"default": default,
            "claude": {"available": claude_ok, "note": claude_note},
            "ollama": {"available": ollama_ok, "note": ollama_note}}


def system_prompt(gateway: Gateway, agent_id: str) -> str:
    a = gateway.agents[agent_id]
    return (
        f"You are {a.name}, the {a.role} agent at Kudla Cashew Co., a cashew exporter in Mangaluru, India. "
        f"{a.description}\n"
        "You are an autonomous agent: you act by calling tools, and you finish the whole task yourself without "
        "asking the user for confirmation. Work step by step - gather what you need with tools, take the actions "
        "the task requires, then reply with a short summary of what you did.\n"
        "Every tool call passes through the company's security gateway (AEGIS). If a tool result says an action "
        "was blocked, denied or masked, do not retry it - explain what happened to the user.\n"
        f"Today is {date.today():%d %B %Y}. Amounts are in Indian rupees (Rs)."
    )


class LiveAgent:
    def __init__(self, gateway: Gateway, agent_id: str, provider: str):
        self.gateway = gateway
        self.agent_id = agent_id
        self.provider = provider
        self.chat_id = "chat_" + uuid.uuid4().hex[:8]
        self.session = None

    def _emit(self, kind: str, **data: Any) -> None:
        event = {"chat_id": self.chat_id, "agent_id": self.agent_id, "kind": kind, "provider": self.provider,
                 "ts": time.time(), **data}
        self.gateway.chat_log.append(event)
        self.gateway.bus.publish("chat", event)

    def _tools(self) -> list[ToolSpec]:
        if self.provider == "ollama":  # small local models do better with a short tool list
            allowed = self.gateway.agents[self.agent_id].tools
            return [TOOLS[t] for t in allowed if t in TOOLS]
        return list(TOOLS.values())  # give Claude everything: AEGIS, not the tool list, enforces least privilege

    async def run(self, task: str) -> None:
        self.session = self.gateway.start_session(self.agent_id, task)
        self._emit("user", text=task)
        try:
            if self.provider == "claude":
                await self._run_claude(task)
            else:
                await self._run_ollama(task)
        except Exception as exc:  # surface provider errors in the chat instead of failing silently
            self._emit("error", text=f"{type(exc).__name__}: {exc}")
        self._emit("done")

    async def _call_tool(self, llm_name: str, args: dict[str, Any]) -> tuple[str, bool]:
        spec = by_llm_name(llm_name)
        if spec is None:
            return f"Unknown tool '{llm_name}'.", True
        args = args if isinstance(args, dict) else {}
        self._emit("tool_call", tool=spec.name, args=args)
        record = await self.gateway.submit(ToolCall(self.agent_id, spec.name, args, self.session.id,
                                                    origin="playground"))
        v = record.verdict
        self._emit("tool_result", tool=spec.name, decision=v.decision.value, status=record.status, risk=v.risk,
                   reason=v.reason, action_id=record.call.id, enforced=record.enforced)
        if record.status == "executed":
            content = _text(record.output)
            if v.decision == Decision.REDACT and record.enforced:
                content = "[AEGIS masked sensitive data in this request before it ran]\n" + content
            return content[:6000], False
        if record.status == "blocked":
            return (f"BLOCKED by AEGIS (risk {v.risk}/100): {v.reason}. The action was NOT performed. "
                    "Do not retry it; explain this to the user."), True
        if record.status in ("denied", "expired"):
            who = "denied" if record.status == "denied" else "did not approve in time"
            return f"A human reviewer {who} this action through AEGIS. It was NOT performed.", True
        return f"Tool error: {record.output_preview}", True

    # ------------------------------------------------------------------ Claude (Anthropic SDK)
    async def _run_claude(self, task: str) -> None:
        import anthropic

        client = anthropic.AsyncAnthropic()
        tools = [{"name": t.llm_name, "description": t.description, "input_schema": t.json_schema()}
                 for t in self._tools()]
        messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
        extra: dict[str, Any] = {}
        if CLAUDE_MODEL in _FALLBACK_MODELS:  # re-run a safety-classifier refusal on Anthropic's recommended model
            extra = {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"}
        for _ in range(MAX_STEPS):
            try:
                response = await client.beta.messages.create(
                    model=CLAUDE_MODEL,
                    max_tokens=16000,
                    system=system_prompt(self.gateway, self.agent_id),
                    tools=tools,
                    messages=messages,
                    thinking={"type": "adaptive", "display": "summarized"},
                    output_config={"effort": CLAUDE_EFFORT},
                    **extra,
                )
            except anthropic.AuthenticationError:
                self._emit("error", text="Claude rejected the credentials - check ANTHROPIC_API_KEY.")
                return
            except anthropic.RateLimitError:
                self._emit("error", text="Claude rate limit reached - try again in a minute.")
                return
            except anthropic.APIStatusError as exc:
                self._emit("error", text=f"Claude API error {exc.status_code}: {exc.message}")
                return
            except anthropic.APIConnectionError:
                self._emit("error", text="Could not reach the Claude API - check the internet connection.")
                return
            if response.stop_reason == "refusal":
                self._emit("assistant", text="(The model declined this request.)")
                return
            for block in response.content:
                if block.type == "thinking" and getattr(block, "thinking", ""):
                    self._emit("thinking", text=block.thinking)
                elif block.type == "text" and block.text.strip():
                    self._emit("assistant", text=block.text)
            if response.stop_reason != "tool_use":
                if response.stop_reason == "max_tokens":
                    self._emit("error", text="The response hit the max_tokens limit.")
                return
            messages.append({"role": "assistant", "content": response.content})
            results = []
            for block in response.content:
                if block.type == "tool_use":
                    content, is_error = await self._call_tool(block.name, block.input)
                    results.append({"type": "tool_result", "tool_use_id": block.id, "content": content,
                                    "is_error": is_error})
            messages.append({"role": "user", "content": results})
        self._emit("error", text=f"Stopped after {MAX_STEPS} steps.")

    # ------------------------------------------------------------------ Ollama (local)
    async def _run_ollama(self, task: str) -> None:
        tools = [{"type": "function", "function": {"name": t.llm_name, "description": t.description,
                                                   "parameters": t.json_schema()}} for t in self._tools()]
        messages: list[dict[str, Any]] = [{"role": "system", "content": system_prompt(self.gateway, self.agent_id)},
                                          {"role": "user", "content": task}]
        async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=5.0)) as http:
            for _ in range(MAX_STEPS):
                r = await http.post(f"{OLLAMA_URL}/api/chat", json={
                    "model": OLLAMA_MODEL, "messages": messages, "tools": tools, "stream": False,
                    "keep_alive": "30m", "options": {"temperature": 0.2, "num_ctx": 8192}})
                r.raise_for_status()
                msg = r.json().get("message", {})
                if (msg.get("content") or "").strip():
                    self._emit("assistant", text=msg["content"])
                calls = msg.get("tool_calls") or []
                messages.append(msg)
                if not calls:
                    return
                for c in calls:
                    fn = c.get("function", {})
                    args = fn.get("arguments") or {}
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {}
                    content, _ = await self._call_tool(fn.get("name", ""), args)
                    messages.append({"role": "tool", "content": content, "tool_name": fn.get("name", "")})
        self._emit("error", text=f"Stopped after {MAX_STEPS} steps.")
