"""HTTP API + live dashboard.

  /                     the AEGIS Command Center (dashboard)
  /api/...              dashboard API (state, live stream, approvals, ledger, policy, red-team lab)
  /v1/...               the public gateway API any agent framework can call (see aegis/sdk.py)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .agents import llm
from .agents.scenarios import BY_ID, SCENARIOS, run_scenario
from .detectors import DETECTOR_LABELS
from .engine import Gateway
from .ledger import Ledger
from .models import ToolCall
from .policy import Policy, PolicyError
from .sandbox.tools import TOOLS

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "dashboard"
DEFAULT_POLICY = ROOT / "policies" / "default.yaml"
DEFAULT_LEDGER = ROOT / "data" / "aegis_ledger.db"
OPERATOR = os.getenv("AEGIS_OPERATOR", "operator@kudlacashew.in")


# --------------------------------------------------------------------------- request bodies
class ApprovalBody(BaseModel):
    approve: bool
    note: str = ""
    actor: str | None = None


class AgentStatusBody(BaseModel):
    status: str = Field(pattern="^(active|paused)$")
    reason: str = ""


class KillSwitchBody(BaseModel):
    engaged: bool


class ModeBody(BaseModel):
    mode: str = Field(pattern="^(enforce|monitor)$")


class PolicyBody(BaseModel):
    text: str


class RunBody(BaseModel):
    delay: float = 0.9


class PlaygroundBody(BaseModel):
    agent_id: str
    task: str = Field(min_length=1, max_length=2000)
    provider: str | None = None


class SessionBody(BaseModel):
    agent_id: str
    task: str = ""


class ActionBody(BaseModel):
    agent_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = None
    execute: bool = True


class ResultBody(BaseModel):
    output: Any = None


# --------------------------------------------------------------------------- app factory
def create_app(policy_path: str | Path | None = None, ledger_path: str | Path | None = "default") -> FastAPI:
    policy = Policy.load(policy_path or os.getenv("AEGIS_POLICY", DEFAULT_POLICY))
    if ledger_path == "default":
        ledger_path = os.getenv("AEGIS_LEDGER", DEFAULT_LEDGER)
    gateway = Gateway(policy, Ledger(ledger_path), operator=OPERATOR)
    tasks: set[asyncio.Task] = set()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        gateway.ledger.append("system", "aegis", "startup", {"version": __version__,
                                                             "policy_sha256": _sha(policy.text)})
        yield
        for t in list(tasks):
            t.cancel()

    app = FastAPI(title="AEGIS - Agent Execution Guard & Intervention System", version=__version__,
                  lifespan=lifespan)
    app.state.gateway = gateway
    app.state.tasks = tasks

    def spawn(coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        return task

    def actor_of(request: Request, explicit: str | None = None) -> str:
        return explicit or request.headers.get("x-operator") or OPERATOR

    # ------------------------------------------------------------------ dashboard
    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(DASHBOARD / "index.html", headers={"Cache-Control": "no-store"})

    app.mount("/static", StaticFiles(directory=DASHBOARD), name="static")

    @app.get("/api/state")
    async def state() -> dict[str, Any]:
        snap = gateway.snapshot()
        snap["actions"] = snap["actions"][-100:]
        return {**snap, "version": __version__, "chat": list(gateway.chat_log)[-200:],
                "scenarios": [s.to_dict() for s in SCENARIOS],
                "detectors": DETECTOR_LABELS, "tools": {k: t.to_dict() for k, t in TOOLS.items()},
                "operator": OPERATOR, "company": gateway.policy.org.get("name", "")}

    @app.get("/api/stream")
    async def stream(request: Request) -> StreamingResponse:
        queue = gateway.bus.subscribe()

        async def events():
            try:
                yield "retry: 2000\n\n"
                while not await request.is_disconnected():
                    try:
                        kind, data = await asyncio.wait_for(queue.get(), timeout=15)
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
                        continue
                    yield f"event: {kind}\ndata: {json.dumps(data, default=str, ensure_ascii=False)}\n\n"
            finally:
                gateway.bus.unsubscribe(queue)

        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/api/actions/{action_id}")
    async def action_detail(action_id: str) -> dict[str, Any]:
        record = gateway.actions.get(action_id)
        if record is None:
            raise HTTPException(404, "unknown action")
        session = gateway.sessions.get(record.call.session_id)
        return {**record.to_dict(include_output=True), "session": session.to_dict() if session else None,
                "detectors": DETECTOR_LABELS}

    # ------------------------------------------------------------------ human controls
    @app.post("/api/approvals/{approval_id}")
    async def decide(approval_id: str, body: ApprovalBody, request: Request) -> dict[str, Any]:
        try:
            approval = gateway.decide_approval(approval_id, body.approve, actor_of(request, body.actor), body.note)
        except KeyError:
            raise HTTPException(404, "unknown approval") from None
        return approval.to_dict()

    @app.post("/api/agents/{agent_id}/status")
    async def agent_status(agent_id: str, body: AgentStatusBody, request: Request) -> dict[str, Any]:
        if agent_id not in gateway.agents:
            raise HTTPException(404, "unknown agent")
        reason = body.reason or ("released by operator" if body.status == "active" else "paused by operator")
        return gateway.set_agent_status(agent_id, body.status, reason, actor_of(request)).to_dict()

    @app.post("/api/agents/{agent_id}/reset")
    async def agent_reset(agent_id: str) -> dict[str, Any]:
        try:
            return gateway.reset_agent(agent_id).to_dict()
        except KeyError:
            raise HTTPException(404, "unknown agent") from None

    @app.post("/api/system/kill-switch")
    async def kill_switch(body: KillSwitchBody, request: Request) -> dict[str, Any]:
        gateway.set_kill_switch(body.engaged, actor_of(request))
        return gateway.system_state()

    @app.post("/api/system/mode")
    async def mode(body: ModeBody, request: Request) -> dict[str, Any]:
        gateway.set_mode(body.mode, actor_of(request))
        return gateway.system_state()

    @app.post("/api/system/reset")
    async def reset() -> dict[str, Any]:
        for t in list(tasks):
            t.cancel()
        gateway.reset(clear_ledger=True)
        return {"ok": True}

    # ------------------------------------------------------------------ red-team lab
    @app.get("/api/scenarios")
    async def scenarios() -> list[dict[str, Any]]:
        return [s.to_dict() for s in SCENARIOS]

    @app.post("/api/scenarios/{scenario_id}/run")
    async def run_one(scenario_id: str, body: RunBody | None = None) -> dict[str, Any]:
        scenario = BY_ID.get(scenario_id)
        if scenario is None:
            raise HTTPException(404, "unknown scenario")
        spawn(run_scenario(gateway, scenario, delay=(body.delay if body else 0.9)))
        return {"started": scenario_id}

    @app.post("/api/scenarios/run-all")
    async def run_all(body: RunBody | None = None) -> dict[str, Any]:
        async def all_in_order():
            for s in SCENARIOS:
                await run_scenario(gateway, s, delay=(body.delay if body else 0.6))
                await asyncio.sleep(1.0)
        spawn(all_in_order())
        return {"started": [s.id for s in SCENARIOS]}

    # ------------------------------------------------------------------ ledger
    @app.get("/api/ledger")
    async def ledger(limit: int = 100, offset: int = 0) -> dict[str, Any]:
        return {"rows": gateway.ledger.rows(min(limit, 500), offset), "count": gateway.ledger.count()}

    @app.get("/api/ledger/verify")
    async def verify() -> dict[str, Any]:
        return gateway.ledger.verify()

    @app.post("/api/ledger/tamper")
    async def tamper() -> dict[str, Any]:
        result = gateway.ledger.tamper()
        gateway.raise_alert("warning", "Ledger record rewritten (tamper simulation)",
                            "Run 'Verify integrity' to see AEGIS detect it.")
        return result

    @app.get("/api/ledger/export")
    async def export() -> JSONResponse:
        return JSONResponse(gateway.ledger.export()[-5000:],
                            headers={"Content-Disposition": "attachment; filename=aegis-ledger.json"})

    # ------------------------------------------------------------------ policy-as-code
    @app.get("/api/policy")
    async def get_policy() -> dict[str, Any]:
        p = gateway.policy
        return {"text": p.text, "sha256": _sha(p.text), "mode": gateway.mode,
                "matrix": {aid: {t: t in a.get("tools", []) for t in TOOLS} for aid, a in p.agents.items()},
                "tools": {k: t.to_dict() for k, t in TOOLS.items()},
                "rules": p.data.get("rules", [])}

    @app.put("/api/policy")
    async def put_policy(body: PolicyBody, request: Request) -> dict[str, Any]:
        try:
            gateway.apply_policy(body.text, actor_of(request))
        except PolicyError as exc:
            raise HTTPException(400, str(exc)) from None
        return {"ok": True, "sha256": _sha(body.text)}

    # ------------------------------------------------------------------ live LLM playground
    @app.get("/api/playground/providers")
    async def playground_providers() -> dict[str, Any]:
        return await llm.providers()

    @app.post("/api/playground/run")
    async def playground_run(body: PlaygroundBody) -> dict[str, Any]:
        if body.agent_id not in gateway.agents:
            raise HTTPException(404, "unknown agent")
        info = await llm.providers()
        provider = body.provider or info["default"]
        if provider not in ("claude", "ollama") or not info.get(provider, {}).get("available"):
            raise HTTPException(400, "No LLM available: set ANTHROPIC_API_KEY for Claude, or run Ollama "
                                     f"with `ollama pull {llm.OLLAMA_MODEL}`.")
        agent = llm.LiveAgent(gateway, body.agent_id, provider)
        spawn(agent.run(body.task))
        return {"chat_id": agent.chat_id, "provider": provider}

    # ------------------------------------------------------------------ public gateway API (/v1)
    @app.post("/v1/sessions")
    async def v1_session(body: SessionBody) -> dict[str, Any]:
        if body.agent_id not in gateway.agents:
            raise HTTPException(404, "unknown agent")
        return gateway.start_session(body.agent_id, body.task).to_dict()

    @app.post("/v1/actions")
    async def v1_action(body: ActionBody) -> dict[str, Any]:
        call = ToolCall(body.agent_id, body.tool, body.args, body.session_id or "", origin="api")
        record = await gateway.submit(call, execute=body.execute)
        out = record.to_dict(include_output=body.execute)
        return {k: out[k] for k in ("id", "decision", "risk", "reason", "status", "effective_args", "signals",
                                    "post_signals", "ledger_seq", "ledger_hash", "session_id", "latency_ms",
                                    "decided_by") + (("output",) if body.execute else ())}

    @app.post("/v1/actions/{action_id}/result")
    async def v1_result(action_id: str, body: ResultBody) -> dict[str, Any]:
        try:
            record = gateway.report_result(action_id, body.output)
        except KeyError:
            raise HTTPException(404, "unknown action") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        return {"id": record.call.id, "post_signals": [s.to_dict() for s in record.post_signals],
                "output": record.output}

    @app.get("/v1/health")
    async def health() -> dict[str, Any]:
        return {"ok": True, "version": __version__, **gateway.system_state(),
                "ledger_records": gateway.ledger.count()}

    return app


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
