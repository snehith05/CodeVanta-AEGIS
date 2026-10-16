from fastapi.testclient import TestClient

from aegis.ledger import Ledger
from aegis.server import create_app


def test_hash_chain_detects_edits_and_deletions():
    led = Ledger(None)
    for i in range(5):
        led.append("action", "finbot", "payments.transfer", {"n": i}, "block", 99)
    assert led.verify()["ok"]
    led.tamper(3)
    v = led.verify()
    assert not v["ok"] and v["broken_at"] == 3 and v["checked"] == 2

    led2 = Ledger(None)
    for i in range(4):
        led2.append("action", "a", "t", {"n": i})
    led2.conn.execute("DELETE FROM ledger WHERE seq = 2")
    assert led2.verify()["broken_at"] == 3


def test_http_api_end_to_end():
    app = create_app(ledger_path=None)
    with TestClient(app) as client:
        assert client.get("/v1/health").json()["ok"]
        session = client.post("/v1/sessions", json={"agent_id": "finbot", "task": "Pay vendor invoices"}).json()
        ok = client.post("/v1/actions", json={"agent_id": "finbot", "tool": "vendors.list", "args": {},
                                              "session_id": session["id"]}).json()
        assert ok["decision"] == "allow" and ok["status"] == "executed" and len(ok["output"]) == 3
        bad = client.post("/v1/actions", json={"agent_id": "finbot", "tool": "shell.run",
                                               "args": {"command": "rm -rf /"}}).json()
        assert bad["status"] == "blocked"
        assert client.put("/api/policy", json={"text": "agents: {}"}).status_code == 400
        policy = client.get("/api/policy").json()
        assert client.put("/api/policy", json={"text": policy["text"]}).status_code == 200
        assert client.get("/api/ledger/verify").json()["ok"]
        state = client.get("/api/state").json()
        assert state["stats"]["total"] == 2 and len(state["scenarios"]) == 7
        assert client.get("/").status_code == 200
