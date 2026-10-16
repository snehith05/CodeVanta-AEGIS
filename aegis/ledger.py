"""Tamper-evident audit ledger.

Every decision, approval and admin action is appended as a record whose hash covers
the previous record's hash (a hash chain, like a blockchain without the blockchain).
Editing, deleting or re-ordering any past record breaks every hash after it, and
``verify()`` pinpoints exactly where.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _digest(prev_hash: str, body: str) -> str:
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class Ledger:
    def __init__(self, path: str | Path | None = None):
        self.path = str(path) if path else ":memory:"
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS ledger (
                seq INTEGER PRIMARY KEY, ts REAL, kind TEXT, actor TEXT, subject TEXT,
                decision TEXT, risk INTEGER, payload TEXT, prev_hash TEXT, hash TEXT)""")
        self.conn.commit()

    def _head(self) -> tuple[int, str]:
        row = self.conn.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return (row["seq"], row["hash"]) if row else (0, GENESIS)

    def append(self, kind: str, actor: str, subject: str, payload: dict[str, Any],
               decision: str = "", risk: int = 0) -> tuple[int, str]:
        with self._lock:
            last_seq, prev = self._head()
            seq, ts = last_seq + 1, time.time()
            body = canonical({"seq": seq, "ts": ts, "kind": kind, "actor": actor, "subject": subject,
                              "decision": decision, "risk": risk, "payload": payload})
            h = _digest(prev, body)
            self.conn.execute("INSERT INTO ledger VALUES (?,?,?,?,?,?,?,?,?,?)",
                              (seq, ts, kind, actor, subject, decision, risk, canonical(payload), prev, h))
            self.conn.commit()
            return seq, h

    def verify(self) -> dict[str, Any]:
        """Recompute the whole chain. Returns where it first breaks, if anywhere."""
        t0 = time.perf_counter()
        prev = GENESIS
        expected_seq = 1
        checked = 0
        with self._lock:
            rows = self.conn.execute("SELECT * FROM ledger ORDER BY seq").fetchall()
        for row in rows:
            body = canonical({"seq": row["seq"], "ts": row["ts"], "kind": row["kind"], "actor": row["actor"],
                              "subject": row["subject"], "decision": row["decision"], "risk": row["risk"],
                              "payload": json.loads(row["payload"])})
            problem = None
            if row["seq"] != expected_seq:
                problem = f"record #{expected_seq} is missing (chain jumps to #{row['seq']})"
            elif row["prev_hash"] != prev:
                problem = f"record #{row['seq']} does not link to the previous record"
            elif _digest(prev, body) != row["hash"]:
                problem = f"record #{row['seq']} was modified after it was written"
            if problem:
                return {"ok": False, "checked": checked, "total": len(rows), "broken_at": row["seq"],
                        "problem": problem, "ms": round((time.perf_counter() - t0) * 1000, 2)}
            prev = row["hash"]
            expected_seq += 1
            checked += 1
        return {"ok": True, "checked": checked, "total": len(rows), "broken_at": None, "problem": None,
                "head": prev, "ms": round((time.perf_counter() - t0) * 1000, 2)}

    def rows(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM ledger ORDER BY seq DESC LIMIT ? OFFSET ?",
                                     (limit, offset)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d["payload"])
            out.append(d)
        return out

    def count(self) -> int:
        with self._lock:
            return self.conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0]

    def head(self) -> str:
        with self._lock:
            return self._head()[1]

    def export(self) -> list[dict[str, Any]]:
        return list(reversed(self.rows(limit=1_000_000)))

    def tamper(self, seq: int | None = None) -> dict[str, Any]:
        """Demo only: quietly rewrite a past record the way a malicious insider would."""
        with self._lock:
            if seq is None:
                row = self.conn.execute(
                    "SELECT seq FROM ledger WHERE decision IN ('block','escalate') ORDER BY seq LIMIT 1").fetchone()
                if row is None:
                    row = self.conn.execute("SELECT seq FROM ledger ORDER BY seq LIMIT 1").fetchone()
                if row is None:
                    return {"ok": False, "error": "ledger is empty"}
                seq = row["seq"]
            self.conn.execute("UPDATE ledger SET decision = 'allow', risk = 0 WHERE seq = ?", (seq,))
            self.conn.commit()
        return {"ok": True, "seq": seq, "change": "decision rewritten to 'allow', risk to 0"}

    def reset(self) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM ledger")
            self.conn.commit()
