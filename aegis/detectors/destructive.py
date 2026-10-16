"""Blast-radius control for databases, shells and files.

Instead of keyword matching, SQL is parsed into statements and DELETE/UPDATE
statements are dry-run as ``SELECT COUNT(*)`` against the live database, so AEGIS
knows *how much* data an action would touch before it runs.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

from ..models import Decision, Signal
from .base import Context

# ----------------------------------------------------------------------------- SQL

_COMMENTS = re.compile(r"/\*.*?\*/|--[^\n]*", re.S)
_TAUTOLOGY = re.compile(r"(?i)^\s*\(?\s*(1\s*=\s*1|true|1|'(\w*)'\s*=\s*'\2'|(\w+)\s*=\s*\3)\s*\)?\s*$|\bor\s+1\s*=\s*1\b")


@dataclass
class SqlStatement:
    kind: str           # select | insert | update | delete | drop | truncate | alter | grant | create | admin | other
    table: str | None
    where: str | None
    text: str


def split_sql(sql: str) -> list[str]:
    clean = _COMMENTS.sub(" ", sql or "")
    parts, buf, quote = [], [], None
    for ch in clean:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == ";":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return [re.sub(r"\s+", " ", p).strip() for p in parts if p.strip()]


def parse_sql(sql: str) -> list[SqlStatement]:
    out = []
    for s in split_sql(sql):
        low = s.lower()
        m = None
        if low.startswith(("select", "with")):
            out.append(SqlStatement("select", None, None, s))
        elif m := re.match(r"(?i)^drop\s+(table|database|schema|view|index)\s+(?:if\s+exists\s+)?[`\"\[]?([\w.]+)", s):
            out.append(SqlStatement("drop" if m.group(1).lower() == "table" else "drop_" + m.group(1).lower(),
                                    m.group(2).lower(), None, s))
        elif m := re.match(r"(?i)^truncate\s+(?:table\s+)?[`\"\[]?([\w.]+)", s):
            out.append(SqlStatement("truncate", m.group(1).lower(), None, s))
        elif m := re.match(r"(?i)^delete\s+from\s+[`\"\[]?([\w.]+)[`\"\]]?(?:\s+where\s+(.*))?$", s):
            out.append(SqlStatement("delete", m.group(1).lower(), m.group(2), s))
        elif m := re.match(r"(?i)^update\s+[`\"\[]?([\w.]+)[`\"\]]?\s+set\s+.*?(?:\s+where\s+(.*))?$", s):
            out.append(SqlStatement("update", m.group(1).lower(), m.group(2), s))
        elif m := re.match(r"(?i)^alter\s+table\s+[`\"\[]?([\w.]+)", s):
            out.append(SqlStatement("alter", m.group(1).lower(), None, s))
        elif re.match(r"(?i)^(grant|revoke)\b", s):
            out.append(SqlStatement("grant", None, None, s))
        elif m := re.match(r"(?i)^insert\s+(?:or\s+\w+\s+)?into\s+[`\"\[]?([\w.]+)", s):
            out.append(SqlStatement("insert", m.group(1).lower(), None, s))
        elif re.match(r"(?i)^create\b", s):
            out.append(SqlStatement("create", None, None, s))
        elif re.match(r"(?i)^(attach|detach|pragma|vacuum)\b", s):
            out.append(SqlStatement("admin", None, None, s))
        else:
            out.append(SqlStatement("other", None, None, s))
    return out


def _sql(ctx: Context) -> list[Signal]:
    statements = parse_sql(str(ctx.args.get("sql") or ""))
    if not statements:
        return [Signal("destructive", 0.4, "Empty or unparseable SQL", "medium", Decision.ESCALATE)]
    signals: list[Signal] = []
    if ctx.call.tool == "db.query":
        writes = [s for s in statements if s.kind != "select"]
        if writes:
            signals.append(Signal("destructive", 0.9,
                                  f"{writes[0].kind.upper()} statement smuggled through the read-only db.query tool",
                                  "critical", Decision.BLOCK, ["ASI02"], {"statement": writes[0].text}))
        return signals
    dp = ctx.policy.data_protection
    criticality = dp.get("table_criticality", {})
    radius = dp.get("blast_radius", {})
    if len(statements) > 1:
        signals.append(Signal("destructive", 0.35, f"{len(statements)} stacked SQL statements in one call", "medium",
                              None, ["ASI02"]))
    for st in statements:
        crit = criticality.get(st.table or "", "high")
        rows = ctx.world.row_count(st.table) if st.table else None
        size = f"{rows:,} rows" if rows is not None else "table"
        if st.kind.startswith("drop_"):
            signals.append(Signal("destructive", 0.98, f"Destructive DDL: {st.text[:60]}", "critical", Decision.BLOCK,
                                  ["ASI02"], {"statement": st.text}))
        elif st.kind in ("drop", "truncate"):
            important = crit in ("critical", "high")
            signals.append(Signal(
                "destructive", 0.95 if important else 0.6,
                f"{st.kind.upper()} TABLE '{st.table}' ({crit} data, {size}) would destroy it",
                "critical" if important else "high", Decision.BLOCK if important else Decision.ESCALATE, ["ASI02"],
                {"table": st.table, "criticality": crit, "rows": rows}))
        elif st.kind in ("delete", "update"):
            unbounded = not st.where or bool(_TAUTOLOGY.search(st.where or ""))
            if unbounded:
                important = crit in ("critical", "high")
                signals.append(Signal(
                    "destructive", 0.9 if important else 0.55,
                    f"Unbounded {st.kind.upper()} on '{st.table}' would touch all {size}"
                    + (" (WHERE clause is always true)" if st.where else " (no WHERE clause)"),
                    "critical" if important else "high", Decision.BLOCK if important else Decision.ESCALATE,
                    ["ASI02"], {"table": st.table, "rows": rows}))
                continue
            affected, total = ctx.world.dry_run_count(st.table, st.where)
            evidence = {"table": st.table, "criticality": crit, "dry_run_rows": affected, "table_rows": total}
            if affected is None:
                signals.append(Signal("destructive", 0.4, f"Could not dry-run the {st.kind.upper()} on '{st.table}'",
                                      "medium", Decision.ESCALATE, ["ASI02"], evidence))
                continue
            share = affected / total if total else 0
            if crit in ("critical", "high") and (affected > radius.get("max_rows", 50)
                                                 or share > radius.get("max_fraction", 0.10)):
                signals.append(Signal(
                    "destructive", 0.6,
                    f"Blast radius: dry-run shows this {st.kind.upper()} would touch {affected:,} of {total:,} rows "
                    f"({share:.0%}) of '{st.table}' ({crit} data)", "high", Decision.ESCALATE, ["ASI02"], evidence))
            else:
                signals.append(Signal(
                    "destructive", 0.05,
                    f"Dry-run: {affected:,} of {total:,} rows of '{st.table}' ({crit} data) - within limits",
                    "info", None, [], evidence))
        elif st.kind == "alter":
            signals.append(Signal("destructive", 0.55, f"Schema change on '{st.table}'", "high", Decision.ESCALATE,
                                  ["ASI02"]))
        elif st.kind == "grant":
            signals.append(Signal("destructive", 0.85, "Database privilege change", "critical", Decision.BLOCK,
                                  ["ASI03"]))
        elif st.kind in ("admin", "other"):
            signals.append(Signal("destructive", 0.4, f"Unrecognised SQL: {st.text[:50]}", "medium",
                                  Decision.ESCALATE))
    return signals


# ----------------------------------------------------------------------------- shell

_SHELL_CRITICAL: list[tuple[str, str, list[str]]] = [
    (r"(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?)\b", "Downloads and executes a remote script",
     ["ASI05"]),
    (r"base64\s+(-d|--decode)[^|]*\|\s*(sh|bash)", "Decodes and executes a hidden payload", ["ASI05"]),
    (r"\bmkfs(\.\w+)?\b", "Formats a disk", ["ASI02"]),
    (r"\bdd\s+[^|;]*of=/dev/", "Overwrites a raw disk device", ["ASI02"]),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "Fork bomb", ["ASI02"]),
    (r"\bchmod\s+(-R\s+)?777\s+/(\s|$)", "Makes the whole filesystem world-writable", ["ASI02"]),
    (r"\b(shutdown|reboot|halt|poweroff)\b", "Shuts down the production server", ["ASI02"]),
    (r"\bkill\s+-9\s+1\b", "Kills the init process", ["ASI02"]),
    (r">\s*/dev/(sd|nvme|hd)\w*", "Overwrites a disk device", ["ASI02"]),
    (r"\b(nc|ncat|netcat)\b[^;|]*\s-e\s", "Opens a reverse shell", ["ASI05"]),
    (r"\bkubectl\s+delete\b", "Deletes Kubernetes resources", ["ASI02"]),
    (r"\bterraform\s+destroy\b", "Destroys cloud infrastructure", ["ASI02"]),
    (r"\baws\s+s3\s+(rm|rb)\b[^;|]*--recursive", "Recursively deletes cloud storage", ["ASI02"]),
    (r"\bgit\s+push\b[^;|]*(--force|-f)\b", "Force-pushes over shared history", ["ASI02"]),
    (r"(?i)\bdrop\s+(table|database)\b", "Drops a database object from the shell", ["ASI02"]),
    (r"(?i)\b(format\s+[a-z]:|rd\s+/s|del\s+/[sfq])", "Destructive Windows command", ["ASI02"]),
]
_SHELL_HIGH: list[tuple[str, str]] = [
    (r"\bsudo\b", "Requests root privileges"),
    (r"\b(curl|wget)\b[^|;]*\s(-d|--data\S*|-F|--form|-T|--upload-file|-X\s*(POST|PUT))\b", "Uploads data to a remote host"),
    (r"\b(scp|rsync|sftp)\b[^;|]*@", "Copies files to another machine"),
    (r"\bchmod\s+(-R\s+)?777\b", "Makes files world-writable"),
    (r"\bcrontab\b|\bsystemctl\s+(enable|disable|mask)\b", "Changes persistent system configuration"),
    (r"\b(useradd|usermod|passwd)\b", "Changes system user accounts"),
]


def _within(path: str, roots: list[str]) -> bool:
    p = posixpath.normpath(path.replace("\\", "/"))
    return any(p == r.rstrip("/") or p.startswith(r.rstrip("/") + "/") for r in roots)


def _shell(ctx: Context) -> list[Signal]:
    cmd = str(ctx.args.get("command") or "")
    signals: list[Signal] = []
    for pattern, reason, tags in _SHELL_CRITICAL:
        if re.search(pattern, cmd, re.I):
            signals.append(Signal("destructive", 0.95, f"Dangerous command: {reason}", "critical", Decision.BLOCK,
                                  tags, {"command": cmd}))
    for pattern, reason in _SHELL_HIGH:
        if re.search(pattern, cmd, re.I):
            signals.append(Signal("destructive", 0.55, f"Risky command: {reason}", "high", Decision.ESCALATE,
                                  ["ASI05"], {"command": cmd}))
    rm = re.search(r"(?:^|[;&|]\s*)(?:sudo\s+)?rm\s+([^;&|]*)", cmd)
    if rm:
        allowed = ctx.policy.system.get("allowed_paths", [])
        targets = [t for t in rm.group(1).split() if not t.startswith("-")]
        outside = [t for t in targets if t.startswith(("/", "~", "$", "*")) and not _within(t, allowed)]
        outside += [t for t in targets if not t.startswith(("/", "~", "$")) and not t.startswith("*") and ".." in t]
        if outside or not targets:
            signals.append(Signal("destructive", 0.95,
                                  f"Deletes outside the allowed paths: {', '.join(outside) or '(no target)'}",
                                  "critical", Decision.BLOCK, ["ASI02"], {"targets": targets, "allowed": allowed}))
        else:
            signals.append(Signal("destructive", 0.05, f"Scoped deletion inside allowed path(s): {', '.join(targets)}",
                                  "info", None, [], {"targets": targets}))
    return signals


# ----------------------------------------------------------------------------- files

def _files(ctx: Context) -> list[Signal]:
    raw = str(ctx.args.get("path") or "")
    path = posixpath.normpath(raw.replace("\\", "/")) if raw else raw
    sysp = ctx.policy.system
    allowed, sensitive = sysp.get("allowed_paths", []), sysp.get("sensitive_paths", [])
    signals: list[Signal] = []
    if ".." in raw.split("/"):
        signals.append(Signal("destructive", 0.6, f"Path traversal: '{raw}' resolves to '{path}'", "high",
                              Decision.ESCALATE, ["ASI02"]))
    is_sensitive = _within(path, [s.replace("~", "/root") for s in sensitive]) or bool(
        re.search(r"(\.env|id_rsa|\.pem|shadow|passwd|authorized_keys|crontab)$", path))
    tool = ctx.call.tool
    if tool == "files.read" and is_sensitive:
        signals.append(Signal("destructive", 0.6, f"Reads a credential/system file: {path}", "high",
                              Decision.ESCALATE, ["ASI03"]))
    elif tool == "files.write" and is_sensitive:
        signals.append(Signal("destructive", 0.9, f"Overwrites a protected system file: {path}", "critical",
                              Decision.BLOCK, ["ASI02"]))
    elif tool == "files.delete":
        if is_sensitive:
            signals.append(Signal("destructive", 0.95, f"Deletes protected files: {path}", "critical", Decision.BLOCK,
                                  ["ASI02"]))
        elif not _within(path.rstrip("*").rstrip("/") or "/", allowed):
            signals.append(Signal("destructive", 0.6, f"Deletes outside the allowed paths: {path}", "high",
                                  Decision.ESCALATE, ["ASI02"]))
    return signals


def destructive(ctx: Context) -> list[Signal]:
    tool = ctx.call.tool
    if tool in ("db.query", "db.execute"):
        return _sql(ctx)
    if tool == "shell.run":
        return _shell(ctx)
    if tool in ("files.read", "files.write", "files.delete"):
        return _files(ctx)
    return []
