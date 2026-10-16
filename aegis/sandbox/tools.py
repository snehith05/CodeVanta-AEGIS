"""The tool catalogue: every business action an agent can request, with its risk metadata.

The metadata is what makes AEGIS context-aware - it knows that reading an email is
harmless but that the email's *content* is untrusted, that a wire transfer is
irreversible, and which parameters are dangerous if an attacker controls them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    params: dict[str, Any]
    required: tuple[str, ...]
    category: str          # finance | comms | support | crm | data | files | system | web | identity
    tier: str              # low | medium | high | critical
    side_effect: str       # read | write
    reversible: bool = True
    untrusted_output: bool = False   # output can contain attacker-controlled text
    trusted_output: bool = False     # output is authoritative internal data
    sensitive_output: bool = False   # output can contain personal data
    sinks: dict[str, float] = field(default_factory=dict)  # param -> weight if attacker-controlled

    @property
    def llm_name(self) -> str:
        return self.name.replace(".", "_")

    def json_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": self.params,
            "required": list(self.required),
            "additionalProperties": False,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "description": self.description, "category": self.category,
            "tier": self.tier, "side_effect": self.side_effect, "reversible": self.reversible,
            "untrusted_output": self.untrusted_output, "params": list(self.params),
        }


def _s(desc: str) -> dict[str, str]:
    return {"type": "string", "description": desc}


def _n(desc: str) -> dict[str, str]:
    return {"type": "number", "description": desc}


TOOLS: dict[str, ToolSpec] = {t.name: t for t in [
    ToolSpec("email.list_inbox", "List emails in the accounts inbox (id, sender, subject).",
             {}, (), "comms", "low", "read", untrusted_output=True),
    ToolSpec("email.read", "Read the full content of one email.",
             {"email_id": _s("Email id, e.g. E-1041")}, ("email_id",), "comms", "low", "read",
             untrusted_output=True),
    ToolSpec("email.send", "Send an email from the company mail server.",
             {"to": _s("Recipient address(es), comma separated"), "subject": _s("Subject line"),
              "body": _s("Plain-text body"), "attachment_name": _s("Optional attachment file name"),
              "attachment_content": _s("Optional attachment content (text/CSV)")},
             ("to", "subject", "body"), "comms", "high", "write", reversible=False,
             sinks={"to": 0.55}),
    ToolSpec("vendors.list", "List approved vendors from the vendor master (bank details on file).",
             {}, (), "finance", "low", "read", trusted_output=True),
    ToolSpec("payments.transfer", "Transfer money from the company current account via NEFT/RTGS.",
             {"to_account": _s("Beneficiary account number"), "ifsc": _s("Beneficiary IFSC code"),
              "beneficiary_name": _s("Beneficiary name"), "amount": _n("Amount in INR"),
              "memo": _s("Payment reference, e.g. invoice number")},
             ("to_account", "ifsc", "beneficiary_name", "amount"), "finance", "critical", "write",
             reversible=False, sinks={"to_account": 0.75, "ifsc": 0.4, "beneficiary_name": 0.45}),
    ToolSpec("payments.refund", "Refund a customer order to the original payment method.",
             {"order_id": _s("Order id, e.g. ORD-7781"), "amount": _n("Refund amount in INR"),
              "reason": _s("Reason for the refund")},
             ("order_id", "amount", "reason"), "finance", "critical", "write", reversible=False,
             sinks={"order_id": 0.3}),
    ToolSpec("db.query", "Run a read-only SQL SELECT on the company database "
                         "(tables: customers, orders, payments, vendors, app_logs).",
             {"sql": _s("A single SELECT statement")}, ("sql",), "data", "medium", "read",
             trusted_output=True, sensitive_output=True),
    ToolSpec("db.execute", "Run a SQL statement that changes data (INSERT/UPDATE/DELETE/DDL).",
             {"sql": _s("SQL statement")}, ("sql",), "data", "high", "write", reversible=False,
             sinks={"sql": 0.7}),
    ToolSpec("files.read", "Read a file from the company file server.",
             {"path": _s("Absolute path")}, ("path",), "files", "low", "read", untrusted_output=True),
    ToolSpec("files.write", "Write or overwrite a file on the company file server.",
             {"path": _s("Absolute path"), "content": _s("File content")}, ("path", "content"),
             "files", "medium", "write", sinks={"path": 0.4}),
    ToolSpec("files.delete", "Delete files on the company file server (glob patterns allowed).",
             {"path": _s("Absolute path or glob")}, ("path",), "files", "high", "write",
             reversible=False, sinks={"path": 0.5}),
    ToolSpec("shell.run", "Run a shell command on the production application server.",
             {"command": _s("Shell command")}, ("command",), "system", "critical", "write",
             reversible=False, sinks={"command": 0.8}),
    ToolSpec("web.fetch", "Fetch a web page or API over HTTP(S).",
             {"url": _s("URL to fetch")}, ("url",), "web", "medium", "read",
             untrusted_output=True, sinks={"url": 0.35}),
    ToolSpec("crm.lookup", "Look up customer records (name, email, phone, KYC) by name, email or id.",
             {"query": _s("Name, email or customer id")}, ("query",), "crm", "medium", "read",
             trusted_output=True, sensitive_output=True),
    ToolSpec("tickets.list", "List customer support tickets with their full text (optionally one ticket by id).",
             {"status": _s("open | resolved | all"), "ticket_id": _s("Optional ticket id, e.g. T-318")}, (),
             "support", "low", "read", untrusted_output=True),
    ToolSpec("tickets.reply", "Reply to a customer support ticket (the customer receives it by email).",
             {"ticket_id": _s("Ticket id, e.g. T-311"), "message": _s("Reply text")},
             ("ticket_id", "message"), "support", "medium", "write", reversible=False),
    ToolSpec("iam.grant_role", "Grant a role/permission to a user or service principal.",
             {"principal": _s("User or agent principal"), "role": _s("Role name")},
             ("principal", "role"), "identity", "critical", "write", sinks={"principal": 0.6}),
]}


def get_tool(name: str) -> ToolSpec | None:
    return TOOLS.get(name)


def by_llm_name(llm_name: str) -> ToolSpec | None:
    return next((t for t in TOOLS.values() if t.llm_name == llm_name), None)
