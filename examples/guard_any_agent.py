"""Protect your own agent's tools with AEGIS.

1. Start AEGIS:          python run.py
2. In another terminal:  python examples/guard_any_agent.py
3. Watch the decisions appear live in the dashboard. The third payment is held for a human:
   approve or deny it from the Approvals panel and this script continues.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.sdk import ActionBlocked, Aegis  # noqa: E402

aegis = Aegis("finbot", task="Pay Coastal Packaging invoice INV-2291")


@aegis.guard("payments.transfer")
def transfer(to_account: str, ifsc: str, beneficiary_name: str, amount: float, memo: str = "") -> dict:
    # Your real banking integration would go here. It only ever runs if AEGIS allows the call.
    print(f"   [bank] sent Rs {amount:,.0f} to {beneficiary_name} (a/c {to_account})")
    return {"status": "completed", "amount": amount}


payments = [
    ("Legitimate invoice to an approved vendor",
     dict(to_account="50100023456781", ifsc="HDFC0000123", beneficiary_name="Coastal Packaging Pvt Ltd",
          amount=18400, memo="INV-2291-B")),
    ("Above FinBot's hard limit",
     dict(to_account="50100023456781", ifsc="HDFC0000123", beneficiary_name="Coastal Packaging Pvt Ltd",
          amount=900000, memo="INV-9999")),
    ("New, unverified beneficiary (held for a human)",
     dict(to_account="77700011122233", ifsc="ICIC0000999", beneficiary_name="Unknown Traders",
          amount=30000, memo="advance")),
]

for label, args in payments:
    print(f"\n> {label}")
    try:
        result = transfer(**args)
        print(f"   ALLOWED -> {result}")
    except ActionBlocked as exc:
        print(f"   STOPPED -> {exc}")
