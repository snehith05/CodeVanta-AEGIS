"""Start AEGIS and open the Command Center.

    python run.py                 # http://127.0.0.1:8000
    python run.py --fresh         # start with an empty audit ledger
    python run.py --port 9000 --no-browser
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS - Agent Execution Guard & Intervention System")
    parser.add_argument("--host", default=os.getenv("AEGIS_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")))
    parser.add_argument("--policy", default=None, help="path to a policy YAML (default: policies/default.yaml)")
    parser.add_argument("--fresh", action="store_true", help="wipe the audit ledger before starting")
    parser.add_argument("--no-browser", action="store_true", help="don't open the dashboard automatically")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.fresh:
        (ROOT / "data" / "aegis_ledger.db").unlink(missing_ok=True)

    import uvicorn

    from aegis.server import create_app

    app = create_app(args.policy)
    shown_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    url = f"http://{shown_host}:{args.port}"
    print(f"\n  AEGIS - Agent Execution Guard & Intervention System\n"
          f"  Command Center : {url}\n"
          f"  Gateway API    : {url}/docs\n"
          f"  Press Ctrl+C to stop.\n")
    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
