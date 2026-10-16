# AEGIS - Agent Execution Guard & Intervention System

**A runtime firewall for autonomous AI agents.** AEGIS sits between AI agents and the business systems
they act on. Every tool call is checked *before* it runs, in context, and then allowed, masked, held for a
human, or blocked - and every decision is written to a tamper-evident ledger.

> Team **CodeVanta** · NMAM Institute of Technology · DevHost 2026 (SOSC × Sahyadri) · Problem statement **2.1 - AI Agent Safety and Control**

| | |
|---|---|
| **Monitor & control** | Every agent action is intercepted pre-execution and streamed live to the AEGIS Command Center. |
| **Detect & block** | 9 deterministic detectors: least privilege, policy-as-code, financial controls, blast radius, data-leak guard, provenance (taint) tracking, intent drift, circuit breaker, lookalike domains - plus a prompt-injection scanner on everything agents read. |
| **Audit & intervene** | Human approval queue (fail-closed), one-click kill switch, per-agent pause/quarantine, hash-chained audit ledger with integrity verification. |

The enforcement layer contains **no LLM**, so it cannot be prompt-injected, and a decision takes about **0.3 ms**.

![AEGIS Command Center during a red-team run](docs/screenshots/command-center.png)

| Why a payment was blocked | Monitor mode: the same attacks with nothing enforced |
|---|---|
| ![Inspector](docs/screenshots/inspector-blocked-payment.png) | ![Monitor mode damage](docs/screenshots/monitor-mode-damage.png) |

---

## Quick start (2 minutes)

```bash
pip install -r requirements.txt
python run.py            # opens http://127.0.0.1:8000
```

Python 3.10+. No API key is needed: the Red-Team Lab replays scripted agents against a simulated company
(**Kudla Cashew Co.**, a fictional cashew exporter in Mangaluru - all data is synthetic).

Demo walkthrough: [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) · Benchmark: [`docs/BENCHMARK.md`](docs/BENCHMARK.md)

## What to try

1. **Command Center → ▶ Poisoned Invoice.** FinBot reads a lookalike email whose hidden HTML comment tells it to pay
   a real invoice to a fraudster's account. The amount (₹42,000) is under every limit, yet AEGIS blocks it: the
   account number was *planted by injected content* (provenance tracking) and the vendor's bank details "changed".
   Click any row to see why.
2. **▶ KYC Exfiltration.** A support ticket contains a fake "compliance" request. The customer gets her own details
   with her Aadhaar **masked**; the bulk export of 40 customers' Aadhaar + PAN to Gmail is **blocked**.
3. **▶ Panicked Agent.** The Replit-style failure: an agent cleaning logs starts dropping tables. Three blocks later
   the **circuit breaker quarantines** it.
4. **▶ Human Approval.** A genuine ₹75,000 refund pauses in the approvals panel - approve or deny it.
5. **Monitor vs Enforce.** Switch to *Monitor*, run Poisoned Invoice, and watch the company systems panel lose
   ₹5.27 lakh. *Reset demo*, switch back to *Enforce*, run it again: ₹0 lost.
6. **Audit Ledger → Simulate insider tampering → Verify integrity.** AEGIS pinpoints the rewritten record.
   ![Ledger tamper detection](docs/screenshots/ledger-tamper-detected.png)
7. **Policy.** Edit the YAML (e.g. lower FinBot's limits) and apply - it takes effect instantly and is logged.
8. **Live Agent.** A real LLM (Claude, or a local model via Ollama) plans and calls tools through AEGIS. Try to
   talk it into something it shouldn't do.

## How it works

```
 AI agent (any framework / model)
        │  tool call: payments.transfer(...)
        ▼
 ┌──────────────────────────── AEGIS gateway ────────────────────────────┐
 │ 1 Identity & least privilege   who is acting, may it use this tool?    │
 │ 2 Policy-as-code rules         organisation rules from YAML            │
 │ 3 Context detectors            financial · blast radius (SQL dry-run)  │
 │                                data-leak · provenance/taint · intent   │
 │                                circuit breaker · lookalike domains     │
 │ 4 Risk engine                  noisy-OR score 0-100 + hard rules       │
 │ 5 Decision                     ALLOW · FLAG · MASK · HOLD · BLOCK      │
 └──────┬──────────────────────────────┬──────────────────────┬──────────┘
        ▼                              ▼                      ▼
 business systems             human approval queue      hash-chained ledger
 (DB, payments, email,        (fail-closed timeout)     + live Command Center
  files, shell, web, CRM)
        │ output
        ▼
 prompt-injection scanner + taint extraction  →  back to the agent (suspicious content annotated)
```

* **Provenance (taint) tracking** - every account number, IFSC code, email address, URL and command that enters an
  agent's context from untrusted content (emails, tickets, web pages, uploads) is remembered. If a later high-impact
  action uses one of those values and nothing trusted vouches for it (vendor master, CRM, the human's own
  instruction), the action is treated as attacker-steered. It follows the *data*, not the wording, so rephrasing an
  injection does not get around it.
* **Context-aware data protection** - PII is found with checksums (Aadhaar Verhoeff, card Luhn, PAN structure), not
  keywords. AEGIS works out *whose* data it is and *where* it is going: your own details to you (Aadhaar masked) is
  fine; forty customers' KYC to Gmail is exfiltration.
* **Blast radius** - SQL is parsed, and `DELETE`/`UPDATE` statements are dry-run as `SELECT COUNT(*)` so AEGIS knows
  how many rows an action would touch before it runs.
* **Fail-closed by design** - unknown tools are denied, unanswered approvals expire as denials, and a crashing
  detector escalates instead of allowing.

## Use it with your own agent

```python
from aegis.sdk import Aegis, ActionBlocked

aegis = Aegis("finbot", task="Pay this week's vendor invoices")      # AEGIS running on :8000

@aegis.guard("payments.transfer")
def transfer(to_account, ifsc, beneficiary_name, amount, memo=""):
    ...  # your real banking code - only runs if AEGIS allows the call
```

Runnable example: `python examples/guard_any_agent.py`. Any language can use the HTTP API -
`POST /v1/sessions`, `POST /v1/actions`, `POST /v1/actions/{id}/result` (interactive docs at `/docs`).

## Live LLM agent

| Provider | Setup |
|---|---|
| Claude (default model `claude-opus-5-5`) | `set ANTHROPIC_API_KEY=...` before `python run.py` |
| Local, offline (Ollama) | `ollama pull qwen2.5:3b` - used automatically when no Claude key is set |

Optional environment variables: `AEGIS_LLM` (`auto`/`claude`/`ollama`), `AEGIS_CLAUDE_MODEL`, `AEGIS_CLAUDE_EFFORT`,
`AEGIS_OLLAMA_MODEL`, `AEGIS_OLLAMA_URL`. The Claude agent uses adaptive thinking and server-side refusal
fallbacks. A small local model on CPU takes 10-40 s per step.

## Tests and benchmark

```bash
python -m pytest -q              # 52 tests
python scripts/benchmark.py      # writes docs/BENCHMARK.md
```

| Metric (7 red-team scenarios, 44 labelled agent actions) | Result |
|---|---|
| Decisions matching the expected outcome | 44 / 44 |
| Harmful actions prevented (masked, held or blocked) | 12 / 13 (the 13th is flagged, and its exfiltration is blocked at the exit) |
| Legitimate actions wrongly held or blocked | 0 / 31 |
| Decision latency p50 / p99 | ~0.3 ms / under 20 ms on a laptop CPU (tail varies with machine load) |

The scenarios are written by the team, so this shows the system works as designed - it is not an independent
evaluation.

## OWASP Top 10 for Agentic Applications (2026) coverage

| Risk | AEGIS control |
|---|---|
| ASI01 Agent Goal Hijack | provenance tracking, injection scanner, intent drift |
| ASI02 Tool Misuse & Exploitation | blast radius, financial controls, policy rules |
| ASI03 Identity & Privilege Abuse | per-agent least privilege, IAM rules |
| ASI05 Unexpected Code Execution | shell command analysis, remote-script blocking |
| ASI06 Memory & Context Poisoning | output scanning, untrusted-content annotation |
| ASI08 Cascading Failures / ASI10 Rogue Agents | circuit breaker, quarantine, kill switch |
| ASI09 Human-Agent Trust Exploitation | lookalike domains, human approval with full context |
| LLM02 Sensitive Information Disclosure | data-leak guard, masking |

## Project layout

```
aegis/
  engine.py          the gateway: evaluate → enforce → execute → inspect → audit
  detectors/         one file per detector
  textscan.py        PII/secret/injection/indicator analysis (checksums, homoglyphs)
  policy.py          policy-as-code loader + rule engine
  ledger.py          hash-chained audit ledger
  approvals.py       human-in-the-loop queue
  server.py          FastAPI: dashboard API, live stream (SSE), public /v1 gateway API
  sdk.py             zero-dependency client + @guard decorator
  agents/            scripted red-team scenarios, live LLM agent (Claude / Ollama)
  sandbox/           the simulated company: tools, data, systems
dashboard/           Command Center (vanilla JS, no build step)
policies/default.yaml
tests/  scripts/  examples/  docs/
```

## Deploy

`docker build -t aegis . && docker run -p 8000:8000 aegis`, or deploy the included `render.yaml` on Render.

## Roadmap

MCP gateway mode (proxy any MCP server) · framework adapters (LangChain, CrewAI, OpenAI Agents SDK, Claude Agent SDK) ·
optional LLM-judge for ambiguous cases · industry policy packs (RBI, DPDP Act 2023, HIPAA) · Slack/WhatsApp
approvals · multi-tenant SaaS with Redis/Postgres state.

## Team CodeVanta

P. Snehith Shree Prannav (lead) · P. Priya Bhat · Panchami B Jain · Poorvi M Mohare - NMAM Institute of Technology
