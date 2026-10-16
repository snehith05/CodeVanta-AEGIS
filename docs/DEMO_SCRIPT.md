# AEGIS - 4-minute demo video script

**Setup before recording**
- `python run.py --fresh`, then **Reset demo** in the dashboard. Close other tabs and notifications.
- Record at 1920×1080 (Windows: `Win + Alt + R` with Xbox Game Bar, or OBS). Browser zoom 90-100 %.
- Speak slowly. Cut silences when editing; keep the total under 4:00.
- Optional: for the live-agent clip, warm up Ollama first (`ollama run qwen2.5:3b "hi"`), record it separately
  and speed it up in the edit.

| Time | Screen | Say (roughly) |
|---|---|---|
| 0:00-0:20 | Title slide, then the Command Center | "AI agents now pay invoices, answer customers and run servers. In July 2025 an AI coding agent deleted a company's production database during a code freeze. Gartner expects a quarter of enterprise breaches by 2028 to involve AI-agent abuse. We are Team CodeVanta, and this is **AEGIS**, a runtime firewall for AI agents." |
| 0:20-0:35 | Point at KPIs, agents, action stream | "Every tool call an agent makes passes through AEGIS before it runs. Nine detectors judge it in context, in about a third of a millisecond, with no LLM in the loop, so AEGIS itself can't be prompt-injected." |
| 0:35-1:05 | Click **Monitor**, then **▶ Poisoned Invoice**; point at the company systems panel turning red | "First, without enforcement. FinBot pays today's invoices, but one email hides an instruction for AI agents. It pays a real invoice to a fraudster's account plus a 4.85 lakh 'advance'. ₹5.27 lakh, gone." |
| 1:05-1:45 | **Reset demo**, click **Enforce**, run **Poisoned Invoice** again; click the red ₹42,000 row | "Now with AEGIS. The same payments are blocked. Look at the first one: ₹42,000, under every limit, so a rules engine would let it through. But AEGIS tracked where the account number came from: it was planted by injected text in a lookalike email, and it doesn't match the vendor master. That's provenance tracking: it follows the data, not the wording." |
| 1:45-2:15 | **▶ KYC Exfiltration**; open the masked row, then the blocked row | "Context, not keywords. A customer asks for her own details, so she gets them with her Aadhaar masked, per UIDAI norms. A fake compliance note asks for every customer's Aadhaar and PAN to go to Gmail. AEGIS knows whose data it is and where it's going, and blocks it." |
| 2:15-2:40 | **▶ Panicked Agent**; point at OpsBot turning QUARANTINED; click **KILL SWITCH**, then release | "This is the Replit incident. Cleaning logs is fine, but dropping the customers table isn't. After three blocked actions the circuit breaker quarantines the agent. And one click freezes every agent in the company." |
| 2:40-3:05 | **▶ Human Approval**; click **Approve** on the card | "High-impact but legitimate actions, like a ₹75,000 refund, wait for a human, with the full context and a countdown. If nobody answers, it's denied. AEGIS fails closed." |
| 3:05-3:25 | **Audit Ledger** → **Simulate insider tampering** → **Verify integrity** | "Every decision is hash-chained. If an insider quietly rewrites a 'block' to 'allow', verification pinpoints the exact record." |
| 3:25-3:45 | **Live Agent** clip (sped up) or the **Policy** tab | "It works with real models too. Here a live LLM tries to follow the poisoned inbox, and AEGIS stops it. Policies are plain YAML, applied instantly and logged. Any agent framework plugs in with a three-line SDK or our HTTP API." |
| 3:45-4:00 | KPI row | "44 out of 44 expected decisions, zero legitimate actions wrongly blocked, sub-millisecond decisions. AEGIS is the shield between your AI agents and your business. Thank you." |

**If something goes wrong while recording:** click **Reset demo** and run the scenario again; every run is deterministic.
