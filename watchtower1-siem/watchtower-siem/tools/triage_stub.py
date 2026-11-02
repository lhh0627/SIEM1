#!/usr/bin/env python3
"""PLACEHOLDER triage service showing the contract between the AI pipeline and Watchtower.
The AI team replaces llm_triage() with the real agent (hosted LLM, fixed read-only tools, 6-step limit).
Flow: GET /api/alerts -> collect context -> triage -> validate -> POST /api/alerts/{id}/report
Usage: python triage_stub.py [--once]"""
import os, sys, json, time, urllib.request
URL, KEY = os.getenv("WATCHTOWER_URL", "http://localhost:8000"), os.getenv("SIEM_API_KEY", "")
def call(m, p, b=None):
    r = urllib.request.Request(URL + "/api" + p, json.dumps(b).encode() if b is not None else None, {"Content-Type": "application/json", "X-API-Key": KEY}, method=m)
    return json.loads(urllib.request.urlopen(r, timeout=30).read())
ACTIONS = {"true_positive": "Isolate host and reset credentials", "escalate": "Escalate to Tier-2 for review", "false_positive": "Close as benign"}
def llm_triage(alert, context):
    """TODO(AI team): call the LLM here. It must return this structure, citing only evidence IDs it was given."""
    lvl = alert["meta"].get("level", 0); verdict = alert["baseline"]      # stub = baseline, so the LLM has to beat this
    ev = [{"id": f"E{alert['id'][1:]}", "text": alert["event"]}] + [{"id": f"E{c['id'][1:]}", "text": c["event"]} for c in context[:5]]
    return {"verdict": verdict, "technique": (alert["meta"].get("mitre") or [""])[0], "confidence": round(min(lvl / 15, 1), 2),
            "summary": f"Stub verdict from Wazuh level {lvl}. Related events in window: {len(context)}.", "evidence": ev, "recommended_action": ACTIONS[verdict], "model": "stub-baseline"}
def validate(rep, allowed):   # AI2: extend with full JSON-schema check and claim-to-evidence checks
    notes = []
    if rep["verdict"] not in ACTIONS: notes.append("bad verdict")
    notes += [f"unknown evidence {e['id']}" for e in rep["evidence"] if e["id"] not in allowed]
    return not notes, "; ".join(notes)
def run():
    n = 0
    for a in call("GET", "/alerts?limit=50"):
        t0 = time.time(); ctx = call("GET", f"/alerts/{a['id'][1:]}/context?minutes=15")
        rep = llm_triage(a, ctx); ok, notes = validate(rep, {f"E{a['id'][1:]}"} | {f"E{c['id'][1:]}" for c in ctx})
        rep.update(latency_ms=int((time.time() - t0) * 1000), cost_usd=0.0, valid=int(ok), validator_notes=notes)
        call("POST", f"/alerts/{a['id'][1:]}/report", rep); n += 1
    return n
if __name__ == "__main__":
    while True:
        print("reports posted:", run())
        if "--once" in sys.argv: break
        time.sleep(5)
