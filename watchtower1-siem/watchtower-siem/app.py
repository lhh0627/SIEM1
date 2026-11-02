"""Watchtower SIEM backend: ingest -> normalize -> store -> detect -> respond."""
import os, re, json, time, sqlite3, asyncio, threading, random, urllib.request
from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI, APIRouter, Request, HTTPException, Depends
from fastapi.staticfiles import StaticFiles

DB = os.getenv("SIEM_DB", "data/siem.db"); KEY = os.getenv("SIEM_API_KEY", "")
RET = int(os.getenv("RETENTION_DAYS", "90")); HOOK = os.getenv("PLAYBOOK_WEBHOOK_URL", "")
WAZUH_DETECT = os.getenv("WAZUH_DETECT", "0") == "1"  # 0 = Wazuh already detects; do not double-alert
AUTO = os.getenv("AUTO_ISOLATE_CRITICAL", "0") == "1"; WIN = 15 * 60 * 1000
os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
lock = threading.Lock(); db = sqlite3.connect(DB, check_same_thread=False); db.row_factory = sqlite3.Row
db.executescript("""
create table if not exists events(id integer primary key autoincrement,t integer,source text,event text,sev text,host text,user text,ip text,msg text,raw text);
create index if not exists ix_t on events(t); create index if not exists ix_h on events(host,t);
create table if not exists rules(id integer primary key autoincrement,name text,q text,thr integer,sev text,mitre text,on_ integer default 1);
create table if not exists incidents(id integer primary key autoincrement,title text,sev text,status text,owner text,host text,rule text,t integer,evs integer,notes text);
create table if not exists iocs(id integer primary key autoincrement,v text,t text,s text);
create table if not exists plog(id integer primary key autoincrement,t integer,pb text,inc text,by text,res text);
create table if not exists audit(id integer primary key autoincrement,t integer,u text,m text);
create table if not exists triage(id integer primary key autoincrement,event_id integer,t integer,verdict text,technique text,confidence real,summary text,evidence text,action text,model text,latency_ms integer,cost_usd real,valid integer,vnotes text,decision text,decided_by text,decided_at integer,note text);
create table if not exists labels(event_id integer,labeler text,label text,primary key(event_id,labeler));""")
for _c in ("meta", "uid"):
    try: db.execute(f"alter table events add column {_c} text")
    except sqlite3.OperationalError: pass
db.execute("create index if not exists ix_uid on events(uid)")
now = lambda: int(time.time() * 1000)
def q(sql, *a):
    with lock: return [dict(r) for r in db.execute(sql, a).fetchall()]
def ex(sql, *a):
    with lock:
        c = db.execute(sql, a); db.commit(); return c.lastrowid
def log(m, u="system"): ex("insert into audit(t,u,m) values(?,?,?)", now(), u, m)
if not q("select 1 from rules"):
    for r in [("Brute force: repeated failed logons","event~fail",5,"high","T1110",1),("Credential dumping tool detected","event~mimikatz",1,"critical","T1003",1),
              ("CloudTrail logging disabled","event~DeleteTrail",1,"high","T1562",1),("Encoded PowerShell execution","event~powershell",1,"high","T1059",1),
              ("Mailbox forwarding rule created","event~MailForward",1,"medium","T1114",1),("Port scan from external IP","event~scan",2,"medium","T1046",0)]:
        ex("insert into rules(name,q,thr,sev,mitre,on_) values(?,?,?,?,?,?)", *r)
    for v, t, s in [("185.220.101.7","IP","AbuseIPDB"),("mimikatz","Keyword","Internal"),("91.240.118.22","IP","AlienVault OTX")]:
        ex("insert into iocs(v,t,s) values(?,?,?)", v, t, s)

# ---------- query language ----------
COLS = ["source", "event", "sev", "host", "user", "ip", "msg"]
def build(qs):
    head, *pipes = qs.split("|"); w, a = [], []
    for t in re.findall(r'(?:[^\s"]+|"[^"]*")+', head):
        m = re.match(r'^(\w+)(!=|=|~)(.+)$', t)
        if m and m[1] in COLS:
            k, op, v = m[1], m[2], m[3].replace('"', '').lower()
            w.append(f"lower({k}) {'=' if op=='=' else '!=' if op=='!=' else 'like'} ?"); a.append(v if op != "~" else f"%{v}%")
        else:
            w.append("lower(" + "||' '||".join(COLS) + ") like ?"); a.append("%" + t.replace('"', '').lower() + "%")
    return w, a, [p.strip() for p in pipes]
def ev_out(r): return {k: r[k] for k in ["t", *COLS]} | {"id": f"e{r['id']}"}
def search(qs, hours=0, limit=100):
    w, a, p = build(qs)
    if hours: w.append("t>=?"); a.append(now() - int(hours) * 3600000)
    cond = (" where " + " and ".join(w)) if w else ""
    m = re.match(r'(?:count by|top)\s+(\w+)', p[0], re.I) if p else None
    if m and m[1] in COLS:
        rows = q(f"select {m[1]} k,count(*) c from events{cond} group by {m[1]} order by c desc limit 25", *a)
        return {"agg": [[r["k"], r["c"]] for r in rows], "total": sum(r["c"] for r in rows)}
    return {"rows": [ev_out(r) for r in q(f"select * from events{cond} order by t desc limit ?", *a, limit)],
            "total": q(f"select count(*) c from events{cond}", *a)[0]["c"]}

# ---------- normalization ----------
SEVMAP = {0:"critical",1:"critical",2:"critical",3:"high",4:"medium",5:"low",6:"info",7:"info"}
SEVS = {"emergency":"critical","alert":"critical","critical":"critical","fatal":"critical","error":"high","high":"high","warning":"medium","warn":"medium","medium":"medium","notice":"low","low":"low"}
SYS = re.compile(r'^<(\d+)>(?:\w{3}\s+\d+\s[\d:]+|\d\S+)\s+(\S+)\s+([\w\-./]+)(?:\[\d+\])?:\s*(.*)$')
def classify(tag, msg, sev):
    l = msg.lower()
    if "failed password" in l or "authentication failure" in l: return "Linux Auth", "sshd failed password", "low"
    if "accepted" in l and tag.startswith("ssh"): return "Linux Auth", "sshd accepted login", "info"
    if tag == "sudo": return "Linux Auth", "sudo command", "info"
    if "port scan" in l or "portscan" in l: return "Firewall", "Port scan detected", "medium"
    if "mimikatz" in l: return "EDR", "Mimikatz signature", "critical"
    if re.search(r"\b(deny|denied|drop)\b", l): return "Firewall", "Deny inbound", "low"
    return tag, msg[:80], sev
def from_syslog(line, peer):
    m = SYS.match(line)
    if not m: return dict(t=now(), source="Syslog", event=line[:80], sev="info", host=peer, user="", ip="", msg=line, raw=line)
    pri, host, tag, msg = int(m[1]), m[2], m[3], m[4]; src, e, sev = classify(tag, msg, SEVMAP[pri % 8])
    ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", msg); u = re.search(r"(?:for|user)\s+(?:invalid user\s+)?([\w.\-]+)", msg)
    return dict(t=now(), source=src, event=e, sev=sev, host=host, user=u[1] if u else "", ip=ip[1] if ip else "", msg=msg, raw=line)
def from_json(d):
    if isinstance(d.get("rule"), dict) and "agent" in d: return from_wazuh(d)
    g = lambda *k: next((str(d[x]) for x in k if d.get(x) not in (None, "")), "")
    ts = d.get("t") or d.get("timestamp") or d.get("@timestamp") or d.get("time"); t = now()
    try:
        t = (float(ts) * (1000 if float(ts) < 1e12 else 1)) if isinstance(ts, (int, float)) or str(ts).replace(".", "").isdigit() else datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp() * 1000
    except Exception: pass
    e = g("event", "event_type", "action", "message") or "log"
    return dict(t=int(t), source=g("source", "product", "log_source") or "Generic", event=e[:120], sev=SEVS.get(g("sev", "severity", "level").lower(), "info"),
                host=g("host", "hostname", "computer") or "unknown", user=g("user", "username", "account"), ip=g("ip", "src_ip", "source_ip", "client_ip"),
                msg=g("msg", "message") or e, raw=json.dumps(d)[:2000])
def ingest_one(it, peer="?"):
    if isinstance(it, str):
        try: it = json.loads(it) if it.lstrip().startswith("{") else it
        except Exception: pass
    e = from_json(it) if isinstance(it, dict) else from_syslog(it, peer)
    if e.get("uid") and q("select 1 from events where uid=?", e["uid"]): return   # replay-safe: skip duplicates
    eid = ex("insert into events(t,source,event,sev,host,user,ip,msg,raw,meta,uid) values(?,?,?,?,?,?,?,?,?,?,?)", e["t"], e["source"], e["event"], e["sev"], e["host"], e["user"], e["ip"], e["msg"], e["raw"], e.get("meta", ""), e.get("uid"))
    if e["source"] != "Wazuh" or WAZUH_DETECT: detect(e, eid)

# ---------- detection ----------
def make_inc(title, sev, host, rule, n):
    i = ex("insert into incidents(title,sev,status,owner,host,rule,t,evs,notes) values(?,?,?,?,?,?,?,?,?)", title, sev, "New", "Unassigned", host, rule, now(), n,
           json.dumps([{"t": now(), "a": "system", "x": "Incident opened by " + rule}]))
    log(f"Incident INC-{1000+i} created: {title}")
    if AUTO and sev == "critical": run_pb(f"INC-{1000+i}", 1, "automation")
    return i
def open_exists(rule, host): return bool(q("select 1 from incidents where rule=? and host=? and status!='Closed'", rule, host))
def detect(e, eid):
    hay = " ".join(str(e[k]) for k in COLS).lower()
    for r in q("select * from rules where on_=1"):
        w, a, _ = build(r["q"]); base = " and ".join(w) or "1=1"
        if not q(f"select 1 from events where id=? and {base}", eid, *a): continue
        n = q(f"select count(*) c from events where host=? and t>=? and {base}", e["host"], e["t"] - WIN, *a)[0]["c"]
        if n >= r["thr"] and not open_exists(r["name"], e["host"]): make_inc(f"{r['name']} on {e['host']}", r["sev"], e["host"], r["name"], n)
    for o in q("select * from iocs"):
        nm = "Threat intel: " + o["v"]
        if o["v"].lower() in hay and not open_exists(nm, e["host"]): make_inc(f"Threat intel match: {o['v']} on {e['host']}", "high", e["host"], nm, 1)

# ---------- response ----------
PBS = ["Block IP at firewall", "Isolate host via EDR", "Disable user account", "Notify on-call analyst"]
def run_pb(inc_id, k, by):
    pk = int(inc_id[4:]) - 1000; r = q("select * from incidents where id=?", pk)
    if not r: raise HTTPException(404, "incident not found")
    res = "Simulated (set PLAYBOOK_WEBHOOK_URL to execute)"
    if HOOK:
        try:
            urllib.request.urlopen(urllib.request.Request(HOOK, json.dumps({"playbook": PBS[k], "incident": inc_id, "host": r[0]["host"], "title": r[0]["title"]}).encode(), {"Content-Type": "application/json"}), timeout=5); res = "Success"
        except Exception as x: res = "Failed: " + str(x)[:80]
    notes = json.loads(r[0]["notes"]) + [{"t": now(), "a": "playbook", "x": f"{PBS[k]}: {res}"}]
    ex("update incidents set notes=?, status=? where id=?", json.dumps(notes), "Investigating" if r[0]["status"] == "New" else r[0]["status"], pk)
    ex("insert into plog(t,pb,inc,by,res) values(?,?,?,?,?)", now(), PBS[k], inc_id, by, res); log(f"Playbook {PBS[k]} ran on {inc_id}: {res}", by)
    return res

# ---------- API ----------
def auth(request: Request):
    if KEY and request.headers.get("x-api-key") != KEY: raise HTTPException(401, "API key required")
api = APIRouter(prefix="/api", dependencies=[Depends(auth)])
inc_out = lambda r: {**r, "id": f"INC-{1000+r['id']}", "notes": json.loads(r["notes"])}
@api.get("/state")
def state(after: int = 0):
    return {"events": [ev_out(r) for r in q("select * from events where id>? order by id desc limit 3000", after)],
            "incidents": [inc_out(r) for r in q("select * from incidents order by id desc")],
            "rules": [{**r, "on": r["on_"]} for r in q("select * from rules")], "iocs": q("select * from iocs"), "plog": q("select * from plog order by id desc limit 100"),
            "audit": q("select * from audit order by id desc limit 100"), "total": q("select count(*) c from events")[0]["c"],
            "sources": q("select source,count(*) c from events where t>=? group by source", now() - 3600000)}
@api.post("/ingest")
async def ingest(request: Request):
    raw = (await request.body()).decode(errors="replace").strip()
    try: d = json.loads(raw); items = d if isinstance(d, list) else [d]
    except Exception: items = [l for l in raw.splitlines() if l.strip()]
    for it in items: ingest_one(it, request.client.host if request.client else "?")
    return {"ingested": len(items)}
@api.post("/search")
async def do_search(b: dict): return search(b.get("q", ""), b.get("hours", 0))
@api.post("/rules")
async def add_rule(b: dict):
    i = ex("insert into rules(name,q,thr,sev,mitre,on_) values(?,?,?,?,?,1)", b["name"], b["q"], int(b.get("thr", 1)), b.get("sev", "medium"), b.get("mitre", "n/a")); log("Rule added: " + b["name"], "analyst"); return {"id": i}
@api.post("/rules/{rid}/toggle")
def toggle(rid: int): ex("update rules set on_=1-on_ where id=?", rid); log(f"Rule {rid} toggled", "analyst"); return {}
@api.delete("/rules/{rid}")
def del_rule(rid: int): ex("delete from rules where id=?", rid); log(f"Rule {rid} deleted", "analyst"); return {}
@api.post("/rules/{rid}/run")
def run_rule(rid: int):
    r = q("select * from rules where id=?", rid)[0]; w, a, _ = build(r["q"]); n = 0
    for g in q(f"select host,count(*) c from events where {' and '.join(w) or '1=1'} group by host", *a):
        if g["c"] >= r["thr"] and not open_exists(r["name"], g["host"]): make_inc(f"{r['name']} on {g['host']}", r["sev"], g["host"], r["name"], g["c"]); n += 1
    log("Rule run: " + r["name"], "analyst"); return {"created": n}
@api.post("/iocs")
async def add_ioc(b: dict): ex("insert into iocs(v,t,s) values(?,?,?)", b["v"], b.get("t", "IP"), b.get("s", "Manual")); log("IOC added " + b["v"], "analyst"); return {}
@api.delete("/iocs/{oid}")
def del_ioc(oid: int): ex("delete from iocs where id=?", oid); log("IOC removed", "analyst"); return {}
@api.post("/iocs/scan")
def scan():
    n = 0
    for o in q("select * from iocs"):
        nm = "Threat intel: " + o["v"]; h = q("select host from events where lower(" + "||' '||".join(COLS) + ") like ? limit 500", "%" + o["v"].lower() + "%")
        if h and not open_exists(nm, h[0]["host"]): make_inc(f"Threat intel match: {o['v']}", "high", h[0]["host"], nm, len(h)); n += 1
    return {"created": n}
@api.patch("/incidents/{iid}")
async def patch(iid: str, b: dict):
    f = b["field"]
    if f not in ("sev", "status", "owner"): raise HTTPException(400, "bad field")
    pk = int(iid[4:]) - 1000; r = q("select notes from incidents where id=?", pk)[0]
    notes = json.loads(r["notes"]) + [{"t": now(), "a": "analyst", "x": f"{f} set to {b['value']}"}]
    ex(f"update incidents set {f}=?, notes=? where id=?", b["value"], json.dumps(notes), pk); log(f"{iid} {f} set to {b['value']}", "analyst"); return {}
@api.post("/incidents/{iid}/notes")
async def note(iid: str, b: dict):
    pk = int(iid[4:]) - 1000; notes = json.loads(q("select notes from incidents where id=?", pk)[0]["notes"]) + [{"t": now(), "a": "analyst", "x": b["text"]}]
    ex("update incidents set notes=? where id=?", json.dumps(notes), pk); return {}
@api.post("/incidents/{iid}/playbook")
async def playbook(iid: str, b: dict): return {"result": run_pb(iid, int(b["k"]), "analyst")}
@api.post("/events/{eid}/incident")
def ev_inc(eid: str):
    e = q("select * from events where id=?", int(eid[1:]))[0]
    return {"id": f"INC-{1000+make_inc(e['event']+' on '+e['host'], 'low' if e['sev']=='info' else e['sev'], e['host'], 'Manual', 1)}"}
@api.post("/simulate")
def simulate():
    h, ip, t = random.choice(["dc01", "web-prod-02", "db-fin-01", "vpn-gw"]), "185.220.101.7", now()
    steps = [("Windows Security", "4625 Failed logon", "low")] * 7 + [("Windows Security", "4624 Logon", "info"), ("EDR", "PowerShell encoded command", "high"), ("EDR", "Mimikatz signature", "critical")]
    for i, (s, e, v) in enumerate(steps): ingest_one({"t": t + i, "source": s, "event": e, "sev": v, "host": h, "user": "admin", "ip": ip, "msg": f"{e} on {h} by admin from {ip}"})
    log("Attack simulation on " + h, "analyst"); return {}

# ---------- Wazuh + triage ----------
def parse_ts(ts):
    try:
        if isinstance(ts, (int, float)): return int(ts * (1000 if ts < 1e12 else 1))
        return int(datetime.fromisoformat(re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", str(ts).replace("Z", "+00:00"))).timestamp() * 1000)
    except Exception: return now()
def first(*v): return next((x for x in v if x not in (None, "")), "")
def from_wazuh(d):
    r, a = d.get("rule") or {}, d.get("agent") or {}; dt = d.get("data") if isinstance(d.get("data"), dict) else {}
    win = (dt.get("win") or {}).get("eventdata") or {}; mt = r.get("mitre") if isinstance(r.get("mitre"), dict) else {}
    lvl = int(r.get("level") or 0); desc = str(r.get("description") or "Wazuh alert")
    sev = "info" if lvl <= 3 else "low" if lvl <= 6 else "medium" if lvl <= 9 else "high" if lvl <= 12 else "critical"
    meta = {"rule_id": r.get("id"), "level": lvl, "mitre": mt.get("id", []), "technique": mt.get("technique", []), "tactic": mt.get("tactic", []),
            "groups": r.get("groups", []), "agent_id": a.get("id"), "alert_id": d.get("id")}
    return dict(t=parse_ts(d.get("timestamp")), source="Wazuh", event=desc[:120], sev=sev, host=str(first(a.get("name"), (d.get("manager") or {}).get("name"), "unknown")),
                user=str(first(dt.get("srcuser"), dt.get("dstuser"), win.get("targetUserName"), win.get("subjectUserName"))),
                ip=str(first(dt.get("srcip"), win.get("ipAddress"), win.get("sourceIp"))), msg=str(first(d.get("full_log"), desc)),
                raw=json.dumps(d)[:20000], meta=json.dumps(meta), uid=str(d.get("id") or "") or None)
def baseline(level): return "true_positive" if level >= 10 else "escalate" if level >= 7 else "false_positive"   # baseline 1: Wazuh rule level
VERD = {"true_positive", "false_positive", "escalate"}
def wz(r): m = json.loads(r["meta"] or "{}"); return {**ev_out(r), "meta": m, "baseline": baseline(m.get("level", 0))}
@api.get("/alerts")
def pending(status: str = "pending", limit: int = 50):
    rows = q("select * from events e where source='Wazuh' and not exists(select 1 from triage t where t.event_id=e.id) order by t limit ?", limit)
    return [{**wz(r), "alert": json.loads(r["raw"] or "{}")} for r in rows]
@api.get("/alerts/{eid}/context")
def context(eid: int, minutes: int = 15):
    e = q("select * from events where id=?", eid)[0]; w = minutes * 60000
    rows = q("select * from events where id!=? and t between ? and ? and (host=? or (user!='' and user=?)) order by t limit 100", eid, e["t"] - w, e["t"] + w, e["host"], e["user"])
    return [ev_out(r) for r in rows]
@api.post("/alerts/{eid}/report")
async def add_report(eid: int, b: dict):
    if b.get("verdict") not in VERD: raise HTTPException(400, "verdict must be one of " + ", ".join(sorted(VERD)))
    if not q("select 1 from events where id=? and source='Wazuh'", eid): raise HTTPException(404, "alert not found")
    rid = ex("insert into triage(event_id,t,verdict,technique,confidence,summary,evidence,action,model,latency_ms,cost_usd,valid,vnotes) values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
             eid, now(), b["verdict"], b.get("technique", ""), b.get("confidence"), b.get("summary", ""), json.dumps(b.get("evidence", [])), b.get("recommended_action", ""),
             b.get("model", ""), b.get("latency_ms"), b.get("cost_usd"), int(b.get("valid", 1)), b.get("validator_notes", ""))
    log(f"Triage report {rid} for alert {eid}: {b['verdict']}", b.get("model") or "triage-agent"); return {"id": rid}
def rep_out(r): return {**r, "evidence": json.loads(r["evidence"] or "[]")}
def summary_text(e, m, r):
    ids = ", ".join(x.get("id", "") if isinstance(x, dict) else str(x) for x in r["evidence"])
    return (f"Incident summary\nAlert: {e['event']} (Wazuh rule {m.get('rule_id')}, level {m.get('level')})\nHost: {e['host']}   User: {e['user'] or 'n/a'}   Source IP: {e['ip'] or 'n/a'}\n"
            f"Time: {datetime.fromtimestamp(e['t']/1000).isoformat()}\nVerdict: {r['verdict']} (confidence {r['confidence']})   MITRE ATT&CK: {r['technique'] or 'n/a'}\n"
            f"Findings: {r['summary']}\nEvidence: {ids}\nRecommended action: {r['action']}\nAnalyst decision: {r['decision'] or 'pending'}")
@api.get("/triage")
def triage_list(limit: int = 300):
    rows = q("""select e.*,t.id rid,t.verdict,t.technique tech,t.decision,(select group_concat(labeler||':'||label) from labels where event_id=e.id) labs
                from events e left join triage t on t.event_id=e.id and t.id=(select max(id) from triage where event_id=e.id)
                where e.source='Wazuh' order by e.t desc limit ?""", limit)
    return [{**wz(r), **{k: r[k] for k in ("rid", "verdict", "tech", "decision", "labs")}} for r in rows]
@api.get("/triage/{eid}")
def triage_detail(eid: int):
    r = q("select * from events where id=?", eid)[0]; w = wz(r); reps = q("select * from triage where event_id=? order by id desc", eid)
    rep = rep_out(reps[0]) if reps else None
    return {"event": ev_out(r), "meta": w["meta"], "baseline": w["baseline"], "alert": json.loads(r["raw"] or "{}"), "report": rep,
            "labels": q("select labeler,label from labels where event_id=?", eid), "summary": summary_text(ev_out(r), w["meta"], rep) if rep else ""}
@api.post("/reports/{rid}/decision")
async def decide(rid: int, b: dict):
    if b.get("decision") not in ("approved", "rejected"): raise HTTPException(400, "decision must be approved or rejected")
    r = q("select * from triage where id=?", rid)[0]
    ex("update triage set decision=?, decided_by=?, decided_at=?, note=? where id=?", b["decision"], "analyst", now(), b.get("note", ""), rid)
    log(f"Report {rid} (alert {r['event_id']}) {b['decision']}: {r['action']}", "analyst")
    if b["decision"] == "approved":   # containment is simulated and logged only, never executed
        ex("insert into plog(t,pb,inc,by,res) values(?,?,?,?,?)", now(), r["action"] or "No action", f"ALERT-{r['event_id']}", "analyst", "Simulated containment (logged only)")
    return {}
@api.post("/alerts/{eid}/label")
async def label(eid: int, b: dict):
    if b.get("label") not in VERD: raise HTTPException(400, "bad label")
    ex("insert or replace into labels(event_id,labeler,label) values(?,?,?)", eid, (b.get("labeler") or "labeler").strip()[:40], b["label"]); log(f"Alert {eid} labelled {b['label']}", b.get("labeler") or "labeler"); return {}
def kappa(pairs):
    n = len(pairs)
    if n < 2: return None
    cats = sorted({x for p in pairs for x in p}); po = sum(a == b for a, b in pairs) / n
    pe = sum((sum(a == c for a, _ in pairs) / n) * (sum(b == c for _, b in pairs) / n) for c in cats)
    return None if pe == 1 else round((po - pe) / (1 - pe), 3)
@api.get("/eval")
def evaluate():
    raw = {}
    for r in q("select event_id,labeler,label from labels"): raw.setdefault(r["event_id"], {})[r["labeler"]] = r["label"]
    truth = {k: (v["adjudicated"] if "adjudicated" in v else next(iter(v.values())) if len(set(v.values())) == 1 else None) for k, v in raw.items()}
    reps = {r["event_id"]: r for r in q("select * from triage where id in (select max(id) from triage group by event_id)")}
    lv = {r["id"]: json.loads(r["meta"] or "{}").get("level", 0) for r in q("select id,meta from events where source='Wazuh'")}
    rows = [(k, v) for k, v in truth.items() if v and k in reps]; n = len(rows); mal = [(k, v) for k, v in rows if v == "true_positive"]
    pct = lambda a, b: round(100 * a / b, 1) if b else None
    lat = sorted(r["latency_ms"] for r in reps.values() if r["latency_ms"]); pairs = []
    for v in raw.values():
        ls = [x for k, x in sorted(v.items()) if k != "adjudicated"]
        if len(ls) >= 2: pairs.append((ls[0], ls[1]))
    dec = [r["decision"] for r in reps.values() if r["decision"]]
    return {"labelled": len(truth), "disputed": sum(1 for v in truth.values() if v is None), "reports": len(reps), "evaluated": n,
            "accuracy_pct": pct(sum(reps[k]["verdict"] == v for k, v in rows), n), "baseline_level_accuracy_pct": pct(sum(baseline(lv.get(k, 0)) == v for k, v in rows), n),
            "malicious_recall_pct": pct(sum(reps[k]["verdict"] == "true_positive" for k, _ in mal), len(mal)),
            "malicious_recall_incl_escalate_pct": pct(sum(reps[k]["verdict"] in ("true_positive", "escalate") for k, _ in mal), len(mal)),
            "valid_reports_pct": pct(sum(1 for r in reps.values() if r["valid"]), len(reps)), "median_latency_ms": lat[len(lat) // 2] if lat else None,
            "total_cost_usd": round(sum(r["cost_usd"] or 0 for r in reps.values()), 4), "labeler_kappa": kappa(pairs), "labeler_pairs": len(pairs),
            "approved": dec.count("approved"), "rejected": dec.count("rejected")}

# ---------- lifecycle ----------
class Syslog(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        for l in data.decode(errors="replace").splitlines():
            if l.strip(): ingest_one(l.strip(), addr[0])
async def retention():
    while True:
        ex("delete from events where t<?", now() - RET * 86400000); await asyncio.sleep(3600)
@asynccontextmanager
async def life(app):
    loop = asyncio.get_running_loop(); tr, _ = await loop.create_datagram_endpoint(Syslog, local_addr=("0.0.0.0", int(os.getenv("SYSLOG_PORT", "5514")))); task = asyncio.create_task(retention())
    yield
    task.cancel(); tr.close()
app = FastAPI(title="Watchtower SIEM", lifespan=life); app.include_router(api)
@app.get("/health")
def health(): return {"ok": True, "auth_required": bool(KEY)}
app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"), html=True))
