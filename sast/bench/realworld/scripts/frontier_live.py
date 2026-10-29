"""Live frontier benchmark: Sentinel (Claude tiers) vs engine-only vs an LLM that reads every file. Metered."""
import json, os, sys, threading, time
from pathlib import Path
sys.path.insert(0, "/home/user/novalang/sast")
os.environ["SENTINEL_LLM"] = "claude"
from anthropic.resources.beta.messages import messages as bm
from anthropic.resources.messages import messages as m1

PRICE = {"in": 4.0, "out": 20.0, "cw": 5.0, "cr": 0.20}
meter = {"calls": 0, "in": 0, "out": 0, "cw": 0, "cr": 0, "refusals": 0, "errors": 0}
lock = threading.Lock()

def wrap(cls):
    orig = cls.create
    def metered(self, *a, **kw):
        try:
            r = orig(self, *a, **kw)
        except Exception:
            with lock: meter["errors"] += 1
            raise
        u = r.usage
        with lock:
            meter["calls"] += 1; meter["in"] += u.input_tokens; meter["out"] += u.output_tokens
            meter["cw"] += getattr(u, "cache_creation_input_tokens", 0) or 0
            meter["cr"] += getattr(u, "cache_read_input_tokens", 0) or 0
            meter["refusals"] += r.stop_reason == "refusal"
        return r
    cls.create = metered
wrap(bm.Messages); wrap(m1.Messages)

def usd(m): return round(sum(m[k] * PRICE[k] / 1e6 for k in PRICE), 3)
def snap(): return dict(meter)
def delta(a, b): return {k: b[k] - a[k] for k in a}

from sentinel.store.db import Store
from sentinel.pipeline import Scanner
from sentinel.engine.analyze import analyze
from sentinel.eval import CountingOracle, read_everything_cost

OSS = Path("/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad/oss")
DEMO = Path("/home/user/novalang/sast/demo")
import os
REPOS = {k: Path("/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad/heldout")/k for k in ["Vulnerable-Flask-App","DSVW","flask-realworld-example-app","microblog","full-stack-fastapi-template"]} if os.environ.get("HELDOUT") == "1" else {k: Path("/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad/heldout2")/k for k in ["vulnpy","DSVPWA","flasky","flaskbb","fastapi-realworld-example-app"]} if os.environ.get("HELDOUT") == "2" else {k: Path("/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad/heldout3")/k for k in ["VAmPI","python-insecure-app","httpbin","redash"]} if os.environ.get("HELDOUT") == "3" else {k: Path("/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad/heldout4")/k for k in ["vulnerable-api","lets-be-bad-guys","bakerydemo","flask-examples"]} if os.environ.get("HELDOUT") == "4" else {"acme-reports": DEMO / "acme-reports", "acme-etl": DEMO / "acme-etl", "dvpwa": OSS / "dvpwa",
         "vulpy": OSS / "vulpy", "pygoat": OSS / "pygoat"}
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad/bench/frontier_live.json")
only = sys.argv[2].split(",") if len(sys.argv) > 2 else list(REPOS)
res = {"repos": {}}
st = Store(":memory:"); st.upsert_org("acme", "Acme")
sc = Scanner(st)
sc.oracle = counting = CountingOracle(sc.oracle)
for name in only:
    st.upsert_repo(name, "acme", name, str(REPOS[name]))
    facts, matches = sc.inputs(name, refresh=True)
    engine_only = [(f.source_fn, f.cls, f.file, f.line, f.status) for f in analyze(facts, matches, [], sc.program).findings
                   if f.status in ("confirmed", "undecided")]
    a, n0, t = snap(), len(counting.calls), time.time()
    stats = sc.scan(name)
    d = delta(a, snap())
    rows = st.q("SELECT fingerprint, cls, lane, source_fn, file, line, engine_status, data FROM findings WHERE repo_id=? AND is_open=1", name)
    res["repos"][name] = {
        "size": read_everything_cost(sc, name),
        "engine_only": engine_only,
        "stats": {k: stats.get(k) for k in ("findings", "lanes", "frontier_questions", "frontier_cached", "frontier_facts",
                                            "found_by_frontier", "tier1_calls", "tier2_calls")},
        "asked": [c[:2] for c in counting.calls[n0:]],
        "findings": [{"fn": r["source_fn"], "cls": r["cls"], "lane": r["lane"], "at": f"{r['file']}:{r['line']}",
                      "learned": [x["subject"] for x in r["data"].get("learned", [])],
                      "verdicts": [{"kind": v["kind"], "verdict": v["verdict"], "why": (v["evidence"] or {}).get("rationale", "")[:300],
                                    "gate": [c for c in (v["gate"] or {}).get("checks", []) if not c.get("ok")]}
                                   for v in st.q("SELECT v.* FROM verdicts v JOIN findings f ON f.id=v.finding_id WHERE f.repo_id=? AND f.fingerprint=?", name, r["fingerprint"])]}
                     for r in rows],
        "spend": {**d, "usd": usd(d)}, "minutes": round((time.time() - t) / 60, 1)}
    print(name, json.dumps(res["repos"][name]["stats"]), res["repos"][name]["spend"]["usd"], flush=True)
    OUT.write_text(json.dumps(res, indent=1, default=str))
res["knowledge"] = [{k: r[k] for k in ("id", "pred", "args", "status", "scope", "confidence", "rationale")}
                    for r in st.q("SELECT * FROM knowledge ORDER BY id")]
res["spend_total"] = {**meter, "usd": usd(meter)}
OUT.write_text(json.dumps(res, indent=1, default=str))
print("TOTAL", res["spend_total"])
