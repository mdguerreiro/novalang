"""Score Sentinel on the pre-registered real-world split. Usage: run.py engine|live OUT.json [DB]"""
import json, os, sys, time
mode, out = sys.argv[1], sys.argv[2]
S = "/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad"
sys.path.insert(0, os.environ.get("SENTINEL_ROOT", "/home/user/novalang/sast"))
os.environ["SENTINEL_LLM"] = "claude" if mode == "live" else "mock"
os.environ.setdefault("SENTINEL_PACKS", "")
meter = {"calls": 0}; usd = lambda m: 0.0
if mode == "live":
    exec(open(S + "/bench/frontier_live.py").read().split("from sentinel.store.db import Store")[0].split("OSS = Path")[0])
from sentinel.store.db import Store
from sentinel.pipeline import Scanner
from sentinel.engine.analyze import analyze
BUDGET = float(os.environ.get("RW2_BUDGET", "60"))
cases = json.load(open(os.environ.get("RW_CASES", S + "/rw2/cases.json")))["cases"]
st = Store(sys.argv[3] if len(sys.argv) > 3 else ":memory:"); st.upsert_org("acme", "Acme"); sc = Scanner(st)


def keyset(target):
    """Names a finding's function must equal or end with: the module-qualified target (`cookiecutter.vcs.clone`) and,
    for methods, the class-qualified name (survives a moved file); never a bare function name (`gen`, `run`)."""
    path, q = target.split(":")
    mod = path[:-3].replace("/", ".").removesuffix(".__init__")
    keys = [f"{mod}.{q}"] + [mod.split(".", i)[-1] + "." + q for i in range(1, mod.count(".") + 1)]
    if "." in q:
        keys.append(q)
    return keys


SAME = {"code": {"code", "ssti"}}  # template injection (CWE-1336) is code injection (CWE-94)


def near(f, keys):
    fns = {f["source_fn"], f["sink_fn"]} | {s.get("fn", "") for s in f.get("path", [])}
    return any(fn == k or fn.endswith("." + k) for fn in fns for k in keys)


def hit(f, cls, keys):
    return f["cls"] in SAME.get(cls, {cls}) and near(f, keys)


res = json.load(open(out)) if os.path.exists(out) else {}  # resume
# Spend of every process, written every 15 s so a container restart mid-tree can't hide what it spent. Processes
# before this file existed: "legacy" = what their completed trees recorded (their interrupted spend is unmetered).
SPEND = out + ".spend.json"
procs = json.load(open(SPEND)) if os.path.exists(SPEND) else {
    "legacy": sum(x.get("usd", 0) for x in res.values() if isinstance(x, dict))}
BASE = sum(procs.values())
ME = f"p{int(time.time())}"
if mode == "live":
    import threading
    def _flush():
        while True:
            procs[ME] = round(usd(meter), 4); json.dump(procs, open(SPEND + ".tmp", "w")); os.replace(SPEND + ".tmp", SPEND)
            time.sleep(15)
    threading.Thread(target=_flush, daemon=True).start()
for c in cases:
    keys = [k for t in c["targets"] for k in keyset(t)]
    for v in ("vul", "fix"):
        already = BASE  # survives restarts; this process's own spend is in the meter
        if mode == "live" and already + usd(meter) > BUDGET:
            res[f"{c['cve']}-{v}"] = {"skipped": "budget"}; continue
        repo = f"{c['cve'].split('id=')[-1]}-{v}"
        if repo in res and ("skipped" not in res[repo] or res[repo]["skipped"] == "memory"):
            continue
        # A tree started twice without finishing killed the process (out of memory): record it, move on.
        tries = json.load(open(out + ".tries")) if os.path.exists(out + ".tries") else {}
        tries[repo] = tries.get(repo, 0) + 1
        json.dump(tries, open(out + ".tries", "w"))
        if tries[repo] > 2:
            res[repo] = {"cls": c["cls"], "skipped": "memory", "flagged": False, "reported": None}
            json.dump(res, open(out, "w"), indent=1)
            print(repo, "skipped: memory", flush=True)
            continue
        st.upsert_repo(repo, "acme", repo, c["trees"][v])
        print("start", repo, time.strftime("%H:%M:%S"), "spent so far", round(already + usd(meter), 2) if mode == "live" else 0, flush=True)
        t, m0 = time.time(), dict(meter)
        if mode == "engine":
            facts, matches = sc.inputs(repo, refresh=True)
            found = [{"cls": f.cls, "source_fn": f.source_fn, "sink_fn": f.sink_fn, "path": [{"fn": s.fn} for s in f.path],
                      "lane": f.status, "kind": f.source_kind} for f in analyze(facts, matches, sc.ks.engine_facts("acme", repo), sc.program).findings
                     if f.status in ("confirmed", "undecided")]
            stats = {}
        else:
            stats = sc.scan(repo)
            found = [{"cls": x["cls"], "source_fn": x["source_fn"], "sink_fn": x["sink_fn"], "path": x["data"].get("path", []),
                      "lane": x["lane"]} for x in st.q("SELECT cls, source_fn, sink_fn, data, lane FROM findings WHERE repo_id=? "
                                                      "AND is_open=1 AND lane IN ('confirmed','review')", repo)]
        d = {k: meter[k] - m0.get(k, 0) for k in meter}
        res[repo] = {"cls": c["cls"], "flagged": any(hit(f, c["cls"], keys) for f in found), "reported": len(found),
                     "minutes": round((time.time() - t) / 60, 1), "usd": round(usd(d), 3) if mode == "live" else 0,
                     "questions": stats.get("frontier_questions"), "tools": c["tools"] if v == "vul" else None,
                     "near": [{k: x.get(k) for k in ("cls", "source_fn", "sink_fn", "lane")} for x in found if near(x, keys)][:20],
                     "kinds": dict(__import__("collections").Counter(f"{x.get('kind') or '?'}/{x['cls']}" for x in found))}
        print(repo, json.dumps({k: res[repo][k] for k in ("cls", "flagged", "reported", "minutes", "usd")}), flush=True)
        json.dump(res, open(out, "w"), indent=1)
        sc._inputs.pop(repo, None)  # large repositories: keep memory flat across the run
        sc.last.pop(repo, None)
        sc.program._memo.clear()
if mode == "live":
    procs[ME] = round(usd(meter), 4); json.dump(procs, open(SPEND, "w"))
print("TOTAL", round(BASE + usd(meter), 2) if mode == "live" else 0)
