"""Position of each case's target functions in the review ranking (engine and naive), no model calls.
Usage: rankpos.py OUT.json CASES.json"""
import json, os, sys, gc
sys.path.insert(0, os.environ["SENTINEL_ROOT"])
os.environ["SENTINEL_LLM"] = "mock"
from sentinel.store.db import Store
from sentinel.pipeline import Scanner
from sentinel.engine.analyze import analyze
from sentinel import review as rv
out = sys.argv[1]
res = json.load(open(out)) if os.path.exists(out) else {}


def keyset(target):
    path, q = target.split(":")
    mod = path[:-3].replace("/", ".").removesuffix(".__init__")
    keys = [f"{mod}.{q}"] + [mod.split(".", i)[-1] + "." + q for i in range(1, mod.count(".") + 1)]
    return keys + ([q] if "." in q else [])


st = Store(":memory:"); st.upsert_org("acme", "Acme"); sc = Scanner(st)
for c in json.load(open(sys.argv[2]))["cases"]:
    cve = c["cve"].split("id=")[-1]
    if cve in res:
        continue
    keys = [k for t in c["targets"] for k in keyset(t)]
    repo = cve + "-vul"; st.upsert_repo(repo, "acme", repo, c["trees"]["vul"])
    try:
        facts, ms = sc.inputs(repo, refresh=True)
        a = analyze(facts, ms, sc.ks.engine_facts("acme", repo), sc.program)
    except Exception as e:  # noqa: BLE001
        res[cve] = {"error": repr(e)[:200]}; continue
    tf = [q for q in facts.functions if any(q == k or q.endswith("." + k) for k in keys)]
    r = {"cls": c["cls"], "functions": len(facts.functions), "targets_found": len(tf)}
    for sel in ("engine", "naive"):
        picks = rv.rank(facts, a, sel)
        pos = {p.fn: (i, p.why) for i, p in enumerate(picks)}
        best = min((pos[q][0] for q in tf if q in pos), default=None)
        r[sel] = {"ranked": len(picks), "best_pos": best, "why": next((pos[q][1] for q in tf if q in pos and pos[q][0] == best), None)}
    res[cve] = r
    print(cve, c["cls"], r["functions"], "engine", r["engine"]["best_pos"], r["engine"]["why"], "naive", r["naive"]["best_pos"], flush=True)
    json.dump(res, open(out, "w"), indent=1)
    sc._inputs.pop(repo, None); sc.program._memo.clear(); del a, facts, ms; gc.collect()
