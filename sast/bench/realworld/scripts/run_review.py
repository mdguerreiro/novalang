"""Held-out evaluation of the engine-guided review. Usage: review_run.py OUT.json CASES.json [CASES.json ...]
Env: SENTINEL_ROOT (engine), REVIEW_SELECT=engine|naive, REVIEW_CAP (USD for this process family), SENTINEL_REVIEW_BUDGET.
Per tree: engine-only hit, review hit, combined hit, reads, cached reads, spend. Reads are cached in OUT.cache.json
(keyed by reader + exact code), so a fixed tree re-reads only the functions its fix changed."""
import json, os, sys, time, gc
S = "/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad"
exec(open(S + "/bench/frontier_live.py").read().split("from sentinel.store.db import Store")[0])  # metered client, usd()
sys.path.insert(0, os.environ["SENTINEL_ROOT"])  # after the exec: it puts the main checkout first
os.environ["SENTINEL_LLM"] = "claude"
from sentinel.store.db import Store
from sentinel.pipeline import Scanner
from sentinel.engine.analyze import analyze
from sentinel import review as rv
from sentinel.agent.reader import make_review_reader

out, case_files = sys.argv[1], sys.argv[2:]
SELECT = os.environ.get("REVIEW_SELECT", "engine")
CAP = float(os.environ.get("REVIEW_CAP", "45"))
res = json.load(open(out)) if os.path.exists(out) else {}
CACHE = out + ".cache.json"
cache = json.load(open(CACHE)) if os.path.exists(CACHE) else {}
SPEND = out + ".spend.json"
spent_before = json.load(open(SPEND))["usd"] if os.path.exists(SPEND) else 0.0
SAME = {"code": {"code", "ssti"}}


def keyset(target):
    path, q = target.split(":")
    mod = path[:-3].replace("/", ".").removesuffix(".__init__")
    keys = [f"{mod}.{q}"] + [mod.split(".", i)[-1] + "." + q for i in range(1, mod.count(".") + 1)]
    if "." in q:
        keys.append(q)
    return keys


def near(fns, keys):
    return any(fn == k or fn.endswith("." + k) for fn in fns for k in keys)


def put(k, fn, issues):
    cache[k] = issues
    json.dump(cache, open(CACHE, "w"))


st = Store(":memory:"); st.upsert_org("acme", "Acme"); sc = Scanner(st)
reader = make_review_reader()
for cf in case_files:
    for c in json.load(open(cf))["cases"]:
        cve = c["cve"].split("id=")[-1]
        keys = [k for t in c["targets"] for k in keyset(t)]
        cls = SAME.get(c["cls"], {c["cls"]})
        for v in ("vul", "fix"):
            repo = f"{cve}-{v}"
            if repo in res:
                continue
            spent = spent_before + usd(meter)
            if spent > CAP:
                print("CAP reached", round(spent, 2), flush=True); res["_cap"] = round(spent, 2)
                json.dump(res, open(out, "w"), indent=1); sys.exit(0)
            st.upsert_repo(repo, "acme", repo, c["trees"][v])
            t, m0 = time.time(), dict(meter)
            try:
                facts, matches = sc.inputs(repo, refresh=True)
                a = analyze(facts, matches, sc.ks.engine_facts("acme", repo), sc.program)
                r = rv.review(facts, a, reader, cache.get, put, select=SELECT)
            except Exception as e:  # noqa: BLE001
                res[repo] = {"error": repr(e)[:300]}; json.dump(res, open(out, "w"), indent=1); continue
            eng = [f for f in a.findings if f.status in ("confirmed", "undecided")]
            eng_hit = any(f.cls in cls and near({f.source_fn, f.sink_fn} | {s.fn for s in f.path}, keys) for f in eng)
            rev_hit = any(x["cls"] in cls and near({x["at"], x["picked"]}, keys) for x in r["issues"])
            d = {k: meter[k] - m0.get(k, 0) for k in meter}
            res[repo] = {"cls": c["cls"], "engine": eng_hit, "review": rev_hit, "flagged": eng_hit or rev_hit,
                         "engine_reported": len(eng), "review_issues": len(r["issues"]), "reads": r["read"], "ranked": r.get("ranked"), "budget": len(r["picks"]),
                         "cached": r["cached"], "target_picked": near(set(r["picks"]), keys),
                         "usd": round(usd(d), 3), "minutes": round((time.time() - t) / 60, 1),
                         "issues": [{k: x.get(k) for k in ("cls", "at", "line", "kind", "confidence", "reason")} for x in r["issues"]],
                         "proposals": r["proposals"]}
            json.dump(res, open(out, "w"), indent=1)
            json.dump({"usd": round(spent_before + usd(meter), 3)}, open(SPEND, "w"))
            print(repo, json.dumps({k: res[repo][k] for k in ("cls", "engine", "review", "target_picked", "review_issues",
                                                              "reads", "cached", "usd", "minutes")}), flush=True)
            sc._inputs.pop(repo, None); sc.program._memo.clear(); del a, facts, matches; gc.collect()
print("DONE total usd", round(spent_before + usd(meter), 2))
