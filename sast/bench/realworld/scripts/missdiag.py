"""Why each held-out CVE is missed, from engine output only (no code is read): is the target function in the tree,
is a sink of the CVE's class modelled inside it, does any finding (any status) touch it, and with which status/class.
Usage: missdiag.py OUT.json CASES.json [CASES.json ...]  (engine at SENTINEL_ROOT)"""
import json, os, sys, gc, collections
os.environ["SENTINEL_LLM"] = "mock"
sys.path.insert(0, os.environ["SENTINEL_ROOT"])
from sentinel.store.db import Store
from sentinel.pipeline import Scanner
from sentinel.engine.analyze import analyze
S = "/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad"
SAME = {"code": {"code", "ssti"}}
out = sys.argv[1]
res = json.load(open(out)) if os.path.exists(out) else {}


def keyset(target):
    path, q = target.split(":")
    mod = path[:-3].replace("/", ".").removesuffix(".__init__")
    keys = [f"{mod}.{q}"] + [mod.split(".", i)[-1] + "." + q for i in range(1, mod.count(".") + 1)]
    if "." in q:
        keys.append(q)
    return keys


def matches(fn, keys):
    return any(fn == k or fn.endswith("." + k) for k in keys)


st = Store(":memory:"); st.upsert_org("acme", "Acme"); sc = Scanner(st)
for cf in sys.argv[2:]:
    for c in json.load(open(cf))["cases"]:
        cve = c["cve"].split("id=")[-1]
        if cve in res:
            continue
        keys = [k for t in c["targets"] for k in keyset(t)]
        cls = SAME.get(c["cls"], {c["cls"]})
        repo = cve + "-vul"
        st.upsert_repo(repo, "acme", repo, c["trees"]["vul"])
        try:
            facts, ms = sc.inputs(repo, refresh=True)
            a = analyze(facts, ms, sc.ks.engine_facts("acme", repo), sc.program)
        except Exception as e:  # noqa: BLE001
            res[cve] = {"error": repr(e)[:200]}; json.dump(res, open(out, "w"), indent=1); continue
        tfns = {q for q in facts.functions if matches(q, keys)}
        sinks = [m for m in ms if m.role == "sink" and m.node in facts.nodes and facts.nodes[m.node].fn in tfns]
        near = [f for f in a.findings if {f.source_fn, f.sink_fn} & tfns or any(s.fn in tfns for s in f.path)]
        r = {"cls": c["cls"], "project": c.get("project", ""), "targets_found": len(tfns), "targets": len(c["targets"]),
             "sinks_in_target": dict(collections.Counter(m.cls for m in sinks)),
             "class_sink_in_target": any(m.cls in cls for m in sinks),
             "near": dict(collections.Counter(f"{f.status}/{f.cls}/{f.source_kind or '?'}" for f in near)),
             "frontier_in_target": sum(1 for q in a.model.get("frontier") or [] if getattr(facts.nodes.get(q[0]), "fn", None) in tfns)
             if a.model else None}
        hitc = [f for f in near if f.cls in cls]
        r["verdict"] = ("target not in tree" if not tfns else
                        "caught" if any(f.status in ("confirmed", "undecided") for f in hitc) else
                        "class flow found but mitigated/test-only" if hitc else
                        "other-class finding at target" if near else
                        "class sink in target, no attacker data reaches it" if r["class_sink_in_target"] else
                        "no sink of the class modelled in target")
        res[cve] = r
        print(cve, c["cls"], r["verdict"], r["near"], r["sinks_in_target"], flush=True)
        json.dump(res, open(out, "w"), indent=1)
        sc._inputs.pop(repo, None); sc.last.pop(repo, None); sc.program._memo.clear(); del a, facts, ms; gc.collect()
print("done")
