"""Dump every reported finding (confirmed + undecided) of the engine for some dev vulnerable trees. Usage: dump.py OUT"""
import json, os, sys, gc
os.environ["SENTINEL_LLM"] = "mock"
sys.path.insert(0, os.environ["SENTINEL_ROOT"])
from sentinel.store.db import Store
from sentinel.pipeline import Scanner
from sentinel.engine.analyze import analyze
S = "/tmp/claude-0/-home-user-novalang/5ebd2589-6346-5f51-a8a0-2efa638ebc48/scratchpad"
PICK = ["CVE-2023-6709", "CVE-2023-40581", "CVE-2021-39207", "CVE-2024-4181", "CVE-2024-41950", "CVE-2024-37060",
        "CVE-2021-34363", "CVE-2022-24065", "CVE-2024-39863"]
cases = {c["cve"].split("id=")[-1]: c for c in json.load(open(S + "/rw2/cases.json"))["cases"]}
st = Store(":memory:"); st.upsert_org("acme", "Acme"); sc = Scanner(st)
out = []
for cve in PICK:
    c = cases[cve]; repo = cve + "-vul"; root = c["trees"]["vul"]
    st.upsert_repo(repo, "acme", repo, root)
    facts, matches = sc.inputs(repo, refresh=True)
    a = analyze(facts, matches, sc.ks.engine_facts("acme", repo), sc.program)
    for f in a.findings:
        if f.status not in ("confirmed", "undecided"):
            continue
        out.append({"repo": cve, "root": root, "cls": f.cls, "kind": f.source_kind, "status": f.status,
                    "source_fn": f.source_fn, "sink_fn": f.sink_fn, "file": f.file, "line": f.line,
                    "source_rule": f.source_rule, "sink_rule": f.sink_rule,
                    "path": [{"file": s.file, "line": s.line, "fn": s.fn, "kind": s.kind, "label": s.label} for s in f.path][:25]})
    print(cve, sum(o["repo"] == cve for o in out), flush=True)
    sc._inputs.pop(repo, None); sc.last.pop(repo, None); sc.program._memo.clear(); del a, facts, matches; gc.collect()
json.dump(out, open(sys.argv[1], "w"), indent=1)
print("total", len(out))
