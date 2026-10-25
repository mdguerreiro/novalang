"""Score Sentinel and the read-every-file LLM baseline on open-source repos against hand labels.

    python bench/score_oss.py LABELS.yaml SENTINEL.json [SENTINEL.json ...] --llm LLM.json [LLM.json ...]

Both systems are matched on (repo, entry function short name, class). Sentinel counts what it puts in front of an
analyst (Open + Review lanes; Candidates are reported separately). Unlabelled reports are listed for adjudication.
"""
import argparse
import json
from collections import defaultdict

import yaml


def short(fn: str) -> str:
    return fn.rsplit(".", 1)[-1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("labels")
    ap.add_argument("sentinel", nargs="+")
    ap.add_argument("--llm", nargs="+", default=[])
    a = ap.parse_args()
    labels = yaml.safe_load(open(a.labels)) or {}
    gt = {(r, e["fn"], e["cls"]): e for r, es in labels.items() for e in es}
    sent, cand, cost_s = defaultdict(set), defaultdict(set), defaultdict(float)
    for p in a.sentinel:
        for repo, v in json.load(open(p))["repos"].items():
            cost_s[repo] += v["spend"]["usd"]
            for f in v["findings"]:
                key = (repo, short(f["fn"]), f["cls"])
                if f["lane"] in ("confirmed", "review"):
                    sent[repo].add(key)
                elif f["lane"] == "candidate":
                    cand[repo].add(key)
    llm, cost_l = defaultdict(set), defaultdict(float)
    for p in a.llm:
        for repo, v in json.load(open(p)).items():
            cost_l[repo] += v["spend"]["usd"]
            for f in v["findings"]:
                llm[repo].add((repo, short(f["function"]), f["cls"]))
    repos = sorted(set(sent) | set(llm) | set(cost_s) | set(cost_l))
    unl = sorted({k for r in repos for k in sent[r] | llm[r] | cand[r] if k not in gt})
    tot = defaultdict(int)
    print(f"{'repo':32} {'S tp/fp/fn':>12} {'L tp/fp/fn':>12} {'S $':>7} {'L $':>7}")
    for r in repos:
        tps = {k for k, e in gt.items() if k[0] == r and e["label"] == "tp"}
        row = []
        for name, rep in (("s", sent[r]), ("l", llm[r])):
            tp = len(rep & tps)
            fp = len([k for k in rep if gt.get(k, {}).get("label") == "fp"])
            fn = len(tps - rep)
            tot[name + "tp"] += tp; tot[name + "fp"] += fp; tot[name + "fn"] += fn
            row.append(f"{tp}/{fp}/{fn}")
        tot["s$"] += cost_s[r]; tot["l$"] += cost_l[r]
        print(f"{r:32} {row[0]:>12} {row[1]:>12} {cost_s[r]:7.2f} {cost_l[r]:7.2f}")
    for n, lab in (("s", "Sentinel"), ("l", "LLM reads all")):
        tp, fp, fn = tot[n + "tp"], tot[n + "fp"], tot[n + "fn"]
        print(f"{lab:16} precision {tp / max(tp + fp, 1):.2f} recall {tp / max(tp + fn, 1):.2f}  (tp {tp}, fp {fp}, fn {fn})  ${tot[n + '$']:.2f}")
    if unl:
        print("\nUNLABELLED (adjudicate):")
        for k in unl:
            print("  ", "/".join(k))


if __name__ == "__main__":
    main()
