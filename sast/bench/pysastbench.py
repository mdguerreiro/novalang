"""Run Sentinel on the PySASTBench synthetic microbenchmark (ICSE '26 SAST study; copy shipped with ZJU-PL/pyflow).

    python bench/pysastbench.py DATASET_DIR METADATA_CSV OUT.json [--limit N] [--mode engine|full]

Scoring follows the PyFlow harness: each *_vul.py is a positive, its *_fix.py a negative; a file counts as flagged
when Sentinel reports the expected class at the ground-truth function (as the entry, the sink function or any step
of the path). Sentinel counts what reaches an analyst: Open + Review lanes. Every file is its own repository in one
organisation, so frontier answers are reused across files (the cross-repo cache is part of what is measured).
CWE-77/78 and CWE-94/95 are treated as the same family, as in the PyFlow harness.
"""
import argparse
import csv
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.engine.analyze import CURATED, analyze  # noqa: E402
from sentinel.pipeline import Scanner  # noqa: E402
from sentinel.store.db import Store  # noqa: E402

CLS = {"22": "path", "502": "deser", "77": "cmdi", "78": "cmdi", "79": "xss", "89": "sqli", "94": "code", "95": "code"}


def hits(target: str, cls: str, findings: list[dict]) -> bool:
    tail = target.split(".")[-1]
    for f in findings:
        if f["cls"] != cls:
            continue
        fns = {f["source_fn"], f["sink_fn"]} | {st["fn"] for st in f.get("path", [])}
        if any(fn == target or fn.endswith("." + target) or fn.endswith("." + tail) for fn in fns):
            return True
    return False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", type=Path)
    ap.add_argument("metadata", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--mode", choices=["engine", "full"], default="full")
    ap.add_argument("--cwe", default="", help="comma-separated CWE ids to run (default: all)")
    ap.add_argument("--part", choices=["all", "train", "test"], default="all",
                    help="train = odd-numbered cases, test = even-numbered (for transfer experiments)")
    ap.add_argument("--store", default=":memory:", help="SQLite store to use/keep (learned knowledge persists)")
    ap.add_argument("--export-pack", type=Path, help="write the learned knowledge as a candidate pack afterwards")
    a = ap.parse_args()
    rows = list(csv.DictReader(open(a.metadata, encoding="utf-8-sig")))
    if a.cwe:
        rows = [r for r in rows if r["CWE Type"] in a.cwe.split(",")]
    if a.limit:
        per = {}
        rows = [r for r in rows if per.setdefault(r["CWE Type"], []).append(r) or len(per[r["CWE Type"]]) <= a.limit]
    if a.part != "all":
        odd = lambda r: int(r["TestCase"].rsplit("-", 1)[-1]) % 2 == 1
        rows = [r for r in rows if odd(r) == (a.part == "train")]
    st = Store(a.store)
    st.upsert_org("bench", "bench")
    sc = Scanner(st)
    work = Path(tempfile.mkdtemp(prefix="psb-"))
    res, t0 = [], time.time()
    tp = fp = fn = tn = 0
    for r in rows:
        case, cwe, target = r["TestCase"], r["CWE Type"], r["Vul Position"]
        cls = CLS[cwe]
        for variant in ("vul", "fix"):
            src = a.dataset / cwe / f"{case}_{variant}.py"
            if not src.exists():
                continue
            repo = f"{case}_{variant}"
            root = work / repo
            root.mkdir()
            shutil.copy(src, root / "app.py")
            st.upsert_repo(repo, "bench", repo, str(root))
            if a.mode == "engine":
                facts, matches = sc.inputs(repo, refresh=True)
                found = [{"cls": f.cls, "source_fn": f.source_fn, "sink_fn": f.sink_fn,
                          "path": [{"fn": s.fn} for s in f.path]}
                         for f in analyze(facts, matches, sc.ks.engine_facts("bench", repo), sc.program).findings
                         if f.status in ("confirmed", "undecided")]
                stats = {}
            else:
                stats = sc.scan(repo)
                found = [{"cls": x["cls"], "source_fn": x["source_fn"], "sink_fn": x["sink_fn"],
                          "path": x["data"].get("path", [])}
                         for x in st.q("SELECT cls, source_fn, sink_fn, data FROM findings WHERE repo_id=? AND is_open=1 "
                                       "AND lane IN ('confirmed','review')", repo)]
            flagged = hits(target, cls, found)
            if variant == "vul":
                tp += flagged
                fn += not flagged
            else:
                fp += flagged
                tn += not flagged
            res.append({"case": case, "variant": variant, "cls": cls, "target": target, "flagged": flagged,
                        "questions": stats.get("frontier_questions"), "cached": stats.get("frontier_cached"),
                        "tier1": stats.get("tier1_calls"), "tier2": stats.get("tier2_calls"),
                        "lanes": stats.get("lanes")})
        print(f"{case:12} tp={tp} fp={fp} fn={fn} tn={tn}", flush=True)
    p = tp / max(tp + fp, 1)
    rc = tp / max(tp + fn, 1)
    summary = {"mode": a.mode, "files": len(res), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(p, 3),
               "recall": round(rc, 3), "f1": round(2 * p * rc / max(p + rc, 1e-9), 3),
               "accuracy": round((tp + tn) / max(len(res), 1), 3), "minutes": round((time.time() - t0) / 60, 1),
               "questions": sum(x["questions"] or 0 for x in res), "cached": sum(x["cached"] or 0 for x in res),
               "tier1": sum(x.get("tier1") or 0 for x in res), "tier2": sum(x.get("tier2") or 0 for x in res)}
    by = {}
    for x in res:
        d = by.setdefault(x["cls"], {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        d[("tp" if x["flagged"] else "fn") if x["variant"] == "vul" else ("fp" if x["flagged"] else "tn")] += 1
    summary["by_class"] = by
    a.out.write_text(json.dumps({"summary": summary, "results": res}, indent=1))
    if a.export_pack:
        from sentinel.learn.packs import export_pack
        a.export_pack.write_text(export_pack(st, "learned-pysastbench"))
    print(json.dumps(summary, indent=1))
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
