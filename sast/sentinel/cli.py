"""Command line: `python -m sentinel <command>`.

  demo   reset the demo database, register the Acme repos and scan them
  scan   scan one registered repo
  serve  run the API + triage UI
  eval   run the evaluation harness and write docs/evaluation.json
  export-rules  write the curated pack + active learned spec rules as one plain Semgrep config
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

SAST_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = SAST_ROOT / ".data" / "sentinel.db"


def _db(args) -> Path:
    p = Path(args.db or os.environ.get("SENTINEL_DB", DEFAULT_DB))
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def cmd_demo(args) -> None:
    from .pipeline import Scanner
    from .store.db import Store
    db = _db(args)
    for suffix in ("", "-wal", "-shm"):
        Path(str(db) + suffix).unlink(missing_ok=True)
    st = Store(db)
    st.upsert_org("acme", "Acme Corp")
    onboard = lambda r: st.upsert_repo(r, "acme", r, str(SAST_ROOT / "demo" / r))
    onboard("acme-shop")
    if args.cold:
        onboard("acme-billing")
    sc = Scanner(st)
    keys = ("lanes", "tier0_rate", "auto_rate", "tier1_calls", "tier2_calls", "resolved_by_learned_knowledge")
    show = lambda label, stats: print(f"{label:34} {json.dumps({k: stats[k] for k in keys})}")
    if args.cold:
        for r in ("acme-shop", "acme-billing"):
            show(f"{r} scan", sc.scan(r))
    else:
        # A realistic history: the team onboards acme-shop, reviews it, rescans it, then onboards
        # acme-billing, which benefits from everything learned on acme-shop.
        from .eval import simulate_appsec_review
        show("acme-shop scan 1", sc.scan("acme-shop"))
        review = simulate_appsec_review(sc, "acme-shop")
        print(f"{'acme-shop reviewed by AppSec lead':34} triaged={review['triaged']} approved={review['approved']}")
        show("acme-shop scan 2", sc.scan("acme-shop", refresh=False))
        onboard("acme-billing")
        show("acme-billing scan 1 (warm)", sc.scan("acme-billing"))
    print(f"database: {db}")


def cmd_scan(args) -> None:
    from .pipeline import Scanner
    from .store.db import Store
    print(json.dumps(Scanner(Store(_db(args))).scan(args.repo), indent=2))


def cmd_serve(args) -> None:
    import uvicorn
    from .api.app import create_app
    from .store.db import Store
    uvicorn.run(create_app(Store(_db(args))), host=args.host, port=args.port, log_level="warning")


def cmd_eval(args) -> None:
    from .eval import run
    out = SAST_ROOT / "docs" / "evaluation.json"
    res = run(write=out)
    for k, v in res["stages"].items():
        print(f"{k:28} precision={v['precision']:.2f} recall={v['recall']:.2f} tp={v['tp']} fp={v['fp']} fn={v['fn']}")
    for k, v in res["spec_rules"].items():
        v = v.get("score", v) if isinstance(v, dict) else {}
        if "precision" in v:
            print(f"S5 {k:58} precision={v['precision']:.2f} recall={v['recall']:.2f} tp={v['tp']} fp={v['fp']} fn={v['fn']}")
    print(f"wrote {out}")


def cmd_export_rules(args) -> None:
    from .learn.rules import export_rules
    from .store.db import Store
    text = export_rules(Store(_db(args)), args.org, args.repo, args.format)
    if args.output:
        Path(args.output).write_text(text)
        print(f"wrote {args.output}")
    else:
        print(text, end="")


def main() -> None:
    ap = argparse.ArgumentParser(prog="sentinel")
    ap.add_argument("--db")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("demo")
    s.add_argument("--cold", action="store_true", help="scan both repos with no history")
    s.set_defaults(fn=cmd_demo)
    s = sub.add_parser("scan")
    s.add_argument("repo")
    s.set_defaults(fn=cmd_scan)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8077)
    s.set_defaults(fn=cmd_serve)
    sub.add_parser("eval").set_defaults(fn=cmd_eval)
    s = sub.add_parser("export-rules", help="write the curated pack + active learned spec rules as one Semgrep config")
    s.add_argument("--org", required=True)
    s.add_argument("--repo", help="also include rules scoped to this repo")
    s.add_argument("--format", choices=("spec", "taint"), default="spec",
                   help="spec: the spec rules; taint: Semgrep OSS taint-mode rules generated from them")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_export_rules)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
