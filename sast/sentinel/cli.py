"""Command line: `python -m sentinel <command>`.

  demo   reset the demo database, register the Acme repos and scan them
  scan   scan one registered repo
  serve  run the API + triage UI
  eval   run the evaluation harness and write docs/evaluation.json
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
    for r in ("acme-shop", "acme-billing"):
        st.upsert_repo(r, "acme", r, str(SAST_ROOT / "demo" / r))
    sc = Scanner(st)
    for r in ("acme-shop", "acme-billing"):
        stats = sc.scan(r)
        print(f"{r}: {json.dumps({k: stats[k] for k in ('lanes', 'tier0_rate', 'auto_rate', 'tier2_calls')})}")
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
    print(f"wrote {out}")


def main() -> None:
    ap = argparse.ArgumentParser(prog="sentinel")
    ap.add_argument("--db")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo").set_defaults(fn=cmd_demo)
    s = sub.add_parser("scan")
    s.add_argument("repo")
    s.set_defaults(fn=cmd_scan)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8077)
    s.set_defaults(fn=cmd_serve)
    sub.add_parser("eval").set_defaults(fn=cmd_eval)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
