"""Knowledge packs: versioned, reviewable YAML files of global facts (framework entry points, sources, sinks,
sanitizers, authorization decorators).

Two ways in, one format:
- curated: a security research team writes or edits a pack; it ships with the product (`knowledge/packs/*.yml`, or
  the directories in SENTINEL_PACKS) and is loaded as active global knowledge, through the canary gate;
- learned: `export_pack` writes the facts the frontier learned from repositories as a candidate pack, with where each
  came from, the model's rationale, its confidence and how many repositories it held up in. A researcher reviews it
  and merges it into a curated pack, so learned knowledge graduates into curated knowledge.

    pack: python-web-frameworks
    version: 3
    owner: appsec-research
    facts:
      - {pred: framework_source, args: [cherrypy.expose, http], note: "exposed handler parameters are request data"}
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

from .knowledge import PREDICATES

PACKS_DIR = Path(__file__).resolve().parents[2] / "knowledge" / "packs"
# What a pack may carry: library/framework facts that mean the same in every repository. Repo- and org-scoped facts
# (a project's own entry points, its validators, its models' privacy) stay where they were learned.
PACK_PREDS = {"framework_source", "not_framework_source", "registrar", "not_registrar", "source_api", "not_source_api",
              "sink_api", "not_sink_api", "sanitizer_api", "propagator_api", "not_sanitizer", "html_return",
              "not_html_return", "authz_decorator", "not_authz_decorator", "safe_type", "weak_kind"}


def pack_dirs() -> list[Path]:
    env = os.environ.get("SENTINEL_PACKS")
    return [Path(p) for p in env.split(os.pathsep) if p] if env is not None else [PACKS_DIR]


def read_pack(path: Path) -> dict:
    doc = yaml.safe_load(path.read_text()) or {}
    name, version = doc.get("pack") or path.stem, doc.get("version", 1)
    facts = []
    for i, f in enumerate(doc.get("facts") or []):
        pred, args = f.get("pred"), list(f.get("args") or [])
        if pred not in PACK_PREDS or PREDICATES.get(pred) != len(args):
            raise ValueError(f"{path}: fact {i}: {pred}/{len(args)} is not a pack predicate")
        facts.append({"pred": pred, "args": args, "note": f.get("note", "")})
    return {"pack": name, "version": version, "owner": doc.get("owner", ""), "facts": facts, "path": str(path)}


def load_packs(scanner, dirs: list[Path] | None = None) -> dict:
    """Load every pack as active global knowledge (idempotent). Each fact passes the canary gate; a fact that would
    hide a canary finding is kept as a blocked candidate, visible in the workbench, not activated."""
    stats = {"packs": 0, "facts": 0, "activated": 0, "blocked": 0}
    for d in dirs if dirs is not None else pack_dirs():
        for path in sorted(Path(d).glob("*.yml")) if Path(d).is_dir() else []:
            pack = read_pack(path)
            origin = f"pack:{pack['pack']}@{pack['version']}"
            stats["packs"] += 1
            for f in pack["facts"]:
                stats["facts"] += 1
                item = scanner.ks.propose(f["pred"], f["args"], "global", None, None, origin, 1.0, f["note"])
                if item["status"] == "active":
                    continue
                report = scanner.ks.gate(item, {}, set(), lambda r, extra: scanner.analyze_repo(r, extra))
                item = scanner.ks.apply_gate(item["id"], report, approved_by=origin)
                stats["activated" if item["status"] == "active" else "blocked"] += 1
    return stats


def export_pack(store, name: str, version: int = 1, owner: str = "", min_repos: int = 0) -> str:
    """Learned global facts as a candidate pack (YAML text), with provenance for the reviewer."""
    rows = store.q("SELECT * FROM knowledge WHERE scope='global' AND status='active' AND origin NOT LIKE 'pack:%' "
                   "AND origin NOT LIKE 'curated%' ORDER BY pred, args")
    facts = []
    for r in rows:
        if r["pred"] not in PACK_PREDS:
            continue
        repos = store.one("SELECT COUNT(DISTINCT f.repo_id) AS n FROM knowledge_links l JOIN findings f ON f.id = l.finding_id "
                          "WHERE l.knowledge_id=?", r["id"])
        n = repos["n"] if repos else 0
        if n < min_repos and not r["pred"].startswith("not_"):
            continue
        facts.append({"pred": r["pred"], "args": r["args"],
                      "note": (r.get("rationale") or "").strip()[:300],
                      "learned": {"origin": r["origin"], "confidence": r.get("confidence"), "repos": n, "id": r["id"]}})
    doc = {"pack": name, "version": version, "owner": owner,
           "description": "Candidate pack exported from learned knowledge: review each fact, drop the `learned` block, merge.",
           "facts": facts}
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120)
