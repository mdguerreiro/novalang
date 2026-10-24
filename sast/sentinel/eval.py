"""Evaluation harness: precision / recall per pipeline stage against demo/ground_truth.yaml.

Stages
  S0  Semgrep OSS taint mode, generated from the same spec pack (the baseline)
  S1  Tier 0: Datalog engine only
  S2  + Tier 1: neural predicates (mock oracle)
  S3  + Tier 2: verifier agent (mock) behind symbolic gates  [what humans see]
  S4  Flywheel transfer: acme-billing scanned *after* acme-shop was triaged and the AppSec team
      approved the knowledge proposals that cleared their gates

With a mocked agent these numbers validate the machinery, not model quality (architecture §8).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .engine.analyze import analyze
from .extract.semgrep_specs import run_baseline
from .pipeline import Scanner
from .store.db import Store
from .triage import Triage

SAST_ROOT = Path(__file__).resolve().parents[1]
DEMO = SAST_ROOT / "demo"
REPOS = ["acme-shop", "acme-billing"]


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    unlabeled: list = field(default_factory=list)
    missed: list = field(default_factory=list)
    false_alarms: list = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    def row(self) -> dict:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn, "precision": round(self.precision, 3),
                "recall": round(self.recall, 3), "missed": self.missed, "false_alarms": self.false_alarms,
                "unlabeled": self.unlabeled}


def ground_truth() -> dict[tuple[str, str, str], dict]:
    gt = yaml.safe_load((DEMO / "ground_truth.yaml").read_text())
    return {(repo, e["fn"], e["cls"]): e for repo, entries in gt.items() for e in entries}


def score(reported: set[tuple[str, str, str]], repos: list[str]) -> Score:
    gt = {k: v for k, v in ground_truth().items() if k[0] in repos}
    s = Score()
    for key in sorted(reported):
        e = gt.get(key)
        if e is None:
            s.unlabeled.append("/".join(key))
            s.fp += 1
        elif e["label"] == "tp":
            s.tp += 1
        else:
            s.fp += 1
            s.false_alarms.append("/".join(key))
    for key, e in sorted(gt.items()):
        if e["label"] == "tp" and key not in reported:
            s.fn += 1
            s.missed.append("/".join(key))
    return s


def _short(fn: str) -> str:
    return fn.rsplit(".", 1)[-1]


def baseline_reported(sc: Scanner, repo: str) -> set:
    facts, _ = sc.inputs(repo)
    root = Path(sc.store.repo(repo)["root"])
    out = set()
    for b in run_baseline(root, sorted(facts.files)):
        fn = next((q for q, f in facts.functions.items() if f.file == b.file and f.line <= b.line <= f.end_line), "?")
        out.add((repo, _short(fn), b.cls))
    return out


def lanes_reported(store: Store, repo: str, lanes=("confirmed", "review")) -> set:
    marks = ",".join("?" * len(lanes))
    rows = store.q(f"SELECT source_fn, cls FROM findings WHERE repo_id=? AND is_open=1 AND lane IN ({marks})", repo, *lanes)
    return {(repo, _short(r["source_fn"]), r["cls"]) for r in rows}


def fresh_scanner(db: str = ":memory:") -> Scanner:
    st = Store(db)
    st.upsert_org("acme", "Acme Corp")
    for r in REPOS:
        st.upsert_repo(r, "acme", r, str(DEMO / r))
    return Scanner(st)


def simulate_appsec_review(sc: Scanner, repo: str, actor: str = "human:appsec-lead") -> dict:
    """An AppSec engineer works the queue using ground truth as their judgement:
    triage every finding in `review`, audit the sampled AI suppressions, and approve shadow
    knowledge whose impact preview is clean."""
    tr = Triage(sc)
    gt = ground_truth()
    done = {"triaged": 0, "approved": [], "audited": 0}
    for f in sc.store.q("SELECT * FROM findings WHERE repo_id=? AND is_open=1 AND (lane='review' OR audit=1)", repo):
        e = gt.get((repo, _short(f["source_fn"]), f["cls"]))
        if e is None:
            continue
        if e["label"] == "tp":
            tr.decide(f["id"], "confirmed", actor, note="validated during review")
        else:
            sugg = tr.suggestions(f)
            learn = next((s for s in sugg if s["reason"] in ("SANITIZED", "GUARDED", "UNREACHABLE")), None)
            if learn:
                tr.decide(f["id"], "not_exploitable", actor, learn["reason"], learn["detail"])
            else:
                tr.decide(f["id"], "not_exploitable", actor, "OTHER", {})
        done["triaged"] += 1
        done["audited"] += f["audit"]
    org = sc.store.repo(repo)["org_id"]
    for k in sc.store.knowledge_in_scope(org, repo, ("shadow",)):
        report = sc.preview(k)
        if report["canary"] == "pass" and not report["conflicts"]:
            tr.set_knowledge(k["id"], "active", actor)
            done["approved"].append(k["id"])
    return done


def run(write: Path | None = None) -> dict:
    results: dict = {"stages": {}, "flywheel": {}}
    # S0..S3 on a cold system, each repo scanned independently.
    cold = fresh_scanner()
    s0, s1, s2, s3 = set(), set(), set(), set()
    for r in REPOS:
        s0 |= baseline_reported(cold, r)
        facts, matches = cold.inputs(r)
        a0 = analyze(facts, matches, [], cold.program)
        s1 |= {(r, _short(f.source_fn), f.cls) for f in a0.findings if f.status in ("confirmed", "undecided")}
    for r in REPOS:
        cold.scan(r)
        s3 |= lanes_reported(cold.store, r)
    # S2: Tier 0 + Tier 1 only = what is still visible if Tier-2 outcomes are ignored.
    for r in REPOS:
        rows = cold.store.q("SELECT source_fn, cls, lane, data FROM findings WHERE repo_id=? AND is_open=1", r)
        for row in rows:
            by = row["data"].get("decided_by")
            if row["lane"] in ("confirmed", "review") or by == "tier2":
                s2.add((r, _short(row["source_fn"]), row["cls"]))
    for name, rep in (("S0 Semgrep OSS baseline", s0), ("S1 Tier 0 engine", s1), ("S2 + Tier 1 oracle", s2),
                      ("S3 + Tier 2 agent (gated)", s3)):
        results["stages"][name] = score(rep, REPOS).row()
    # Auto-suppression safety: every AI-suppressed finding should be a ground-truth FP.
    gt = ground_truth()
    ai_supp = cold.store.q("SELECT repo_id, source_fn, cls FROM findings WHERE lane='suppressed_ai'")
    wrong = [f"{x['repo_id']}/{_short(x['source_fn'])}/{x['cls']}" for x in ai_supp
             if gt.get((x["repo_id"], _short(x["source_fn"]), x["cls"]), {}).get("label") == "tp"]
    results["ai_suppression"] = {"suppressed": len(ai_supp), "wrongly_suppressed_tps": wrong}
    human_queue = cold.store.q("SELECT COUNT(*) AS n FROM findings WHERE lane='review' AND is_open=1")[0]["n"]
    total = cold.store.q("SELECT COUNT(*) AS n FROM findings WHERE is_open=1")[0]["n"]
    results["coverage"] = {"findings": total, "human_queue": human_queue, "auto_decided": round(1 - human_queue / max(total, 1), 3)}

    # S4 flywheel: shop scanned + reviewed, then billing scanned for the first time.
    warm = fresh_scanner()
    shop1 = warm.scan("acme-shop")
    review = simulate_appsec_review(warm, "acme-shop")
    bill_warm = warm.scan("acme-billing")
    cold_bill = fresh_scanner()
    bill_cold = cold_bill.scan("acme-billing")
    shop2 = warm.scan("acme-shop", refresh=False)
    keep = ("tier0_rate", "auto_rate", "tier1_calls", "tier1_cache_hits", "tier2_calls", "resolved_by_learned_knowledge", "lanes")
    results["flywheel"] = {
        "acme-shop scan 1": {k: shop1[k] for k in keep},
        "appsec review of acme-shop": review,
        "acme-shop scan 2 (after review)": {k: shop2[k] for k in keep},
        "acme-billing cold (no shop knowledge)": {k: bill_cold[k] for k in keep},
        "acme-billing warm (after shop review)": {k: bill_warm[k] for k in keep},
        "acme-billing warm precision/recall": score(lanes_reported(warm.store, "acme-billing"), ["acme-billing"]).row(),
        "active learned knowledge": [{"id": k["id"], "pred": k["pred"], "args": k["args"], "scope": k["scope"], "origin": k["origin"]}
                                     for k in warm.store.q("SELECT * FROM knowledge WHERE status='active' ORDER BY id")],
    }
    if write:
        write.write_text(json.dumps(results, indent=2, default=str))
    return results
