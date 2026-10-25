"""Evaluation harness: precision / recall per pipeline stage against demo/ground_truth.yaml.

Stages
  S0  Semgrep OSS taint mode, generated from the same spec pack (the baseline)
  S1  Tier 0: Datalog engine only
  S2  + Tier 1: neural predicates (mock oracle)
  S3  + Tier 2: verifier agent (mock) behind symbolic gates  [what humans see]
  S4  Flywheel transfer: acme-billing scanned *after* acme-shop was triaged and the AppSec team
      approved the knowledge proposals that cleared their gates
  S6  Frontier inference (recall): acme-reports and acme-etl use sinks, sources and frameworks the curated
      pack does not model. Semgrep OSS, the engine without the frontier, and the engine with it (oracle asked
      only where a tainted path meets an unmodelled API or entry point), then acme-etl after acme-reports
      (answers transfer). Cost compared with an LLM that reads every function.
  S5  Learned spec rules: acme-admin (acme_common installed, not vendored) scanned cold, then after
      shop and billing were triaged and the synthesized spec rules approved; plus Semgrep OSS on
      acme-admin with the curated pack vs the exported pack (curated + learned)

With a mocked agent these numbers validate the machinery, not model quality (architecture §8).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .engine.analyze import analyze
from .extract.semgrep_specs import load_rules, run_baseline
from .learn.knowledge import gate_passed
from .learn.rules import active_rules, materialize
from .pipeline import Scanner
from .store.db import Store
from .triage import Triage

SAST_ROOT = Path(__file__).resolve().parents[1]
DEMO = SAST_ROOT / "demo"
REPOS = ["acme-shop", "acme-billing"]
ADMIN = "acme-admin"  # third repo of the org: installs acme_common as a package (S5 only)
FRONTIER_REPOS = ["acme-reports", "acme-etl"]  # unmodelled libraries and frameworks (S6)


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


def baseline_reported(sc: Scanner, repo: str, rules: list[dict] | None = None) -> set:
    """Semgrep OSS taint mode built from `rules` (default: the curated pack)."""
    facts, _ = sc.inputs(repo)
    root = Path(sc.store.repo(repo)["root"])
    out = set()
    for b in run_baseline(root, sorted(facts.files), rules):
        fn = next((q for q, f in facts.functions.items() if f.file == b.file and f.line <= b.line <= f.end_line), "?")
        out.add((repo, _short(fn), b.cls))
    return out


def lanes_reported(store: Store, repo: str, lanes=("confirmed", "review")) -> set:
    marks = ",".join("?" * len(lanes))
    rows = store.q(f"SELECT source_fn, cls FROM findings WHERE repo_id=? AND is_open=1 AND lane IN ({marks})", repo, *lanes)
    return {(repo, _short(r["source_fn"]), r["cls"]) for r in rows}


def onboard(sc: Scanner, repo: str) -> None:
    sc.store.upsert_repo(repo, "acme", repo, str(DEMO / repo))


def fresh_scanner(db: str = ":memory:", repos: list[str] | None = None) -> Scanner:
    st = Store(db)
    st.upsert_org("acme", "Acme Corp")
    sc = Scanner(st)
    for r in REPOS if repos is None else repos:
        onboard(sc, r)
    return sc


def simulate_appsec_review(sc: Scanner, repo: str, actor: str = "human:appsec-lead", validate_confirmed: bool = False,
                           approve_rules: bool = False) -> dict:
    """An AppSec engineer works the queue using ground truth as their judgement:
    triage every finding in `review`, audit the sampled AI suppressions, and approve shadow
    knowledge whose impact preview is clean.
    validate_confirmed: also confirm the engine-confirmed findings (filing tickets), which is what
                        triggers sink-rule synthesis for flows through shared helpers.
    approve_rules:      also approve shadow spec rules (off for the S4 stage, which predates them)."""
    tr = Triage(sc)
    gt = ground_truth()
    done = {"triaged": 0, "approved": [], "audited": 0}
    lanes = "(lane='review' OR audit=1 OR (lane='confirmed' AND triage_state='untriaged'))" if validate_confirmed \
        else "(lane='review' OR audit=1)"
    for f in sc.store.q(f"SELECT * FROM findings WHERE repo_id=? AND is_open=1 AND {lanes}", repo):
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
        if k["pred"] == "spec_rule" and not approve_rules:
            continue
        report = sc.preview(k)
        if gate_passed(report) and not report["conflicts"]:
            tr.set_knowledge(k["id"], "active", actor)
            done["approved"].append(k["id"])
    return done


class CountingOracle:
    """Wraps an oracle; counts frontier questions and the prompt size a real model would get."""

    def __init__(self, inner):
        self.inner, self.name = inner, inner.name
        self.calls: list[tuple[str, str, int]] = []

    def __getattr__(self, attr):
        return getattr(self.inner, attr)

    def classify_sink(self, api, args, usage):
        from .agent.claude import ClaudeSpecOracle
        self.calls.append(("sink", api, len(ClaudeSpecOracle._sink_prompt(api, args, usage))))
        return self.inner.classify_sink(api, args, usage)

    def classify_registrar(self, api, arg, usage):
        from .agent.claude import ClaudeSpecOracle
        self.calls.append(("reg", api, len(ClaudeSpecOracle._registrar_prompt(api, arg, usage))))
        return self.inner.classify_registrar(api, arg, usage)

    def classify_entry(self, fn, decorators, params, source):
        from .agent.claude import ClaudeSpecOracle
        self.calls.append(("entry", fn, len(ClaudeSpecOracle._entry_prompt(fn, decorators, params, source))))
        return self.inner.classify_entry(fn, decorators, params, source)


def read_everything_cost(sc: Scanner, repo: str) -> dict:
    """What an LLM-reads-every-function scanner sends: every function body once (no fan-out, no retries)."""
    facts, _ = sc.inputs(repo)
    chars = sum(len(sc._source_of(facts, q)) for q in facts.functions)
    return {"functions": len(facts.functions), "prompt_tokens": chars // 4}


def run_frontier() -> dict:
    out: dict = {}
    sc = fresh_scanner(repos=FRONTIER_REPOS)
    sc.oracle = counting = CountingOracle(sc.oracle)
    off = fresh_scanner(repos=FRONTIER_REPOS)
    off.frontier = False
    for r in FRONTIER_REPOS:
        n0 = len(counting.calls)
        stats = sc.scan(r)
        off.scan(r)
        asked = counting.calls[n0:]
        rep = lanes_reported(sc.store, r)
        sc_row, off_row = score(rep, [r]).row(), score(lanes_reported(off.store, r), [r]).row()
        new_tp = sc_row["tp"] - off_row["tp"]
        llm = read_everything_cost(sc, r)
        out[r] = {
            "Semgrep OSS": score(baseline_reported(sc, r), [r]).row(),
            "engine without frontier": off_row,
            "engine with frontier": sc_row,
            "frontier": {"questions": len(asked), "answered_from_cache": stats["frontier_cached"],
                         "facts": stats["frontier_facts"], "subjects": [s for _k, s, _n in asked],
                         "prompt_tokens": sum(n for *_x, n in asked) // 4, "new_tps": new_tp,
                         "questions_per_new_tp": round(len(asked) / new_tp, 2) if new_tp else None},
            "read-every-function LLM (input only)": llm,
            "tier2_calls": stats["tier2_calls"],
        }
    return out


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
    warm = fresh_scanner(repos=["acme-shop"])
    shop1 = warm.scan("acme-shop")
    review = simulate_appsec_review(warm, "acme-shop")
    shop2 = warm.scan("acme-shop", refresh=False)
    onboard(warm, "acme-billing")  # billing is onboarded only after shop was reviewed
    bill_warm = warm.scan("acme-billing")
    cold_bill = fresh_scanner(repos=["acme-billing"])
    bill_cold = cold_bill.scan("acme-billing")
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
    results["spec_rules"] = run_spec_rules(cold)
    results["frontier"] = run_frontier()
    if write:
        write.write_text(json.dumps(results, indent=2, default=str))
    return results


def run_spec_rules(sc: Scanner) -> dict:
    """S5: learned spec rules on a repo that installs the shared package instead of vendoring it.
    `sc` has scanned acme-shop and acme-billing (the S3 scanner). acme-admin is scanned cold by a fresh
    scanner, then warm by `sc` after AppSec triaged both repos (confirming reported findings, which
    triggers sink-rule synthesis) and approved the knowledge, spec rules included, that passed its gates."""
    keep = ("tier0_rate", "auto_rate", "tier1_calls", "tier2_calls", "found_by_learned_rules", "lanes")
    cold = fresh_scanner(repos=[ADMIN])
    cold_stats = cold.scan(ADMIN)
    review = {r: simulate_appsec_review(sc, r, validate_confirmed=True, approve_rules=True) for r in REPOS}
    onboard(sc, ADMIN)
    warm_stats = sc.scan(ADMIN)
    rules = active_rules(sc.store, "acme")
    exported = load_rules() + [materialize(k) for k in rules]
    attribution = {}
    for row in sc.store.q("SELECT source_fn, cls, engine_status, data FROM findings WHERE repo_id=? AND is_open=1", ADMIN):
        used = sorted(set(row["data"].get("spec_knowledge", [])) | {k for m in row["data"]["mitigations"] for k in m["knowledge"]})
        attribution[f"{_short(row['source_fn'])}/{row['cls']}"] = {"status": row["engine_status"], "knowledge": used}
    return {
        "acme-admin cold (no org knowledge)": {**{k: cold_stats[k] for k in keep},
                                               "score": score(lanes_reported(cold.store, ADMIN), [ADMIN]).row()},
        "review of acme-shop and acme-billing": review,
        "learned spec rules": [{"id": k["id"], "rule": k["args"][0], "role": k["args"][1], "cls": k["args"][2],
                                "status": k["status"], "origin": k["origin"], "scope": k["scope"],
                                "gates": {g: k["gate"].get(g) for g in ("sanity", "differential", "generalization", "canary")},
                                "support": sc.ks.support(k["id"])}
                               for k in sc.store.q("SELECT * FROM knowledge WHERE pred='spec_rule' ORDER BY id")],
        "acme-admin warm (after review, rules approved)": {**{k: warm_stats[k] for k in keep},
                                                          "score": score(lanes_reported(sc.store, ADMIN), [ADMIN]).row()},
        "acme-admin warm decisions": attribution,
        "acme-admin Semgrep OSS, curated pack": score(baseline_reported(sc, ADMIN), [ADMIN]).row(),
        "acme-admin Semgrep OSS, exported pack (curated + learned)": score(baseline_reported(sc, ADMIN, exported), [ADMIN]).row(),
    }
