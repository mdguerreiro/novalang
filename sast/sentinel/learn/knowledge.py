"""Knowledge lifecycle: the flywheel's memory.

Every behaviour change of the engine is a knowledge item (a Datalog fact) with
    scope       repo ⊂ org ⊂ global
    status      candidate → shadow → active → retired
    origin      curated | oracle:<model> | agent:<model> | human:<user>
    provenance  links to the verdicts / findings that created or corroborated it
Items are activated only through gates:
  1. sanity       known predicate, right arity, no wildcard over-reach
  2. canaries     the canary corpus and every human-confirmed finding must stay open
  3. impact       large blast radius -> shadow + human approval
  4. scope rules  human-origin may activate at repo/org; machine-origin needs corroboration;
                  global only for public-library facts, never customer code
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable

from ..engine.analyze import Analysis, KnowledgeFact, analyze
from ..extract.python_facts import extract
from ..extract.semgrep_specs import match_specs
from ..store.db import Store

PREDICATES = {  # pred -> arity
    "sanitizer_api": 2, "propagator_api": 1, "safe_pred": 2, "not_safe_pred": 1, "safe_type": 2,
    "dead_fn": 1, "internal_only": 1, "not_sanitizer": 1, "weak_kind": 1,
}
SUPPRESSING = {"sanitizer_api", "safe_pred", "safe_type", "dead_fn", "internal_only"}
CANARY_ROOT = Path(__file__).resolve().parents[2] / "canaries"


@dataclass
class Policy:
    corroborations_to_activate: int = 3  # independent machine verdicts before a machine item goes active
    impact_budget: int = 10  # max findings an item may suppress without explicit approval
    machine_global_allowed: bool = True  # oracle facts about public libraries may become global (still gated)


@lru_cache(maxsize=1)
def _canary_inputs():
    facts = extract(CANARY_ROOT)
    return facts, match_specs(CANARY_ROOT, facts)


def to_fact(item: dict) -> KnowledgeFact:
    return KnowledgeFact(item["id"], item["pred"], tuple(item["args"]))


class KnowledgeService:
    def __init__(self, store: Store, policy: Policy | None = None):
        self.store = store
        self.policy = policy or Policy()

    # ── reading ──────────────────────────────────────────────────────────────────────────
    def engine_facts(self, org_id: str, repo_id: str, statuses: tuple[str, ...] = ("active",)) -> list[KnowledgeFact]:
        return [to_fact(k) for k in self.store.knowledge_in_scope(org_id, repo_id, statuses)]

    def lookup(self, pred: str, args: list) -> dict | None:
        """Cache lookup across all scopes (used to avoid re-asking the oracle the same question)."""
        return self.store.one("SELECT * FROM knowledge WHERE pred=? AND args=? AND status != 'retired' ORDER BY id LIMIT 1",
                              pred, json.dumps(args))

    # ── proposing ────────────────────────────────────────────────────────────────────────
    def propose(self, pred: str, args: list, scope: str, org_id: str | None, repo_id: str | None, origin: str,
                confidence: float, rationale: str, finding_id: int | None = None, verdict_id: int | None = None) -> dict:
        if pred not in PREDICATES or len(args) != PREDICATES[pred]:
            raise ValueError(f"unknown knowledge predicate {pred}/{len(args)}")
        if scope == "global":
            org_id = repo_id = None
        elif scope == "org":
            repo_id = None
        existing = self.store.find_knowledge(pred, args, scope, org_id, repo_id)
        now = time.time()
        if existing:
            if origin.split(":")[0] != existing["origin"].split(":")[0] or verdict_id is not None or finding_id is not None:
                self.store.x("UPDATE knowledge SET corroborations=corroborations+1, updated_at=? WHERE id=?", now, existing["id"])
            kid = existing["id"]
        else:
            kid = self.store.next_knowledge_id()
            self.store.x("INSERT INTO knowledge(id, scope, org_id, repo_id, pred, args, status, origin, confidence, rationale, "
                         "corroborations, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         kid, scope, org_id, repo_id, pred, json.dumps(args), "candidate", origin, confidence, rationale,
                         1, now, now)
            self.store.event(origin, "knowledge.proposed", finding_id, kid, pred=pred, args=args, scope=scope)
        if finding_id is not None or verdict_id is not None:
            self.store.link(kid, "created_from" if not existing else "corroborated_by", finding_id, verdict_id)
        return self.store.knowledge(kid)

    # ── gates ────────────────────────────────────────────────────────────────────────────
    def gate(self, item: dict, analyses: dict[str, Analysis], confirmed_fps: set[str],
             rerun: Callable[[str, list[KnowledgeFact]], Analysis]) -> dict:
        """Evaluate an item against the gates. `analyses` = current analysis per repo in scope;
        `rerun(repo, extra)` re-analyses a repo with extra knowledge."""
        report: dict = {"checked_at": time.time(), "sanity": "pass", "canary": "pass", "impact": [], "conflicts": []}
        if item["pred"] == "safe_pred" and str(item["args"][0]).startswith(("regex:.*", "call:*")):
            report["sanity"] = "fail: predicate pattern is a wildcard"
        if item["pred"] in ("sanitizer_api", "safe_pred", "safe_type") and item["args"][-1] == "all" and item["scope"] == "global" \
                and item["origin"].startswith(("agent:", "human:")):
            report["sanity"] = "fail: global all-class sanitizers must come from curated or corroborated library knowledge"
        fact = to_fact(item)
        # Canary corpus: nothing may disappear.
        cf, cm = _canary_inputs()
        base = {f.fingerprint for f in analyze(cf, cm).findings if f.status in ("confirmed", "undecided")}
        after = {f.fingerprint for f in analyze(cf, cm, [fact]).findings if f.status in ("confirmed", "undecided")}
        lost = sorted(base - after)
        if lost:
            report["canary"] = f"fail: {len(lost)} canary finding(s) would be suppressed"
            report["canary_lost"] = lost
        # Impact + human-confirmed findings in every repo in scope.
        for repo_id, a in analyses.items():
            before = {f.fingerprint: f for f in a.findings}
            b2 = rerun(repo_id, [fact])
            for f in b2.findings:
                old = before.get(f.fingerprint)
                if old and old.status != f.status:
                    entry = {"repo": repo_id, "fingerprint": f.fingerprint, "from": old.status, "to": f.status,
                             "cls": f.cls, "source_fn": f.source_fn}
                    report["impact"].append(entry)
                    if f.fingerprint in confirmed_fps and f.status in ("mitigated",):
                        report["conflicts"].append(entry)
        if report["conflicts"]:
            report["canary"] = f"fail: would suppress {len(report['conflicts'])} human-confirmed finding(s)"
        suppressed = [i for i in report["impact"] if i["to"] == "mitigated"]
        report["suppresses"] = len(suppressed)
        report["over_budget"] = len(suppressed) > self.policy.impact_budget
        return report

    def decide_status(self, item: dict, report: dict, approved_by: str | None = None) -> str:
        if report["sanity"] != "pass" or report["canary"] != "pass":
            return "candidate"  # blocked; stays visible in the workbench with its failing gate
        human = item["origin"].startswith("human:") or approved_by is not None
        if human:
            return "shadow" if report["over_budget"] and approved_by is None else "active"
        if item["pred"] not in SUPPRESSING:
            # Knowledge that only *removes an assumption toward reporting* (not_sanitizer, propagator_api,
            # not_safe_pred) can never hide a vulnerability, so it activates once its gates pass.
            return "active"
        # Only independent evidence counts: re-verifying the same finding on every scan is not corroboration.
        support = self.support(item["id"])
        if support >= self.policy.corroborations_to_activate and not report["over_budget"]:
            return "active"
        return "shadow"

    def support(self, kid: str) -> int:
        """Independent evidence for an item. Each agent run is an independent sample, so agent items
        count distinct findings with their own verdict. An oracle label reused on many findings is
        still *one* judgement, so oracle items count distinct repositories where it held up."""
        item = self.store.knowledge(kid)
        if item and item["origin"].startswith("oracle:"):
            sql = ("SELECT COUNT(DISTINCT f.repo_id) AS n FROM knowledge_links l JOIN findings f ON f.id = l.finding_id "
                   "WHERE l.knowledge_id=?")
        else:
            sql = "SELECT COUNT(DISTINCT finding_id) AS n FROM knowledge_links WHERE knowledge_id=? AND finding_id IS NOT NULL"
        r = self.store.one(sql, kid)
        return r["n"] if r else 0

    def apply_gate(self, kid: str, report: dict, approved_by: str | None = None) -> dict:
        item = self.store.knowledge(kid)
        status = self.decide_status(item, report, approved_by)
        if item["status"] == "retired":
            return item
        self.store.x("UPDATE knowledge SET gate=?, status=?, updated_at=? WHERE id=?", json.dumps(report), status, time.time(), kid)
        if status != item["status"]:
            self.store.event(approved_by or "system", f"knowledge.{status}", None, kid,
                             previous=item["status"], suppresses=report.get("suppresses"), canary=report.get("canary"))
        return self.store.knowledge(kid)

    # ── human actions ────────────────────────────────────────────────────────────────────
    def set_status(self, kid: str, status: str, actor: str) -> dict:
        item = self.store.knowledge(kid)
        if item is None:
            raise KeyError(kid)
        if status == "active" and (item.get("gate") or {}).get("canary", "pass") != "pass":
            raise ValueError(f"{kid} failed its canary gate and cannot be activated")
        self.store.x("UPDATE knowledge SET status=?, updated_at=? WHERE id=?", status, time.time(), kid)
        self.store.event(actor, f"knowledge.{status}", None, kid, previous=item["status"])
        return self.store.knowledge(kid)
