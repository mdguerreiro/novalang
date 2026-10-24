"""Scan orchestration: Tier 0 (engine) -> Tier 1 (neural predicates) -> Tier 2 (verifier agent),
followed by shadow evaluation, audit sampling, Bayesian ranking and persistence."""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict
from pathlib import Path

from .agent.interfaces import SpecOracle, VerificationCase, Verifier
from .agent.mock import MockSpecOracle, MockVerifier
from .agent.orchestrator import Tools, gate
from .engine.analyze import CWE, Analysis, Finding, KnowledgeFact, analyze
from .engine.datalog import Program
from .extract.python_facts import Facts, content_hash, extract
from .extract.semgrep_specs import SpecMatch, match_specs
from .learn import bayes
from .learn.knowledge import KnowledgeService, Policy
from .store.db import Store

LANES = ("review", "confirmed", "suppressed", "suppressed_ai", "test")
AUDIT_RATE = float(os.environ.get("SENTINEL_AUDIT_RATE", "0.34"))


def make_neural() -> tuple[SpecOracle, Verifier]:
    if os.environ.get("SENTINEL_LLM") == "claude":
        from .agent.claude import ClaudeSpecOracle, ClaudeVerifier
        return ClaudeSpecOracle(), ClaudeVerifier()
    return MockSpecOracle(), MockVerifier()


class Scanner:
    def __init__(self, store: Store, oracle: SpecOracle | None = None, verifier: Verifier | None = None,
                 policy: Policy | None = None):
        self.store = store
        default_oracle, default_verifier = make_neural()
        self.oracle = oracle or default_oracle
        self.verifier = verifier or default_verifier
        self.ks = KnowledgeService(store, policy)
        self.program = Program()
        self._inputs: dict[str, tuple[Facts, list[SpecMatch]]] = {}
        self.last: dict[str, Analysis] = {}

    # ── inputs ───────────────────────────────────────────────────────────────────────────
    def inputs(self, repo_id: str, refresh: bool = False) -> tuple[Facts, list[SpecMatch]]:
        if refresh or repo_id not in self._inputs:
            root = Path(self.store.repo(repo_id)["root"])
            facts = extract(root)
            self._inputs[repo_id] = (facts, match_specs(root, facts))
        return self._inputs[repo_id]

    def analyze_repo(self, repo_id: str, extra: list[KnowledgeFact] | None = None,
                     statuses: tuple[str, ...] = ("active",)) -> Analysis:
        repo = self.store.repo(repo_id)
        facts, matches = self.inputs(repo_id)
        kn = self.ks.engine_facts(repo["org_id"], repo_id, statuses) + list(extra or [])
        return analyze(facts, matches, kn, self.program)

    # ── the scan ─────────────────────────────────────────────────────────────────────────
    def scan(self, repo_id: str, refresh: bool = True) -> dict:
        t0 = time.time()
        repo = self.store.repo(repo_id)
        org = repo["org_id"]
        scan_id = self.store.x("INSERT INTO scans(repo_id, started_at) VALUES (?, ?)", repo_id, t0)
        facts, matches = self.inputs(repo_id, refresh=refresh)
        self.store.save_files(repo_id, {p: (content_hash(c), c) for p, c in facts.files.items()})

        # Tier 0 — deterministic decisions from facts + active knowledge.
        a0 = self.analyze_repo(repo_id)
        outcome: dict[str, dict] = {}
        for f in a0.findings:
            lane = {"confirmed": "confirmed", "mitigated": "suppressed", "test_only": "test"}.get(f.status, "review")
            outcome[f.fingerprint] = {"finding": f, "lane": lane, "decided_by": "engine" if lane != "review" else None,
                                      "verdicts": []}
        learned = {k.kid for k in a0.knowledge if not k.kid.startswith("K-cur")}
        auto_by_knowledge = [f for f in a0.findings if f.status == "mitigated"
                             and any(set(m["knowledge"]) & learned for m in f.mitigations)]

        # Tier 1 — neural predicates for assumption points on undecided findings (lazy, cached).
        undecided = [f for f in a0.findings if f.status == "undecided"]
        t1_facts, t1_calls, t1_hits = self._tier1(undecided, facts, org, repo_id)
        a1 = self.analyze_repo(repo_id, t1_facts) if t1_facts else a0
        a1_by_fp = {f.fingerprint: f for f in a1.findings}
        t1_ids = {k.kid for k in t1_facts}
        for f in undecided:
            g = a1_by_fp.get(f.fingerprint)
            if g is None:
                continue
            used = {kid for m in g.mitigations for kid in m["knowledge"]}
            if g.status == "mitigated" and used & t1_ids:
                outcome[f.fingerprint].update(finding=g, lane="suppressed_ai", decided_by="tier1")
                outcome[f.fingerprint]["verdicts"].append(self._oracle_verdict(g, used & t1_ids, "FALSE_POSITIVE"))
            elif g.status == "confirmed" and f.status == "undecided" and t1_facts:
                outcome[f.fingerprint].update(finding=g, lane="confirmed", decided_by="tier1")
                outcome[f.fingerprint]["verdicts"].append(self._oracle_verdict(g, t1_ids, "TRUE_POSITIVE"))
            else:
                outcome[f.fingerprint]["finding"] = g

        # Tier 2 — the verifier agent on what is still undecided, behind symbolic gates.
        rerun = lambda extra: self.analyze_repo(repo_id, t1_facts + extra)
        tools = Tools(facts, a1, rerun)
        t2_calls, t2_cost = 0, {"tokens_in": 0, "tokens_out": 0, "tool_calls": 0}
        for fp, o in outcome.items():
            f: Finding = o["finding"]
            if o["lane"] != "review" or f.status != "undecided":
                continue
            case = VerificationCase(fp, repo_id, f.cls, f.title, f.status, f.assumptions,
                                    [asdict(s) for s in f.path], f.source_fn, f.sink_fn, f.proof)
            verdict = self.verifier.verify(case, tools)
            result = gate(verdict, tools)
            t2_calls += 1
            for k_ in t2_cost:
                t2_cost[k_] += verdict.cost.get(k_, 0)
            o["verdicts"].append({"kind": "agent", "actor": f"agent:{verdict.model}", "verdict": verdict.verdict,
                                  "reason_code": verdict.reason_code, "evidence": verdict.to_json(), "gate": result.to_json()})
            if result.accepted:
                o.update(lane=result.lane, decided_by="tier2")
                o["proposals"] = verdict.proposed

        # Shadow evaluation: what would candidate/shadow knowledge change? (shown, never applied)
        shadow_items = self.ks.engine_facts(org, repo_id, ("shadow", "candidate"))
        shadow_by: dict[str, str] = {}
        if shadow_items:
            a_sh = self.analyze_repo(repo_id, shadow_items)
            sh_ids = {k.kid for k in shadow_items}
            for g in a_sh.findings:
                o = outcome.get(g.fingerprint)
                if o and o["lane"] in ("review", "confirmed") and g.status == "mitigated":
                    kids = sorted({kid for m in g.mitigations for kid in m["knowledge"]} & sh_ids)
                    if kids:
                        shadow_by[g.fingerprint] = kids[0]

        # Persist findings, verdicts and knowledge proposals.
        seen_ids = []
        for fp, o in outcome.items():
            fid = self._upsert_finding(repo_id, scan_id, o, shadow_by.get(fp))
            seen_ids.append(fid)
            for v in o["verdicts"]:
                vid = self.store.x("INSERT INTO verdicts(finding_id, scan_id, actor, kind, verdict, reason_code, evidence, gate, created_at) "
                                   "VALUES (?,?,?,?,?,?,?,?,?)", fid, scan_id, v["actor"], v["kind"], v["verdict"],
                                   v.get("reason_code"), json.dumps(v.get("evidence", {}), default=str),
                                   json.dumps(v.get("gate", {})), time.time())
                if v["kind"] == "oracle":
                    for kid in v["evidence"].get("knowledge", []):
                        self.store.link(kid, "corroborated_by", fid, vid)
                if v["kind"] == "agent" and v["gate"].get("accepted"):
                    for p in o.get("proposals", []):
                        item = self.ks.propose(p.pred, p.args, p.scope, org, repo_id, v["actor"],
                                               v["evidence"]["confidence"], p.rationale, fid, vid)
                        self._gate_item(item["id"])
        if seen_ids:
            marks = ",".join("?" * len(seen_ids))
            self.store.x(f"UPDATE findings SET is_open=0 WHERE repo_id=? AND id NOT IN ({marks})", repo_id, *seen_ids)
        for kid in t1_ids:
            self._gate_item(kid)

        self.rank(repo_id)
        self.last[repo_id] = a1
        stats = self._stats(outcome, a0, t1_calls, t1_hits, t2_calls, t2_cost, auto_by_knowledge, time.time() - t0)
        self.store.x("UPDATE scans SET finished_at=?, stats=? WHERE id=?", time.time(), json.dumps(stats), scan_id)
        self.store.event("system", "scan.completed", None, None, repo=repo_id, scan=scan_id, **{k: v for k, v in stats.items() if k != "lanes"})
        return {"scan_id": scan_id, **stats}

    # ── tiers ────────────────────────────────────────────────────────────────────────────
    def _tier1(self, undecided: list[Finding], facts: Facts, org: str, repo_id: str):
        """Ask the spec oracle about each distinct unknown API / unknown guard, once (cross-scan cache)."""
        questions: dict[tuple, None] = {}
        for f in undecided:
            for a in f.assumptions:
                kind, *args = a["asm"]
                if kind in ("unknown_api", "unknown_guard"):
                    questions[(kind, args[0])] = None
        out: list[KnowledgeFact] = []
        calls = hits = 0

        def admit(item: dict) -> None:
            item = self._gate_item(item["id"])
            if _gate_ok(item):
                out.append(KnowledgeFact(item["id"], item["pred"], tuple(item["args"])))
        for kind, subject in questions:
            if kind == "unknown_api":
                cached = [k for p in ("sanitizer_api", "propagator_api") for k in self._cached(p, subject)]
                if cached:
                    hits += 1
                    out += [KnowledgeFact(k["id"], k["pred"], tuple(k["args"])) for k in cached if k["status"] != "retired"]
                    continue
                calls += 1
                label = self.oracle.classify_api(subject, "")
                origin = f"oracle:{label.model}"
                if label.role == "sanitizer":
                    for c in label.classes:
                        admit(self.ks.propose("sanitizer_api", [subject, c], "global", None, None, origin, label.confidence, label.rationale))
                elif label.role == "propagator" and label.confidence >= 0.8:
                    admit(self.ks.propose("propagator_api", [subject], "global", None, None, origin, label.confidence, label.rationale))
            else:
                cached = self._cached("safe_pred", subject) + self._cached("not_safe_pred", subject)
                if cached:
                    hits += 1
                    out += [KnowledgeFact(k["id"], k["pred"], tuple(k["args"])) for k in cached]
                    continue
                calls += 1
                label = self.oracle.judge_guard(subject, facts.pred_sources.get(subject, ""))
                origin = f"oracle:{label.model}"
                # Validators in customer code are org knowledge; regex literals are portable facts.
                scope = "global" if subject.startswith("regex:") else "org"
                if label.safe_for:
                    for c in label.safe_for:
                        admit(self.ks.propose("safe_pred", [subject, c], scope, org, repo_id, origin, label.confidence, label.rationale))
                elif label.confidence >= 0.8:
                    admit(self.ks.propose("not_safe_pred", [subject], scope, org, repo_id, origin, label.confidence, label.rationale))
        return out, calls, hits

    def _cached(self, pred: str, subject: str) -> list[dict]:
        rows = self.store.q("SELECT * FROM knowledge WHERE pred=? AND json_extract(args, '$[0]')=? AND status != 'retired'",
                            pred, subject)
        return [r for r in rows if _gate_ok(r)]

    def _oracle_verdict(self, g: Finding, kids: set[str], verdict: str) -> dict:
        items = [self.store.knowledge(k) for k in sorted(kids)]
        items = [i for i in items if i]
        return {"kind": "oracle", "actor": items[0]["origin"] if items else "oracle", "verdict": verdict,
                "reason_code": "SANITIZED" if verdict == "FALSE_POSITIVE" else "ASSUMPTION_REFUTED",
                "evidence": {"knowledge": sorted(kids), "labels": [{"id": i["id"], "pred": i["pred"], "args": i["args"],
                                                                     "confidence": i["confidence"], "rationale": i["rationale"]}
                                                                    for i in items],
                             "mitigations": g.mitigations},
                "gate": {"accepted": True, "lane": "suppressed_ai" if verdict == "FALSE_POSITIVE" else "confirmed",
                         "checks": [{"gate": "discharge", "ok": True,
                                     "detail": "engine re-derived the decision with the oracle's facts applied to this finding"}]}}

    # ── knowledge gating ─────────────────────────────────────────────────────────────────
    def repos_in_scope(self, item: dict) -> list[str]:
        if item["scope"] == "repo":
            return [item["repo_id"]]
        if item["scope"] == "org":
            return [r["id"] for r in self.store.q("SELECT id FROM repos WHERE org_id=?", item["org_id"])]
        return [r["id"] for r in self.store.q("SELECT id FROM repos")]

    def confirmed_fps(self) -> set[str]:
        return {r["fingerprint"] for r in self.store.q("SELECT fingerprint FROM findings WHERE triage_state='confirmed'")}

    def preview(self, item: dict) -> dict:
        repos = self.repos_in_scope(item)
        analyses = {r: self.analyze_repo(r) for r in repos}
        return self.ks.gate(item, analyses, self.confirmed_fps(), lambda r, extra: self.analyze_repo(r, extra))

    def _gate_item(self, kid: str, approved_by: str | None = None) -> dict:
        item = self.store.knowledge(kid)
        if item["status"] in ("active", "retired"):
            return item
        return self.ks.apply_gate(kid, self.preview(item), approved_by)

    # ── persistence helpers ──────────────────────────────────────────────────────────────
    def _upsert_finding(self, repo_id: str, scan_id: int, o: dict, shadow: str | None) -> int:
        f: Finding = o["finding"]
        data = {"path": [asdict(s) for s in f.path], "proof": f.proof, "mitigations": f.mitigations,
                "assumptions": f.assumptions, "source_rule": f.source_rule, "sink_rule": f.sink_rule,
                "decided_by": o.get("decided_by"), "source_node": f.source, "sink_node": f.sink}
        audit = 1 if o["lane"] == "suppressed_ai" and (int(hashlib.sha1(f.fingerprint.encode()).hexdigest(), 16) % 1000) < AUDIT_RATE * 1000 else 0
        group = _group_key(f)
        existing = self.store.one("SELECT id, triage_state FROM findings WHERE repo_id=? AND fingerprint=?", repo_id, f.fingerprint)
        now = time.time()
        if existing:
            self.store.x("UPDATE findings SET cls=?, cwe=?, severity=?, title=?, engine_status=?, lane=?, source_fn=?, sink_fn=?, "
                         "file=?, line=?, source_kind=?, data=?, group_key=?, shadow_by=?, audit=CASE WHEN triage_state='untriaged' THEN ? ELSE audit END, "
                         "is_open=1, last_scan=?, updated_at=? WHERE id=?",
                         f.cls, CWE.get(f.cls), f.severity, f.title, f.status, o["lane"], f.source_fn, f.sink_fn, f.file, f.line,
                         f.source_kind, json.dumps(data, default=str), group, shadow, audit, scan_id, now, existing["id"])
            return existing["id"]
        return self.store.x("INSERT INTO findings(repo_id, fingerprint, cls, cwe, severity, title, engine_status, lane, source_fn, "
                            "sink_fn, file, line, source_kind, data, group_key, shadow_by, audit, first_scan, last_scan, updated_at) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            repo_id, f.fingerprint, f.cls, CWE.get(f.cls), f.severity, f.title, f.status, o["lane"], f.source_fn,
                            f.sink_fn, f.file, f.line, f.source_kind, json.dumps(data, default=str), group, shadow, audit,
                            scan_id, scan_id, now)

    def rank(self, repo_id: str) -> dict[str, float]:
        """Recompute Bayesian posteriors for all open findings of a repo (and return them)."""
        rows = self.store.q("SELECT * FROM findings WHERE repo_id=? AND is_open=1", repo_id)
        net = bayes.Network()
        rule_stats = self._rule_stats()
        for r in rows:
            d = r["data"]
            hs = bayes.hypotheses_for(r["source_kind"] or "", f"{r['source_kind']}:{r['source_fn']}", d.get("sink_rule", ""),
                                      r["sink_fn"], r["source_fn"], [a["asm"] for a in d.get("assumptions", [])])
            for h, p in hs:
                if h.startswith("sink:") and h[5:] in rule_stats:
                    tp, fp = rule_stats[h[5:]]
                    p = (tp + 5 * 0.95) / (tp + fp + 5)
                net.add_hypothesis(h, p)
            net.findings.append(bayes.BayesFinding(str(r["id"]), [h for h, _ in hs], _evidence(r)))
        post = bayes.posteriors(net) if net.findings else {}
        with self.store.tx() as c:
            for fid, p in post.items():
                c.execute("UPDATE findings SET posterior=? WHERE id=?", (round(p, 4), int(fid)))
        self._net = net
        return post

    def _rule_stats(self) -> dict[str, tuple[int, int]]:
        out: dict[str, list[int]] = {}
        for r in self.store.q("SELECT data, triage_state FROM findings WHERE triage_state IN ('confirmed','not_exploitable')"):
            rule = r["data"].get("sink_rule", "")
            out.setdefault(rule, [0, 0])[0 if r["triage_state"] == "confirmed" else 1] += 1
        return {k: (v[0], v[1]) for k, v in out.items()}

    def _stats(self, outcome, a0: Analysis, t1_calls, t1_hits, t2_calls, t2_cost, auto_by_knowledge, elapsed) -> dict:
        lanes = {l: 0 for l in LANES}
        decided = {"engine": 0, "tier1": 0, "tier2": 0, "human_queue": 0}
        for o in outcome.values():
            lanes[o["lane"]] += 1
            if o["lane"] == "review":
                decided["human_queue"] += 1
            else:
                decided[o["decided_by"] or "engine"] += 1
        total = max(len(outcome), 1)
        return {"findings": len(outcome), "lanes": lanes, "decided": decided,
                "tier0_rate": round(decided["engine"] / total, 3),
                "auto_rate": round((total - decided["human_queue"]) / total, 3),
                "tier1_calls": t1_calls, "tier1_cache_hits": t1_hits, "tier2_calls": t2_calls, "agent_cost": t2_cost,
                "resolved_by_learned_knowledge": len(auto_by_knowledge), "seconds": round(elapsed, 2)}


def _group_key(f: Finding) -> str:
    """Root-cause grouping: findings that share the deciding element are triaged together."""
    for a in f.assumptions:
        kind, *args = a["asm"]
        if kind in ("maybe_sanitizer", "unknown_api", "unknown_guard"):
            return f"{kind}:{args[0]}"
    if f.sink_fn != f.source_fn:
        return f"via:{f.sink_fn}:{f.cls}"
    return f"route:{f.source_fn}:{f.cls}"


def _gate_ok(item: dict) -> bool:
    g = item.get("gate") or {}
    return g.get("sanity", "pass") == "pass" and g.get("canary", "pass") == "pass"


def _evidence(row: dict) -> float | None:
    if row["triage_state"] == "confirmed":
        return 0.99
    if row["triage_state"] == "not_exploitable":
        return 0.01
    return None
