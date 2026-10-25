"""Scan orchestration: Tier 0 (engine) -> Tier 1 (neural predicates) -> Tier 2 (verifier agent),
followed by shadow evaluation, audit sampling, Bayesian ranking and persistence."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path

from .agent.interfaces import RuleContext, RuleSynthesizer, SpecOracle, VerificationCase, Verifier
from .agent.mock import MockRuleSynthesizer, MockSpecOracle, MockVerifier, _scope_for
from .agent.orchestrator import Tools, gate
from .engine.analyze import CLASSES, CWE, Analysis, Finding, KnowledgeFact, analyze
from .engine.datalog import Program
from .extract.python_facts import Facts, content_hash, extract
from .extract.semgrep_specs import SpecMatch, match_specs
from .learn import bayes
from .learn.knowledge import SPEC_RULE, SUPPRESSING, KnowledgeService, Policy, gate_passed
from .learn.rules import RepoView, RuleGate, hides_body, match_rules, parse_rule
from .store.db import Store

LANES = ("review", "confirmed", "suppressed", "suppressed_ai", "test", "candidate")
AUDIT_RATE = float(os.environ.get("SENTINEL_AUDIT_RATE", "0.34"))


def make_neural() -> tuple[SpecOracle, Verifier]:
    if os.environ.get("SENTINEL_LLM") == "claude":
        from .agent.claude import ClaudeSpecOracle, ClaudeVerifier
        return ClaudeSpecOracle(), ClaudeVerifier()
    return MockSpecOracle(), MockVerifier()


def make_synth() -> RuleSynthesizer:
    if os.environ.get("SENTINEL_LLM") == "claude":
        from .agent.claude import ClaudeRuleSynthesizer
        return ClaudeRuleSynthesizer()
    return MockRuleSynthesizer()


FRONTIER_WORKERS = int(os.environ.get("SENTINEL_FRONTIER_WORKERS", "8"))
VERIFY_LEARNED = float(os.environ.get("SENTINEL_VERIFY_LEARNED", "0.9"))  # oracle confidence that skips verification


class Scanner:
    def __init__(self, store: Store, oracle: SpecOracle | None = None, verifier: Verifier | None = None,
                 policy: Policy | None = None, synth: RuleSynthesizer | None = None):
        self.store = store
        default_oracle, default_verifier = make_neural()
        self.oracle = oracle or default_oracle
        self.verifier = verifier or default_verifier
        self.synth = synth or make_synth()
        self.ks = KnowledgeService(store, policy)
        self.rule_gate = RuleGate(self.ks.policy)
        self.program = Program()
        self._inputs: dict[str, tuple[Facts, list[SpecMatch]]] = {}
        self._rule_matches: dict[tuple[str, str, str], list[SpecMatch]] = {}  # (repo, rule item, yaml hash) -> matches
        self.last: dict[str, Analysis] = {}
        self.frontier = os.environ.get("SENTINEL_FRONTIER", "1") != "0"  # off = the engine without frontier inference

    # ── inputs ───────────────────────────────────────────────────────────────────────────
    def inputs(self, repo_id: str, refresh: bool = False) -> tuple[Facts, list[SpecMatch]]:
        """Facts and curated-pack matches. Matches of learned spec rules are added per analysis by
        `learned_matches`, cached on the exact rule set (item id + YAML), so a change to the active or
        shadow rules re-runs Semgrep for the new rules only."""
        if refresh or repo_id not in self._inputs:
            root = Path(self.store.repo(repo_id)["root"])
            facts = extract(root)
            self._inputs[repo_id] = (facts, match_specs(root, facts))
            self._rule_matches = {k: v for k, v in self._rule_matches.items() if k[0] != repo_id}
        return self._inputs[repo_id]

    def learned_matches(self, repo_id: str, items: list[dict]) -> list[SpecMatch]:
        facts, _ = self.inputs(repo_id)
        key = lambda k: (repo_id, k["id"], hashlib.sha1(k["payload"]["yaml"].encode()).hexdigest())
        missing = [k for k in items if key(k) not in self._rule_matches]
        if missing:
            try:
                got = match_rules(Path(self.store.repo(repo_id)["root"]), facts, missing)
            except RuntimeError as e:  # a rule that passed its gates should never break a scan; be safe anyway
                self.store.event("system", "rules.match_failed", None, None, repo=repo_id, error=str(e)[:500])
                got = []
            for k in missing:
                self._rule_matches[key(k)] = [m for m in got if m.knowledge == k["id"]]
        return [m for k in items for m in self._rule_matches[key(k)]]

    def analyze_repo(self, repo_id: str, extra: list[KnowledgeFact] | None = None,
                     statuses: tuple[str, ...] = ("active",), extra_matches: list[SpecMatch] | None = None) -> Analysis:
        repo = self.store.repo(repo_id)
        facts, matches = self.inputs(repo_id)
        kn = self.ks.engine_facts(repo["org_id"], repo_id, statuses) + list(extra or [])
        rules = self.ks.spec_rules(repo["org_id"], repo_id, statuses)
        matches = matches + (self.learned_matches(repo_id, rules) if rules else []) + list(extra_matches or [])
        return analyze(facts, matches, kn, self.program)

    # ── the scan ─────────────────────────────────────────────────────────────────────────
    def scan(self, repo_id: str, refresh: bool = True, trigger: str = "scan") -> dict:
        """`trigger` is "scan" for a real scan, "knowledge" when knowledge changed and decisions are re-derived."""
        t0 = time.time()
        repo = self.store.repo(repo_id)
        org = repo["org_id"]
        scan_id = self.store.x("INSERT INTO scans(repo_id, started_at) VALUES (?, ?)", repo_id, t0)
        facts, matches = self.inputs(repo_id, refresh=refresh)
        self.store.save_files(repo_id, {p: (content_hash(c), c) for p, c in facts.files.items()})

        # Frontier: where tainted data meets an unmodelled library call or an unknown entry point, ask the
        # oracle about exactly that API / function (cached across repos), gate the answers, re-derive.
        fr = self._frontier(repo_id, org, facts) if self.frontier and hasattr(self.oracle, "classify_sink") else {"questions": 0, "cached": 0, "facts": []}

        # Tier 0: deterministic decisions from facts + active knowledge.
        a0 = self.analyze_repo(repo_id)
        outcome: dict[str, dict] = {}
        for f in a0.findings:
            lane = {"confirmed": "confirmed", "mitigated": "suppressed", "test_only": "test"}.get(f.status, "review")
            outcome[f.fingerprint] = {"finding": f, "lane": lane, "decided_by": "engine" if lane != "review" else None,
                                      "verdicts": []}
        learned = {k.kid for k in a0.knowledge if not k.kid.startswith("K-cur")} | {m.knowledge for m in a0.matches if m.knowledge}
        auto_by_knowledge = [f for f in a0.findings if f.status == "mitigated"
                             and any(set(m["knowledge"]) & learned for m in f.mitigations)]

        # Tier 1: neural predicates for assumption points on undecided findings (lazy, cached).
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

        # Findings that exist only because of a learned sink/source the oracle was not sure about are not
        # auto-confirmed: the verifier reads them like any undecided finding.
        conf = {k["id"]: k["confidence"] or 0 for k in self.store.q("SELECT id, confidence FROM knowledge WHERE origin LIKE 'oracle:%'")}
        verify_learned = set()
        for fp, o in outcome.items():
            f = o["finding"]
            low = [x for x in f.learned if x["knowledge"] and min(conf.get(k, 1) for k in x["knowledge"]) < VERIFY_LEARNED]
            if o["lane"] == "confirmed" and o["decided_by"] == "engine" and low:
                o.update(lane="review", decided_by=None)
                f.assumptions = f.assumptions + [{"asm": ["learned_spec", x["subject"]],
                                                  "label": f"Learned {x['kind']}, unverified: {x['subject']}"} for x in low]
                verify_learned.add(fp)

        # Tier 2: the verifier agent on what is still undecided, behind symbolic gates.
        rerun = lambda extra: self.analyze_repo(repo_id, t1_facts + extra)
        tools = Tools(facts, a1, rerun)
        t2_calls, t2_hits, t2_cost = 0, 0, {"tokens_in": 0, "tokens_out": 0, "tool_calls": 0}
        for fp, o in outcome.items():
            f: Finding = o["finding"]
            if o["lane"] != "review" or (f.status != "undecided" and fp not in verify_learned):
                continue
            # IDOR on a model the oracle called public content: not worth an agent run; it stays a candidate.
            if f.cls == "idor" and self._public_model(f, org):
                continue
            # Unchanged code is never re-verified: reuse the last verdict for the same evidence.
            key = self._evidence_key(f, facts)
            prev = self.store.one("SELECT v.* FROM verdicts v JOIN findings x ON x.id = v.finding_id WHERE x.repo_id=? "
                                  "AND x.fingerprint=? AND v.kind='agent' ORDER BY v.id DESC LIMIT 1", repo_id, fp)
            if prev and prev["evidence"].get("evidence_key") == key:
                t2_hits += 1
                if prev["gate"].get("accepted"):
                    o.update(lane=prev["gate"]["lane"], decided_by="tier2")
                continue
            case = VerificationCase(fp, repo_id, f.cls, f.title, f.status, f.assumptions,
                                    [asdict(s) for s in f.path], f.source_fn, f.sink_fn, f.proof)
            verdict = self.verifier.verify(case, tools)
            result = gate(verdict, tools)
            t2_calls += 1
            for k_ in t2_cost:
                t2_cost[k_] += verdict.cost.get(k_, 0)
            o["verdicts"].append({"kind": "agent", "actor": f"agent:{verdict.model}", "verdict": verdict.verdict,
                                  "reason_code": verdict.reason_code, "evidence": {**verdict.to_json(), "evidence_key": key},
                                  "gate": result.to_json()})
            if result.accepted:
                o.update(lane=result.lane, decided_by="tier2")
                o["proposals"] = verdict.proposed

        # Missing-authorization findings are semantic: unless the verifier confirmed one, it is a candidate
        # (its own lane, out of the review queue), so authorization patterns we cannot see never flood triage.
        for o in outcome.values():
            if o["finding"].cls == "idor" and o["lane"] == "review":
                o["lane"] = "candidate"

        # Shadow evaluation: what would candidate/shadow knowledge change? (shown, never applied)
        # Shadow spec rules are matched the same way; candidate rules never run (they failed a gate, and
        # a rule Semgrep rejects must not reach a scan).
        shadow_items = self.ks.engine_facts(org, repo_id, ("shadow", "candidate"))
        shadow_rules = self.ks.spec_rules(org, repo_id, ("shadow",))
        shadow_by: dict[str, str] = {}
        shadow_new: list[dict] = []  # findings a shadow sink/source rule would add
        if shadow_items or shadow_rules:
            a_sh = self.analyze_repo(repo_id, shadow_items, extra_matches=self.learned_matches(repo_id, shadow_rules))
            sh_ids = {k.kid for k in shadow_items} | {k["id"] for k in shadow_rules}
            for g in a_sh.findings:
                o = outcome.get(g.fingerprint)
                if o and o["lane"] in ("review", "confirmed") and g.status == "mitigated":
                    kids = sorted({kid for m in g.mitigations for kid in m["knowledge"]} & sh_ids)
                    if kids:
                        shadow_by[g.fingerprint] = kids[0]
                elif o is None and g.status in ("confirmed", "undecided") and set(g.spec_knowledge) & sh_ids:
                    shadow_new.append({"knowledge": sorted(set(g.spec_knowledge) & sh_ids)[0], "fingerprint": g.fingerprint,
                                       "cls": g.cls, "source_fn": g.source_fn, "file": g.file, "line": g.line})

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
                    # Rule synthesis from accepted agent verdicts (machine origin: shadow until approved/corroborated).
                    f_: Finding = o["finding"]
                    view = _finding_view(f_)
                    trig = {"kind": "agent_verdict", "by": v["actor"], "verdict": v["verdict"]}
                    if v["verdict"] == "TRUE_POSITIVE":
                        self.learn_sink_rule(repo_id, view, fid, vid, trig, a1)
                    for p in o.get("proposals", []):
                        if p.pred == "sanitizer_api" and p.scope in ("repo", "org"):
                            self.learn_sanitizer_rule(repo_id, view, p.args[0], p.args[1], p.scope, fid, vid, trig, a1)
        if seen_ids:
            marks = ",".join("?" * len(seen_ids))
            self.store.x(f"UPDATE findings SET is_open=0 WHERE repo_id=? AND id NOT IN ({marks})", repo_id, *seen_ids)
        for kid in t1_ids:
            self._gate_item(kid)

        self.rank(repo_id)
        self.last[repo_id] = a1
        stats = self._stats(outcome, a0, t1_calls, t1_hits, t2_calls, t2_cost, auto_by_knowledge, time.time() - t0)
        stats.update(frontier_questions=fr["questions"], frontier_cached=fr["cached"], frontier_facts=len(fr["facts"]),
                     found_by_frontier=sum(1 for o in outcome.values() if o["finding"].learned
                                           and o["finding"].status in ("confirmed", "undecided")))
        stats.update(trigger=trigger, tier2_cache_hits=t2_hits,
                     found_by_learned_rules=sum(1 for o in outcome.values() if o["finding"].spec_knowledge),
                     shadow_rule_findings=shadow_new)
        self.store.x("UPDATE scans SET finished_at=?, stats=? WHERE id=?", time.time(), json.dumps(stats), scan_id)
        self.store.event("system", "scan.completed", None, None, repo=repo_id, scan=scan_id, **{k: v for k, v in stats.items() if k != "lanes"})
        return {"scan_id": scan_id, **stats}

    # ── tiers ────────────────────────────────────────────────────────────────────────────
    def _tier1(self, undecided: list[Finding], facts: Facts, org: str, repo_id: str):
        """Ask the spec oracle about each distinct unknown API / unknown guard, once (cross-scan cache).
        With SENTINEL_ORACLE_BATCH=1 and an oracle that supports it, the questions go out as one
        Message Batch (half price, minutes to an hour): meant for scheduled scans, not interactive ones."""
        questions: dict[tuple, None] = {}
        for f in undecided:
            for a in f.assumptions:
                kind, *args = a["asm"]
                if kind in ("unknown_api", "unknown_guard"):
                    questions[(kind, args[0])] = None
        out: list[KnowledgeFact] = []
        hits = 0

        def admit(item: dict) -> None:
            item = self._gate_item(item["id"])
            if _gate_ok(item):
                out.append(KnowledgeFact(item["id"], item["pred"], tuple(item["args"])))

        todo = []
        for kind, subject in questions:
            preds = ("sanitizer_api", "propagator_api") if kind == "unknown_api" else ("safe_pred", "not_safe_pred")
            cached = [k for p in preds for k in self._cached(p, subject, org, repo_id)]
            if cached:
                hits += 1
                out += [KnowledgeFact(k["id"], k["pred"], tuple(k["args"])) for k in cached]
            else:
                todo.append((kind, subject, "" if kind == "unknown_api" else facts.pred_sources.get(subject, "")))
        if os.environ.get("SENTINEL_ORACLE_BATCH") == "1" and hasattr(self.oracle, "ask_many"):
            labels = self.oracle.ask_many(todo)
        else:
            labels = {(k, s): (self.oracle.classify_api(s, ctx) if k == "unknown_api" else self.oracle.judge_guard(s, ctx))
                      for k, s, ctx in todo}
        for (kind, subject), label in labels.items():
            origin = f"oracle:{label.model}"
            # A model may enumerate every class instead of saying "all": store one fact, not nine.
            if kind == "unknown_api" and set(CLASSES) <= set(label.classes):
                label.classes = ["all"]
            if kind == "unknown_guard" and set(CLASSES) <= set(label.safe_for):
                label.safe_for = ["all"]
            if kind == "unknown_api":
                if label.role == "sanitizer":
                    for c in label.classes:
                        admit(self.ks.propose("sanitizer_api", [subject, c], "global", None, None, origin, label.confidence, label.rationale))
                elif label.role == "propagator" and label.confidence >= 0.8:
                    admit(self.ks.propose("propagator_api", [subject], "global", None, None, origin, label.confidence, label.rationale))
            else:
                # Validators in customer code are org knowledge; regex literals are portable facts.
                scope = "global" if subject.startswith("regex:") else "org"
                if label.safe_for:
                    for c in label.safe_for:
                        admit(self.ks.propose("safe_pred", [subject, c], scope, org, repo_id, origin, label.confidence, label.rationale))
                elif label.confidence >= 0.8:
                    admit(self.ks.propose("not_safe_pred", [subject], scope, org, repo_id, origin, label.confidence, label.rationale))
        return out, len(todo), hits

    def scan_diff(self, repo_id: str, base_root: Path) -> dict:
        """Pull-request mode. The base snapshot is analysed by the engine alone (no model calls); the head is
        scanned normally, so the only model calls are frontier questions about APIs/entry points the diff
        introduces and verification of findings whose evidence changed. Reports what the diff adds and fixes."""
        repo = self.store.repo(repo_id)
        bf = extract(base_root)
        bm = match_specs(base_root, bf)
        kn = self.ks.engine_facts(repo["org_id"], repo_id)
        base = {f.fingerprint for f in analyze(bf, bm, kn, self.program).findings if f.status in ("confirmed", "undecided")}
        stats = self.scan(repo_id)
        head_facts, _ = self.inputs(repo_id)
        changed = sorted(p for p in set(bf.files) | set(head_facts.files) if bf.files.get(p) != head_facts.files.get(p))
        rows = self.store.q("SELECT id, fingerprint, cls, lane, source_fn, file, line FROM findings WHERE repo_id=? AND is_open=1",
                            repo_id)
        reported = [r for r in rows if r["lane"] in ("confirmed", "review")]
        new = [r for r in reported if r["fingerprint"] not in base]
        head_fps = {r["fingerprint"] for r in reported}
        return {"changed_files": changed, "new": new, "fixed": sorted(base - head_fps),
                "model_calls": stats["frontier_questions"] + stats["tier1_calls"] + stats["tier2_calls"], "stats": stats}

    def _frontier(self, repo_id: str, org: str, facts: Facts, rounds: int = 3) -> dict:
        """Recall without reading the repository: the engine names the few places where its model of the code
        runs out on a tainted path, and only those become oracle questions. Answers are ordinary knowledge
        items (gated, scoped, cached), so the next repository using the same library asks nothing."""
        stats = {"questions": 0, "cached": 0, "facts": [], "rounds": 0}
        self._org_of_facts = org
        asked: set[tuple] = set()
        for _ in range(rounds):
            a = self.analyze_repo(repo_id)
            sinks: dict[str, set] = defaultdict(set)
            for q, i in a.model.get("sink_frontier"):
                sinks[q].add(i)
            entries = sorted({fn for fn, _i in a.model.get("src_frontier")})
            # One representative handler per unanswered route-shaped decorator.
            for (d,) in sorted(set(a.model.get("dec_frontier"))):
                rep = min((f for f, dd in facts.decorated if dd == d), default=None)
                if rep and rep not in entries:
                    entries.append(rep)
            regs = sorted(set(a.model.get("reg_frontier")), key=str)
            decs = sorted({d for (d,) in a.model.get("authz_frontier")})
            models = sorted({m for (m,) in a.model.get("privacy_frontier")})
            srcapis = sorted({q for (q,) in a.model.get("srcapi_frontier")})
            todo = [("sink", q) for q in sorted(sinks)] + [("reg", r) for r in regs] + [("entry", fn) for fn in entries] \
                + [("authz", d) for d in decs] + [("model", m) for m in models] + [("srcapi", q) for q in srcapis]
            todo = [t for t in todo if t not in asked]
            if not todo:
                break
            stats["rounds"] += 1
            admitted = 0
            fresh, pending_decs = [], set()
            for kind, subj in todo:
                asked.add((kind, subj))
                preds = {"sink": ("sink_api", "not_sink_api"), "entry": ("entry_source", "not_entry"),
                         "reg": ("registrar", "not_registrar"),
                         "authz": ("authz_decorator", "not_authz_decorator"),
                         "model": ("private_model", "public_model"),
                         "srcapi": ("source_api", "not_source_api")}[kind]
                key = subj[0] if kind == "reg" else subj
                if any(self._known(p, key, org, repo_id) for p in preds) or (
                        kind == "entry" and any(self._known(p, d, org, repo_id)
                                                for f, d in facts.decorated if f == subj
                                                for p in ("framework_source", "not_framework_source"))):
                    stats["cached"] += 1
                    continue
                if kind == "entry":
                    decs = {d for f, d in facts.decorated if f == subj}
                    if decs & pending_decs:  # a sibling handler's answer about the same decorator comes first
                        asked.discard((kind, subj))
                        continue
                    pending_decs |= decs
                stats["questions"] += 1
                fresh.append((kind, subj))

            def ask(q):
                kind, subj = q
                return (self._ask_sink(subj, sorted(sinks[subj], key=str), facts) if kind == "sink"
                        else self._ask_registrar(*subj, facts) if kind == "reg"
                        else self._ask_authz(subj, facts, org) if kind == "authz"
                        else self._ask_model(subj, facts, org) if kind == "model"
                        else self._ask_source(subj, facts) if kind == "srcapi"
                        else self._ask_entry(subj, facts, org, repo_id))
            # Questions are independent: a real model answers them concurrently (the mock stays sequential so
            # knowledge ids are deterministic in tests). Gating stays sequential.
            workers = FRONTIER_WORKERS if getattr(self.oracle, "concurrent", False) else 1
            with ThreadPoolExecutor(max_workers=workers) as pool:
                answers = list(pool.map(ask, fresh))
            for items in answers:
                for item in items:
                    item = self._gate_frontier_item(item)
                    stats["facts"].append(item["id"])
                    admitted += item["status"] == "active"
            if not admitted:
                break
            self._enforce_adds_budget(repo_id, stats["facts"])
        return stats

    def _gate_frontier_item(self, item: dict) -> dict:
        """Frontier facts that only add findings (or stop a question) are gated on the canary corpus; what they add
        in this repository is checked once per round (_enforce_adds_budget) instead of re-analysing every repo per
        fact. Facts that can hide findings take the full gate."""
        if item["status"] in ("active", "retired") or item["pred"] in SUPPRESSING:
            return self._gate_item(item["id"])
        report = self.ks.gate(item, {}, set(), lambda r, extra: self.analyze_repo(r, extra))
        return self.ks.apply_gate(item["id"], report)

    def _enforce_adds_budget(self, repo_id: str, kids: list[str]) -> None:
        a = self.analyze_repo(repo_id)
        adds: dict[str, int] = defaultdict(int)
        for f in a.findings:
            if f.status in ("confirmed", "undecided"):
                for x in f.learned:
                    for k in x["knowledge"]:
                        adds[k] += 1
        for k in set(kids):
            if adds[k] > self.ks.policy.adds_budget:
                item = self.store.knowledge(k)
                gate = {**item["gate"], "adds": adds[k], "over_budget": True}
                self.store.x("UPDATE knowledge SET status='shadow', gate=?, updated_at=? WHERE id=?", json.dumps(gate), time.time(), k)
                self.store.event("system", "knowledge.shadow", None, k, reason="adds budget", adds=adds[k])

    def _known(self, pred: str, subject: str, org: str, repo_id: str) -> bool:
        """Already answered (any status but retired): a frontier question is asked once per scope."""
        return bool(self.store.one("SELECT 1 FROM knowledge WHERE pred=? AND json_extract(args, '$[0]')=? AND status != 'retired' "
                                   "AND (scope='global' OR (scope='org' AND org_id=?) OR (scope='repo' AND repo_id=?))",
                                   pred, subject, org, repo_id))

    def _ask_sink(self, api: str, args: list, facts: Facts) -> list[dict]:
        site = next(((n.file, n.l1) for k, q in sorted(facts.libcalls.items()) if q == api for n in [facts.nodes[k]]), None)
        usage = f"{site[0]}:{site[1]}: {facts.files[site[0]].splitlines()[site[1] - 1].strip()}" if site else ""
        label = self.oracle.classify_sink(api, args, usage)
        origin = f"oracle:{label.model}"
        sinks = [x for x in label.sinks if x["cls"] in CWE]
        if sinks and label.confidence >= 0.7:
            return [self.ks.propose("sink_api", [api, x["arg"], x["cls"]], "global", None, None, origin, label.confidence,
                                    label.rationale) for x in sinks]
        if not sinks and label.confidence >= 0.8:
            return [self.ks.propose("not_sink_api", [api], "global", None, None, origin, label.confidence, label.rationale)]
        return []

    def _ask_registrar(self, api: str, arg, facts: Facts) -> list[dict]:
        site = next(((facts.nodes[k].file, facts.nodes[k].l1) for k, q in sorted(facts.callnames) if q == api), None)
        usage = facts.config_sites.get(api) or (
            f"{site[0]}:{site[1]}: {facts.files[site[0]].splitlines()[site[1] - 1].strip()}" if site else "")
        label = self.oracle.classify_registrar(api, arg, usage)
        origin = f"oracle:{label.model}"
        # `*.add_route` names a method, not a type: such facts stay in the org that taught them.
        scope = "org" if api.startswith(("*.", "config:")) else "global"  # config keys mean different things per project
        org, repo = (self._org_of_facts, None) if scope == "org" else (None, None)
        if label.registers and label.confidence >= 0.7:
            return [self.ks.propose("registrar", [api, arg], scope, org, repo, origin, label.confidence, label.rationale)]
        if not label.registers and label.confidence >= 0.8:
            return [self.ks.propose("not_registrar", [api], scope, org, repo, origin, label.confidence, label.rationale)]
        return []

    def _ask_source(self, api: str, facts: Facts) -> list[dict]:
        node = next((n for n, q in sorted(facts.attrnames | facts.callnames) if q == api), None)
        usage = ""
        if node is not None:
            n = facts.nodes[node]
            usage = f"{n.file}:{n.l1}: {facts.files.get(n.file, '').splitlines()[n.l1 - 1].strip()}" if n.file in facts.files else ""
        label = self.oracle.classify_source(api, usage)
        origin = f"oracle:{label.model}"
        if label.is_source and label.confidence >= 0.7:
            return [self.ks.propose("source_api", [api, label.kind or "http"], "global", None, None, origin,
                                    label.confidence, label.rationale)]
        if not label.is_source and label.confidence >= 0.8:
            return [self.ks.propose("not_source_api", [api], "global", None, None, origin, label.confidence, label.rationale)]
        return []

    def _public_model(self, f: Finding, org: str) -> bool:
        models = [a["asm"][1] for a in f.assumptions if a["asm"][0] == "unknown_privacy"]
        return any(self.store.one("SELECT 1 FROM knowledge WHERE pred='public_model' AND args=? AND status != 'retired' "
                                  "AND confidence >= 0.8 AND (scope='global' OR org_id=?)", json.dumps([m]), org)
                   for m in models)

    def _ask_model(self, model: str, facts: Facts, org: str) -> list[dict]:
        fn = facts.functions.get(model)
        src = ""
        for rel, text in facts.files.items():  # class source: the model is a class, not a function
            m = re.search(rf"^class {re.escape(model.rsplit('.', 1)[-1])}\b.*?(?=^\S|\Z)", text, re.M | re.S)
            if m and rel.replace("/", ".").startswith(model.rsplit(".", 2)[0].split(".")[0]):
                src = m.group(0)[:3000]
                break
        label = self.oracle.classify_model(model, src)
        if label.confidence < 0.7:
            return []
        return [self.ks.propose("private_model" if label.private else "public_model", [model], "org", org, None,
                                f"oracle:{label.model_name}", label.confidence, label.rationale)]

    def _ask_authz(self, dec: str, facts: Facts, org: str) -> list[dict]:
        label = self.oracle.classify_authz(dec, self._source_of(facts, dec))
        origin = f"oracle:{label.model}"
        # A project decorator is org knowledge; a library one (flask_security...) holds everywhere.
        scope, o = ("org", org) if dec in facts.functions else ("global", None)
        if label.confidence < 0.7:
            return []
        pred = "authz_decorator" if label.authorizes else "not_authz_decorator"
        return [self.ks.propose(pred, [dec], scope, o, None, origin, label.confidence, label.rationale)]

    def _ask_entry(self, fn: str, facts: Facts, org: str, repo_id: str) -> list[dict]:
        decorators = sorted(d for f, d in facts.decorated if f == fn)
        f = facts.functions.get(fn)
        label = self.oracle.classify_entry(fn, decorators, f.params if f else [], self._source_of(facts, fn))
        origin = f"oracle:{label.model}"
        out = []
        if label.kind == "framework" and label.decorator and label.confidence >= 0.7:
            kind = label.source_kind if label.source_kind in ("http", "event", "queue", "cli") else "http"
            out.append(self.ks.propose("framework_source", [label.decorator, kind], "global", None, None, origin,
                                       label.confidence, label.rationale))
        elif label.kind == "handler" and label.params and label.confidence >= 0.7:
            out += [self.ks.propose("entry_source", [fn, i, label.source_kind or "event"], "repo", org, repo_id, origin,
                                    label.confidence, label.rationale) for i in label.params]
        elif label.kind == "none" and label.confidence >= 0.8:
            out.append(self.ks.propose("not_entry", [fn], "repo", org, repo_id, origin, label.confidence, label.rationale))
            out += [self.ks.propose("not_framework_source", [d], "org", org, repo_id, origin, label.confidence,
                                    label.rationale) for d in decorators]
        return out

    def _cached(self, pred: str, subject: str, org: str, repo_id: str) -> list[dict]:
        """Earlier answers for the same question, visible from this repo (global, this org, or this repo)."""
        rows = self.store.q("SELECT * FROM knowledge WHERE pred=? AND json_extract(args, '$[0]')=? AND status != 'retired' "
                            "AND (scope='global' OR (scope='org' AND org_id=?) OR (scope='repo' AND repo_id=?))",
                            pred, subject, org, repo_id)
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
                                     "detail": "re-derived with the oracle's facts"}]}}

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
        if item["pred"] == SPEC_RULE:
            origin = (item.get("payload") or {}).get("origin_repo")
            if origin and origin not in repos and self.store.repo(origin):
                repos.append(origin)  # the generalization gate checks the rule against where it came from
            views = {r: RepoView(Path(self.store.repo(r)["root"]), self.inputs(r)[0], lambda r=r: self.analyze_repo(r),
                                 lambda ms, r=r: self.analyze_repo(r, extra_matches=ms)) for r in repos}
            report = self.rule_gate.gate(item, views, self.confirmed_fps())
            yaml_hash = hashlib.sha1(item["payload"]["yaml"].encode()).hexdigest()
            for r, ms in self.rule_gate.repo_matches.pop(item["id"], {}).items():
                self._rule_matches[(r, item["id"], yaml_hash)] = [] if hides_body(item, views[r].facts) else ms
            return report
        analyses = {r: self.analyze_repo(r) for r in repos}
        return self.ks.gate(item, analyses, self.confirmed_fps(), lambda r, extra: self.analyze_repo(r, extra))

    def _gate_item(self, kid: str, approved_by: str | None = None) -> dict:
        item = self.store.knowledge(kid)
        if item["status"] in ("active", "retired"):
            return item
        return self.ks.apply_gate(kid, self.preview(item), approved_by)

    # ── spec rule synthesis ──────────────────────────────────────────────────────────────
    # A finding is passed as a "view": {fingerprint, cls, title, source_fn, sink_fn, path: [step dicts]},
    # which both a fresh engine Finding (_finding_view) and a persisted finding row (data.path) provide.
    def learn_sink_rule(self, repo_id: str, view: dict, finding_id: int | None, verdict_id: int | None,
                        trigger: dict, analysis: Analysis | None = None) -> dict | None:
        """A confirmed flow reaches its sink inside a shared helper: propose a sink rule for the helper,
        focused on the parameter the flow enters by. Repos that install the package without its source
        can then see the sink at every call site."""
        facts, _ = self.inputs(repo_id)
        helper = view["sink_fn"]
        if helper == view["source_fn"] or helper not in facts.functions or _scope_for(helper) != "org":
            return None  # app-local helper: every repo that calls it also contains its body
        path = view["path"]
        idx = next((i for i in range(len(path) - 1, -1, -1) if path[i]["kind"] == "param" and path[i]["fn"] == helper), None)
        index = next((i for fn, i, p in facts.params if fn == helper and idx is not None and p == path[idx]["node"]), None)
        if index is None:
            return None
        params = facts.functions[helper].params
        site = path[idx - 1] if idx > 0 else None
        ctx = RuleContext("sink", view["cls"], helper, repo_id, index, params[index] if index < len(params) else None,
                          self._source_of(facts, helper), self._site(facts, site), _brief(view))
        return self._synthesize(ctx, "org", finding_id, verdict_id, trigger, analysis)

    def learn_sanitizer_rule(self, repo_id: str, view: dict, fn: str, cls: str, scope: str, finding_id: int | None,
                             verdict_id: int | None, trigger: dict, analysis: Analysis | None = None) -> dict | None:
        """`fn` was judged to sanitize `cls` (human triage at org scope, or a gated agent FP verdict):
        propose a sanitizer rule for it, alongside the sanitizer_api fact."""
        if scope not in ("repo", "org"):
            return None
        facts, _ = self.inputs(repo_id)
        on_path = {st["node"] for st in view.get("path", [])}
        nodes = sorted((n for n in facts.nodes.values() if n.callee == fn),
                       key=lambda n: (n.id not in on_path, n.fn != view.get("source_fn"), n.file, n.l1))
        site = {"file": nodes[0].file, "line": nodes[0].l1} if nodes else None
        ctx = RuleContext("sanitizer", cls, fn, repo_id, helper_source=self._source_of(facts, fn),
                          site=self._site(facts, site), finding=_brief(view))
        return self._synthesize(ctx, scope, finding_id, verdict_id, trigger, analysis)

    def submit_rule(self, repo_id: str, yaml_text: str, role: str, cls: str | None, scope: str, actor: str,
                    vulnerable_example: str, fixed_example: str, rationale: str = "", target: str | None = None,
                    site: dict | None = None) -> dict:
        """A rule written by a human (API / workbench). Human origin: it activates once every gate passes."""
        repo = self.store.repo(repo_id)
        rule, _ = parse_rule(yaml_text)
        payload = {"yaml": yaml_text, "role": role, "cls": cls, "rule_id": (rule or {}).get("id") or f"human.{role}.{cls}",
                   "target": target, "vulnerable_example": vulnerable_example, "fixed_example": fixed_example,
                   "rationale": rationale, "synthesizer": None, "origin_repo": repo_id, "site": site,
                   "trigger": {"kind": "authored", "by": actor}}
        item = self.ks.propose_rule(payload, scope, repo["org_id"], repo_id, actor, 1.0, rationale or "authored rule")
        return self._gate_item(item["id"])

    def _synthesize(self, ctx: RuleContext, scope: str, finding_id: int | None, verdict_id: int | None, trigger: dict,
                    analysis: Analysis | None) -> dict | None:
        repo = self.store.repo(ctx.repo)
        facts, _ = self.inputs(ctx.repo)
        a = analysis or self.last.get(ctx.repo) or self.analyze_repo(ctx.repo)
        tools = Tools(facts, a, lambda extra: self.analyze_repo(ctx.repo, extra))
        proposals = self.synth.propose(ctx, tools)
        if not proposals:
            return None
        prop = proposals[0]
        rule, _ = parse_rule(prop.yaml)
        payload = {"yaml": prop.yaml, "role": prop.role, "cls": prop.cls,
                   "rule_id": (rule or {}).get("id") or f"invalid.{ctx.role}.{ctx.cls}.{ctx.target}", "target": ctx.target,
                   "vulnerable_example": prop.vulnerable_example, "fixed_example": prop.fixed_example,
                   "rationale": prop.rationale, "synthesizer": prop.model or self.synth.name, "origin_repo": ctx.repo,
                   "site": {k: ctx.site[k] for k in ("file", "line")} if ctx.site else None, "trigger": trigger}
        item = self.ks.propose_rule(payload, scope, repo["org_id"], ctx.repo, f"agent:{self.synth.name}", 0.9,
                                    prop.rationale, finding_id, verdict_id)
        gated = self._gate_item(item["id"])
        return {**gated, "newly_active": item["status"] != "active" and gated["status"] == "active"}

    @staticmethod
    def _source_of(facts: Facts, qname: str) -> str:
        fn = facts.functions.get(qname)
        if fn is None:
            return ""
        return "\n".join(facts.files.get(fn.file, "").splitlines()[fn.line - 1: fn.end_line])

    @staticmethod
    def _site(facts: Facts, step: dict | None) -> dict | None:
        if not step:
            return None
        lines = facts.files.get(step["file"], "").splitlines()
        code = lines[step["line"] - 1].strip() if 0 < step["line"] <= len(lines) else ""
        return {"file": step["file"], "line": step["line"], "code": code}

    # ── persistence helpers ──────────────────────────────────────────────────────────────
    def _upsert_finding(self, repo_id: str, scan_id: int, o: dict, shadow: str | None) -> int:
        f: Finding = o["finding"]
        data = {"path": [asdict(s) for s in f.path], "proof": f.proof, "mitigations": f.mitigations,
                "assumptions": f.assumptions, "source_rule": f.source_rule, "sink_rule": f.sink_rule,
                "decided_by": o.get("decided_by"), "source_node": f.source, "sink_node": f.sink,
                "spec_knowledge": f.spec_knowledge, "learned": f.learned}
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

    def _evidence_key(self, f: Finding, facts: Facts) -> str:
        files = sorted({st.file for st in f.path})
        blob = "|".join([f.fingerprint, getattr(self.verifier, "name", "")] + [f"{p}:{content_hash(facts.files.get(p, ''))}" for p in files])
        return hashlib.sha256(blob.encode()).hexdigest()[:24]

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


def _finding_view(f: Finding) -> dict:
    return {"fingerprint": f.fingerprint, "cls": f.cls, "title": f.title, "source_fn": f.source_fn, "sink_fn": f.sink_fn,
            "path": [asdict(s) for s in f.path]}


def _brief(view: dict) -> dict:
    return {k: view.get(k) for k in ("fingerprint", "title", "source_fn", "sink_fn")}


def _gate_ok(item: dict) -> bool:
    return gate_passed(item.get("gate") or {})


def _evidence(row: dict) -> float | None:
    """Likelihood that a finding is real given what is known about it. Human triage dominates; a
    proof-carrying engine decision is strong evidence; a gated machine verdict is weaker."""
    if row["triage_state"] == "confirmed":
        return 0.99
    if row["triage_state"] == "not_exploitable":
        return 0.01
    by = (row.get("data") or {}).get("decided_by")
    return {"suppressed": 0.03, "test": 0.2, "suppressed_ai": 0.12 if by == "tier2" else 0.08}.get(
        row["lane"], 0.85 if (row["lane"] == "confirmed" and by == "tier2") else None)
