"""Learned Semgrep spec rules: the second kind of flywheel knowledge.

A `spec_rule` item carries one ordinary Semgrep rule, in the same shape as specs/python-web.yml
(metadata.sentinel role/cls). Where a Datalog fact is keyed by a callee name, a rule describes code
shape: it can model a shared helper whose body a repository cannot see (an installed package), and it
can be exported and run by plain Semgrep in CI. A rule is proposed by a RuleSynthesizer (or written
by a human) and must pass every gate below before it can leave `candidate` (KNighter, Autogrep):

  sanity          YAML parses, exactly one rule, search mode, metadata.sentinel role/cls valid and equal
                  to the item's, sinks focus the dangerous argument, and Semgrep accepts the rule
  differential    patch-differential oracle: the vulnerable/fixed pair is analysed by the full engine
                  (extract + spec matching + Datalog) with and without the rule.
                    sink/source: vulnerable gets an open finding of the class that does not exist
                                 without the rule; fixed has none with the rule
                    sanitizer:   the sanitized variant is open without the rule and mitigated by it;
                                 the unsanitized variant stays open with it
  generalization  the rule matches the real site of the originating finding (an over-specific rule
                  that only matches its own example is rejected)
  canary          no canary finding disappears, and a sink/source rule adds at most
                  Policy.rule_fp_budget findings on the reference corpora beyond those already reported

The gate also reports the impact on every repo in scope, like fact knowledge: human-confirmed findings
must not be suppressed, and a large blast radius sends the item to shadow.

All Semgrep work for one gate is a single Semgrep run over every target (examples, repos in scope,
reference corpora), because Semgrep's start-up dominates its cost.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable

import yaml

from ..engine.analyze import CLASSES, Analysis, analyze
from ..extract.python_facts import Facts, extract
from ..extract.semgrep_specs import (DEFAULT_SPECS, SpecMatch, build_baseline_rules, lift, load_rules, match_specs,
                                     rule_meta, run_semgrep_raw)
from .knowledge import CANARY_ROOT, SPEC_RULE, Policy

SAST_ROOT = Path(__file__).resolve().parents[2]
REFERENCE_CORPORA = [CANARY_ROOT, SAST_ROOT / "demo" / "acme-shop", SAST_ROOT / "demo" / "acme-billing"]
ROLES = ("source", "sink", "sanitizer")
SOURCE_KINDS = {"http", "cookie", "header", "cli"}
OPEN = ("confirmed", "undecided")
PATTERN_KEYS = ("pattern", "patterns", "pattern-either", "pattern-regex")


# ── the rule itself ──────────────────────────────────────────────────────────────────────

def parse_rule(text: str) -> tuple[dict | None, str]:
    """Structural sanity of a rule YAML document. Returns (rule, "pass") or (None|rule, "fail: ...")."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return None, f"fail: YAML does not parse ({str(e).splitlines()[0]})"
    rules = doc.get("rules") if isinstance(doc, dict) else None
    if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
        return None, "fail: expected exactly one rule under `rules:`"
    r = rules[0]
    meta = (r.get("metadata") or {}).get("sentinel") if isinstance(r.get("metadata"), dict) else None
    if not r.get("id") or "python" not in (r.get("languages") or []):
        return r, "fail: the rule needs an id and `languages: [python]`"
    if r.get("mode", "search") != "search":
        return r, "fail: spec rules are search-mode rules (sources, sinks and sanitizers are separate rules)"
    if not any(k in r for k in PATTERN_KEYS):
        return r, "fail: no pattern"
    if not isinstance(meta, dict) or meta.get("role") not in ROLES:
        return r, "fail: metadata.sentinel.role must be source, sink or sanitizer"
    role, cls = meta["role"], meta.get("cls")
    if role == "sink" and cls not in CLASSES:
        return r, f"fail: unknown sink class {cls!r}"
    if role == "sanitizer" and cls not in (*CLASSES, "all"):
        return r, f"fail: unknown sanitizer class {cls!r}"
    if role == "source" and meta.get("kind") not in SOURCE_KINDS:
        return r, f"fail: source kind must be one of {sorted(SOURCE_KINDS)}"
    if role == "sink" and "focus-metavariable" not in json.dumps(r.get("patterns", [])):
        return r, "fail: a sink rule must focus the dangerous argument (focus-metavariable)"
    return r, "pass"


def check_rule(text: str, role: str, cls: str | None) -> tuple[dict | None, str]:
    rule, verdict = parse_rule(text)
    if verdict != "pass":
        return rule, verdict
    meta = rule["metadata"]["sentinel"]
    if meta["role"] != role or (role != "source" and meta.get("cls") != cls):
        return rule, f"fail: metadata.sentinel says {meta['role']}/{meta.get('cls')}, the item says {role}/{cls}"
    return rule, "pass"


def learned_id(kid: str, rule_id: str) -> str:
    """Rule id as matched and exported: carries the knowledge id, keeps the `spec.` prefix of the pack."""
    return f"spec.learned.{kid}." + rule_id.removeprefix("spec.").removeprefix("learned.")


def materialize(item: dict) -> dict:
    """The item's rule with its knowledge id injected (rule id and metadata.sentinel.knowledge)."""
    rule = yaml.safe_load(item["payload"]["yaml"])["rules"][0]
    rule["id"] = learned_id(item["id"], rule["id"])
    rule.setdefault("metadata", {}).setdefault("sentinel", {})["knowledge"] = item["id"]
    return rule


def write_rules(items: list[dict], path: Path) -> Path:
    path.write_text(yaml.safe_dump({"rules": [materialize(i) for i in items]}, sort_keys=False))
    return path


def hides_body(item: dict, facts: Facts) -> bool:
    """A sink/source rule models a helper whose body is invisible. Where the repository contains the body,
    the engine already sees the real sink, and a second sink at every call site would only duplicate findings."""
    p = item.get("payload") or {}
    return p.get("role") in ("sink", "source") and p.get("target") in facts.functions


def match_rules(root: Path, facts: Facts, items: list[dict]) -> list[SpecMatch]:
    """Spec matches of learned rules on one repository (curated matches are computed separately)."""
    items = [i for i in items if not hides_body(i, facts)]
    if not items:
        return []
    with tempfile.TemporaryDirectory() as td:
        cfg = write_rules(items, Path(td) / "learned.yml")
        return match_specs(root, facts, [cfg], include_default=False)


def active_rules(store, org_id: str, repo_id: str | None = None) -> list[dict]:
    """ACTIVE learned rule items in scope: global + org (+ the repo's own when repo_id is given)."""
    return [k for k in store.knowledge_in_scope(org_id, repo_id or "", ("active",)) if k["pred"] == SPEC_RULE]


def export_rules(store, org_id: str, repo_id: str | None = None, fmt: str = "spec") -> str:
    """One plain Semgrep config: the curated pack plus every ACTIVE learned rule in scope.
    fmt=spec  the spec rules themselves (sources, sinks, sanitizers; what Sentinel consumes)
    fmt=taint Semgrep OSS taint-mode rules generated from them (what CI runs to report flows)"""
    if fmt not in ("spec", "taint"):
        raise ValueError("format must be spec or taint")
    items = active_rules(store, org_id, repo_id)
    rules = load_rules() + [materialize(k) for k in items]
    doc = build_baseline_rules(rules=rules) if fmt == "taint" else {"rules": rules}
    head = (f"# Sentinel rules for org {org_id}{' repo ' + repo_id if repo_id else ''}: curated pack + "
            f"{len(items)} learned rule(s) ({', '.join(k['id'] for k in items) or 'none'}). Format: {fmt}.\n")
    return head + yaml.safe_dump(doc, sort_keys=False)


# ── reference corpora (canaries + demo repos): extracted and matched once per process ──────

@dataclass(frozen=True)
class Corpus:
    root: Path
    facts: Facts
    matches: list
    open_fps: frozenset
    open_keys: frozenset  # (source function, class) of open findings


@lru_cache(maxsize=8)
def corpus(root: str) -> Corpus:
    p = Path(root)
    facts = extract(p)
    matches = match_specs(p, facts)
    a = analyze(facts, matches)
    return Corpus(p, facts, matches, frozenset(_open_fps(a)), frozenset(_open_keys(a)))


@lru_cache(maxsize=64)
def example_inputs(vulnerable: str, fixed: str) -> dict[str, tuple[Facts, list]]:
    """Facts and curated-pack matches of a validation pair (one Semgrep run for both; cached by content,
    since template-written pairs repeat)."""
    with tempfile.TemporaryDirectory() as td:
        out = {}
        for name, text in (("vulnerable", vulnerable), ("fixed", fixed)):
            root = Path(td) / name
            root.mkdir()
            (root / "app.py").write_text(text)
            out[name] = (root, extract(root))
        code, res, err = run_semgrep_raw(DEFAULT_SPECS, SAST_ROOT, [str(r / "app.py") for r, _ in out.values()])
        if code not in (0, 1) or res is None:
            raise RuntimeError(f"semgrep failed on the curated pack ({code}): {err}")
        meta = rule_meta(DEFAULT_SPECS)
        return {name: (facts, lift([r for r in res["results"] if Path(r["path"]).parent.name == name], facts, meta,
                                   path_of=lambda r: "app.py"))
                for name, (_root, facts) in out.items()}


def _open_fps(a: Analysis, cls: str | None = None) -> set[str]:
    return {f.fingerprint for f in a.findings if f.status in OPEN and (cls is None or f.cls == cls)}


def _open_keys(a: Analysis) -> set[tuple[str, str]]:
    return {(f.source_fn, f.cls) for f in a.findings if f.status in OPEN}


def _files_hash(facts: Facts) -> str:
    return hashlib.sha256(json.dumps(sorted(facts.files.items())).encode()).hexdigest()[:16]


# ── the gate ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RepoView:
    """A repository in scope as the gate sees it: its files, and the engine with or without extra matches."""
    root: Path
    facts: Facts
    current: Callable[[], Analysis]
    with_matches: Callable[[list[SpecMatch]], Analysis]


class RuleGate:
    def __init__(self, policy: Policy | None = None):
        self.policy = policy or Policy()
        self._static: dict[str, tuple[dict, dict]] = {}  # validation is deterministic: cache by inputs
        self.repo_matches: dict[str, dict[str, list[SpecMatch]]] = {}  # item id -> repo -> raw candidate matches

    def gate(self, item: dict, repos: dict[str, RepoView], confirmed_fps: set[str]) -> dict:
        p = item.get("payload") or {}
        report: dict = {"checked_at": time.time(), "kind": SPEC_RULE, "role": p.get("role"), "cls": p.get("cls"),
                        "sanity": "pass", "differential": "not run", "generalization": "not run", "canary": "not run",
                        "impact": [], "conflicts": [], "suppresses": 0, "adds": 0, "over_budget": False}
        rule, sanity = check_rule(p.get("yaml", ""), p.get("role"), p.get("cls"))
        if sanity != "pass":
            report["sanity"] = sanity
            return report
        key = hashlib.sha256(json.dumps([item["id"], p.get("yaml"), p.get("vulnerable_example"), p.get("fixed_example"),
                                         p.get("site"), p.get("origin_repo"), self.policy.rule_fp_budget,
                                         sorted((r, str(v.root), _files_hash(v.facts)) for r, v in repos.items())],
                                        default=str).encode()).hexdigest()
        if key not in self._static:
            self._static[key] = self._validate(item, repos)
        static, cand = self._static[key]
        self.repo_matches[item["id"]] = cand  # reused by the scanner, so a scan does not match the rule again
        report.update(static)
        if report["sanity"] != "pass":
            return report
        self._impact(item, report, repos, cand, confirmed_fps)
        return report

    # Static part: everything that depends only on the rule, its examples and the code it runs on.
    def _validate(self, item: dict, repos: dict[str, RepoView]) -> tuple[dict, dict]:
        p, kid = item["payload"], item["id"]
        out: dict = {}
        with tempfile.TemporaryDirectory() as td_:
            td = Path(td_).resolve()
            cfg = td / "rule.yml"
            cfg.write_text(yaml.safe_dump({"rules": [materialize(item)]}, sort_keys=False))
            # Curated matches of the pair come from a cached run; this run matches only the candidate rule.
            pair = example_inputs(p.get("vulnerable_example") or "", p.get("fixed_example") or "")
            examples, curated = {}, {}
            for name in ("vulnerable", "fixed"):
                root = td / f"example-{name}"
                root.mkdir()
                (root / "app.py").write_text(p.get(f"{name}_example") or "")
                examples[name] = (root, pair[name][0])
                curated[f"example:{name}"] = pair[name][1]
            roots: dict[str, tuple[Path, Facts]] = {f"example:{n}": v for n, v in examples.items()}
            roots.update({f"repo:{r}": (v.root.resolve(), v.facts) for r, v in repos.items()})
            corpora = {f"corpus:{c.name}": corpus(str(c)) for c in REFERENCE_CORPORA}
            roots.update({k: (c.root.resolve(), c.facts) for k, c in corpora.items()})
            # A repo in scope can also be a reference corpus: scan each file once, credit every root holding it.
            targets = list(dict.fromkeys(str(root / f) for root, facts in roots.values() for f in sorted(facts.files)))
            # Targets are absolute; a cwd under the system temp dir makes Semgrep start ~1.5 s slower.
            code, res, err = run_semgrep_raw([cfg], SAST_ROOT, targets)
            errors = [e for e in (res or {}).get("errors", []) if "rule" in str(e.get("type", "")).lower()]
            if code not in (0, 1) or res is None or errors:
                if errors:
                    msg = errors[0].get("message") or errors[0].get("type")
                else:
                    msg = (err.strip().splitlines() or [f"exit code {code}"])[-1]
                out["sanity"] = f"fail: Semgrep rejected the rule: {str(msg).strip()[:300]}"
                return out, {}
            meta = rule_meta([cfg])
            by_root: dict[str, list[tuple[dict, str]]] = {k: [] for k in roots}
            for r in res.get("results", []):
                path = Path(r["path"]) if Path(r["path"]).is_absolute() else SAST_ROOT / r["path"]
                path = path.resolve()
                for k, (root, _f) in roots.items():
                    if path.is_relative_to(root):
                        by_root[k].append((r, str(path.relative_to(root))))
            lifted = {}
            for k, (root, facts) in roots.items():
                rel = {id(r): rp for r, rp in by_root[k]}
                lifted[k] = curated.get(k, []) + lift([r for r, _ in by_root[k]], facts, meta,
                                                      path_of=lambda r, rel=rel: rel[id(r)])
        cand = {k: [m for m in ms if m.knowledge == kid] for k, ms in lifted.items()}
        out.update(self._differential(p, kid, examples, lifted))
        out.update(self._generalization(p, cand))
        out.update(self._canary(p, corpora, cand))
        out["rule_matches"] = {k.split(":", 1)[1]: len(v) for k, v in cand.items() if k.startswith("repo:")}
        return out, {k.split(":", 1)[1]: v for k, v in cand.items() if k.startswith("repo:")}

    @staticmethod
    def _differential(p: dict, kid: str, examples: dict, lifted: dict) -> dict:
        role, cls = p["role"], p.get("cls")
        c = cls if cls in CLASSES else None  # source rules and `all` sanitizers: any class counts

        def run(name: str, with_rule: bool) -> Analysis:
            _root, facts = examples[name]
            ms = [m for m in lifted[f"example:{name}"] if with_rule or m.knowledge is None]
            return analyze(facts, ms)

        detail: dict = {}
        if role in ("sink", "source"):
            new = _open_fps(run("vulnerable", True), c) - _open_fps(run("vulnerable", False), c)
            fixed_open = _open_fps(run("fixed", True), c)
            detail = {"vulnerable_new_findings": len(new), "fixed_open_findings": len(fixed_open)}
            if not new:
                verdict = f"fail: the vulnerable example has no new open {cls or 'any'} finding with the rule"
            elif fixed_open:
                verdict = f"fail: the fixed example still has {len(fixed_open)} open {cls or 'any'} finding(s) with the rule"
            else:
                verdict = "pass"
        else:
            without = run("fixed", False)
            with_ = {f.fingerprint: f for f in run("fixed", True).findings}
            flipped = [fp for fp in _open_fps(without, c) if fp in with_ and with_[fp].status == "mitigated"
                       and any(kid in m["knowledge"] for m in with_[fp].mitigations)]
            raw_open = _open_fps(run("vulnerable", True), c)
            detail = {"sanitized_open_without_rule": len(_open_fps(without, c)), "sanitized_mitigated_by_rule": len(flipped),
                      "unsanitized_open_with_rule": len(raw_open)}
            if not flipped:
                verdict = "fail: the sanitized example is not open without the rule and mitigated by it"
            elif not raw_open:
                verdict = "fail: the unsanitized example is no longer open with the rule (the rule hides real flows)"
            else:
                verdict = "pass"
        return {"differential": verdict, "differential_detail": detail}

    @staticmethod
    def _generalization(p: dict, cand: dict) -> dict:
        origin, site = p.get("origin_repo"), p.get("site")
        ms = cand.get(f"repo:{origin}")
        if ms is None:
            return {"generalization": "fail: the originating repository is not available to check the rule against"}
        if site:
            hit = any(m.file == site["file"] and m.l1 <= site["line"] <= m.l2 for m in ms)
            return {"generalization": "pass" if hit else
                    f"fail: the rule does not match the originating site {site['file']}:{site['line']} (over-specific)",
                    "generalization_detail": {"matches_in_origin": len(ms), "site": site}}
        return {"generalization": "pass" if ms else f"fail: the rule matches nothing in {origin}",
                "generalization_detail": {"matches_in_origin": len(ms)}}

    def _canary(self, p: dict, corpora: dict, cand: dict) -> dict:
        lost, new = [], []
        for k, c in corpora.items():
            extra = cand.get(k, [])
            if not extra:
                continue
            after = analyze(c.facts, c.matches + extra)
            if k == f"corpus:{CANARY_ROOT.name}":
                lost += sorted(c.open_fps - _open_fps(after))
            if p["role"] in ("sink", "source"):
                new += [f"{c.root.name}/{fn.rsplit('.', 1)[-1]}/{cls}" for fn, cls in sorted(_open_keys(after) - c.open_keys)]
        out = {"canary": "pass", "fp_budget": {"budget": self.policy.rule_fp_budget, "new_findings": new,
                                              "corpora": [c.root.name for c in corpora.values()]}}
        if lost:
            out.update(canary=f"fail: {len(lost)} canary finding(s) would be suppressed", canary_lost=lost)
        elif len(new) > self.policy.rule_fp_budget:
            out["canary"] = (f"fail: {len(new)} new finding(s) on the reference corpora beyond those already reported "
                             f"(budget {self.policy.rule_fp_budget})")
        return out

    # Dynamic part: what the rule would change in the repos in scope, given current knowledge.
    def _impact(self, item: dict, report: dict, repos: dict[str, RepoView], cand: dict, confirmed_fps: set[str]) -> None:
        for repo_id, view in repos.items():
            ms = [] if hides_body(item, view.facts) else cand.get(repo_id, [])
            if not ms:
                continue
            before = {f.fingerprint: f for f in view.current().findings}
            for f in view.with_matches(ms).findings:
                old = before.get(f.fingerprint)
                entry = {"repo": repo_id, "fingerprint": f.fingerprint, "from": old.status if old else "absent",
                         "to": f.status, "cls": f.cls, "source_fn": f.source_fn}
                if old and old.status != f.status:
                    report["impact"].append(entry)
                    if f.fingerprint in confirmed_fps and f.status == "mitigated":
                        report["conflicts"].append(entry)
                elif old is None and f.status in OPEN:
                    report["impact"].append(entry)
        if report["conflicts"]:
            report["canary"] = f"fail: would suppress {len(report['conflicts'])} human-confirmed finding(s)"
        report["suppresses"] = sum(1 for i in report["impact"] if i["to"] == "mitigated")
        report["adds"] = sum(1 for i in report["impact"] if i["from"] == "absent")
        report["over_budget"] = max(report["suppresses"], report["adds"]) > self.policy.impact_budget
