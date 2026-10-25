"""Learned Semgrep spec rules: rule sanity, the validation gate (Semgrep, patch-differential oracle,
generalization, canaries + FP budget), lifecycle in scans (active vs shadow), triggers, and export."""
from __future__ import annotations

import sqlite3
import textwrap

import pytest
import yaml

from sentinel.agent.interfaces import RuleContext, Verdict
from sentinel.agent.mock import MockRuleSynthesizer, example_app
from sentinel.learn.knowledge import gate_passed
from sentinel.learn.rules import check_rule, export_rules, materialize, parse_rule
from sentinel.pipeline import Scanner
from sentinel.store.db import Store
from sentinel.triage import Triage

from conftest import DEMO

ALL = ["acme-shop", "acme-billing", "acme-admin"]
RUN_SHELL = "acme_common.shell.run_shell"
QUOTE_SQL = "acme_common.db.quote_sql"


class AbstainingVerifier:
    name = "abstain"

    def verify(self, case, tools):
        return Verdict(case.fingerprint, "ABSTAIN", case.cls, None, [], [], {"k": 1, "agree": 1}, 0.0, "n/a", self.name)


def _line(repo: str, rel: str, needle: str) -> int:
    return next(i for i, ln in enumerate((DEMO / repo / rel).read_text().splitlines(), 1) if needle in ln)


ARCHIVE_SITE = {"file": "billing/app.py", "line": _line("acme-billing", "billing/app.py", 'run_shell("tar czf')}
ORDER_SITE = {"file": "shop/app.py", "line": _line("acme-shop", "shop/app.py", "ref = quote_sql(")}


def _rule(body: dict, role: str, cls: str, rid: str = "t.rule") -> str:
    meta = {"role": role, "cls": cls}
    return yaml.safe_dump({"rules": [{"id": rid, "languages": ["python"], "severity": "INFO", "message": role,
                                      "metadata": {"sentinel": meta}, **body}]}, sort_keys=False)


def _sink(pattern: str, cls: str = "cmdi") -> str:
    return _rule({"patterns": [{"pattern": pattern}, {"focus-metavariable": "$X"}]}, "sink", cls)


def _mock(role: str, cls: str, target: str, repo: str, index: int | None = None, name: str | None = None):
    return MockRuleSynthesizer().propose(RuleContext(role, cls, target, repo, index, name), tools=None)[0]


_n = iter(range(10_000))


def _item(yaml_text: str, role: str, cls: str, vuln: str, fixed: str, origin: str, site: dict | None,
          target: str | None = None, scope: str = "org") -> dict:
    rule, _ = parse_rule(yaml_text)
    return {"id": f"T-{next(_n)}", "pred": "spec_rule", "scope": scope, "org_id": "acme",
            "repo_id": origin if scope == "repo" else None, "origin": "human:test", "status": "candidate",
            "payload": {"yaml": yaml_text, "role": role, "cls": cls, "rule_id": (rule or {}).get("id", "x"),
                        "target": target, "vulnerable_example": vuln, "fixed_example": fixed,
                        "origin_repo": origin, "site": site, "trigger": {"kind": "test"}}}


def _world(demo_inputs, repos=ALL, verifier=None) -> Scanner:
    st = Store()
    st.upsert_org("acme", "Acme")
    for r in repos:
        st.upsert_repo(r, "acme", r, str(DEMO / r))
    sc = Scanner(st, verifier=verifier or AbstainingVerifier())
    sc._inputs.update({r: v for r, v in demo_inputs.items() if r in repos})
    return sc


@pytest.fixture(scope="module")
def gate_world(demo_inputs):
    """All three repos scanned once. Gate previews do not mutate it; mutating tests use `world`."""
    sc = _world(demo_inputs)
    for r in ALL:
        sc.scan(r, refresh=r not in demo_inputs)
    return sc


@pytest.fixture
def world(gate_world):
    """A private copy of the scanned state (SQLite backup + the same extracted inputs)."""
    st = Store()
    gate_world.store.conn.backup(st.conn)
    sc = Scanner(st, verifier=AbstainingVerifier())
    sc._inputs.update(gate_world._inputs)
    sc.last.update(gate_world.last)
    return sc, Triage(sc)


def _row(store, repo, fn, cls):
    return store.one("SELECT * FROM findings WHERE repo_id=? AND source_fn LIKE ? AND cls=? AND is_open=1 "
                     "ORDER BY id LIMIT 1", repo, f"%.{fn}", cls)


# ── rule sanity (structural, no Semgrep) ─────────────────────────────────────────────────

def test_mock_proposals_are_well_formed():
    sink = _mock("sink", "cmdi", RUN_SHELL, "acme-billing", 0, "command")
    assert check_rule(sink.yaml, "sink", "cmdi")[1] == "pass"
    assert "focus-metavariable" in sink.yaml and "command=$X" in sink.yaml
    san = _mock("sanitizer", "sqli", QUOTE_SQL, "acme-shop")
    assert check_rule(san.yaml, "sanitizer", "sqli")[1] == "pass" and "quote_sql(value)" in san.fixed_example
    assert MockRuleSynthesizer().propose(RuleContext("sink", "sqli", "hashlib.sha256().hexdigest", "r", 0), None) == []


@pytest.mark.parametrize("text,why", [
    ("rules: [", "does not parse"),
    ("rules: []", "exactly one rule"),
    (yaml.safe_dump({"rules": [{"id": "a", "languages": ["python"], "pattern": "f()"}] * 2}), "exactly one rule"),
    (_rule({"pattern": "f($X)"}, "sink", "cmdi"), "focus"),
    (_rule({"pattern": "f(...)"}, "propagator", "cmdi"), "role"),
    (_rule({"pattern": "f(...)"}, "sanitizer", "nosuchclass"), "unknown sanitizer class"),
    (_rule({"mode": "taint", "pattern-sources": []}, "sink", "cmdi"), "search-mode"),
])
def test_structural_sanity_failures(text, why):
    _, verdict = parse_rule(text)
    assert verdict.startswith("fail") and why in verdict, verdict


def test_declared_role_must_match_item():
    assert "item says" in check_rule(_sink(f"{RUN_SHELL}($X, ...)"), "sink", "sqli")[1]


# ── the validation gate ──────────────────────────────────────────────────────────────────

def test_good_sink_rule_passes_every_gate(gate_world):
    p = _mock("sink", "cmdi", RUN_SHELL, "acme-billing", 0, "command")
    item = _item(p.yaml, "sink", "cmdi", p.vulnerable_example, p.fixed_example, "acme-billing", ARCHIVE_SITE, RUN_SHELL)
    rep = gate_world.preview(item)
    assert gate_passed(rep), rep
    assert rep["differential_detail"] == {"vulnerable_new_findings": 1, "fixed_open_findings": 0}
    assert rep["fp_budget"]["new_findings"] == [] and rep["canary"] == "pass"
    # acme-admin cannot see run_shell's body: the rule reveals backup (backup_safe is shlex-quoted, so not open).
    # shop and billing contain the body: no duplicate findings there.
    adds = {(i["repo"], i["source_fn"].rsplit(".", 1)[-1], i["from"], i["to"]) for i in rep["impact"]}
    assert adds == {("acme-admin", "backup", "absent", "confirmed")}
    assert rep["adds"] == 1 and rep["suppresses"] == 0 and not rep["over_budget"]
    assert rep["rule_matches"] == {"acme-shop": 0, "acme-billing": 2, "acme-admin": 2}


def test_semgrep_invalid_rule_is_rejected(gate_world):
    bad = _rule({"pattern": "run_shell(((("}, "sanitizer", "cmdi")
    assert parse_rule(bad)[1] == "pass"  # structurally fine; only Semgrep can tell
    rep = gate_world.preview(_item(bad, "sanitizer", "cmdi", "", "", "acme-billing", None))
    assert rep["sanity"].startswith("fail: Semgrep rejected the rule"), rep["sanity"]
    assert not gate_passed(rep)


def test_over_specific_rule_is_rejected_by_generalization(gate_world):
    imp = [f"from acme_common.shell import run_shell"]
    vuln = example_app(imp, ['run_shell("echo " + value)'])
    fixed = example_app(imp, ["if not value.isalnum():", "    abort(400)", 'run_shell("echo " + value)'])
    rule = _rule({"patterns": [{"pattern": f'{RUN_SHELL}("echo " + $X)'}, {"focus-metavariable": "$X"}]}, "sink", "cmdi")
    rep = gate_world.preview(_item(rule, "sink", "cmdi", vuln, fixed, "acme-billing", ARCHIVE_SITE, RUN_SHELL))
    assert rep["differential"] == "pass"  # it does catch its own example...
    assert rep["generalization"].startswith("fail") and "over-specific" in rep["generalization"]  # ...but not the real site


def test_over_broad_sink_rule_is_rejected_by_fp_budget(gate_world):
    p = _mock("sink", "cmdi", RUN_SHELL, "acme-billing", 0, "command")
    rep = gate_world.preview(_item(_sink("$F($X, ...)"), "sink", "cmdi", p.vulnerable_example, p.fixed_example,
                                   "acme-billing", ARCHIVE_SITE))
    assert rep["canary"].startswith("fail") and "budget" in rep["canary"], rep["canary"]
    assert len(rep["fp_budget"]["new_findings"]) > rep["fp_budget"]["budget"]
    assert not gate_passed(rep)


def test_over_broad_sanitizer_rule_is_rejected_by_canaries(gate_world):
    p = _mock("sanitizer", "all", QUOTE_SQL, "acme-shop")
    rep = gate_world.preview(_item(_rule({"pattern": "$F(...)"}, "sanitizer", "all"), "sanitizer", "all",
                                   p.vulnerable_example, p.fixed_example, "acme-shop", ORDER_SITE))
    assert rep["canary"].startswith("fail") and rep["canary_lost"], rep["canary"]
    assert rep["differential"].startswith("fail")  # it also hides the unsanitized flow


def test_good_sanitizer_rule_passes_and_reports_impact(gate_world):
    p = _mock("sanitizer", "sqli", QUOTE_SQL, "acme-shop")
    rep = gate_world.preview(_item(p.yaml, "sanitizer", "sqli", p.vulnerable_example, p.fixed_example, "acme-shop",
                                   ORDER_SITE, QUOTE_SQL))
    assert gate_passed(rep), rep
    assert rep["differential_detail"] == {"sanitized_open_without_rule": 1, "sanitized_mitigated_by_rule": 1,
                                          "unsanitized_open_with_rule": 1}
    hit = {(i["repo"], i["source_fn"].rsplit(".", 1)[-1], i["to"]) for i in rep["impact"]}
    assert {("acme-shop", "order_lookup", "mitigated"), ("acme-billing", "invoice_search", "mitigated"),
            ("acme-admin", "user_lookup", "mitigated")} <= hit


def test_patch_differential_rejects_a_pair_that_does_not_differ(gate_world):
    p = _mock("sink", "cmdi", RUN_SHELL, "acme-billing", 0, "command")
    # "fixed" example identical to the vulnerable one: the fix is not a fix
    rep = gate_world.preview(_item(p.yaml, "sink", "cmdi", p.vulnerable_example, p.vulnerable_example, "acme-billing",
                                   ARCHIVE_SITE, RUN_SHELL))
    assert rep["differential"].startswith("fail: the fixed example still has")
    # a vulnerable example the rule does not change (the sink is already curated)
    curated = example_app(["import os"], ["os.system('echo ' + value)"])
    rep = gate_world.preview(_item(p.yaml, "sink", "cmdi", curated, p.fixed_example, "acme-billing", ARCHIVE_SITE, RUN_SHELL))
    assert rep["differential"].startswith("fail: the vulnerable example has no new open")
    # sanitizer pair swapped: the "sanitized" variant does not use the sanitizer
    s = _mock("sanitizer", "sqli", QUOTE_SQL, "acme-shop")
    rep = gate_world.preview(_item(s.yaml, "sanitizer", "sqli", s.fixed_example, s.vulnerable_example, "acme-shop",
                                   ORDER_SITE, QUOTE_SQL))
    assert rep["differential"].startswith("fail: the sanitized example")


def test_sanitizer_rule_conflicting_with_a_confirmed_finding_is_blocked(world):
    sc, tr = world
    shop = _row(sc.store, "acme-shop", "order_lookup", "sqli")
    tr.decide(shop["id"], "confirmed", "human:alice")
    p = _mock("sanitizer", "sqli", QUOTE_SQL, "acme-shop")
    rep = sc.preview(_item(p.yaml, "sanitizer", "sqli", p.vulnerable_example, p.fixed_example, "acme-shop", ORDER_SITE))
    assert rep["canary"].startswith("fail: would suppress 1 human-confirmed")
    assert [c["fingerprint"] for c in rep["conflicts"]] == [shop["fingerprint"]]


# ── lifecycle in scans ───────────────────────────────────────────────────────────────────

def test_human_rule_activates_and_rescan_applies_it(world):
    sc, tr = world
    assert _row(sc.store, "acme-admin", "backup", "cmdi") is None  # cold: the helper body is invisible
    p = _mock("sink", "cmdi", RUN_SHELL, "acme-billing", 0, "command")
    item = sc.submit_rule("acme-billing", p.yaml, "sink", "cmdi", "org", "human:lead", p.vulnerable_example,
                          p.fixed_example, target=RUN_SHELL, site=ARCHIVE_SITE)
    assert item["id"].startswith("R-") and item["status"] == "active" and item["origin"] == "human:lead"
    assert item["payload"]["yaml"] == p.yaml and gate_passed(item["gate"])
    tr.rescan_scope(item)
    row = _row(sc.store, "acme-admin", "backup", "cmdi")
    assert row["lane"] == "confirmed" and row["data"]["spec_knowledge"] == [item["id"]]
    safe = _row(sc.store, "acme-admin", "backup_safe", "cmdi")
    assert safe["lane"] == "suppressed"  # shlex.quote still applies
    # billing contains run_shell's body: the rule adds no duplicate there
    assert sc.store.one("SELECT COUNT(*) AS n FROM findings WHERE repo_id='acme-billing' AND source_fn LIKE '%.archive' "
                        "AND is_open=1")["n"] == 1
    # retiring the rule removes what it found
    tr.set_knowledge(item["id"], "retired", "human:lead")
    assert _row(sc.store, "acme-admin", "backup", "cmdi") is None


def test_machine_rules_stay_shadow_and_are_only_evaluated(world):
    sc, tr = world
    before = sc.store.one("SELECT stats FROM scans WHERE repo_id='acme-admin' ORDER BY id DESC LIMIT 1")["stats"]["lanes"]
    lookup = _row(sc.store, "acme-admin", "user_lookup", "sqli")
    assert lookup["lane"] == "review" and lookup["shadow_by"] is None
    # human confirms a shop TP that reaches run_query -> synthesized sink rule (machine origin)
    search = _row(sc.store, "acme-shop", "search", "sqli")
    res = tr.decide(search["id"], "confirmed", "human:alice")
    [rule] = res["rules"]
    assert rule["status"] == "shadow" and rule["origin"] == "agent:mock-synth-v1" and rule["scope"] == "org"
    assert rule["args"] == ["learned.sink.sqli.acme_common.db.run_query", "sink", "sqli"]
    assert rule["payload"]["trigger"] == {"kind": "human_confirmed", "by": "human:alice"}
    assert rule["payload"]["site"]["file"] == "shop/catalog.py"
    links = sc.store.q("SELECT relation, finding_id, verdict_id FROM knowledge_links WHERE knowledge_id=?", rule["id"])
    assert links == [{"relation": "created_from", "finding_id": search["id"], "verdict_id": res["verdict_id"]}]
    # human marks a quote_sql finding not exploitable at org scope -> fact + sanitizer rule (shadow)
    order = _row(sc.store, "acme-shop", "order_lookup", "sqli")
    res2 = tr.decide(order["id"], "not_exploitable", "human:alice", "SANITIZED", {"fn": QUOTE_SQL})
    assert res2["knowledge"]["status"] == "active"
    [san] = res2["rules"]
    assert san["status"] == "shadow" and san["args"][1:] == ["sanitizer", "sqli"]
    # shadow rules change nothing in acme-admin, but are evaluated
    stats = sc.scan("acme-admin", refresh=False)
    assert stats["lanes"]["confirmed"] == before["confirmed"]
    shadow_new = {(s["knowledge"], s["source_fn"].rsplit(".", 1)[-1]) for s in stats["shadow_rule_findings"]}
    assert {(rule["id"], "user_search"), (rule["id"], "audit_log")} <= shadow_new
    assert _row(sc.store, "acme-admin", "user_search", "sqli") is None
    # user_lookup is now suppressed by the active fact; the shadow rule is reported, not applied
    assert _row(sc.store, "acme-admin", "user_lookup", "sqli")["lane"] == "suppressed"
    # approval activates the sink rule; a rescan then reports the flows it reveals
    tr.set_knowledge(rule["id"], "active", "human:lead")
    assert _row(sc.store, "acme-admin", "user_search", "sqli")["lane"] == "confirmed"


def test_shadow_sanitizer_rule_marks_findings_shadow_by(world):
    sc, tr = world
    order = _row(sc.store, "acme-shop", "order_lookup", "sqli")
    p = _mock("sanitizer", "sqli", QUOTE_SQL, "acme-shop")
    item = sc.ks.propose_rule({"yaml": p.yaml, "role": "sanitizer", "cls": "sqli", "rule_id": "learned.sanitizer.sqli.q",
                               "target": QUOTE_SQL, "vulnerable_example": p.vulnerable_example,
                               "fixed_example": p.fixed_example, "origin_repo": "acme-shop", "site": ORDER_SITE},
                              "org", "acme", "acme-shop", "agent:mock-synth-v1", 0.9, "t", order["id"])
    assert sc._gate_item(item["id"])["status"] == "shadow"
    sc.scan("acme-admin", refresh=False)
    assert _row(sc.store, "acme-admin", "user_lookup", "sqli")["shadow_by"] == item["id"]
    assert _row(sc.store, "acme-admin", "user_lookup", "sqli")["lane"] == "review"
    # SANITIZED at repo scope teaches the fact only, no rule
    bill = _row(sc.store, "acme-billing", "invoice_search", "sqli")
    res = tr.decide(bill["id"], "not_exploitable", "human:bob", "SANITIZED", {"fn": QUOTE_SQL}, scope="repo")
    assert res["knowledge"]["scope"] == "repo" and res["rules"] == []


def test_confirming_a_direct_sink_proposes_no_rule(world):
    sc, tr = world
    f = _row(sc.store, "acme-shop", "export_catalog", "cmdi")  # os.system in the route itself
    assert tr.decide(f["id"], "confirmed", "human:alice")["rules"] == []


def test_agent_verdicts_trigger_rule_synthesis(demo_inputs):
    from sentinel.agent.mock import MockVerifier
    sc = _world(demo_inputs, ["acme-shop", "acme-billing"], MockVerifier())
    for r in ("acme-shop", "acme-billing"):
        sc.scan(r, refresh=False)
    rules = {tuple(k["args"]): k for k in sc.store.q("SELECT * FROM knowledge WHERE pred='spec_rule'")}
    # gated agent FP on order_lookup proposed sanitizer_api(quote_sql) -> sanitizer rule
    san = rules[("learned.sanitizer.sqli.acme_common.db.quote_sql", "sanitizer", "sqli")]
    # gated agent TP on list_invoices (sink inside acme_common.db.run_query) -> sink rule
    sink = rules[("learned.sink.sqli.acme_common.db.run_query", "sink", "sqli")]
    for k in (san, sink):
        assert k["status"] == "shadow" and k["payload"]["trigger"]["kind"] == "agent_verdict" and gate_passed(k["gate"])
        assert sc.store.one("SELECT verdict_id FROM knowledge_links WHERE knowledge_id=?", k["id"])["verdict_id"]


# ── export ───────────────────────────────────────────────────────────────────────────────

def test_export_contains_curated_and_active_learned_rules_only(world, tmp_path):
    sc, tr = world
    p = _mock("sink", "cmdi", RUN_SHELL, "acme-billing", 0, "command")
    active = sc.submit_rule("acme-billing", p.yaml, "sink", "cmdi", "org", "human:lead", p.vulnerable_example,
                            p.fixed_example, target=RUN_SHELL, site=ARCHIVE_SITE)
    bad = sc.submit_rule("acme-billing", _sink("$F($X, ...)"), "sink", "cmdi", "org", "human:lead", p.vulnerable_example,
                         p.fixed_example, site=ARCHIVE_SITE)
    assert active["status"] == "active" and bad["status"] == "candidate"
    doc = yaml.safe_load(export_rules(sc.store, "acme"))
    ids = [r["id"] for r in doc["rules"]]
    assert "spec.sink.cmdi.os" in ids and materialize(active)["id"] in ids
    assert not any(bad["id"] in i for i in ids)
    learned = next(r for r in doc["rules"] if r["id"] == materialize(active)["id"])
    assert learned["metadata"]["sentinel"] == {"role": "sink", "cls": "cmdi", "cwe": "CWE-78", "knowledge": active["id"]}
    taint = yaml.safe_load(export_rules(sc.store, "acme", fmt="taint"))
    cmdi = next(r for r in taint["rules"] if r["id"] == "baseline.cmdi")
    assert cmdi["mode"] == "taint" and RUN_SHELL in yaml.safe_dump(cmdi["pattern-sinks"])
    # CLI
    from sentinel import cli
    out = tmp_path / "out.yml"
    db = tmp_path / "s.db"
    st = Store(db)
    st.upsert_org("acme", "Acme")
    cli.cmd_export_rules(type("A", (), {"db": str(db), "org": "acme", "repo": None, "format": "spec", "output": str(out)})())
    assert len(yaml.safe_load(out.read_text())["rules"]) == len(yaml.safe_load(export_rules(st, "acme"))["rules"])


def test_api_exports_rules_and_returns_payload(world):
    from fastapi.testclient import TestClient
    from sentinel.api.app import create_app
    sc, _ = world
    p = _mock("sink", "cmdi", RUN_SHELL, "acme-billing", 0, "command")
    client = TestClient(create_app(sc.store, sc))
    r = client.post("/api/rules", json={"repo": "acme-billing", "yaml": p.yaml, "role": "sink", "cls": "cmdi",
                                         "scope": "org", "vulnerable_example": p.vulnerable_example,
                                         "fixed_example": p.fixed_example, "target": RUN_SHELL, "site": ARCHIVE_SITE,
                                         "actor": "human:lead"})
    assert r.status_code == 200 and r.json()["status"] == "active" and r.json()["rescanned"]
    kid = r.json()["id"]
    exp = client.get("/api/rules/export", params={"org": "acme"})
    assert exp.status_code == 200 and exp.headers["content-type"].startswith("application/yaml")
    assert any(rule["id"].startswith(f"spec.learned.{kid}.") for rule in yaml.safe_load(exp.text)["rules"])
    assert client.get("/api/rules/export", params={"org": "acme", "format": "xml"}).status_code == 400
    k = next(x for x in client.get("/api/knowledge").json() if x["id"] == kid)
    assert k["payload"]["yaml"] == p.yaml and k["gate"]["differential"] == "pass" and k["applied_to"]


# ── storage ──────────────────────────────────────────────────────────────────────────────

def test_existing_database_gets_payload_column(tmp_path):
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE knowledge (id TEXT PRIMARY KEY, scope TEXT NOT NULL, org_id TEXT, repo_id TEXT, "
                "pred TEXT NOT NULL, args TEXT NOT NULL, status TEXT NOT NULL, origin TEXT NOT NULL, confidence REAL, "
                "rationale TEXT, gate TEXT NOT NULL DEFAULT '{}', corroborations INTEGER NOT NULL DEFAULT 0, "
                "created_at REAL NOT NULL, updated_at REAL NOT NULL)")
    con.execute("INSERT INTO knowledge VALUES ('K-001','org','acme',NULL,'sanitizer_api','[\"f\",\"sqli\"]','active',"
                "'human:a',1.0,'',  '{}', 1, 0, 0)")
    con.commit()
    con.close()
    st = Store(db)
    assert st.knowledge("K-001")["payload"] == {}
    assert st.next_knowledge_id() == "K-002" and st.next_knowledge_id("R") == "R-001"
    Store(db)  # idempotent
