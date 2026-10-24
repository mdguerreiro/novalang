"""Knowledge lifecycle gates and Bingo-style Bayesian ranking."""
from __future__ import annotations

import pytest

from sentinel.engine.analyze import analyze
from sentinel.learn import bayes
from sentinel.learn.knowledge import KnowledgeService, Policy
from sentinel.store.db import Store

from conftest import one_finding

CLEAN = {"sanity": "pass", "canary": "pass", "impact": [], "conflicts": [], "suppresses": 0, "over_budget": False}


@pytest.fixture
def ks():
    st = Store()
    st.upsert_org("acme", "Acme")
    for r in ("r1", "r2", "r3"):
        st.upsert_repo(r, "acme", r, "/nonexistent")
    return KnowledgeService(st)


def _finding(store, repo, fp):
    return store.x("INSERT INTO findings(repo_id, fingerprint, cls, engine_status, lane) VALUES (?,?,?,?,?)",
                   repo, fp, "sqli", "undecided", "review")


def _item(pred, args, scope="global", origin="oracle:m"):
    return {"id": "T", "pred": pred, "args": list(args), "scope": scope, "origin": origin, "corroborations": 1}


# ── canary gate ──────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("pred,args", [
    ("sanitizer_api", ("os.path.join", "all")),
    ("safe_pred", ("regex:[a-z]+", "all")),
    ("sanitizer_api", ("*.strip", "all")),
])
def test_canary_gate_blocks_overbroad_items(ks, pred, args):
    report = ks.gate(_item(pred, args), {}, set(), lambda r, extra: None)
    assert report["canary"].startswith("fail"), report
    assert report["canary_lost"]
    assert ks.decide_status({**_item(pred, args), "origin": "human:alice"}, report, approved_by="human:alice") == "candidate"


def test_canary_gate_passes_narrow_item(ks):
    report = ks.gate(_item("sanitizer_api", ("acme_common.db.quote_sql", "sqli"), "org", "human:a"), {}, set(),
                     lambda r, extra: None)
    assert report["canary"] == "pass" and report["sanity"] == "pass"


def test_sanity_rejects_wildcards_and_global_all_class_from_agents(ks):
    r1 = ks.gate(_item("safe_pred", ("regex:.*", "sqli"), "org", "human:a"), {}, set(), lambda r, e: None)
    assert r1["sanity"].startswith("fail")
    r2 = ks.gate(_item("sanitizer_api", ("acme.lib.clean", "all"), "global", "agent:m"), {}, set(), lambda r, e: None)
    assert r2["sanity"].startswith("fail")


def test_human_confirmed_finding_blocks_item(ks, demo_inputs, demo_tier0):
    facts, matches = demo_inputs["acme-shop"]
    a = demo_tier0["acme-shop"]
    ping = one_finding(a, "ping", "cmdi")
    item = _item("dead_fn", ("shop.app.ping",), "repo", "human:bob")
    rerun = lambda repo, extra: analyze(facts, matches, extra)
    report = ks.gate(item, {"acme-shop": a}, {ping.fingerprint}, rerun)
    assert [c["fingerprint"] for c in report["conflicts"]] == [ping.fingerprint]
    assert report["canary"].startswith("fail: would suppress 1 human-confirmed")
    assert ks.decide_status(item, report, approved_by="human:bob") == "candidate"
    # without the human confirmation the same item is merely impactful
    free = ks.gate(item, {"acme-shop": a}, set(), rerun)
    assert free["canary"] == "pass" and free["suppresses"] == 1


# ── status decisions ─────────────────────────────────────────────────────────────────────

def test_machine_suppressing_item_stays_shadow_until_support(ks):
    st = ks.store
    item = ks.propose("sanitizer_api", ["acme.clean", "sqli"], "org", "acme", None, "agent:m", 0.9, "x",
                      finding_id=_finding(st, "r1", "f1"))
    assert ks.decide_status(item, CLEAN) == "shadow"
    ks.propose("sanitizer_api", ["acme.clean", "sqli"], "org", "acme", None, "agent:m", 0.9, "x",
               finding_id=_finding(st, "r1", "f2"))
    assert ks.decide_status(st.knowledge(item["id"]), CLEAN) == "shadow"
    ks.propose("sanitizer_api", ["acme.clean", "sqli"], "org", "acme", None, "agent:m", 0.9, "x",
               finding_id=_finding(st, "r2", "f3"))
    assert ks.support(item["id"]) == 3
    assert ks.decide_status(st.knowledge(item["id"]), CLEAN) == "active"
    # ...but never when the blast radius is over budget
    assert ks.decide_status(st.knowledge(item["id"]), {**CLEAN, "over_budget": True}) == "shadow"


def test_non_suppressing_machine_items_activate(ks):
    for pred, args in (("not_sanitizer", ["acme.wrap"]), ("propagator_api", ["mylib.transform"]),
                       ("not_safe_pred", ["regex:[a-z]+"])):
        item = ks.propose(pred, args, "global", None, None, "oracle:m", 0.9, "x")
        assert item["status"] == "candidate"
        assert ks.apply_gate(item["id"], CLEAN)["status"] == "active"


def test_human_items_activate_unless_over_budget(ks):
    item = ks.propose("sanitizer_api", ["acme.clean", "sqli"], "repo", "acme", "r1", "human:alice", 1.0, "x")
    assert ks.decide_status(item, CLEAN) == "active"
    assert ks.decide_status(item, {**CLEAN, "over_budget": True}) == "shadow"
    assert ks.decide_status(item, {**CLEAN, "over_budget": True}, approved_by="human:lead") == "active"


def test_oracle_support_counts_distinct_repos(ks):
    st = ks.store
    item = ks.propose("sanitizer_api", ["slugify.slugify", "all"], "global", None, None, "oracle:m", 0.93, "x")
    for i in range(4):
        st.link(item["id"], "corroborated_by", _finding(st, "r1", f"a{i}"))
    assert ks.support(item["id"]) == 1, "one oracle judgement reused in one repo is one piece of evidence"
    st.link(item["id"], "corroborated_by", _finding(st, "r2", "b"))
    assert ks.support(item["id"]) == 2
    assert ks.decide_status(st.knowledge(item["id"]), CLEAN) == "shadow"
    st.link(item["id"], "corroborated_by", _finding(st, "r3", "c"))
    assert ks.decide_status(st.knowledge(item["id"]), CLEAN) == "active"


def test_propose_validates_and_dedupes(ks):
    with pytest.raises(ValueError):
        ks.propose("sanitizer_api", ["only-one-arg"], "global", None, None, "human:a", 1.0, "x")
    with pytest.raises(ValueError):
        ks.propose("make_everything_safe", ["x"], "global", None, None, "human:a", 1.0, "x")
    a = ks.propose("dead_fn", ["m.f"], "repo", "acme", "r1", "human:a", 1.0, "x")
    b = ks.propose("dead_fn", ["m.f"], "repo", "acme", "r1", "human:a", 1.0, "x")
    assert a["id"] == b["id"] and b["corroborations"] == 1  # same origin, no new evidence
    c = ks.propose("dead_fn", ["m.f"], "repo", "acme", "r2", "human:a", 1.0, "x")
    assert c["id"] != a["id"], "repo scope is per repository"


def test_retired_items_are_not_regated_and_failed_canary_cannot_be_forced(ks):
    item = ks.propose("dead_fn", ["m.g"], "repo", "acme", "r1", "human:a", 1.0, "x")
    ks.set_status(item["id"], "retired", "human:a")
    assert ks.apply_gate(item["id"], CLEAN)["status"] == "retired"
    bad = ks.propose("sanitizer_api", ["os.path.join", "all"], "global", None, None, "oracle:m", 0.9, "x")
    ks.apply_gate(bad["id"], {**CLEAN, "canary": "fail: 1 canary finding(s) would be suppressed"})
    with pytest.raises(ValueError):
        ks.set_status(bad["id"], "active", "human:a")


def test_rescans_of_same_finding_are_not_independent_corroboration(ks):
    st = ks.store
    fid = _finding(st, "r1", "f1")
    for verdict_id in (1, 2, 3):  # the agent re-verifies the same finding on each scan
        item = ks.propose("sanitizer_api", ["acme.clean", "sqli"], "org", "acme", None, "agent:m", 0.9, "x",
                          finding_id=fid, verdict_id=verdict_id)
    assert ks.support(item["id"]) == 1
    assert ks.decide_status(st.knowledge(item["id"]), CLEAN) == "shadow"


# ── Bayesian ranking ─────────────────────────────────────────────────────────────────────

def _net(evidence_a=None):
    net = bayes.Network()
    spec = {
        "A": bayes.hypotheses_for("http", "http:app.a", "spec.sink.sqli", "lib.helper", "app.a",
                                  [["maybe_sanitizer", "lib.escape"]]),
        "B": bayes.hypotheses_for("http", "http:app.b", "spec.sink.sqli", "lib.helper", "app.b",
                                  [["maybe_sanitizer", "lib.escape"]]),
        "C": bayes.hypotheses_for("cookie", "cookie:app.c", "spec.sink.cmdi", "app.c", "app.c",
                                  [["unknown_api", "other.lib"]]),
    }
    for fid, hs in spec.items():
        for h, p in hs:
            net.add_hypothesis(h, p)
        net.findings.append(bayes.BayesFinding(fid, [h for h, _ in hs], evidence_a if fid == "A" else None))
    return net


def test_hypotheses_cover_source_sink_summary_and_assumptions():
    hs = dict(bayes.hypotheses_for("cli", "cli:t", "r", "helper", "src", [["unknown_api", "x.y"]]))
    assert hs == {"src:cli:t": 0.35, "sink:r": 0.95, "summ:helper": 0.97, "asm:unknown_api:x.y": 0.55}


def test_fp_verdict_lowers_related_and_spares_unrelated():
    base = bayes.posteriors(_net())
    fp = bayes.posteriors(_net(evidence_a=0.01))
    assert fp["A"] < base["A"]
    assert fp["B"] < base["B"] - 0.05, (base, fp)
    assert fp["C"] == pytest.approx(base["C"], abs=1e-9)


def test_tp_verdict_raises_related():
    base = bayes.posteriors(_net())
    tp = bayes.posteriors(_net(evidence_a=0.99))
    assert tp["B"] > base["B"] + 0.05, (base, tp)
    assert tp["C"] == pytest.approx(base["C"], abs=1e-9)


def test_related_groups_by_shared_hypothesis_excluding_sinks():
    rel = bayes.related(_net(), "A")
    assert rel == {"summ:lib.helper": ["B"], "asm:maybe_sanitizer:lib.escape": ["B"]}
    assert bayes.related(_net(), "C") == {}
