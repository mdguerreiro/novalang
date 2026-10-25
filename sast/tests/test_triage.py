"""Human triage -> knowledge -> rescan: the flywheel, impact preview and truth maintenance."""
from __future__ import annotations

import pytest

from sentinel.agent.interfaces import Verdict
from sentinel.pipeline import Scanner
from sentinel.store.db import Store
from sentinel.triage import Triage

from conftest import DEMO, REPOS

QUOTE_SQL = "acme_common.db.quote_sql"


class AbstainingVerifier:
    """Keeps Tier 2 out of the way so the human decision is the only thing that can learn."""
    name = "abstain"

    def verify(self, case, tools):
        return Verdict(case.fingerprint, "ABSTAIN", case.cls, None, [], [], {"k": 1, "agree": 1}, 0.0, "n/a", self.name)


@pytest.fixture
def world(demo_inputs):
    st = Store()
    st.upsert_org("acme", "Acme")
    for r in REPOS:
        st.upsert_repo(r, "acme", r, str(DEMO / r))
    sc = Scanner(st, verifier=AbstainingVerifier())
    sc._inputs.update(demo_inputs)  # reuse the session's extraction + Semgrep matches
    for r in REPOS:
        sc.scan(r, refresh=False)
    return sc, Triage(sc)


def _row(store, repo, fn, cls):
    return store.one("SELECT * FROM findings WHERE repo_id=? AND source_fn LIKE ? AND cls=?", repo, f"%.{fn}", cls)


def test_baseline_lanes(world):
    sc, _ = world
    assert _row(sc.store, "acme-shop", "order_lookup", "sqli")["lane"] == "review"
    assert _row(sc.store, "acme-billing", "invoice_search", "sqli")["lane"] == "review"
    assert _row(sc.store, "acme-shop", "search", "sqli")["lane"] == "confirmed"


def test_preview_reports_impact_without_committing(world):
    sc, tr = world
    f = _row(sc.store, "acme-shop", "order_lookup", "sqli")
    n_knowledge = sc.store.one("SELECT COUNT(*) AS n FROM knowledge")["n"]
    n_verdicts = sc.store.one("SELECT COUNT(*) AS n FROM verdicts")["n"]
    pv = tr.preview(f["id"], "SANITIZED", {"fn": QUOTE_SQL})
    assert pv["learns"] and pv["canary"] == "pass" and pv["sanity"] == "pass" and not pv["conflicts"]
    assert pv["knowledge"]["pred"] == "sanitizer_api" and pv["knowledge"]["args"] == [QUOTE_SQL, "sqli"]
    assert pv["knowledge"]["scope"] == "org"  # shared helper package -> org scope
    hit = {(i["repo"], i["finding"]["source_fn"].rsplit(".", 1)[-1], i["to"]) for i in pv["impact"]}
    assert hit == {("acme-shop", "order_lookup", "mitigated"), ("acme-billing", "invoice_search", "mitigated")}
    assert pv["suppresses"] == 2 and not pv["over_budget"]
    # nothing committed
    assert sc.store.one("SELECT COUNT(*) AS n FROM knowledge")["n"] == n_knowledge
    assert sc.store.one("SELECT COUNT(*) AS n FROM verdicts")["n"] == n_verdicts
    assert _row(sc.store, "acme-billing", "invoice_search", "sqli")["lane"] == "review"
    assert _row(sc.store, "acme-shop", "order_lookup", "sqli")["triage_state"] == "untriaged"


def test_preview_of_non_learning_reason(world):
    sc, tr = world
    f = _row(sc.store, "acme-shop", "order_lookup", "sqli")
    assert tr.preview(f["id"], "ACCEPTED_RISK", {}) == {"knowledge": None, "impact": [], "canary": "n/a", "learns": False}


def test_accepted_risk_learns_nothing(world):
    sc, tr = world
    f = _row(sc.store, "acme-shop", "order_lookup", "sqli")
    before = sc.store.q("SELECT id, status FROM knowledge ORDER BY id")
    res = tr.decide(f["id"], "accepted_risk", "human:alice", "ACCEPTED_RISK", {"fn": QUOTE_SQL})
    assert res["knowledge"] is None and res["rescanned"] == []
    assert sc.store.q("SELECT id, status FROM knowledge ORDER BY id") == before
    assert _row(sc.store, "acme-shop", "order_lookup", "sqli")["triage_state"] == "accepted_risk"
    assert _row(sc.store, "acme-billing", "invoice_search", "sqli")["lane"] == "review"


def test_flywheel_transfer_and_retraction(world):
    sc, tr = world
    f = _row(sc.store, "acme-shop", "order_lookup", "sqli")
    res = tr.decide(f["id"], "not_exploitable", "human:alice", "SANITIZED", {"fn": QUOTE_SQL})
    k = res["knowledge"]
    assert k["pred"] == "sanitizer_api" and k["args"] == [QUOTE_SQL, "sqli"]
    assert k["scope"] == "org" and k["origin"] == "human:alice" and k["status"] == "active"
    assert {r["repo"] for r in res["rescanned"]} == set(REPOS)

    # transfer: the other repo's finding through the same shared helper is now proven safe by the engine
    bill = _row(sc.store, "acme-billing", "invoice_search", "sqli")
    assert bill["lane"] == "suppressed" and bill["engine_status"] == "mitigated"
    assert any(k["id"] in m["knowledge"] for m in bill["data"]["mitigations"])
    shop = _row(sc.store, "acme-shop", "order_lookup", "sqli")
    assert shop["lane"] == "suppressed" and shop["triage_state"] == "not_exploitable"
    # unrelated true positives are untouched
    assert _row(sc.store, "acme-shop", "search", "sqli")["lane"] == "confirmed"
    assert _row(sc.store, "acme-billing", "list_invoices", "sqli")["lane"] != "suppressed"

    # truth maintenance: retiring the item re-opens everything it suppressed
    item = tr.set_knowledge(k["id"], "retired", "human:lead")
    assert item["status"] == "retired" and {r["repo"] for r in item["rescanned"]} == set(REPOS)
    bill = _row(sc.store, "acme-billing", "invoice_search", "sqli")
    assert bill["lane"] == "review" and bill["engine_status"] == "undecided"
    assert _row(sc.store, "acme-shop", "order_lookup", "sqli")["lane"] == "review"
    reopened = sc.store.q("SELECT finding_id FROM events WHERE type='finding.reopened_by_retraction' AND knowledge_id=?",
                          k["id"])
    assert f["id"] in {e["finding_id"] for e in reopened}


def test_human_tp_confirmation_blocks_conflicting_knowledge(world):
    sc, tr = world
    # A reviewer judged the shop's quote_sql use exploitable...
    shop = _row(sc.store, "acme-shop", "order_lookup", "sqli")
    tr.decide(shop["id"], "confirmed", "human:alice")
    # ...so another reviewer's "quote_sql sanitizes" in billing must not silently suppress it org-wide.
    bill = _row(sc.store, "acme-billing", "invoice_search", "sqli")
    pv = tr.preview(bill["id"], "SANITIZED", {"fn": QUOTE_SQL})
    assert [c["fingerprint"] for c in pv["conflicts"]] == [shop["fingerprint"]]
    assert pv["canary"].startswith("fail")
    res = tr.decide(bill["id"], "not_exploitable", "human:bob", "SANITIZED", {"fn": QUOTE_SQL})
    assert res["knowledge"]["status"] == "candidate" and res["rescanned"] == []
    assert _row(sc.store, "acme-shop", "order_lookup", "sqli")["lane"] == "review"
    assert _row(sc.store, "acme-billing", "invoice_search", "sqli")["lane"] == "review"
    with pytest.raises(ValueError):
        tr.set_knowledge(res["knowledge"]["id"], "active", "human:lead")


def test_triage_evidence_moves_posterior(world):
    sc, tr = world
    f = _row(sc.store, "acme-shop", "order_lookup", "sqli")
    before = f["posterior"]
    tr.decide(f["id"], "confirmed", "human:alice")
    assert _row(sc.store, "acme-shop", "order_lookup", "sqli")["posterior"] > before


def test_suggestions_offer_learnable_reason(world):
    sc, tr = world
    f = _row(sc.store, "acme-shop", "order_lookup", "sqli")
    sugg = tr.suggestions(f)
    assert {"reason": "SANITIZED", "detail": {"fn": QUOTE_SQL}, "label": "Sanitized: db.quote_sql"} in sugg
    assert any(s["reason"] == "ACCEPTED_RISK" for s in sugg)
