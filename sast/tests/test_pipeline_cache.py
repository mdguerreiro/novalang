"""Unchanged code is never re-verified, and knowledge re-derivations are not counted as scans."""
from sentinel.eval import fresh_scanner


def test_rescan_reuses_agent_verdicts_and_tags_trigger():
    sc = fresh_scanner(repos=["acme-billing"])
    first = sc.scan("acme-billing")
    assert first["tier2_calls"] > 0 and first["trigger"] == "scan"
    n_verdicts = sc.store.one("SELECT COUNT(*) AS n FROM verdicts WHERE kind='agent'")["n"]

    second = sc.scan("acme-billing", refresh=False, trigger="knowledge")
    assert second["tier2_calls"] == 0
    # Every earlier agent call is either served from cache or no longer needed because knowledge
    # the agent proposed (e.g. not_sanitizer) is now active and the engine decides the finding itself.
    assert second["tier2_cache_hits"] + (second["decided"]["engine"] - first["decided"]["engine"]) == first["tier2_calls"]
    assert second["trigger"] == "knowledge"
    assert sc.store.one("SELECT COUNT(*) AS n FROM verdicts WHERE kind='agent'")["n"] == n_verdicts
    # Cached outcomes keep their lanes.
    assert second["lanes"] == first["lanes"]


def test_tier1_cache_respects_knowledge_scope():
    """A repo-scoped fact learned on one repository must never decide findings in another one."""
    from sentinel.eval import onboard
    sc = fresh_scanner(repos=["acme-billing"])
    item = sc.ks.propose("sanitizer_api", ["acme_common.db.quote_sql", "sqli"], "repo", "acme", "acme-billing",
                         "human:tester", 1.0, "billing only")
    sc.ks.set_status(item["id"], "active", "human:tester")
    onboard(sc, "acme-admin")
    sc.scan("acme-admin")
    row = sc.store.one("SELECT * FROM findings WHERE repo_id='acme-admin' AND source_fn LIKE '%.user_lookup' AND cls='sqli'")
    assert row is not None
    used = {kid for m in row["data"].get("mitigations", []) for kid in m.get("knowledge", [])}
    assert item["id"] not in used
