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
