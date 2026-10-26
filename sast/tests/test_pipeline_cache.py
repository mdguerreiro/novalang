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


def test_oracle_class_lists_collapse_to_all():
    from sentinel.agent.interfaces import ApiLabel
    from sentinel.engine.analyze import CWE

    class EnumeratingOracle:
        name = "enum"

        def classify_api(self, api, usage):
            return ApiLabel(api, "sanitizer", sorted(CWE), 0.9, "hex output", "enum")

        def judge_guard(self, pred, source):
            raise AssertionError("not used")

    sc = fresh_scanner(repos=["acme-shop"])
    sc.oracle = EnumeratingOracle()
    sc.scan("acme-shop")
    rows = sc.store.q("SELECT args FROM knowledge WHERE pred='sanitizer_api' AND json_extract(args, '$[0]')='slugify.slugify'")
    assert [r["args"] for r in rows] == [["slugify.slugify", "all"]]


def test_same_code_in_another_repo_reuses_agent_verdicts(tmp_path):
    """A fork / branch / snapshot of a repository already verified in the org costs no new agent runs."""
    import shutil
    from sentinel.eval import DEMO
    sc = fresh_scanner(repos=["acme-billing"])
    first = sc.scan("acme-billing")
    assert first["tier2_calls"] > 0
    copy = tmp_path / "acme-billing-fork"
    shutil.copytree(DEMO / "acme-billing", copy)
    sc.store.upsert_repo("acme-billing-fork", "acme", "acme-billing-fork", str(copy))
    second = sc.scan("acme-billing-fork")
    assert second["tier2_calls"] == 0 and second["tier2_cache_hits"] > 0
