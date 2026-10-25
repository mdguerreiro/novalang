"""Tier-0 decisions on the demo corpus against ground truth, and the staged evaluation harness."""
from __future__ import annotations

import pytest

from conftest import REPOS, short

REPORTED = ("confirmed", "undecided")


@pytest.fixture(scope="module")
def tier0_by_key(demo_tier0):
    out = {}
    for repo, a in demo_tier0.items():
        for f in a.findings:
            key = (repo, short(f.source_fn), f.cls)
            assert key not in out, f"duplicate finding for {key}"
            out[key] = f
    return out


def test_every_finding_is_labelled(tier0_by_key, ground_truth):
    assert set(tier0_by_key) <= set(ground_truth), sorted(set(tier0_by_key) - set(ground_truth))


def test_no_flow_entries_produce_no_finding(tier0_by_key, ground_truth):
    no_flow = [k for k, e in ground_truth.items() if e.get("expect_flow") is False]
    assert no_flow
    for k in no_flow:
        assert k not in tier0_by_key, k


def test_tier0_recall_is_complete(tier0_by_key, ground_truth):
    tps = {k for k, e in ground_truth.items() if e["label"] == "tp"}
    reported = {k for k, f in tier0_by_key.items() if f.status in REPORTED}
    assert tps <= reported, sorted(tps - reported)


def test_confirmed_are_exactly_the_assumption_free_tps(tier0_by_key, ground_truth):
    tps = {k for k, e in ground_truth.items() if e["label"] == "tp"}
    confirmed = {k for k, f in tier0_by_key.items() if f.status == "confirmed"}
    tps_needing_assumptions = {k for k in tps if tier0_by_key[k].assumptions}
    assert confirmed == tps - tps_needing_assumptions
    # current behaviour: the two TPs behind sanitizer-looking helpers stay undecided for the neural tiers
    assert tps_needing_assumptions == {("acme-billing", "list_invoices", "sqli"), ("acme-billing", "attachment", "path")}
    assert {a["asm"][0] for k in tps_needing_assumptions for a in tier0_by_key[k].assumptions} == {"maybe_sanitizer"}


def test_mitigated_are_all_false_positives_with_reasons(tier0_by_key, ground_truth):
    mitigated = {k: f for k, f in tier0_by_key.items() if f.status == "mitigated"}
    assert all(ground_truth[k]["label"] == "fp" for k in mitigated)
    expected = {
        ("acme-shop", "product", "sqli"): ["type", "int"],
        ("acme-shop", "user_profile", "sqli"): ["guard", "isdigit"],
        ("acme-shop", "thumbnail", "path"): "spec.sanitizer.path.basename",
        ("acme-shop", "hello", "xss"): "spec.sanitizer.xss.escape",
        ("acme-shop", "avatar", "ssrf"): ["guard", "host_allowlist"],
        ("acme-shop", "sales_report", "sqli"): "spec.sanitizer.type-cast",
        ("acme-billing", "invoice", "sqli"): ["type", "int"],
        ("acme-billing", "statements", "path"): ["guard", "isalnum"],
    }
    assert {k: f.mitigations[0]["why"] for k, f in mitigated.items()} == expected


def test_undecided_fps_carry_the_assumption_the_neural_tier_must_resolve(tier0_by_key):
    asm = {k: sorted(a["asm"][0] for a in f.assumptions) for k, f in tier0_by_key.items()
           if f.status == "undecided"}
    assert asm[("acme-shop", "coupon", "sqli")] == ["unknown_api", "unknown_api"]
    assert asm[("acme-shop", "category", "sqli")] == ["unknown_api"]
    assert asm[("acme-shop", "order_lookup", "sqli")] == ["maybe_sanitizer"]
    assert asm[("acme-shop", "legacy_debug_console", "code")] == ["unreachable"]
    for fn, cls in (("invoice_by_plan", "sqli"), ("invoice_pdf", "cmdi"), ("invoice_pdf", "path")):
        assert asm[("acme-billing", fn, cls)] == ["unknown_guard"]


def test_test_code_is_test_only(tier0_by_key):
    assert tier0_by_key[("acme-shop", "test_replay_fixture", "cmdi")].status == "test_only"


def test_confirmed_findings_have_witness_path(tier0_by_key):
    for k, f in tier0_by_key.items():
        if f.status == "confirmed" and f.source != f.sink:  # import_legacy: the source *is* the sink argument
            assert f.path[0].kind == "source" and f.path[-1].kind == "sink", k
            assert not any(s.kind == "sanitizer" for s in f.path), k


def test_interprocedural_tps_cross_functions(tier0_by_key):
    for k in [("acme-shop", "search", "sqli"), ("acme-shop", "link_preview", "ssrf"),
              ("acme-billing", "webhook_test", "ssrf"), ("acme-billing", "list_invoices", "sqli")]:
        f = tier0_by_key[k]
        assert f.sink_fn != f.source_fn, k


# ── evaluation harness ───────────────────────────────────────────────────────────────────

def _stage(results, prefix):
    return next(v for k, v in results["stages"].items() if k.startswith(prefix))


def test_eval_stage_scores(eval_results):
    s0, s1, s3 = (_stage(eval_results, p) for p in ("S0", "S1", "S3"))
    assert s3["precision"] == 1.0 and s3["recall"] == 1.0, s3
    assert s0["recall"] < 1.0
    assert s1["recall"] == 1.0
    assert s1["precision"] < s3["precision"]
    s2 = _stage(eval_results, "S2")
    assert s1["precision"] <= s2["precision"] <= s3["precision"]


def test_eval_baseline_misses_interprocedural_tps(eval_results):
    missed = set(_stage(eval_results, "S0")["missed"])
    assert {"acme-shop/search/sqli", "acme-shop/link_preview/ssrf", "acme-billing/webhook_test/ssrf",
            "acme-billing/list_invoices/sqli"} <= missed


def test_eval_ai_never_suppresses_a_true_positive(eval_results):
    assert eval_results["ai_suppression"]["wrongly_suppressed_tps"] == []
    assert eval_results["ai_suppression"]["suppressed"] > 0


def test_eval_flywheel_transfer(eval_results):
    fw = eval_results["flywheel"]
    cold, warm = fw["acme-billing cold (no shop knowledge)"], fw["acme-billing warm (after shop review)"]
    assert warm["tier0_rate"] > cold["tier0_rate"]
    assert warm["tier2_calls"] < cold["tier2_calls"]
    assert warm["resolved_by_learned_knowledge"] >= 1
    p = fw["acme-billing warm precision/recall"]
    assert p["precision"] == 1.0 and p["recall"] == 1.0
    shop2 = fw["acme-shop scan 2 (after review)"]
    assert shop2["tier0_rate"] == 1.0 and shop2["tier2_calls"] == 0
    assert set(REPOS) == {"acme-shop", "acme-billing"}


def test_eval_spec_rules_on_a_repo_without_the_helper_source(eval_results):
    """S5: acme-admin installs acme_common, so the engine cannot see the helper bodies. Cold it misses every
    flow through run_shell / run_query / fetch; with the rules learned on shop + billing it finds them, and
    quote_sql's sanitizer knowledge keeps its uses suppressed."""
    s5 = eval_results["spec_rules"]
    cold = s5["acme-admin cold (no org knowledge)"]["score"]
    assert (cold["tp"], cold["fp"], cold["fn"]) == (1, 1, 4)
    assert set(cold["missed"]) == {"acme-admin/backup/cmdi", "acme-admin/user_search/sqli", "acme-admin/audit_log/sqli",
                                   "acme-admin/health_probe/ssrf"}
    assert cold["false_alarms"] == ["acme-admin/user_lookup/sqli"]
    warm = s5["acme-admin warm (after review, rules approved)"]
    assert (warm["score"]["tp"], warm["score"]["fp"], warm["score"]["fn"]) == (5, 0, 0) and warm["score"]["unlabeled"] == []
    assert warm["tier2_calls"] == 0 and warm["found_by_learned_rules"] >= 4
    rules = {r["rule"]: r for r in s5["learned spec rules"]}
    assert {"learned.sink.cmdi.acme_common.shell.run_shell", "learned.sink.sqli.acme_common.db.run_query",
            "learned.sink.ssrf.acme_common.net.fetch", "learned.sanitizer.sqli.acme_common.db.quote_sql"} <= set(rules)
    assert all(r["status"] == "active" and set(r["gates"].values()) == {"pass"} for r in rules.values())
    decisions = s5["acme-admin warm decisions"]
    san = rules["learned.sanitizer.sqli.acme_common.db.quote_sql"]["id"]
    assert decisions["user_lookup/sqli"]["status"] == "mitigated" and san in decisions["user_lookup/sqli"]["knowledge"]
    assert decisions["user_by_ref/sqli"]["status"] == "mitigated"
    assert decisions["backup_safe/cmdi"]["status"] == "mitigated"  # shlex.quote, seen at the rule's call site
    # The same rules exported to plain Semgrep: the helper sinks and the sanitizer work there too.
    oss, exported = s5["acme-admin Semgrep OSS, curated pack"], s5["acme-admin Semgrep OSS, exported pack (curated + learned)"]
    assert (oss["tp"], oss["fp"]) == (1, 1) and (exported["tp"], exported["fp"], exported["fn"]) == (4, 0, 1)
    assert exported["missed"] == ["acme-admin/audit_log/sqli"]  # interprocedural: Semgrep OSS cannot follow it
