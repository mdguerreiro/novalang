"""Symbolic gates around agent verdicts, and the deterministic spec oracle."""
from __future__ import annotations

from dataclasses import asdict

import pytest

from sentinel.agent.interfaces import Citation, Claim, Verdict, VerificationCase
from sentinel.agent.mock import MockSpecOracle, MockVerifier
from sentinel.agent.orchestrator import Tools, gate
from sentinel.engine.analyze import analyze

from conftest import one_finding

QUOTE_SQL = "acme_common.db.quote_sql"


@pytest.fixture(scope="module")
def shop(demo_inputs, demo_tier0):
    facts, matches = demo_inputs["acme-shop"]
    return facts, matches, demo_tier0["acme-shop"]


@pytest.fixture
def tools(shop):
    facts, matches, a = shop
    return Tools(facts, a, lambda extra: analyze(facts, matches, extra))


def _cite(tools, qname):
    file, l1, l2, _text, sha = tools.function_source(qname)
    return Citation(file, l1, l2, sha)


def _verdict(fp, kind, cls, claims, agree=5, k=5, reason=None):
    return Verdict(fp, kind, cls, reason, claims, [], {"k": k, "agree": agree, "dissent": []}, 0.9, "test", "test-model")


def _san_claim(tools, fact=True, cite=None):
    return Claim("c1", "sanitizer", "quote_sql escapes quotes", cite or _cite(tools, QUOTE_SQL),
                 {"pred": "sanitizer_api", "args": [QUOTE_SQL, "sqli"]} if fact else None)


def _checks(res, name):
    return [c for c in res.checks if c["gate"] == name]


def test_valid_fp_with_discharging_fact_is_accepted(shop, tools):
    f = one_finding(shop[2], "order_lookup", "sqli")
    assert f.status == "undecided"
    res = gate(_verdict(f.fingerprint, "FALSE_POSITIVE", "sqli", [_san_claim(tools)], reason="SANITIZED"), tools)
    assert res.accepted and res.lane == "suppressed_ai"
    assert all(c["ok"] for c in res.checks)
    assert {c["gate"] for c in res.checks} == {"citation", "votes", "discharge"}


def test_tampered_citation_is_rejected(shop, tools):
    f = one_finding(shop[2], "order_lookup", "sqli")
    good = _cite(tools, QUOTE_SQL)
    bad = Citation(good.file, good.l1, good.l2, "0" * 64)
    res = gate(_verdict(f.fingerprint, "FALSE_POSITIVE", "sqli", [_san_claim(tools, cite=bad)]), tools)
    assert not res.accepted and res.lane == "review"
    assert _checks(res, "citation")[0]["ok"] is False
    assert "hash mismatch" in _checks(res, "citation")[0]["detail"]


def test_fp_without_checkable_fact_is_rejected(shop, tools):
    f = one_finding(shop[2], "order_lookup", "sqli")
    res = gate(_verdict(f.fingerprint, "FALSE_POSITIVE", "sqli", [_san_claim(tools, fact=False)]), tools)
    assert not res.accepted and res.lane == "review"
    assert _checks(res, "discharge")[0]["ok"] is False
    assert "no checkable fact" in _checks(res, "discharge")[0]["detail"]


def test_fp_vote_split_is_rejected(shop, tools):
    f = one_finding(shop[2], "order_lookup", "sqli")
    res = gate(_verdict(f.fingerprint, "FALSE_POSITIVE", "sqli", [_san_claim(tools)], agree=4), tools)
    assert not res.accepted and res.lane == "review"
    assert _checks(res, "votes")[0]["ok"] is False
    assert _checks(res, "discharge")[0]["ok"] is True  # only the vote gate fails


def test_fp_whose_fact_does_not_discharge_is_rejected(shop, tools):
    f = one_finding(shop[2], "order_lookup", "sqli")
    wrong_cls = Claim("c1", "sanitizer", "quote_sql is an xss sanitizer", _cite(tools, QUOTE_SQL),
                      {"pred": "sanitizer_api", "args": [QUOTE_SQL, "xss"]})
    res = gate(_verdict(f.fingerprint, "FALSE_POSITIVE", "sqli", [wrong_cls]), tools)
    assert not res.accepted
    assert "not re-derived" in _checks(res, "discharge")[0]["detail"]


def test_tp_whose_own_facts_mitigate_is_rejected(shop, tools):
    f = one_finding(shop[2], "order_lookup", "sqli")
    res = gate(_verdict(f.fingerprint, "TRUE_POSITIVE", "sqli", [_san_claim(tools)]), tools)
    assert not res.accepted and res.lane == "review"
    assert _checks(res, "alarm")[0]["ok"] is True
    assert _checks(res, "discharge")[0]["ok"] is False


def test_tp_on_confirmed_flow_is_accepted_with_majority(shop, tools):
    f = one_finding(shop[2], "search", "sqli")
    assert gate(_verdict(f.fingerprint, "TRUE_POSITIVE", "sqli", [], agree=3), tools).lane == "confirmed"
    assert not gate(_verdict(f.fingerprint, "TRUE_POSITIVE", "sqli", [], agree=2), tools).accepted


def test_tp_without_engine_alarm_is_rejected(shop, tools):
    f = one_finding(shop[2], "user_profile", "sqli")
    assert f.status == "mitigated"
    res = gate(_verdict(f.fingerprint, "TRUE_POSITIVE", "sqli", []), tools)
    assert not res.accepted and _checks(res, "alarm")[0]["ok"] is False


def test_never_auto_suppress_policy(shop, tools):
    f = one_finding(shop[2], "order_lookup", "sqli")
    v = _verdict(f.fingerprint, "FALSE_POSITIVE", "sqli", [_san_claim(tools)])
    res = gate(v, tools, never_auto_suppress={"sqli"})
    assert not res.accepted and res.lane == "review"
    assert _checks(res, "policy")[0]["ok"] is False
    assert gate(v, tools, never_auto_suppress={"xss"}).accepted


def test_abstain_and_needs_human_route_to_review(shop, tools):
    f = one_finding(shop[2], "order_lookup", "sqli")
    for kind in ("ABSTAIN", "NEEDS_HUMAN"):
        res = gate(_verdict(f.fingerprint, kind, "sqli", []), tools)
        assert not res.accepted and res.lane == "review"


def test_what_if_reports_changes_without_mutating_analysis(shop, tools):
    f = one_finding(shop[2], "order_lookup", "sqli")
    out = tools.what_if([{"pred": "sanitizer_api", "args": [QUOTE_SQL, "sqli"]}])
    assert {"fingerprint": f.fingerprint, "from": "undecided", "to": "mitigated"} in out["changed"]
    assert one_finding(shop[2], "order_lookup", "sqli").status == "undecided"


def test_mock_verifier_dead_code_verdict_passes_gates(shop, tools):
    f = one_finding(shop[2], "legacy_debug_console", "code")
    case = VerificationCase(f.fingerprint, "acme-shop", f.cls, f.title, f.status, f.assumptions,
                            [asdict(s) for s in f.path], f.source_fn, f.sink_fn, f.proof)
    v = MockVerifier().verify(case, tools)
    assert v.verdict == "FALSE_POSITIVE" and v.reason_code == "UNREACHABLE"
    assert gate(v, tools).accepted


# ── MockSpecOracle.judge_guard ───────────────────────────────────────────────────────────

def test_judge_guard_anchored_fullmatch_is_safe_for_all():
    src = 'SLUG_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")\ndef is_safe_slug(v):\n    return SLUG_RE.fullmatch(v) is not None\n'
    lab = MockSpecOracle().judge_guard("call:acme_common.validators.is_safe_slug", src)
    assert lab.safe_for == ["all"]


def test_judge_guard_caret_dollar_regex_is_safe_for_all():
    lab = MockSpecOracle().judge_guard("regex:^[a-z]+$", 're.match(r"^[a-z]+$", name)')
    assert lab.safe_for == ["all"]


def test_judge_guard_unanchored_match_is_not_safe():
    lab = MockSpecOracle().judge_guard("regex:[a-z]+", 're.match(r"[a-z]+", name)')
    assert lab.safe_for == []
    assert lab.confidence >= 0.8  # confident enough to become not_safe_pred


def test_judge_guard_permissive_anchored_regex_is_class_limited():
    lab = MockSpecOracle().judge_guard("regex:^[a-z./]+$", 're.fullmatch(r"^[a-z./]+$", p)')
    assert "path" not in lab.safe_for and "all" not in lab.safe_for
    assert "sqli" in lab.safe_for


def test_judge_guard_without_regex_abstains():
    lab = MockSpecOracle().judge_guard("call:x.check", "def check(v):\n    return len(v) < 10\n")
    assert lab.safe_for == [] and lab.confidence < 0.8


def test_classify_api_known_and_unknown():
    o = MockSpecOracle()
    assert o.classify_api("slugify.slugify", "").role == "sanitizer"
    assert o.classify_api("hashlib.sha512().hexdigest", "").classes == ["all"]
    assert o.classify_api("mylib.transform", "").role == "unknown"
