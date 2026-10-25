"""Datalog engine end-to-end on a small Flask corpus (one Semgrep run, shared by the module)."""
from __future__ import annotations

import pytest

from sentinel.engine.analyze import CURATED, KnowledgeFact, analyze
from sentinel.engine.datalog import Program, fact, term
from sentinel.extract.semgrep_specs import run_baseline

from conftest import findings_for, one_finding, scan_dir, write_repo

CORPUS = {
    "helpers.py": """
        import sqlite3


        def run_sql(q):
            sqlite3.connect("x").cursor().execute(q)


        def build(term):
            return "SELECT * FROM t WHERE a = '" + term + "'"
    """,
    "app.py": """
        import html
        import sqlite3

        import mylib
        from flask import Flask, abort, make_response, request

        from helpers import build, run_sql

        app = Flask(__name__)
        MODES = {"asc", "desc"}


        def cur():
            return sqlite3.connect("x").cursor()


        @app.route("/inter")
        def inter():
            q = request.args.get("q", "")
            run_sql(build(q))


        @app.route("/direct")
        def direct():
            q = request.args.get("q", "")
            cur().execute("SELECT * FROM t WHERE a = '" + q + "'")


        @app.route("/escaped")
        def escaped():
            q = html.escape(request.args.get("q", ""))
            cur().execute("SELECT * FROM t WHERE a = '" + q + "'")
            return make_response("<b>" + q + "</b>")


        @app.route("/guarded")
        def guarded():
            x = request.args.get("x", "")
            if not x.isdigit():
                abort(400)
            cur().execute("SELECT * FROM t WHERE id = " + x)


        @app.route("/allow")
        def allow():
            x = request.args.get("x", "")
            if x not in MODES:
                raise ValueError("bad")
            cur().execute("SELECT * FROM t ORDER BY a " + x)


        @app.route("/item/<int:item_id>")
        def item(item_id):
            cur().execute("SELECT * FROM t WHERE id = " + str(item_id))


        @app.route("/rebind")
        def rebind():
            x = request.args.get("x", "")
            x = int(x)
            cur().execute("SELECT * FROM t WHERE id = " + str(x))


        @app.route("/branch")
        def branch():
            x = request.args.get("x", "")
            if request.args.get("cast"):
                x = int(x)
            cur().execute("SELECT * FROM t WHERE id = " + str(x))


        @app.route("/unknown")
        def unknown():
            x = mylib.transform(request.args.get("x", ""))
            cur().execute("SELECT * FROM t WHERE a = '" + x + "'")


        def orphan():
            x = request.args.get("x", "")
            cur().execute("SELECT " + x)
    """,
}


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    root = write_repo(tmp_path_factory.mktemp("engine"), CORPUS)
    facts, matches, analysis = scan_dir(root)
    return root, facts, matches, analysis


def test_spec_matches_attach_to_nodes(corpus):
    _, facts, matches, _ = corpus
    roles = {m.role for m in matches}
    assert roles == {"source", "sink", "sanitizer"}
    assert all(m.node is not None and m.node in facts.nodes for m in matches)


def test_interprocedural_flow_found_where_semgrep_baseline_misses(corpus):
    root, facts, _, a = corpus
    f = one_finding(a, "inter", "sqli")
    assert f.status == "confirmed"
    assert f.sink_fn == "helpers.run_sql" and f.source_fn == "app.inter"
    kinds = [s.kind for s in f.path]
    assert kinds[0] == "source" and kinds[-1] == "sink" and "param" in kinds
    # Semgrep OSS taint mode (same specs) is intraprocedural: it sees `direct` but not `inter`.
    base = run_baseline(root, sorted(facts.files))
    inter_fn, direct_fn = facts.functions["app.inter"], facts.functions["app.direct"]
    lines = {(b.file, b.line) for b in base if b.cls == "sqli"}
    assert any(fl == "app.py" and direct_fn.line <= ln <= direct_fn.end_line for fl, ln in lines)
    assert not any(fl == "app.py" and inter_fn.line <= ln <= inter_fn.end_line for fl, ln in lines)
    assert not any(fl == "helpers.py" for fl, _ in lines)


def test_class_specific_sanitizer(corpus):
    a = corpus[3]
    sqli = one_finding(a, "escaped", "sqli")
    xss = one_finding(a, "escaped", "xss")
    assert sqli.status == "confirmed", "html escaping does not neutralise SQL injection"
    assert xss.status == "mitigated"
    assert [m["why"] for m in xss.mitigations] == ["spec.sanitizer.xss.escape"]


@pytest.mark.parametrize("fn,why,label,kid", [
    ("guarded", ["guard", "isdigit"], "Validation: isdigit()", "K-cur-isdigit"),
    ("allow", ["guard", "in_allowlist"], "Validation: allow-list check", "K-cur-allowlist"),
    ("item", ["type", "int"], "Type cast: int", "K-cur-int"),
])
def test_guard_and_type_mitigations_are_named(corpus, fn, why, label, kid):
    f = one_finding(corpus[3], fn, "sqli")
    assert f.status == "mitigated"
    assert f.mitigations == [{"why": why, "label": label, "knowledge": [kid]}]
    assert f.assumptions == []


def test_rebinding_and_branch_merge(corpus):
    a = corpus[3]
    rebind = one_finding(a, "rebind", "sqli")
    assert rebind.status == "mitigated"
    assert rebind.mitigations[0]["why"] == "spec.sanitizer.type-cast"
    assert one_finding(a, "branch", "sqli").status == "confirmed"


def test_unknown_library_call_is_undecided_with_assumption(corpus):
    a = corpus[3]
    f = one_finding(a, "unknown", "sqli")
    assert f.status == "undecided"
    assert {"asm": ["unknown_api", "mylib.transform"],
            "label": "Unmodelled call: mylib.transform"} in f.assumptions
    assert any(s.kind == "assumption" for s in f.path)


def test_knowledge_resolves_unknown_api(corpus):
    _, facts, matches, _ = corpus
    prop = analyze(facts, matches, [KnowledgeFact("K-x", "propagator_api", ("mylib.transform",))])
    assert one_finding(prop, "unknown", "sqli").status == "confirmed"
    san = analyze(facts, matches, [KnowledgeFact("K-y", "sanitizer_api", ("mylib.transform", "sqli"))])
    f = one_finding(san, "unknown", "sqli")
    assert f.status == "mitigated"
    assert f.mitigations[0]["why"] == ["api", "mylib.transform"] and f.mitigations[0]["knowledge"] == ["K-y"]
    # class-specific: an xss-only sanitizer is a modelled API that still carries sqli taint
    xss_only = analyze(facts, matches, [KnowledgeFact("K-z", "sanitizer_api", ("mylib.transform", "xss"))])
    assert one_finding(xss_only, "unknown", "sqli").status == "confirmed"


def test_unreachable_source_is_undecided(corpus):
    f = one_finding(corpus[3], "orphan", "sqli")
    assert f.status == "undecided"
    assert ["unreachable", "app.orphan"] in [x["asm"] for x in f.assumptions]
    dead = analyze(corpus[1], corpus[2], [KnowledgeFact("K-d", "dead_fn", ("app.orphan",))])
    g = one_finding(dead, "orphan", "sqli")
    assert g.status == "mitigated" and g.mitigations[0]["knowledge"] == ["K-d"]


def test_every_finding_has_exactly_one_status(corpus):
    a = corpus[3]
    assert {f.status for f in a.findings} <= {"confirmed", "undecided", "mitigated", "test_only"}
    for f in a.findings:
        if f.status == "mitigated":
            assert f.mitigations, f
        if f.status == "undecided":
            assert f.assumptions, f
        if f.status == "confirmed":
            assert not f.assumptions, f


def test_findings_carry_proof_tree_root(corpus):
    a = corpus[3]
    for f in a.findings:
        assert f.proof is not None
        head = f.proof["atom"].split("(", 1)[0]
        assert head == {"confirmed": "confirmed", "undecided": "undecided", "mitigated": "mitigated",
                        "test_only": "test_only"}[f.status]
        assert f.proof["atom"].startswith(f"{head}({f.source},{f.sink},")


def test_proof_tree_is_backed_by_derivations(corpus):
    a = corpus[3]
    derivs = a.model.derivations()
    for f in a.findings:
        assert f.proof["atom"] in derivs, f.proof["atom"]
        assert "rule" in f.proof and f.proof.get("children"), f.proof


def test_engine_derivations_exist_for_status_atoms(corpus):
    """The derivation graph itself is complete; only the lookup key above is wrong."""
    a = corpus[3]
    derivs = a.model.derivations()
    f = one_finding(a, "inter", "sqli")
    key = f'confirmed({f.source},{f.sink},"sqli")'
    assert key in derivs
    rid, pos, neg = derivs[key][0]
    assert a.model.rules[rid].head == "confirmed" and a.model.rules[rid].file == "decide.lp"
    assert any(p.startswith("open(") for p in pos)


def test_curated_knowledge_attribution():
    assert {k.kid for k in CURATED} >= {"K-cur-isdigit", "K-cur-int", "K-cur-allowlist", "K-cur-hostallow"}


# ── datalog layer ────────────────────────────────────────────────────────────────────────

RULES = """
reach(X) :- entry(X).
reach(Y) :- reach(X), edge(X,Y,_).
open(X)  :- reach(X), not safe_node(X,_).
safe_node(X,W) :- reach(X), guard(X,W).
"""


def test_program_instrumentation_with_anonymous_variables(tmp_path):
    rf = tmp_path / "r.lp"
    rf.write_text(RULES)
    prog = Program([rf])
    assert "fire(" in prog.text
    facts = [fact("entry", 1), fact("edge", 1, 2, "a"), fact("edge", 2, 3, "b"), fact("guard", 3, "g")]
    model = prog.solve(facts)
    assert sorted(model.get("reach")) == [(1,), (2,), (3,)]
    assert sorted(model.get("open")) == [(1,), (2,)]
    derivs = model.derivations()
    rid, pos, neg = derivs["reach(3)"][0]
    assert pos == ["reach(2)", 'edge(2,3,"b")'], "anonymous var is named and bound in the recorded premises"
    assert model.rules[rid].head == "reach" and model.rules[rid].file == "r.lp"
    rid2, pos2, neg2 = derivs["open(1)"][0]
    assert pos2 == ["reach(1)"] and neg2 == ["safe_node(1,any)"]
    # safe_node is not a provenance head: no fire atoms for it
    assert not any(k.startswith("safe_node(") for k in derivs)


def test_program_extra_rules_are_instrumented(tmp_path):
    rf = tmp_path / "r.lp"
    rf.write_text("reach(X) :- entry(X).")
    prog = Program([rf], extra_rules="kill(X,C,learned) :- reach(X), cls(C), not guard(X,_).")
    model = prog.solve([fact("entry", 7), fact("cls", "sqli")])
    assert ("kill(7,\"sqli\",learned)") in model.derivations()
    assert any(r.file == "<learned>" for r in prog.rules.values())


def test_default_rule_base_fires(corpus):
    a = corpus[3]
    assert a.model.fires
    heads = {a.model.rules[rid].head for rid, *_ in a.model.fires}
    assert {"cand", "alarm", "confirmed", "mitigated", "kill"} <= heads


def test_term_quoting():
    assert term("a\"b") == '"a\\"b"'
    assert term(3) == "3" and term(True) == "1"
    assert term(("guard", "isdigit")) == 'guard("isdigit")'
    assert fact("p") == "p." and fact("p", "x", 1) == 'p("x",1).'


def test_findings_deduplicated_by_fingerprint(corpus):
    a = corpus[3]
    fps = [f.fingerprint for f in a.findings]
    assert len(fps) == len(set(fps))
    assert len(findings_for(a, "inter", "sqli")) == 1


# ── soundness bugs found while writing the suite ─────────────────────────────────────────

def test_host_allowlist_does_not_survive_url_rebinding(tmp_path):
    root = write_repo(tmp_path, {"app.py": """
        from urllib.parse import urlparse
        import requests
        from flask import Flask, request

        app = Flask(__name__)
        ALLOWED = {"cdn.example"}

        @app.route("/stale")
        def stale():
            url = request.args.get("u", "")
            host = urlparse(url).hostname
            url = request.args.get("other", "")
            if host not in ALLOWED:
                raise ValueError("no")
            return requests.get(url).text
    """})
    _, _, a = scan_dir(root)
    f = findings_for(a, "stale", "ssrf")
    assert f and all(x.status != "mitigated" for x in f), [(x.status, x.mitigations) for x in f]


def test_chained_string_method_is_not_an_assumption(tmp_path):
    root = write_repo(tmp_path, {"app.py": """
        import requests
        from flask import Flask, request

        app = Flask(__name__)

        @app.route("/chained")
        def chained():
            url = request.args.get("u", "").strip()
            return requests.get(url).text
    """})
    _, _, a = scan_dir(root)
    f = one_finding(a, "chained", "ssrf")
    assert f.status == "confirmed", f.assumptions
