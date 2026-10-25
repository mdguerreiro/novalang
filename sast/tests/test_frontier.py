"""Recall: frontier inference, symbolic call resolution, missing authorization, pull-request scans."""
import textwrap
from pathlib import Path

from sentinel.engine.analyze import CURATED, analyze
from sentinel.eval import lanes_reported, run_authz, run_diff, run_frontier, score
from sentinel.extract.python_facts import extract
from sentinel.extract.semgrep_specs import match_specs


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src))
    return root


def test_frontier_finds_unmodelled_sinks_and_transfers():
    r = run_frontier()
    rep, etl = r["acme-reports"], r["acme-etl"]
    assert rep["Semgrep OSS"]["tp"] == 0 and rep["engine without frontier"]["tp"] == 0
    assert rep["engine with frontier"]["recall"] == 1.0 and rep["engine with frontier"]["fp"] == 0
    assert rep["frontier"]["questions"] <= 12
    # The second repository only asks about what the first did not teach.
    assert etl["engine with frontier"]["recall"] == 1.0 and etl["engine with frontier"]["fp"] == 0
    assert sorted(etl["frontier"]["subjects"]) == ["dill.loads", "etl.api.archive"]


def test_script_style_import_and_orm_base_resolution(tmp_path):
    root = _write(tmp_path, {
        "app/libuser.py": """
            import sqlite3
            def login(name):
                return sqlite3.connect("x").cursor().execute("SELECT * FROM u WHERE n = '%s'" % name)
        """,
        "app/web.py": """
            from flask import Flask, request
            from flask_sqlalchemy import SQLAlchemy
            import libuser
            app = Flask(__name__)
            db = SQLAlchemy()
            class User(db.Model):
                pass
            @app.route("/login")
            def do_login():
                return str(libuser.login(request.args["n"]))
            @app.route("/u")
            def find():
                return str(User.query.filter_by(name=request.args["n"]).first())
        """})
    f = extract(root)
    assert ("app.web.do_login" in {f.nodes[k].fn for k, g in f.calls if g == "app.libuser.login"})
    assert "flask_sqlalchemy.SQLAlchemy().Model.query.filter_by" in set(f.libcalls.values())
    a = analyze(f, match_specs(root, f))
    assert any(x.cls == "sqli" and x.source_fn == "app.web.do_login" and x.status == "confirmed" for x in a.findings)


def test_registrar_frontier_covers_all_handlers(tmp_path):
    root = _write(tmp_path, {
        "svc/views.py": """
            import os
            async def run(request):
                os.system(request.query["cmd"])
            async def ping(request):
                os.system("ping " + request.query["host"])
        """,
        "svc/routes.py": """
            from svc import views
            def setup(app):
                app.router.add_route("GET", "/run", views.run)
                app.router.add_route("GET", "/ping", views.ping)
        """})
    f = extract(root)
    a = analyze(f, match_specs(root, f))
    assert sorted(set(a.model.get("reg_frontier"))) == [("*.add_route", 2)]
    from sentinel.engine.analyze import KnowledgeFact
    b = analyze(f, match_specs(root, f), [KnowledgeFact("K1", "registrar", ("*.add_route", 2))])
    assert {x.source_fn for x in b.findings if x.status == "confirmed"} == {"svc.views.run", "svc.views.ping"}


def test_idor_statuses():
    root = Path(__file__).resolve().parents[1] / "demo" / "acme-docs"
    f = extract(root)
    by = {x.source_fn.rsplit(".", 1)[-1]: x for x in analyze(f, match_specs(root, f), list(CURATED)).findings}
    # The engine proposes IDOR candidates but never confirms one alone (authorization may live elsewhere).
    assert by["get_document"].status == "undecided" and by["comment_raw"].status == "undecided"
    assert by["get_document_checked"].status == "mitigated" and by["delete_comment"].status == "mitigated"
    assert by["get_invoice"].mitigations[0]["label"] == "Query scoped to current user"
    assert by["admin_invoice"].status == "undecided" and "get_product" not in by
    r = run_authz()
    assert r["engine + oracle + verifier"]["precision"] == 1.0 and r["engine + oracle + verifier"]["recall"] == 1.0
    assert r["Semgrep OSS"]["tp"] == 0


def test_pull_request_scan_reports_only_what_the_diff_adds():
    r = run_diff()
    assert sorted(x.split(" ")[0] for x in r["new_findings"]) == sorted(r["expected_new"])
    assert r["frontier_subjects"] == ["PIL.ImageMath.eval"]


def test_same_rule_text_is_corroboration():
    from sentinel.learn.knowledge import KnowledgeService
    from sentinel.store.db import Store
    st = Store()
    st.upsert_org("acme", "Acme")
    ks = KnowledgeService(st)
    y = "rules:\n- id: {id}\n  languages: [python]\n  message: m\n  severity: INFO\n  pattern: acme.q($X)\n  metadata: {{sentinel: {{role: sanitizer, cls: sqli}}}}\n"
    a = ks.propose_rule({"yaml": y.format(id="a"), "role": "sanitizer", "cls": "sqli", "rule_id": "a"}, "repo", "acme", "r1",
                        "agent:x", 0.9, "", finding_id=None)
    b = ks.propose_rule({"yaml": y.format(id="b"), "role": "sanitizer", "cls": "sqli", "rule_id": "b"}, "org", "acme", "r2",
                        "agent:x", 0.9, "", finding_id=1)
    assert a["id"] == b["id"] and b["corroborations"] == 2
