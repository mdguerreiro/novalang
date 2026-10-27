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
    # Curated specs know one of these sinks (a Jinja2 template compiled from a string); the rest are unmodelled.
    assert rep["Semgrep OSS"]["tp"] <= 1 and rep["engine without frontier"]["tp"] <= 1
    assert rep["engine with frontier"]["recall"] == 1.0 and rep["engine with frontier"]["fp"] == 0
    assert rep["frontier"]["questions"] <= 16
    # The second repository only asks about what the first did not teach.
    assert etl["engine with frontier"]["recall"] == 1.0 and etl["engine with frontier"]["fp"] == 0
    # `dill.loads` is a curated deserialization sink now: the frontier only asks about the project's own entry point.
    assert "etl.api.archive" in set(etl["frontier"]["subjects"]) and "dill.loads" not in set(etl["frontier"]["subjects"])
    assert etl["frontier"]["questions"] <= 3


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


def test_dynamic_dispatch_and_framework_attributes(tmp_path):
    root = _write(tmp_path, {
        "srv/h.py": """
            import os
            from http.server import BaseHTTPRequestHandler
            class Ping:
                def run(self, arg):
                    os.system("ping " + arg)
            class Echo:
                def run(self, arg):
                    return arg
            ATTACKS = {"ping": Ping(), "echo": Echo()}
            class H(BaseHTTPRequestHandler):
                def do_GET(self):
                    attack = ATTACKS[self.path.split("/")[1]]
                    self.wfile.write(attack.run(self.path).encode())
        """})
    f = extract(root)
    assert {g for k, g in f.calls if f.resolved.get(k) == "cha-name"} == {"srv.h.Ping.run", "srv.h.Echo.run"}
    assert "http.server.BaseHTTPRequestHandler.wfile.write" in set(f.libcalls.values())


def test_no_framework_knowledge_still_finds_everything(monkeypatch):
    """Generalization: with stdlib sinks only (no Flask/FastAPI/pandas/jinja2 specs), the frontier learns the
    frameworks itself and reaches the same recall, at the cost of more first-time questions."""
    import importlib
    import sentinel.extract.semgrep_specs as ss
    monkeypatch.setenv("SENTINEL_SPECS", "minimal")
    importlib.reload(ss)
    try:
        import sentinel.eval as ev
        importlib.reload(ev)
        r = ev.run_frontier()
        assert r["acme-reports"]["engine with frontier"]["recall"] == 1.0
        assert r["acme-reports"]["engine with frontier"]["fp"] == 0
        assert r["acme-etl"]["engine with frontier"]["recall"] == 1.0
    finally:
        monkeypatch.delenv("SENTINEL_SPECS")
        importlib.reload(ss)


def test_neighbor_preoracle_answers_like_apis_and_abstains_otherwise():
    from sentinel.learn.neighbors import NeighborOracle
    data = [(f"lib{i}.db.read_sql", '["0", "sqli"]') for i in range(5)] + \
           [(f"lib{i}.text.strip_html", "no") for i in range(5)] + [(f"x{i}.util.format_date", "no") for i in range(15)]
    o = NeighborOracle(k=3, min_sim=0.45).fit(data)
    label, sim, nbrs = o.predict("newlib.db.read_sql")
    assert label == '["0", "sqli"]' and len(nbrs) == 3
    assert o.predict("totally.unrelated.thing") is None  # no confident unanimous neighbourhood: ask the LLM


def test_frontier_uses_preoracle_before_the_model():
    from sentinel.eval import fresh_scanner
    sc = fresh_scanner(repos=["acme-reports"])
    for i in range(25):  # prior answers from other customers/repos
        sc.ks.propose("not_sink_api", [f"vendor{i}.metrics.emit_counter"], "global", None, None, "oracle:m", 0.9, "r")
    for i in range(3):
        sc.ks.propose("sink_api", [f"vendor{i}.sql.read_sql", 0, "sqli"], "global", None, None, "oracle:m", 0.95, "r")
    asked = []
    inner = sc.oracle.classify_sink
    sc.oracle.classify_sink = lambda api, args, usage: asked.append(api) or inner(api, args, usage)
    stats = sc.scan("acme-reports")
    assert stats["knn_answers"] >= 1 and "pandas.read_sql" not in asked


def test_frontier_budget_caps_model_calls_and_batches_entry_points(monkeypatch):
    """A scan never spends more than FRONTIER_BUDGET model calls on frontier questions; entry points go in batches."""
    import sentinel.pipeline as pl
    from sentinel.eval import fresh_scanner
    monkeypatch.setattr(pl, "FRONTIER_BUDGET", 2)
    monkeypatch.setattr(pl, "ENTRY_CALLS", 1)
    sc = fresh_scanner(repos=["acme-etl"])
    batches = []
    inner = sc.oracle.classify_entries
    monkeypatch.setattr(sc.oracle, "classify_entries", lambda items: batches.append(len(items)) or inner(items), raising=False)
    s = sc.scan("acme-etl")
    assert s["frontier_questions"] - sum(batches) <= 2 and len(batches) <= 1  # each budget holds
