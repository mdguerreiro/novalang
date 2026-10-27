"""Engine-guided review: the engine ranks the attack surface, a reader reads the top of it, issues become review-lane
findings, and API-level answers become proposed knowledge."""
from pathlib import Path

from sentinel import review as rv
from sentinel.agent.reader import MockReviewReader, ReviewIssue
from sentinel.engine.analyze import analyze
from sentinel.extract.python_facts import extract
from sentinel.extract.semgrep_specs import match_specs

APP = {
    "web/__init__.py": "",
    "web/app.py": (
        "import fancylib\n"
        "from flask import Flask, request, redirect\n"
        "app = Flask(__name__)\n\n"
        "def is_safe_target(url):\n"
        "    return url.startswith('/')\n\n"            # '//evil.com' passes: a bypassable check
        "@app.route('/next')\n"
        "def go_next():\n"
        "    target = request.args.get('next', '/')\n"
        "    if not is_safe_target(target):\n"
        "        target = '/'\n"
        "    return redirect(target)\n\n"
        "@app.route('/convert')\n"
        "def convert():\n"
        "    doc = request.args['doc']\n"
        "    return fancylib.render_unsafe(doc)\n\n"    # a library call no spec models
        "def unused_helper(path):\n"
        "    return open(path).read()\n"),              # not reachable from an entry point
}


def _setup(tmp_path: Path):
    for rel, body in APP.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(body)
    facts = extract(tmp_path)
    matches = match_specs(tmp_path, facts)
    return facts, analyze(facts, matches)


def _mem_cache():
    store = {}
    return store, (lambda k: store.get(k)), (lambda k, fn, issues: store.__setitem__(k, issues))


def test_ranking_prefers_the_reachable_attack_surface(tmp_path):
    facts, a = _setup(tmp_path)
    picks = [p.fn for p in rv.rank(facts, a)]
    assert "web.app.go_next" in picks and "web.app.convert" in picks
    assert "web.app.unused_helper" not in picks  # sensitive, but nothing reaches it
    naive = [p.fn for p in rv.rank(facts, a, select="naive")]
    assert "web.app.unused_helper" in naive  # the grep baseline cannot tell


def test_issues_become_review_findings_and_reads_are_cached(tmp_path):
    facts, a = _setup(tmp_path)
    store, get, put = _mem_cache()
    res = rv.review(facts, a, MockReviewReader(), get, put, budget=10)
    assert res["read"] > 0
    got = {(f.sink_fn, f.cls) for f in res["findings"]}
    assert ("web.app.is_safe_target", "redirect") in got  # the bypassable validator
    assert all(f.status == "undecided" and f.sink_rule == "guided-review" for f in res["findings"])
    again = rv.review(facts, a, MockReviewReader(), get, put, budget=10)
    assert again["read"] == 0 and again["cached"] == res["read"]
    # A validator the reader shows to be bypassable is proposed as not a sanitizer, for this repository only.
    assert ("not_sanitizer", ["web.app.is_safe_target"], "repo") in [(p, a_, s) for p, a_, s, _c, _w in res["proposals"]]


def test_an_unmodelled_dangerous_library_call_is_taught_as_a_sink(tmp_path):
    facts, a = _setup(tmp_path)

    class Reader:
        name = "stub"

        def read(self, chunks, context=""):
            out = []
            for file, l1, src in chunks:
                for i, ln in enumerate(src.splitlines()):
                    if "render_unsafe(" in ln:
                        out.append(ReviewIssue("xss", l1 + i, file, "", 0.8, "unescaped HTML", "flow",
                                               "fancylib.render_unsafe", 0))
                    if "open(" in ln:  # a cited line outside what was read is never accepted (not read: unreachable)
                        out.append(ReviewIssue("path", l1 + i, file, "", 0.9, "x", "flow", "open", 0))
            out.append(ReviewIssue("xss", 9999, "web/app.py", "", 0.9, "hallucinated line", "flow", "", -1))
            return out

    _store, get, put = _mem_cache()
    res = rv.review(facts, a, Reader(), get, put, budget=10)
    assert ("sink_api", ["fancylib.render_unsafe", 0, "xss"], "global") in [(p, x, s) for p, x, s, _c, _w in res["proposals"]]
    assert all(f.line != 9999 for f in res["findings"])
    assert "web.app.unused_helper" not in {f.sink_fn for f in res["findings"]}


def test_scanner_runs_the_review_tier_when_enabled(tmp_path, monkeypatch):
    from sentinel.pipeline import Scanner
    from sentinel.store.db import Store
    for rel, body in APP.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(body)
    monkeypatch.setenv("SENTINEL_REVIEW", "1")
    monkeypatch.setenv("SENTINEL_FRONTIER", "0")
    st = Store(":memory:"); st.upsert_org("acme", "Acme"); sc = Scanner(st)
    st.upsert_repo("app", "acme", "app", str(tmp_path))
    first = sc.scan("app")
    assert first["review_reads"] > 0 and first["review_issues"] > 0
    rows = st.q("SELECT lane, data FROM findings WHERE repo_id='app' AND is_open=1")
    assert any(r["lane"] == "review" and "guided-review" in str(r["data"]) for r in rows)
    second = sc.scan("app", refresh=False)
    assert second["review_reads"] == 0  # unchanged code is not read again


def test_ranking_sees_text_built_sql_and_view_methods_behind_unknown_decorators(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/ops.py": (
            "class Ops:\n"
            "    def explain_prefix(self, fmt, **options):\n"
            "        extra = ', '.join('%s %s' % (k, v) for k, v in options.items())\n"
            "        return 'EXPLAIN (%s) ' % extra\n"),
        "pkg/views.py": (
            "from fab import BaseView, expose\n\n"
            "class ProviderView(BaseView):\n"
            "    @expose('/providers')\n"
            "    def index(self):\n"
            "        def clean(desc):\n"
            "            return '<a href=\"%s\">x</a>' % desc\n"
            "        return clean(self.desc)\n"),
        "pyproject.toml": "[project]\nname='pkg'\n",
    }
    for rel, body in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(body)
    facts = extract(tmp_path)
    a = analyze(facts, match_specs(tmp_path, facts))
    picks = {p.fn: p.why for p in rv.rank(facts, a)}
    assert "builds SQL/HTML/shell text" in picks["pkg.ops.Ops.explain_prefix"]
    assert "in a view class" in picks["pkg.views.ProviderView.index.clean"]
