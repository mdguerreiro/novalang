"""Attack surface beyond HTTP requests: a library's public API parameters (only toward sinks that execute what they are
given) and replies from remote servers. Both are weak sources: they reach review, never `confirmed` on their own."""
from pathlib import Path

from sentinel.engine.analyze import analyze, api_sources
from sentinel.extract.python_facts import extract
from sentinel.extract.semgrep_specs import match_specs

LIB = Path(__file__).parent / "fixtures" / "lib_app"


def _run():
    facts = extract(LIB)
    matches = match_specs(LIB, facts)
    return facts, matches, [f for f in analyze(facts, matches).findings if f.status in ("confirmed", "undecided")]


def test_public_api_parameters_reach_execution_sinks():
    _facts, _m, fs = _run()
    by = {(f.sink_fn, f.cls) for f in fs if f.source_kind == "api"}
    assert ("mylib.cards.load", "deser") in by
    assert ("mylib.cards.clone", "cmdi") not in by  # a library's own arguments to a program: not argument injection


def test_api_input_is_weak_and_limited_to_execution_classes():
    facts, matches, fs = _run()
    api = [f for f in fs if f.source_kind == "api"]
    assert api and all(f.status == "undecided" for f in api)
    assert all(f.cls in ("code", "ssti", "deser", "cmdi") for f in api)
    assert not [f for f in fs if f.sink_fn == "mylib.cards.export"]  # a path a library writes: not reported
    params = {f for f, _i, _p in api_sources(facts, matches)}
    assert "mylib.cards._private_load" not in params and "mylib.cards.run_fixed" not in params


def test_remote_server_reply_reaches_eval():
    _f, _m, fs = _run()
    assert [f for f in fs if f.source_kind == "network" and f.cls == "code" and f.sink_fn == "mylib.cards.fetch_and_run"]


def test_constructor_argument_to_template_compiled_from_string():
    _f, _m, fs = _run()
    print(sorted((f.source_fn, f.sink_fn, f.cls, f.source_kind) for f in fs))
    assert [f for f in fs if f.cls == "ssti" and f.sink_fn == "mylib.cards.Card.to_html"]


def test_application_helpers_are_not_library_api(tmp_path):
    import shutil
    app = tmp_path / "app"
    shutil.copytree(LIB, app)
    (app / "pyproject.toml").unlink()  # not a distributable package: an application
    facts = extract(app)
    matches = match_specs(app, facts)
    assert not api_sources(facts, matches)
    assert not [f for f in analyze(facts, matches).findings if f.source_kind == "api"]


def test_closure_reads_the_enclosing_functions_variables(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "m.py").write_text(
        "import requests\n\n\n"
        "def stream(url):\n"
        "    response = requests.post(url)\n\n"
        "    def gen():\n"
        "        for line in response.iter_lines():\n"
        "            eval(line)\n\n"
        "    return gen()\n\n\n"
        "def shadow(url):\n"
        "    response = requests.post(url)\n\n"
        "    def gen(response):\n"
        "        eval(response)\n\n"
        "    return gen('1+1')\n")
    facts = extract(tmp_path)
    fs = [(f.source_fn, f.sink_fn) for f in analyze(facts, match_specs(tmp_path, facts)).findings if f.cls == "code"]
    assert fs == [("pkg.m.stream", "pkg.m.stream.gen")]  # the shadowing parameter is not the outer variable


def test_one_library_input_finding_per_sink_named_by_its_entry():
    _f, _m, fs = _run()
    api = [f for f in fs if f.source_kind == "api"]
    assert len({(f.sink, f.cls) for f in api}) == len(api)
    assert all(f.source_fn.startswith("mylib.") for f in api)  # the public function, not the synthetic node


def test_remote_reply_counts_only_where_it_is_executed(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "m.py").write_text(
        "import requests, sqlite3\n\n\n"
        "def sync(url):\n"
        "    name = requests.get(url).text\n"
        "    open(name, 'w').write('x')\n"
        "    sqlite3.connect('db').cursor().execute(\"SELECT * FROM t WHERE n = '%s'\" % name)\n"
        "    eval(name)\n")
    facts = extract(tmp_path)
    fs = {f.cls for f in analyze(facts, match_specs(tmp_path, facts)).findings
          if f.source_kind == "network" and f.status in ("confirmed", "undecided")}
    assert fs == {"code"}
