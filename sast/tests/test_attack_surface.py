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
    assert ("mylib.cards.clone", "cmdi") in by  # argument injection through a list element


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
