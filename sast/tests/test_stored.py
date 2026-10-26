"""Second-order flows (RIPS): attacker data written to a table or file is a source again where it is read back,
and only then (a table written with constants is not)."""
from pathlib import Path

from sentinel.engine.analyze import analyze
from sentinel.extract.python_facts import extract
from sentinel.extract.semgrep_specs import match_specs

APP = Path(__file__).parent / "fixtures" / "stored_app"


def _findings():
    facts = extract(APP)
    return [f for f in analyze(facts, match_specs(APP, facts)).findings if f.status in ("confirmed", "undecided")]


def test_stored_xss_through_a_table_written_by_the_attacker():
    hits = [f for f in _findings() if f.cls == "xss" and f.source_kind == "stored"]
    assert [f.sink_fn for f in hits] == ["app.comments"]
    assert hits[0].source_rule == "stored:db:comments"


def test_table_written_only_with_constants_is_not_a_source():
    assert not [f for f in _findings() if f.sink_fn == "app.settings"]


def test_uploaded_file_read_back_and_deserialized():
    assert [f for f in _findings() if f.cls == "deser" and f.source_kind == "stored" and f.sink_fn == "app.load"]
