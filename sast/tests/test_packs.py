"""Knowledge packs: curated facts load as active global knowledge; learned facts export as a reviewable pack."""
import yaml

from sentinel.eval import fresh_scanner
from sentinel.learn.packs import export_pack, load_packs


def test_curated_pack_loads_as_active_global_knowledge(tmp_path):
    (tmp_path / "web.yml").write_text(yaml.safe_dump({"pack": "web", "version": 2, "owner": "appsec", "facts": [
        {"pred": "framework_source", "args": ["cherrypy.expose", "http"], "note": "exposed handler params are request data"}]}))
    sc = fresh_scanner(repos=[])
    stats = load_packs(sc, [tmp_path])
    assert stats == {"packs": 1, "facts": 1, "activated": 1, "blocked": 0}
    row = sc.store.one("SELECT * FROM knowledge WHERE pred='framework_source'")
    assert row["status"] == "active" and row["scope"] == "global" and row["origin"] == "pack:web@2"
    assert load_packs(sc, [tmp_path])["activated"] == 0  # idempotent


def test_pack_fact_that_hides_canary_findings_is_blocked(tmp_path):
    (tmp_path / "bad.yml").write_text(yaml.safe_dump({"pack": "bad", "facts": [
        {"pred": "sanitizer_api", "args": ["os.path.normpath", "all"], "note": "wrong: normpath does not contain a path"}]}))
    sc = fresh_scanner(repos=[])
    assert load_packs(sc, [tmp_path])["blocked"] == 1


def test_learned_facts_export_as_a_candidate_pack():
    sc = fresh_scanner(repos=[])
    item = sc.ks.propose("source_api", ["bottle.request.query", "http"], "global", None, None, "oracle:test", 0.9,
                         "query-string values")
    sc._gate_item(item["id"])
    doc = yaml.safe_load(export_pack(sc.store, "learned"))
    facts = [f for f in doc["facts"] if f["pred"] == "source_api"]
    assert facts and facts[0]["args"] == ["bottle.request.query", "http"] and facts[0]["learned"]["origin"] == "oracle:test"
