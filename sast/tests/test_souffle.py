"""The Soufflé backend derives exactly what clingo derives: kept relations, provenance and the findings built on them."""
import json
import shutil

import pytest

from sentinel.engine.analyze import CURATED, KEEP, build_findings, edb
from sentinel.engine.datalog import Program

pytestmark = pytest.mark.skipif(shutil.which("souffle") is None, reason="souffle not installed")


@pytest.mark.parametrize("repo", ["acme-shop", "acme-billing"])
def test_souffle_matches_clingo(demo_inputs, repo):
    from sentinel.engine.souffle import SouffleProgram
    facts, matches = demo_inputs[repo]
    inputs = sorted(set(edb(facts, matches) + [k.text() for k in CURATED]))
    mc = Program()._solve(inputs, KEEP)
    ms = SouffleProgram(outputs=KEEP)._solve(inputs, KEEP)
    for rel in KEEP:
        assert set(mc.atoms.get(rel, [])) == set(ms.atoms.get(rel, [])), rel
    assert {(r, str(h), tuple(map(str, p)), tuple(map(str, n))) for r, h, p, n in mc.fires} == set(ms.fires)
    dump = lambda m: [json.dumps([f.fingerprint, f.status, f.mitigations, f.assumptions, f.proof], sort_keys=True, default=str)
                      for f in build_findings(facts, matches, m, list(CURATED))]
    assert dump(mc) == dump(ms)
