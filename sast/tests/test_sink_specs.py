"""Curated sink specs: templates compiled from strings, mark_safe/Markup, argument injection, pickle-backed loaders."""
from __future__ import annotations

import textwrap
from pathlib import Path

from sentinel.extract.semgrep_specs import run_semgrep_raw

SPECS = Path(__file__).resolve().parents[1] / "specs" / "python-web.yml"

CODE = textwrap.dedent('''
    import jinja2, subprocess, pickle, yaml, torch, numpy, joblib
    from jinja2.sandbox import SandboxedEnvironment
    from django.utils.safestring import mark_safe
    from markupsafe import Markup

    def ssti(t):
        jinja2.Environment(loader=jinja2.BaseLoader()).from_string(t).render()  # L8 ssti
        env = jinja2.Environment()
        env.from_string(t)                                                       # L10 ssti
        jinja2.Template(t)                                                       # L11 ssti
        SandboxedEnvironment().from_string(t)                                    # L12 not a sink

    def xss(h):
        mark_safe("<br>" + h)                                                    # L15 xss
        Markup(h)                                                                # L16 xss

    def argv(url, rev):
        subprocess.check_output(["git", "clone", url])                           # L19 cmdi (argv)
        subprocess.call(["hg", "update", rev], cwd=".")                          # L20 cmdi (argv)
        subprocess.call(url, shell=True)                                         # L21 cmdi (shell), not argv

    def deser(p, b):
        joblib.load(p)                                                           # L24 deser
        torch.load(p)                                                            # L25 deser
        torch.load(p, weights_only=True)                                         # L26 not a sink
        numpy.load(p, allow_pickle=True)                                         # L27 deser
        numpy.load(p)                                                            # L28 not a sink
        yaml.unsafe_load(b)                                                      # L29 deser
        yaml.load(b, Loader=yaml.SafeLoader)                                     # L30 not a sink
''')


def _hits(tmp_path: Path) -> dict[int, set[str]]:
    (tmp_path / "a.py").write_text(CODE)
    rc, out, err = run_semgrep_raw([SPECS], tmp_path, ["a.py"])
    assert out is not None, err
    hits: dict[int, set[str]] = {}
    for r in out["results"]:
        hits.setdefault(r["start"]["line"], set()).add(r["check_id"].rsplit(".", 2)[-2] + "." + r["check_id"].rsplit(".", 1)[-1])
    return hits


def test_new_sinks_match_and_safe_forms_do_not(tmp_path):
    h = _hits(tmp_path)
    ids = lambda line: {i for i in h.get(line, set())}
    assert any("template-from-string" in i for i in ids(8))
    assert any("template-from-string" in i for i in ids(10))
    assert any("template-from-string" in i for i in ids(11))
    assert not any("template-from-string" in i for i in ids(12))
    assert any("markup" in i for i in ids(15)) and any("markup" in i for i in ids(16))
    assert any("subprocess-argv" in i for i in ids(19)) and any("subprocess-argv" in i for i in ids(20))
    assert not any("subprocess-argv" in i for i in ids(21)) and any("subprocess-shell" in i for i in ids(21))
    assert any(i.startswith("deser.") for i in ids(24)) and any(i.startswith("deser.") for i in ids(25))
    assert not ids(26) and not ids(28) and not ids(30)
    assert any(i.startswith("deser.") for i in ids(27)) and any(i.startswith("deser.") for i in ids(29))
