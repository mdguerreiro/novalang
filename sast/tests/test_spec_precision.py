"""Sink specs that matched safe uses on dev repositories (precision audit): safe YAML loaders, zipfile extraction,
and test clients' replies."""
from pathlib import Path

from sentinel.engine.analyze import analyze
from sentinel.extract.python_facts import extract
from sentinel.extract.semgrep_specs import match_specs


def _run(tmp_path: Path, files: dict[str, str]):
    for rel, body in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(body)
    facts = extract(tmp_path)
    return [f for f in analyze(facts, match_specs(tmp_path, facts)).findings if f.status in ("confirmed", "undecided")]


def test_yaml_loaders(tmp_path):
    fs = _run(tmp_path, {"app/__init__.py": "", "app/m.py": (
        "import sys, yaml\n\n"
        "class Strict(yaml.SafeLoader):\n    pass\n\n"
        "def default():\n    p = sys.argv[1]\n    return yaml.load(open(p).read())\n\n"
        "def unsafe():\n    p = sys.argv[1]\n    return yaml.load(open(p).read(), Loader=yaml.Loader)\n\n"
        "def full():\n    p = sys.argv[1]\n    return yaml.load(open(p).read(), yaml.FullLoader)\n\n"
        "def safe():\n    p = sys.argv[1]\n    return yaml.load(open(p).read(), Loader=yaml.SafeLoader)\n\n"
        "def own():\n    p = sys.argv[1]\n    return yaml.load(open(p).read(), Loader=Strict)\n")})
    assert {f.sink_fn.rsplit(".", 1)[-1] for f in fs if f.cls == "deser"} == {"default", "unsafe", "full"}


def test_zipfile_extractall_is_not_zip_slip_but_tarfile_is(tmp_path):
    fs = _run(tmp_path, {"app/__init__.py": "", "app/m.py": (
        "import sys, tarfile, zipfile\n\n"
        "def unzip():\n    p = sys.argv[1]\n"
        "    with zipfile.ZipFile(p) as z:\n        z.extractall('/tmp/x')\n\n"
        "def unzip2():\n    p = sys.argv[1]\n"
        "    z = zipfile.ZipFile(p)\n    z.extractall('/tmp/x')\n\n"
        "def untar():\n    p = sys.argv[1]\n"
        "    with tarfile.open(p) as t:\n        t.extractall('/tmp/x')\n")})
    assert {f.sink_fn.rsplit(".", 1)[-1] for f in fs if f.cls == "path"} == {"untar"}


def test_test_clients_replies_are_not_sources(tmp_path):
    fs = _run(tmp_path, {"lib/__init__.py": "", "tests/__init__.py": "", "tests/helpers.py": (
        "import requests\nfrom lib.run import go\n\n"
        "def call(url):\n    go(requests.get(url).text)\n"),
        "lib/run.py": "def go(code):\n    eval(code)\n"})
    assert not [f for f in fs if f.source_kind == "network"]
