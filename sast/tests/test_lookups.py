"""Precision: a lookup's key does not taint what it returns, and a call bound by method name alone does not pour the
receiver into an unrelated class's `self` (both measured as the main sources of spurious flows on airflow)."""
from pathlib import Path

from sentinel.engine.analyze import analyze
from sentinel.extract.python_facts import extract
from sentinel.extract.semgrep_specs import match_specs


def _findings(tmp_path: Path, src: str) -> set[tuple[str, str]]:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "__init__.py").write_text("")
    (tmp_path / "app" / "web.py").write_text(src)
    facts = extract(tmp_path)
    return {(f.sink_fn.rsplit(".", 1)[-1], f.cls) for f in analyze(facts, match_specs(tmp_path, facts)).findings
            if f.status in ("confirmed", "undecided")}


def test_lookup_key_does_not_taint_the_value(tmp_path):
    src = (
        "import os, subprocess\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "PATHS = {'a': '/srv/a', 'b': '/srv/b'}\n\n"
        "@app.route('/by_key')\n"
        "def by_key():\n"
        "    p = PATHS.get(request.args['k'], '/srv/default')\n"
        "    return open(p).read()\n\n"
        "@app.route('/by_default')\n"
        "def by_default():\n"
        "    p = PATHS.get('a', request.args['k'])\n"
        "    return open(p).read()\n\n"
        "@app.route('/tainted_container')\n"
        "def tainted_container():\n"
        "    d = request.get_json()\n"
        "    return open(d.get('path')).read()\n")
    found = _findings(tmp_path, src)
    assert ("by_key", "path") not in found
    assert ("by_default", "path") in found and ("tainted_container", "path") in found


def test_query_filter_value_does_not_taint_the_record(tmp_path):
    src = (
        "import subprocess\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/job')\n"
        "def job():\n"
        "    rec = Job.query.filter_by(name=request.args['name']).first()\n"
        "    subprocess.call(rec.command, shell=True)\n")
    assert ("job", "cmdi") not in _findings(tmp_path, src)


def test_name_bound_call_does_not_taint_unrelated_self(tmp_path):
    src = (
        "import subprocess\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n\n"
        "class Deployer:\n"
        "    def __init__(self, cmd):\n"
        "        self.cmd = cmd\n"
        "    def run(self, arg):\n"
        "        subprocess.call(self.cmd, shell=True)\n\n"
        "class Echo:\n"
        "    def run(self, arg):\n"
        "        return arg\n\n"
        "@app.route('/go')\n"
        "def go():\n"
        "    thing = pick(request.args['t'])\n"
        "    return thing.run('x')\n")
    assert ("run", "cmdi") not in _findings(tmp_path, src)


def test_name_bound_call_does_not_return_the_candidates_own_taint(tmp_path):
    src = (
        "import os, subprocess\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n\n"
        "class PoolView:\n"
        "    def delete(self, pk):\n"
        "        return request.args['origin']\n\n"
        "class Cleaner:\n"
        "    def wipe(self, table):\n"
        "        stmt = table.delete()\n"           # receiver type unknown: bound to PoolView.delete by name
        "        os.system(stmt)\n\n"
        "class Shell:\n"
        "    def run_it(self, cmd):\n"
        "        return cmd\n\n"
        "def passthrough(runner):\n"
        "    os.system(runner.run_it(request.args['c']))\n\n"  # what the caller passes still comes back (p2r)
        "@app.route('/p')\n"
        "def view():\n"
        "    passthrough(Shell())\n"
        "    Cleaner().wipe(None)\n")
    found = _findings(tmp_path, src)
    assert ("wipe", "cmdi") not in found
    assert ("passthrough", "cmdi") in found
