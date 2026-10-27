"""Web framework entry points: the curated pack's registrars/decorators, and class-based views."""
from pathlib import Path

from sentinel.engine.analyze import KnowledgeFact, analyze, view_methods
from sentinel.extract.python_facts import extract
from sentinel.extract.semgrep_specs import match_specs
from sentinel.learn.packs import PACKS_DIR, read_pack


def _pack() -> list[KnowledgeFact]:
    p = read_pack(PACKS_DIR / "python-web-frameworks.yml")
    return [KnowledgeFact(f"P-{i}", f["pred"], tuple(f["args"])) for i, f in enumerate(p["facts"])]


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body)
    return root


def test_django_urlconf_and_class_based_views(tmp_path):
    root = _write(tmp_path, {
        "app/__init__.py": "",
        "app/views.py": (
            "import os\n"
            "from django.views import View\n"
            "from rest_framework.views import APIView\n\n"
            "def show(request, name):\n"
            "    return open(os.path.join('/srv', name)).read()\n\n"
            "class Base(APIView):\n"
            "    pass\n\n"
            "class Files(Base):\n"
            "    def get(self, request, path):\n"
            "        return open(path).read()\n\n"
            "class Cache(dict):\n"
            "    def get(self, key):\n"
            "        return open(key).read()\n"),
        "app/urls.py": "from django.urls import path\nfrom . import views\nurlpatterns = [path('x/<name>', views.show)]\n",
    })
    facts = extract(root)
    assert view_methods(facts) == {"app.views.Files.get"}  # through a project base class; a dict subclass is not a view
    found = {f.sink_fn for f in analyze(facts, match_specs(root, facts), _pack()).findings
             if f.cls == "path" and f.status in ("confirmed", "undecided")}
    assert found == {"app.views.show", "app.views.Files.get"}


def test_flask_blueprints_and_add_url_rule(tmp_path):
    root = _write(tmp_path, {
        "web/__init__.py": "",
        "web/app.py": (
            "import subprocess\n"
            "from flask import Flask, Blueprint\n"
            "app = Flask(__name__)\n"
            "bp = Blueprint('b', __name__)\n\n"
            "@bp.route('/a/<cmd>')\n"
            "def a(cmd):\n"
            "    subprocess.call(cmd, shell=True)\n\n"
            "def b(cmd):\n"
            "    subprocess.call(cmd, shell=True)\n\n"
            "app.add_url_rule('/b/<cmd>', 'b', b)\n"),
    })
    facts = extract(root)
    found = {f.sink_fn for f in analyze(facts, match_specs(root, facts), _pack()).findings
             if f.cls == "cmdi" and f.status in ("confirmed", "undecided")}
    assert found == {"web.app.a", "web.app.b"}
