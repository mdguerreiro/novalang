"""Template engines: only the values a template writes unescaped become XSS sinks (one adapter per engine)."""
from pathlib import Path

from sentinel.extract.python_facts import extract
from sentinel.extract.templates import DJANGO, JINJA, MAKO, raw_roots

APP = Path(__file__).parent / "fixtures" / "templates_app"


def test_each_engine_marks_exactly_its_raw_variables():
    f = extract(APP)
    sinks = {(f.nodes[n].fn.rsplit(".", 1)[-1], f.nodes[n].label) for n, c in f.extra_sinks if c == "xss"}
    assert sinks == {
        ("inline", "[{'body': q}]"),                   # {% for c in comments %}{{ c.body|safe }}
        ("from_file", "request.args.get('bio')"),       # {% autoescape false %} block in templates/profile.html
        ("jinja_direct", "request.args.get('msg')"),    # jinja2.Template does not autoescape by default
        ("django_view", "request.args.get('note')"),    # {% autoescape off %} in dj.html
        ("tornado_view", "request.args.get('b')"),      # {% raw blurb %}
        ("bottle_view", "request.args.get('r')"),       # {{!raw}}
        ("mako_view", "request.args.get('x')"),         # ${body} (Mako does not escape by default; | h does)
    }


def test_raw_roots_follow_aliases_and_respect_escape_filters():
    assert raw_roots("{% set u = user %}{{ u.bio|safe }}{{ user.name }}", JINJA) == {"user"}
    assert raw_roots("{{ x|safe|e }}{{ y|e }}", JINJA) == {"x"}
    assert raw_roots("{% for a, b in pairs.items() %}{{ b|safe }}{% endfor %}", JINJA) == {"pairs"}
    assert raw_roots("{{ note|safe }}{% autoescape off %}{{ other }}{% endautoescape %}{{ fine }}", DJANGO) == {"note", "other"}
    assert raw_roots("${a}${b | h}", MAKO) == {"a"}
