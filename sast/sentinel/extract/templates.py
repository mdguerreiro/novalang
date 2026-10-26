"""Template engines: which template variables are written to HTML without escaping.

One adapter per engine, written from that engine's documented escaping rules (not from any application): whether it
escapes by default, what marks one output raw, how a block or a whole template turns escaping off, and how loops and
assignments alias variables. `raw_roots` returns the context variable names whose value reaches the page unescaped;
the extractor turns the values passed under those names into XSS sinks, and data flow decides whether attacker data
reaches them. An engine without an adapter is a frontier question, not a silent gap.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

IDENT = r"[A-Za-z_]\w*"


@dataclass(frozen=True)
class Engine:
    name: str
    escapes_by_default: bool
    output: str                       # regex: one output expression, group "e"
    raw_output: tuple[str, ...] = ()  # regexes: an output written raw whatever the default (group "e")
    raw_filters: tuple[str, ...] = ()  # filters that disable escaping for that output (`|safe`)
    escape_filters: tuple[str, ...] = ()  # filters that escape it (`|e`, `|h`)
    off_block: str | None = None      # regex opening a block with escaping off (closed by `on_block`)
    on_block: str | None = None
    off_global: tuple[str, ...] = ()  # regexes turning escaping off for the rest of the template
    loops: tuple[str, ...] = ()       # regexes binding loop names (group "v") to an iterable expression (group "e")
    sets: tuple[str, ...] = field(default_factory=tuple)  # regexes binding a name (group "v") to an expression (group "e")


JINJA = Engine(
    "jinja2", True, r"\{\{-?(?P<e>.*?)-?\}\}",
    raw_filters=("safe",), escape_filters=("e", "escape", "forceescape", "striptags", "urlencode", "tojson", "int",
                                            "float", "length", "count"),
    off_block=r"\{%-?\s*autoescape\s+(false|False)\s*-?%\}", on_block=r"\{%-?\s*endautoescape\s*-?%\}",
    loops=(rf"\{{%-?\s*for\s+(?P<v>{IDENT}(?:\s*,\s*{IDENT})*)\s+in\s+(?P<e>.+?)\s*-?%\}}",),
    sets=(rf"\{{%-?\s*set\s+(?P<v>{IDENT})\s*=\s*(?P<e>.+?)\s*-?%\}}",
          rf"\{{%-?\s*with\s+(?P<v>{IDENT})\s*=\s*(?P<e>.+?)\s*-?%\}}"))
JINJA_RAW = Engine(**{**JINJA.__dict__, "name": "jinja2-noescape", "escapes_by_default": False})
DJANGO = Engine(
    "django", True, r"\{\{(?P<e>.*?)\}\}",
    raw_filters=("safe", "safeseq"), escape_filters=("escape", "force_escape", "escapejs", "urlencode", "length",
                                                     "add", "date", "json_script"),
    off_block=r"\{%\s*autoescape\s+off\s*%\}", on_block=r"\{%\s*endautoescape\s*%\}",
    loops=(rf"\{{%\s*for\s+(?P<v>{IDENT}(?:\s*,\s*{IDENT})*)\s+in\s+(?P<e>.+?)\s*%\}}",),
    sets=(rf"\{{%\s*with\s+(?P<v>{IDENT})\s*=\s*(?P<e>\S+)",))
TORNADO = Engine(
    "tornado", True, r"\{\{(?P<e>.*?)\}\}", raw_output=(r"\{%\s*raw\s+(?P<e>.+?)\s*%\}",),
    off_global=(r"\{%\s*autoescape\s+None\s*%\}",),
    loops=(rf"\{{%\s*for\s+(?P<v>{IDENT}(?:\s*,\s*{IDENT})*)\s+in\s+(?P<e>.+?)\s*%\}}",),
    sets=(rf"\{{%\s*set\s+(?P<v>{IDENT})\s*=\s*(?P<e>.+?)\s*%\}}",))
BOTTLE = Engine(
    "bottle", True, r"\{\{(?!!)(?P<e>.*?)\}\}", raw_output=(r"\{\{!(?P<e>.*?)\}\}",),
    loops=(rf"^\s*%\s*for\s+(?P<v>{IDENT}(?:\s*,\s*{IDENT})*)\s+in\s+(?P<e>.+?):\s*$",),
    sets=(rf"^\s*%\s*(?P<v>{IDENT})\s*=\s*(?P<e>.+)$",))
MAKO = Engine(
    "mako", False, r"\$\{(?P<e>.*?)\}", escape_filters=("h", "u", "x"),
    loops=(rf"^\s*%\s*for\s+(?P<v>{IDENT}(?:\s*,\s*{IDENT})*)\s+in\s+(?P<e>.+?):\s*$",),
    sets=(rf"^\s*%\s*(?P<v>{IDENT})\s*=\s*(?P<e>.+)$",))

ENGINES = {e.name: e for e in (JINJA, JINJA_RAW, DJANGO, TORNADO, BOTTLE, MAKO)}


def _root(expr: str) -> str | None:
    m = re.match(rf"\s*\(*\s*({IDENT})", expr)
    return m.group(1) if m else None


def _filters(expr: str) -> list[str]:
    """`x.body|safe|upper` -> ["safe", "upper"]; Mako `x | n,h` -> ["n", "h"]."""
    parts = re.split(r"\|(?!\|)", expr)[1:]
    out = []
    for p in parts:
        out += [f.strip().split("(")[0].strip() for f in p.split(",") if f.strip()]
    return out


def raw_roots(text: str, engine: Engine) -> set[str]:
    """Context variable names whose value (or something read from it) is written to the page unescaped."""
    lines = text.split("\n")
    # Aliases: loop / set names -> the root they read from, so `{% for c in comments %}{{ c.body|safe }}` reports
    # `comments`. Applied transitively; a name bound to a literal maps to nothing.
    alias: dict[str, str | None] = {}
    for pat in engine.loops + engine.sets:
        for m in re.finditer(pat, text, re.M):
            r = _root(m.group("e"))
            for v in re.split(r"\s*,\s*", m.group("v")):
                alias[v.strip()] = r

    def resolve(name: str | None) -> str | None:
        seen = set()
        while name in alias and name not in seen:
            seen.add(name)
            name = alias[name]
        return name

    # Regions with escaping off.
    off_spans: list[tuple[int, int]] = []
    if engine.off_block:
        for m in re.finditer(engine.off_block, text):
            end = re.compile(engine.on_block).search(text, m.end()) if engine.on_block else None
            off_spans.append((m.end(), end.start() if end else len(text)))
    for pat in engine.off_global:
        m = re.search(pat, text)
        if m:
            off_spans.append((m.end(), len(text)))
    escaping_off = lambda pos: any(a <= pos < b for a, b in off_spans)

    roots: set[str] = set()
    for pat in engine.raw_output:
        for m in re.finditer(pat, text, re.S):
            r = resolve(_root(m.group("e")))
            if r:
                roots.add(r)
    for m in re.finditer(engine.output, text, re.S):
        e = m.group("e")
        fs = _filters(e)
        if any(f in engine.escape_filters for f in fs) and not any(f in engine.raw_filters for f in fs):
            continue
        raw = (not engine.escapes_by_default) or escaping_off(m.start()) or any(f in engine.raw_filters for f in fs) \
            or (engine.name == "mako" and "n" in fs)
        if raw:
            r = resolve(_root(e))
            if r:
                roots.add(r)
    del lines
    return roots
