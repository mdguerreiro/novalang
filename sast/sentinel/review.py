"""Engine-guided review: the engine decides where a model reads; what the model finds is checked and taught back.

Taint analysis only reaches code that tainted data reaches through modelled sources and sinks. Real CVEs often sit
where it cannot see: a validator that can be bypassed, a framework API whose caller is the attacker, a sink the specs
do not name. Reading every function costs too much and re-reports patched code every scan. Here the engine ranks the
attack surface (functions reachable from an entry point or a library's public API that do something security-relevant,
and the validators guarding them) and a model reads only the top of that list, one function plus its project callees
per read, cached by a hash of exactly that code. Issues become review-lane findings (never auto-confirmed), and their
API-level content becomes proposed knowledge: a dangerous library call the specs did not know (sink_api) or a project
validator shown to be bypassable (not_sanitizer), gated like any other machine-proposed fact.

select="naive" ranks by keyword grep alone (no engine signals), for the ablation that measures what the engine adds.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field

from .engine.analyze import CLASSES, CWE, VIEW_BASE_RE, Analysis, Finding, Step, _public
from .extract.python_facts import Facts, is_test_path

# Reads per scan, highest-ranked first. "auto": 5% of the ranked attack surface, at least 30 and at most 100 (a fixed 30
# covers a library of 400 functions and 1% of a 28k-function framework).
REVIEW_BUDGET = os.environ.get("SENTINEL_REVIEW_BUDGET", "30")
AUTO_MIN, AUTO_MAX, AUTO_SHARE = 30, 100, 0.05


def budget_for(ranked: int, budget: int | str | None = None) -> int:
    b = REVIEW_BUDGET if budget is None else budget
    if str(b) == "auto":
        return max(AUTO_MIN, min(AUTO_MAX, -(-int(ranked * AUTO_SHARE * 100) // 100)))
    return int(b)
MIN_CONFIDENCE = float(os.environ.get("SENTINEL_REVIEW_MIN_CONF", "0.6"))
MAX_LINES = 260  # lines per read (function + callees)

VALIDATOR_RE = re.compile(r"(safe|valid|saniti[sz]|allow|check|escape|clean|normali[sz]|quote|verify|permit|"
                          r"whitelist|allowlist|trusted|filter|restrict|guard|secure)", re.I)
SENSITIVE_RE = re.compile(r"(redirect|url|open|path|join|sql|execute|raw|extra|subprocess|popen|system|spawn|eval|exec|"
                          r"compile|render|template|markup|mark_safe|format_html|safestring|html|pickle|load|yaml|marshal|"
                          r"urlopen|fetch|socket|send_file|send_from_directory|extract|unzip|tarfile|zipfile|request|"
                          r"rmtree|remove|unlink|rename|copy|write|chmod|shell|cursor|query|deserial|import_module|getattr)",
                          re.I)

# Text of another language built by string formatting: SQL, HTML or a shell command assembled in Python is where
# injection happens even when no modelled sink is called (an ORM's SQL compiler, a template tag's HTML).
INTERP_RE = re.compile(r"""["'][^"'\n]*(\b(SELECT|INSERT INTO|UPDATE|DELETE FROM|WHERE|EXPLAIN|ORDER BY|JOIN|UNION)\b|"""
                       r"""<\s*(a|script|img|iframe|div|span|li|input|form|br|p|style|svg)\b|\b(sh|bash|cmd) /?-?c\b)""")
FORMAT_RE = re.compile(r"""%\s*[(\w]|\.format\(|\bf["']|["']\s*\+|\+\s*["']|\.join\(""")


@dataclass
class Pick:
    fn: str
    score: float
    why: list[str] = field(default_factory=list)


def rank(facts: Facts, a: Analysis | None, select: str = "engine") -> list[Pick]:
    """Functions worth a read, best first. `engine` uses reachability, public API, modelled sinks, guards and the
    engine's own findings; `naive` only greps names (the ablation baseline)."""
    sink_cls: dict[str, set[str]] = defaultdict(set)
    if a is not None:
        for m in a.matches:
            if m.role == "sink" and m.node in facts.nodes and m.cls:
                sink_cls[facts.nodes[m.node].fn].add(m.cls)
    lib_names: dict[str, set[str]] = defaultdict(set)
    for k, q in facts.libcalls.items():
        if k in facts.nodes:
            lib_names[facts.nodes[k].fn].add(q)
    guards = defaultdict(int)
    for n, _p, _v in facts.guards:
        if n in facts.nodes:
            guards[facts.nodes[n].fn] += 1
    reach = {t[0] for t in a.model.get("reach")} if a is not None else set()
    views = {c for c, bases in facts.classes.items()
             if VIEW_BASE_RE.search(c.rsplit(".", 1)[-1]) or any(VIEW_BASE_RE.search(b.rsplit(".", 1)[-1]) for b in bases)}

    def in_view(q: str, fn) -> bool:  # a method of a view class, or a function nested in one
        while fn is not None:
            if fn.cls in views:
                return True
            q = q.rpartition(".")[0]
            fn = facts.functions.get(q)
        return False
    touched, explained = set(), set()
    if a is not None:
        for f in a.findings:
            fns = {f.source_fn, f.sink_fn} | {s.fn for s in f.path}
            touched |= fns
            if f.status in ("confirmed", "undecided"):
                explained.add(f.sink_fn)
    out = []
    for q, fn in facts.functions.items():
        if is_test_path(fn.file) or fn.end_line <= fn.line:
            continue
        name = q.rsplit(".", 1)[-1]
        why, s = [], 0.0
        if VALIDATOR_RE.search(name):
            s += 3; why.append("validator")
        sens = {x for x in lib_names.get(q, ()) if SENSITIVE_RE.search(x.rsplit(".", 1)[-1])}
        if select == "naive":
            src = "\n".join(facts.files.get(fn.file, "").splitlines()[fn.line - 1: fn.end_line])
            hits = len(set(m.group(0).lower() for m in SENSITIVE_RE.finditer(src)))
            s += min(hits, 4)
            if s > 0:
                out.append(Pick(q, s, why + [f"{hits} keywords"]))
            continue
        if sens:
            s += min(len(sens), 4); why.append("calls " + ", ".join(sorted(x.rsplit(".", 1)[-1] for x in sens)[:3]))
        if sink_cls.get(q):
            s += 3 * min(len(sink_cls[q]), 2); why.append("sink " + "/".join(sorted(sink_cls[q])))
        if guards.get(q):
            s += 1; why.append("guards input")
        src = "\n".join(facts.files.get(fn.file, "").splitlines()[fn.line - 1: fn.end_line])
        if INTERP_RE.search(src) and FORMAT_RE.search(src):
            s += 3; why.append("builds SQL/HTML/shell text")
        if s == 0:
            continue  # nothing security-relevant happens here
        surface = 0.0
        if q in reach:
            surface = 4; why.append("reachable from an entry point")
        elif in_view(q, fn):
            surface = 3; why.append("in a view class")
        elif getattr(facts, "package", False) and _public(q, fn):
            surface = 2; why.append("public library API")
        if q in touched:
            surface += 2; why.append("on a tainted path")
        if surface == 0:
            continue  # not on the attack surface the engine can see
        s += surface
        if q in explained:
            s -= 3; why.append("already reported")
        out.append(Pick(q, s, why))
    out.sort(key=lambda p: (-p.score, p.fn))
    return out


def chunks_for(facts: Facts, fn: str) -> list[tuple[str, int, str]]:
    """The function and its direct project callees, within MAX_LINES."""
    callees = sorted({g for k, g in facts.calls if k in facts.nodes and facts.nodes[k].fn == fn and g in facts.functions
                      and g != fn})
    out, total = [], 0
    for q in [fn] + callees:
        f = facts.functions[q]
        lines = facts.files.get(f.file, "").splitlines()[f.line - 1: f.end_line]
        if out and total + len(lines) > MAX_LINES:
            continue
        out.append((f.file, f.line, "\n".join(lines[:MAX_LINES])))
        total += len(lines)
    return out


def context_for(facts: Facts, pick: Pick) -> str:
    callers = sorted({facts.nodes[k].fn for k, g in facts.calls if g == pick.fn and k in facts.nodes})[:4]
    kind = "a library (distributable package)" if getattr(facts, "package", False) else "an application"
    lines = [f"Project: {kind}.", f"Function under review: {pick.fn} ({'; '.join(pick.why)})."]
    if callers:
        lines.append("Called from: " + ", ".join(callers) + ".")
    return "\n".join(lines)


def innermost(facts: Facts, file: str, line: int) -> str | None:
    best = None
    for q, f in facts.functions.items():
        if f.file == file and f.line <= line <= f.end_line and (best is None or f.line > facts.functions[best].line):
            best = q
    return best


def review(facts: Facts, a: Analysis, reader, cache_get, cache_put, budget: int | str | None = None,
           select: str = "engine") -> dict:
    """Read the top `budget` picks. Returns {"picks", "read", "cached", "issues": [...], "findings": [Finding],
    "proposals": [(pred, args, scope, confidence, rationale)]}. `cache_get(key)` / `cache_put(key, fn, issues)` persist
    reads (the same code is never read twice by the same reader)."""
    ranked = rank(facts, a, select)
    picks = ranked[:budget_for(len(ranked), budget)]
    reported = {(f.sink_fn, f.cls) for f in a.findings if f.status in ("confirmed", "undecided")}
    spec_sink_nodes = {m.node for m in a.matches if m.role == "sink"}
    res = {"picks": [p.fn for p in picks], "ranked": len(ranked), "read": 0, "cached": 0, "issues": [], "findings": [], "proposals": []}
    seen = set()
    for p in picks:
        chunks = chunks_for(facts, p.fn)
        ctx = context_for(facts, p)
        key = hashlib.sha256(json.dumps([reader.name, ctx, chunks]).encode()).hexdigest()[:24]
        found = cache_get(key)
        if found is None:
            found = [i.__dict__ for i in reader.read(chunks, ctx)]
            cache_put(key, p.fn, found)
            res["read"] += 1
        else:
            res["cached"] += 1
        shown = {(c[0], c[1] + i) for c in chunks for i in range(len(c[2].splitlines()))}
        for x in found:
            if x.get("cls") not in CWE or (x.get("file"), x.get("line")) not in shown:
                continue  # a cited line that was not in what the model saw is discarded
            if x.get("confidence", 0) < MIN_CONFIDENCE:
                continue
            at = innermost(facts, x["file"], x["line"]) or p.fn
            if (at, x["cls"]) in reported or (at, x["cls"]) in seen:
                continue  # the engine already reports it, or another read did
            seen.add((at, x["cls"]))
            res["issues"].append({**x, "picked": p.fn, "at": at})
            res["findings"].append(_finding(facts, p.fn, at, x))
            res["proposals"] += _teach(facts, x, at, spec_sink_nodes)
    return res


def _finding(facts: Facts, picked: str, at: str, x: dict) -> Finding:
    nodes = [n for n, nd in facts.nodes.items() if nd.fn == at and nd.file == x["file"] and nd.l1 == x["line"]]
    node = nodes[0] if nodes else next((n for n, nd in facts.nodes.items() if nd.fn == at), -1)
    g = Finding(source=node, sink=node, cls=x["cls"], status="undecided")
    g.fingerprint = hashlib.sha1(f"review|{at}|{x['cls']}".encode()).hexdigest()[:16]
    g.source_fn, g.sink_fn = picked, at
    g.file, g.line = x["file"], x["line"]
    g.source_kind, g.source_rule, g.sink_rule = "review", "guided-review", "guided-review"
    lines = facts.files.get(x["file"], "").splitlines()
    g.path = [Step(node, x["file"], x["line"], 1, x["line"], 1, at, "sink",
                   lines[x["line"] - 1].strip()[:80] if 0 < x["line"] <= len(lines) else "", note=x.get("reason", "")[:300])]
    g.assumptions = [{"asm": ["read_only", picked], "label": "Reported by a guided review; no engine path"}]
    return g


def _teach(facts: Facts, x: dict, at: str, spec_sink_nodes: set[int]) -> list[tuple]:
    """API-level knowledge in an issue: the library call at the cited line that the specs do not model as a sink, or a
    project validator the model says can be bypassed."""
    out = []
    call = (x.get("sink_call") or "").strip()
    if call and x.get("kind") != "validator_bypass":
        name = re.split(r"[(\s]", call.split(".")[-1] if "(" not in call else call.split("(")[0].split(".")[-1])[0]
        at_line = [(k, q) for k, q in facts.libcalls.items() if k in facts.nodes and facts.nodes[k].file == x["file"]
                   and facts.nodes[k].l1 <= x["line"] <= facts.nodes[k].l2 and q.rsplit(".", 1)[-1] == name]
        for k, q in at_line[:1]:
            if k in spec_sink_nodes or q == "<dynamic>":
                continue
            arg = x.get("arg") if isinstance(x.get("arg"), int) and x.get("arg") >= 0 else 0
            scope = "org" if q.startswith("*.") else "global"  # a bare method name means different things elsewhere
            out.append(("sink_api", [q, arg, x["cls"]], scope, x.get("confidence", 0.6), x.get("reason", "")[:300]))
    if x.get("kind") == "validator_bypass":
        v = (x.get("validator") or "").strip()
        cand = [q for q in facts.functions if v and (q == v or q.endswith("." + v))] or ([at] if VALIDATOR_RE.search(at) else [])
        for q in cand[:1]:
            out.append(("not_sanitizer", [q], "repo", x.get("confidence", 0.6), x.get("reason", "")[:300]))
    return out
