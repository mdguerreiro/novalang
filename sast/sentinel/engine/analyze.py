"""From program facts + knowledge to decided findings.

`analyze()` is the deterministic heart of Sentinel (Tier 0). It
1. emits EDB facts from the Python extractor and the Semgrep spec matches,
2. adds every *active* knowledge item (curated or learned) as Datalog facts,
3. evaluates the instrumented rule base with clingo, and
4. builds `Finding`s with a status, named mitigations, open assumptions, a witness path over the
   real code, and a proof tree taken from the derivation graph.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from ..extract.python_facts import Facts, is_test_path
from ..extract.semgrep_specs import SpecMatch
from .datalog import Model, Program, fact

CLASSES = ["sqli", "cmdi", "path", "xss", "ssti", "ssrf", "deser", "code", "redirect"]
CWE = {"sqli": "CWE-89", "cmdi": "CWE-78", "path": "CWE-22", "xss": "CWE-79", "ssti": "CWE-1336",
       "ssrf": "CWE-918", "deser": "CWE-502", "code": "CWE-95", "redirect": "CWE-601"}
TITLE = {"sqli": "SQL injection", "cmdi": "OS command injection", "path": "Path traversal",
         "xss": "Cross-site scripting", "ssti": "Server-side template injection",
         "ssrf": "Server-side request forgery", "deser": "Unsafe deserialization",
         "code": "Code injection", "redirect": "Open redirect"}
SEVERITY = {"sqli": "critical", "cmdi": "critical", "code": "critical", "deser": "critical",
            "ssti": "high", "path": "high", "ssrf": "high", "xss": "medium", "redirect": "medium"}
SANITIZER_LIKE = re.compile(r"(quote|escape|sanitiz|clean|safe|valid|filter|strip_tags|encode_for)", re.I)


@dataclass(frozen=True)
class KnowledgeFact:
    """A knowledge item as seen by the engine: one Datalog fact plus its identity."""
    kid: str
    pred: str  # sanitizer_api | propagator_api | safe_pred | not_safe_pred | safe_type | dead_fn | internal_only | not_sanitizer | weak_kind
    args: tuple

    def text(self) -> str:
        return fact(self.pred, *self.args)


# Curated base knowledge shipped with the engine (scope: global, origin: curated).
CURATED: list[KnowledgeFact] = [
    KnowledgeFact("K-cur-isdigit", "safe_pred", ("isdigit", "all")),
    KnowledgeFact("K-cur-isalnum", "safe_pred", ("isalnum", "all")),
    KnowledgeFact("K-cur-allowlist", "safe_pred", ("in_allowlist", "all")),
    KnowledgeFact("K-cur-hostallow", "safe_pred", ("host_allowlist", "ssrf")),
    KnowledgeFact("K-cur-isinst-int", "safe_pred", ("isinstance_int", "all")),
    KnowledgeFact("K-cur-int", "safe_type", ("int", "all")),
    KnowledgeFact("K-cur-float", "safe_type", ("float", "all")),
    KnowledgeFact("K-cur-uuid", "safe_type", ("uuid", "all")),
    KnowledgeFact("K-cur-bool", "safe_type", ("bool", "all")),
    KnowledgeFact("K-cur-cli-weak", "weak_kind", ("cli",)),
]


@dataclass
class Step:
    node: int
    file: str
    line: int
    col: int
    end_line: int
    end_col: int
    fn: str
    kind: str  # source | flow | call | param | return | guard | sanitizer | assumption | sink
    label: str
    note: str = ""
    other_kills: list[str] = field(default_factory=list)  # sanitizers here that protect *other* classes


@dataclass
class Finding:
    source: int
    sink: int
    cls: str
    status: str  # confirmed | undecided | mitigated | test_only
    fingerprint: str = ""
    mitigations: list[dict] = field(default_factory=list)  # {why, label, knowledge}
    assumptions: list[dict] = field(default_factory=list)  # {asm, label}
    path: list[Step] = field(default_factory=list)
    proof: dict | None = None
    source_fn: str = ""
    sink_fn: str = ""
    source_kind: str = ""
    source_rule: str = ""
    sink_rule: str = ""
    file: str = ""
    line: int = 0
    spec_knowledge: list[str] = field(default_factory=list)  # learned spec rules that located this source/sink

    @property
    def key(self) -> tuple[int, int, str]:
        return (self.source, self.sink, self.cls)

    @property
    def severity(self) -> str:
        return SEVERITY.get(self.cls, "medium")

    @property
    def title(self) -> str:
        return TITLE.get(self.cls, self.cls)


@dataclass
class Analysis:
    facts: Facts
    matches: list[SpecMatch]
    model: Model
    findings: list[Finding]
    knowledge: list[KnowledgeFact]

    def by_key(self) -> dict[tuple[int, int, str], Finding]:
        return {f.key: f for f in self.findings}


def edb(facts: Facts, matches: list[SpecMatch]) -> list[str]:
    out = [fact("cls", c) for c in CLASSES]
    for n in facts.nodes.values():
        out.append(fact("node", n.id, n.fn))
        if is_test_path(n.file):
            out.append(fact("test_node", n.id))
    out += [fact("edge", a, b) for a, b in facts.edges]
    out += [fact("call", k, g) for k, g in facts.calls]
    out += [fact("arg_in", k, i, a) for k, i, a in facts.arg_in]
    out += [fact("param", f, i, p) for f, i, p in facts.params]
    out += [fact("ret", f, r) for f, r in facts.rets]
    out += [fact("callname", k, q) for k, q in facts.callnames]
    out += [fact("libcall", k, q) for k, q in facts.libcalls.items()]
    out += [fact("guard", g, p) for g, p, _ in facts.guards]
    out += [fact("typed", n, t) for n, t in facts.typed]
    out += [fact("entry", f) for f, _ in facts.entrypoints]
    for fn, _name, conv, pid in facts.route_params:
        out.append(fact("src", pid, "route"))
    for q in facts.functions:
        if SANITIZER_LIKE.search(q.rsplit(".", 1)[-1]):
            out.append(fact("sanitizer_like", q))
    for m in matches:
        if m.node is None:
            continue
        if m.role == "source":
            out.append(fact("src", m.node, m.kind or "http"))
        elif m.role == "sink":
            out.append(fact("sink", m.node, m.cls))
        elif m.role == "sanitizer":
            out.append(fact("san", m.node, m.cls, m.rule_id))
    return out


KEEP = {"cand", "alarm", "mitigated", "undecided", "confirmed", "test_only", "asm", "mit", "assume_at",
        "kill", "reach", "safe", "open"}


def analyze(facts: Facts, matches: list[SpecMatch], knowledge: list[KnowledgeFact] | None = None,
            program: Program | None = None) -> Analysis:
    kn = list(CURATED) + list(knowledge or [])
    program = program or Program()
    model = program.solve(edb(facts, matches) + [k.text() for k in kn], keep=KEEP)
    return Analysis(facts, matches, model, build_findings(facts, matches, model, kn), kn)


# ── building findings ──────────────────────────────────────────────────────────────────

def _why_label(why, facts: Facts) -> str:
    if isinstance(why, tuple):
        kind, *args = why
        if kind == "api":
            return f"sanitized by {args[0]}"
        if kind == "guard":
            return f"validated by guard {args[0]}"
        if kind == "type":
            return f"value is typed {args[0]}"
        if kind == "dead":
            return f"dead code: {args[0]} is never executed"
        if kind == "exposure":
            return f"{args[0]} is not externally exposed"
    if isinstance(why, str) and why.startswith("spec."):
        return f"sanitized ({why})"
    return str(why)


def _asm_label(asm) -> str:
    if isinstance(asm, tuple):
        kind, *args = asm
        return {
            "unknown_api": f"assumed `{args[0]}` passes tainted data through (library call not modelled)",
            "unknown_guard": f"assumed guard `{args[0]}` does not validate the input",
            "maybe_sanitizer": f"assumed `{args[0]}` does not sanitize (looks like a sanitizer)",
            "weak_source": f"source kind `{args[0]}` may not be attacker-controlled",
            "unreachable": f"`{args[0]}` is not reachable from any entrypoint",
        }.get(kind, str(asm))
    return str(asm)


def knowledge_for(why, kn: list[KnowledgeFact]) -> list[str]:
    if not isinstance(why, tuple):
        return []
    kind, *args = why
    want = {"api": ("sanitizer_api", 0), "guard": ("safe_pred", 0), "type": ("safe_type", 0),
            "dead": ("dead_fn", 0), "exposure": ("internal_only", 0)}.get(kind)
    if not want:
        return []
    pred, idx = want
    return [k.kid for k in kn if k.pred == pred and k.args[idx] == args[0]]


def fingerprint(facts: Facts, src: int, sink: int, cls: str) -> str:
    s, k = facts.nodes[src], facts.nodes[sink]
    sig = "|".join([cls, s.fn, s.callee or s.label, k.fn, k.callee or _norm(k.label)])
    return hashlib.sha1(sig.encode()).hexdigest()[:16]


def _norm(label: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"'[^']*'|\"[^\"]*\"", "S", label))


def build_findings(facts: Facts, matches: list[SpecMatch], model: Model, kn: list[KnowledgeFact]) -> list[Finding]:
    status: dict[tuple, str] = {}
    for pred, st in (("confirmed", "confirmed"), ("undecided", "undecided"), ("test_only", "test_only")):
        for s, k, c in model.get(pred):
            status[(s, k, c)] = st
    mits: dict[tuple, list] = defaultdict(list)
    for s, k, c, w in model.get("mitigated"):
        status[(s, k, c)] = "mitigated"
        mits[(s, k, c)].append(w)
    asms: dict[tuple, list] = defaultdict(list)
    for s, k, c, a in model.get("asm"):
        asms[(s, k, c)].append(a)
    alarm_any = {(s, k, c) for s, k, c, m in model.get("alarm") if m == "any"}
    for s, k, c in model.get("cand"):
        status.setdefault((s, k, c), "mitigated")

    kills = defaultdict(set)
    for n, c, w in model.get("kill"):
        kills[(n, c)].add(w)
    asm_nodes = defaultdict(list)
    for n, a in model.get("assume_at"):
        asm_nodes[n].append(a)
    # Curated matches win the node when a learned rule matches the same span.
    src_rule = {m.node: m for m in sorted((m for m in matches if m.role == "source"), key=lambda m: m.knowledge is None)}
    sink_rule = {m.node: m for m in sorted((m for m in matches if m.role == "sink"), key=lambda m: m.knowledge is None)}
    rule_kid = {m.rule_id: m.knowledge for m in matches if m.knowledge}  # learned spec rule id -> knowledge item
    derivs = model.derivations()

    findings = []
    graph = _Graph(facts)
    for (s, k, c), st in sorted(status.items()):
        sn, kn_ = facts.nodes[s], facts.nodes[k]
        f = Finding(source=s, sink=k, cls=c, status=st)
        f.fingerprint = fingerprint(facts, s, k, c)
        f.source_fn, f.sink_fn = sn.fn, kn_.fn
        sm = src_rule.get(s)
        f.source_kind = sm.kind if sm else ("route" if sn.kind == "param" else "")
        f.source_rule = sm.rule_id if sm else "route-parameter"
        f.sink_rule = sink_rule[k].rule_id if k in sink_rule else ""
        f.file, f.line = sn.file, sn.l1
        uniq = []
        for w in mits.get((s, k, c), []):
            if w not in uniq:
                uniq.append(w)
        f.mitigations = [{"why": _jsonable(w), "label": _why_label(w, facts),
                          "knowledge": [rule_kid[w]] if isinstance(w, str) and w in rule_kid else knowledge_for(w, kn)}
                         for w in uniq]
        f.spec_knowledge = sorted({m.knowledge for m in (sm, sink_rule.get(k)) if m is not None and m.knowledge})
        seen = []
        for a in asms.get((s, k, c), []) if (s, k, c) in alarm_any else []:
            if a not in seen:
                seen.append(a)
        f.assumptions = [{"asm": _jsonable(a), "label": _asm_label(a)} for a in seen]
        avoid = st in ("confirmed", "undecided")
        f.path = graph.witness(s, k, c, kills, asm_nodes, avoid_kills=avoid)
        f.proof = proof_tree(derivs, _status_atom(f), facts)
        findings.append(f)
    return dedupe(findings)


STATUS_RANK = {"confirmed": 0, "undecided": 1, "test_only": 2, "mitigated": 3}


def dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per fingerprint (e.g. two `execute` sinks in the same helper), keeping the most
    severe status, and merging assumptions and mitigations across its flows."""
    best: dict[str, Finding] = {}
    for f in findings:
        cur = best.get(f.fingerprint)
        if cur is None or STATUS_RANK[f.status] < STATUS_RANK[cur.status]:
            if cur is not None:
                f.assumptions += [a for a in cur.assumptions if a not in f.assumptions]
            best[f.fingerprint] = f
        else:
            cur.assumptions += [a for a in f.assumptions if a not in cur.assumptions]
            if cur.status == "mitigated":
                cur.mitigations += [m for m in f.mitigations if m not in cur.mitigations]
    return sorted(best.values(), key=lambda f: (f.file, f.line, f.cls))


def _jsonable(v):
    if isinstance(v, tuple):
        return [v[0], *[_jsonable(a) for a in v[1:]]]
    return v


def _status_atom(f: Finding) -> str:
    """The status atom exactly as clingo prints it, so it can be looked up in the derivation graph."""
    if f.status == "mitigated" and f.mitigations:
        return f"mitigated({f.source},{f.sink},{_term_str(f.cls)},{_term_str(f.mitigations[0]['why'])})"
    pred = {"confirmed": "confirmed", "undecided": "undecided", "test_only": "test_only"}.get(f.status, "cand")
    return f"{pred}({f.source},{f.sink},{_term_str(f.cls)})"


def _term_str(v) -> str:
    if isinstance(v, list):
        return f"{v[0]}({','.join(_term_str(a) for a in v[1:])})"
    if isinstance(v, int):
        return str(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def proof_tree(derivs: dict, atom: str, facts: Facts, depth: int = 0, seen: frozenset = frozenset()) -> dict:
    node = {"atom": atom}
    if depth > 7 or atom in seen or atom not in derivs:
        return node
    rid, pos, neg = min(derivs[atom], key=lambda d: (len(d[1]), d[0]))
    node["rule"] = rid
    node["children"] = [proof_tree(derivs, p, facts, depth + 1, seen | {atom}) for p in pos
                        if not p.startswith(("cls(", "mode(", "node("))]
    if neg:
        node["absent"] = neg
    return node


class _Graph:
    """Explicit value-flow graph used to find a human-readable witness path."""

    def __init__(self, facts: Facts):
        self.f = facts
        self.succ = defaultdict(list)
        for a, b in facts.edges:
            self.succ[a].append(b)
        self.args = defaultdict(list)  # arg node -> [(call, index)]
        for k, i, a in facts.arg_in:
            self.args[a].append((k, i))
        self.callee = dict(facts.calls)
        self.params = {(fn, i): p for fn, i, p in facts.params}
        self.rets = defaultdict(list)
        for fn, r in facts.rets:
            self.rets[fn].append(r)
        self.callers = defaultdict(list)
        for k, g in facts.calls:
            self.callers[g].append(k)

    def _next(self, n: int, stack: tuple):
        for b in self.succ[n]:
            yield b, stack, "flow"
        for k, i in self.args[n]:
            g = self.callee.get(k)
            p = self.params.get((g, i)) if g else None
            if p is not None and len(stack) < 6:
                yield p, stack + (k,), "param"
        node = self.f.nodes[n]
        if n in self.rets.get(node.fn, []):
            if stack:
                yield stack[-1], stack[:-1], "return"
            else:
                for k in self.callers.get(node.fn, []):
                    yield k, stack, "return"

    def witness(self, s: int, k: int, cls: str, kills, asm_nodes, avoid_kills: bool) -> list[Step]:
        for avoid in ([True, False] if avoid_kills else [False]):
            path = self._bfs(s, k, cls, kills, avoid)
            if path:
                return self._steps(path, cls, kills, asm_nodes, s, k)
        return self._steps([(s, "source"), (k, "flow")], cls, kills, asm_nodes, s, k)

    def _bfs(self, s, k, cls, kills, avoid):
        start = (s, ())
        prev = {start: None}
        how = {start: "source"}
        q = deque([start])
        while q:
            cur = q.popleft()
            n, stack = cur
            if n == k:
                out = []
                while cur is not None:
                    out.append((cur[0], how[cur]))
                    cur = prev[cur]
                return list(reversed(out))
            for b, st, kind in self._next(n, stack):
                if avoid and (kills.get((b, cls)) or kills.get((b, "all"))):
                    continue
                nxt = (b, st)
                if nxt not in prev:
                    prev[nxt] = cur
                    how[nxt] = kind
                    q.append(nxt)
        return None

    def _steps(self, path, cls, kills, asm_nodes, s, k) -> list[Step]:
        steps = []
        for n, how in path:
            node = self.f.nodes[n]
            kind = {"param": "param", "return": "return"}.get(how, "flow")
            note = ""
            if n == s:
                kind = "source"
            elif n == k:
                kind = "sink"
            elif node.kind == "guard":
                kind = "guard"
            elif kills.get((n, cls)):
                kind = "sanitizer"
                note = ", ".join(_why_label(w, self.f) for w in kills[(n, cls)])
            elif how == "return":
                kind = "return"
            elif node.kind == "call" and n in self.callee:
                kind = "call"
            if n in asm_nodes and kind not in ("source", "sink"):
                kind = "assumption" if kind == "flow" else kind
                note = "; ".join(_asm_label(a) for a in asm_nodes[n])
            if node.kind == "guard" and kills.get((n, cls)):
                note = ", ".join(_why_label(w, self.f) for w in kills[(n, cls)])
            other = sorted({_why_label(w, self.f) for (n2, c2), ws in kills.items() if n2 == n and c2 != cls for w in ws}
                           - {_why_label(w, self.f) for w in kills.get((n, cls), ())})
            steps.append(Step(n, node.file, node.l1, node.c1, node.l2, node.c2, node.fn, kind, node.label, note, other))
        # One step per source line: a plain `flow` step on the same line as its predecessor adds
        # nothing, and a more specific step replaces a plain `flow` on its line.
        compact: list[Step] = []
        for st in steps:
            same_line = compact and compact[-1].line == st.line and compact[-1].file == st.file
            if same_line and st.kind == "flow":
                continue
            if same_line and compact[-1].kind == "flow":
                compact[-1] = st
                continue
            compact.append(st)
        return compact
