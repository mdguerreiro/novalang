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
import logging
import os
import shutil
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from ..extract.python_facts import Facts, is_test_path
from ..extract.semgrep_specs import SpecMatch
from .datalog import Model, Program, fact

CLASSES = ["sqli", "cmdi", "path", "xss", "ssti", "ssrf", "deser", "code", "redirect", "xxe"]
CWE = {"sqli": "CWE-89", "cmdi": "CWE-78", "path": "CWE-22", "xss": "CWE-79", "ssti": "CWE-1336",
       "ssrf": "CWE-918", "deser": "CWE-502", "code": "CWE-95", "redirect": "CWE-601", "xxe": "CWE-611",
       "idor": "CWE-639"}
TITLE = {"sqli": "SQL injection", "cmdi": "OS command injection", "path": "Path traversal",
         "xss": "Cross-site scripting", "ssti": "Server-side template injection",
         "ssrf": "Server-side request forgery", "deser": "Unsafe deserialization",
         "code": "Code injection", "redirect": "Open redirect", "xxe": "XML external entity",
         "idor": "Missing object-level authorization"}
SEVERITY = {"sqli": "critical", "cmdi": "critical", "code": "critical", "deser": "critical",
            "ssti": "high", "path": "high", "ssrf": "high", "xss": "medium", "redirect": "medium", "xxe": "high",
            "idor": "high"}
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
    KnowledgeFact("K-cur-contained", "safe_pred", ("path_contained", "path")),
    KnowledgeFact("K-cur-isinst-int", "safe_pred", ("isinstance_int", "all")),
    KnowledgeFact("K-cur-int", "safe_type", ("int", "all")),
    KnowledgeFact("K-cur-float", "safe_type", ("float", "all")),
    KnowledgeFact("K-cur-uuid", "safe_type", ("uuid", "all")),
    KnowledgeFact("K-cur-bool", "safe_type", ("bool", "all")),
    KnowledgeFact("K-cur-any-conv", "safe_type", ("any", "all")),
    KnowledgeFact("K-cur-cli-weak", "weak_kind", ("cli",)),
    KnowledgeFact("K-cur-archive-weak", "weak_kind", ("archive",)),
    # Outside data that is attacker-controlled only in some deployments: a library's API input, a remote server's reply.
    KnowledgeFact("K-cur-api-weak", "weak_kind", ("api",)),
    KnowledgeFact("K-cur-network-weak", "weak_kind", ("network",)),
    KnowledgeFact("K-cur-fixed-host", "safe_type", ("fixed_host", "ssrf")),
    KnowledgeFact("K-cur-fixed-host-r", "safe_type", ("fixed_host", "redirect")),
    KnowledgeFact("K-cur-rel-path", "safe_type", ("relative_path", "redirect")),
    # Authentication is not authorization; permission/role decorators are.
    KnowledgeFact("K-cur-login-req", "not_authz_decorator", ("flask_login.login_required",)),
    KnowledgeFact("K-cur-login-req2", "not_authz_decorator", ("flask_login.utils.login_required",)),
    KnowledgeFact("K-cur-dj-login-req", "not_authz_decorator", ("django.contrib.auth.decorators.login_required",)),
    KnowledgeFact("K-cur-dj-perm", "authz_decorator", ("django.contrib.auth.decorators.permission_required",)),
    KnowledgeFact("K-cur-fs-roles", "authz_decorator", ("flask_security.roles_required",)),
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
    learned: list[dict] = field(default_factory=list)  # frontier-learned sink/source facts this finding depends on

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


# Sinks that execute what they are given. A library's public API parameters reach them only by the caller's choice,
# but whoever calls the library with outside data (a model file, a template, a downloaded record) is exposed.
EXEC_CLASSES = ("code", "ssti", "deser", "cmdi")
API_DEPTH = 3  # call levels above an execution sink whose public parameters count as API input


def _public(q: str, fn) -> bool:
    if is_test_path(fn.file):
        return False
    parts = q.split(".")
    return not any(p.startswith("_") and not (p.startswith("__") and p.endswith("__")) for p in parts)


def api_sources(facts: Facts, matches: list[SpecMatch]) -> list[tuple[str, int, int]]:
    """(function, index, param node) for parameters of public functions within API_DEPTH calls of an execution sink.
    Only in a distributable package: an application's helpers are called by the application, not by outsiders."""
    if not getattr(facts, "package", False):
        return []
    sink_fns = {facts.nodes[m.node].fn for m in matches
                if m.role == "sink" and m.cls in EXEC_CLASSES and m.node in facts.nodes}
    sink_fns |= {facts.nodes[n].fn for n, c in facts.extra_sinks if c in EXEC_CLASSES and n in facts.nodes}
    callers: dict[str, set[str]] = {}
    for k, g in facts.calls:
        if k in facts.nodes:
            callers.setdefault(g, set()).add(facts.nodes[k].fn)
    methods: dict[str, set[str]] = {}
    for q, fn in facts.functions.items():
        if fn.cls:
            methods.setdefault(fn.cls, set()).add(q)
    near, frontier = set(sink_fns), set(sink_fns)
    for _ in range(API_DEPTH):
        # Data enters an object through any of its methods (the constructor, a setter) and reaches the sink through
        # another: a method near a sink brings its class's other methods with it.
        frontier |= {m for f in frontier if facts.functions.get(f) and facts.functions[f].cls
                     for m in methods.get(facts.functions[f].cls, ())}
        frontier = {c for f in frontier for c in callers.get(f, ())} | frontier
        frontier -= near
        near |= frontier
    out = []
    for f, i, p in facts.params:
        fn = facts.functions.get(f)
        if f in near and fn and _public(f, fn) and fn.params[i:i + 1] not in (["self"], ["cls"]):
            out.append((f, i, p))
    return out


def edb(facts: Facts, matches: list[SpecMatch]) -> list[str]:
    out = [fact("cls", c) for c in CLASSES]
    out += [fact("kind_cls", "api", c) for c in EXEC_CLASSES]
    out += [fact("src", p, "api") for _f, _i, p in api_sources(facts, matches)]
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
    out += [fact("lib_arg", k, i, a) for k, i, a in facts.lib_args]
    out += [fact("decorated", f, d) for f, d in facts.decorated]
    out += [fact("fn_ref", k, i, f) for k, i, f in facts.fn_refs]
    out += [fact("attrname", n, q) for n, q in facts.attrnames]
    out += [fact("sink", n, c) for n, c in facts.extra_sinks]
    out += [fact("self_param", p) for q, i, p in facts.params if i == 0 and facts.functions[q].cls
            and facts.functions[q].params[:1] in (["self"], ["cls"])]
    out += [fact("store_w", w, key, x) for w, key, x in facts.store_writes]
    out += [fact("store_r", r, key) for r, key in facts.store_reads]
    out += [fact("file_w", w, p, x) for w, p, x in facts.file_writes]
    out += [fact("file_r", r, q) for r, q in facts.file_reads]
    out += [fact("lookup", k, m) for k, m in facts.lookups]
    out += [fact("lookup_dep", k, n) for k, n in facts.lookup_deps]
    out += [fact("user_ref", n) for n in facts.user_refs]
    out += [fact("scoped", k) for k in facts.scoped]
    out += [fact("compare", a, b) for a, b in facts.compares]
    out += [fact("owner_field", m, n) for m, n in facts.owner_fields]
    # Any handler parameter can be a record key (`book_title`, `username`, `doc_id`); `self`/`request` cannot.
    out += [fact("id_param", q, i) for q, fn in facts.functions.items() for i, p in enumerate(fn.params)
            if p not in ("self", "cls", "request", "req")]
    # A user/account model is owned by the user it represents.
    out += [fact("owner_field", c, "<self>") for c in facts.classes if SELF_OWNED_RE.search(c.rsplit(".", 1)[-1])]
    out += [fact("route_dec", d) for _f, d in facts.decorated if ROUTE_DEC_RE.search(d)]
    tops = {q.split(".")[0] for q in facts.functions}
    out += [fact("lib_dec", d) for d in {d for _f, d in facts.decorated}
            if d and d.split(".")[0] not in tops and not GENERIC_DEC_RE.search(d)]
    # HTTP-verb methods of classes that extend a library class (tornado RequestHandler, MethodView, falcon resources)
    out += [fact("http_method", q) for q, fn in facts.functions.items()
            if fn.cls and q.rsplit(".", 1)[-1] in HTTP_METHOD_NAMES
            and any(b not in facts.classes for b in facts.classes.get(fn.cls, []))]
    out += [fact("generic_reg", q) for q in {q for _k, q in facts.callnames}
            if q.startswith("*.") and q[2:] in GENERIC_METHODS or q in BUILTIN_CALLS]
    out += [fact("generic_api", q) for q in {q for _k, q in facts.callnames} | set(facts.libcalls.values())
            if q.startswith("*.") or q == "<dynamic>" or q in _BUILTINS]  # builtin sinks are curated
    out += [fact("test_fn", q) for q, fn in facts.functions.items() if is_test_path(fn.file)]
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


SELF_OWNED_RE = re.compile(r"^(User|Account|Profile|Member|Customer)(Model)?$")
ROUTE_DEC_RE = re.compile(r"\.(route|get|post|put|patch|delete|api_route|websocket)$|^functools\.wraps$")
GENERIC_DEC_RE = re.compile(r"^(functools|typing|abc|contextlib|dataclasses|pytest|unittest|enum|asyncio)\.|"
                            r"^(property|staticmethod|classmethod|cached_property|lru_cache|wraps|overload|override)$|"
                            r"\.(setter|getter|deleter)$")
HTTP_METHOD_NAMES = {"get", "post", "put", "patch", "delete", "head", "options", "on_get", "on_post", "on_put",
                     "on_patch", "on_delete", "GET", "POST", "PUT", "DELETE", "do_GET", "do_POST", "do_PUT", "do_DELETE"}
_BUILTINS = set(dir(__import__("builtins")))
# Callbacks handed to these are not request handlers (and builtins are never registrars).
GENERIC_METHODS = {"append", "extend", "insert", "add", "update", "setdefault", "get", "pop", "remove", "sort",
                   "connect", "submit", "map", "apply_async", "start", "register"}
BUILTIN_CALLS = {"map", "filter", "sorted", "min", "max", "list", "tuple", "set", "dict", "partial",
                 "functools.partial", "functools.wraps", "functools.reduce", "atexit.register", "threading.Thread",
                 "signal.signal"}
KEEP = {"cand", "alarm", "mitigated", "undecided", "confirmed", "test_only", "asm", "mit", "assume_at",
        "kill", "reach", "safe", "open", "sink_frontier", "src_frontier", "learned_sink", "learned_src", "reg_frontier",
        "authz_frontier", "privacy_frontier", "dec_frontier",
        "srcapi_frontier", "html_frontier", "handler_of", "read_signal", "stored_at"}


_DEFAULT_PROGRAM: Program | None = None


def default_program() -> Program:
    """The rule base compiled once per process (instrumenting it is not free)."""
    global _DEFAULT_PROGRAM
    if _DEFAULT_PROGRAM is None:
        # Soufflé (compiled, 3-22x faster on large repos, same results) when installed; SENTINEL_ENGINE=clingo opts out.
        engine = os.environ.get("SENTINEL_ENGINE") or ("souffle" if shutil.which("souffle") else "clingo")
        if engine == "souffle":
            try:
                from .souffle import SouffleProgram
                _DEFAULT_PROGRAM = SouffleProgram(outputs=KEEP)
            except Exception as e:  # a broken toolchain must not stop a scan: the reference engine takes over
                logging.getLogger(__name__).warning("Soufflé unavailable (%s); using clingo", e)
                _DEFAULT_PROGRAM = Program()
        else:
            _DEFAULT_PROGRAM = Program()
    return _DEFAULT_PROGRAM


def analyze(facts: Facts, matches: list[SpecMatch], knowledge: list[KnowledgeFact] | None = None,
            program: Program | None = None) -> Analysis:
    kn = list(CURATED) + list(knowledge or [])
    program = program or default_program()
    model = program.solve(edb(facts, matches) + [k.text() for k in kn], keep=KEEP)
    return Analysis(facts, matches, model, build_findings(facts, matches, model, kn), kn)


# ── building findings ──────────────────────────────────────────────────────────────────

def _tail(name: str, parts: int = 2) -> str:
    return ".".join(str(name).removeprefix("call:").split(".")[-parts:])


GUARD_NAMES = {"in_allowlist": "allow-list check", "host_allowlist": "host allow-list", "path_contained": "path stays in base directory"}


def _why_label(why, facts: Facts) -> str:
    """Short label for a mitigation, as shown in the UI checklist and trace."""
    if isinstance(why, tuple):
        kind, *args = why
        if kind == "api":
            return f"Sanitizer: {_tail(args[0])}"
        if kind == "guard":
            pred = str(args[0])
            name = GUARD_NAMES.get(pred, f"{_tail(pred)}()" if not pred.startswith("regex") else pred)
            return f"Validation: {name}"
        if kind == "type":
            return {"fixed_host": "Fixed host in URL", "relative_path": "Relative path"}.get(args[0], f"Type cast: {args[0]}")
        if kind == "dead":
            return f"Dead code: {_tail(args[0], 1)}()"
        if kind == "exposure":
            return f"Internal only: {_tail(args[0], 1)}()"
        if kind == "authz":
            return f"Authorization: @{_tail(args[0])}"
    if why == "owner_check":
        return "Owner checked against current user"
    if why == "scoped_query":
        return "Query scoped to current user"
    if isinstance(why, str) and why.startswith("spec."):
        return f"Sanitizer: {why.split('.', 3)[-1]}"
    return str(why)


def _asm_label(asm) -> str:
    """Short label for an open assumption."""
    if isinstance(asm, tuple):
        kind, *args = asm
        return {
            "unknown_api": f"Unmodelled call: {args[0]}",
            "unknown_guard": f"Unverified validation: {_tail(args[0])}",
            "maybe_sanitizer": f"Unverified sanitizer: {_tail(args[0])}",
            "weak_source": f"Weak source: {args[0]}",
            "unreachable": f"No route or caller: {_tail(args[0], 1)}()",
            "unknown_authz": f"Unverified decorator: @{_tail(args[0])}",
            "unknown_privacy": f"Unverified: {_tail(args[0])} records are private",
            "authz_context": "Authorization outside the handler not checked",
        }.get(kind, str(asm))
    return str(asm)


def knowledge_for(why, kn: list[KnowledgeFact]) -> list[str]:
    if not isinstance(why, tuple):
        return []
    kind, *args = why
    want = {"api": ("sanitizer_api", 0), "guard": ("safe_pred", 0), "type": ("safe_type", 0),
            "dead": ("dead_fn", 0), "exposure": ("internal_only", 0),
            "authz": ("authz_decorator", 0)}.get(kind)
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
    # Engines enumerate atoms in different orders (clingo, Soufflé): read every relation sorted, so findings,
    # their mitigation/assumption lists and witness paths do not depend on the backend.
    get = lambda pred: sorted(model.get(pred), key=repr)
    status: dict[tuple, str] = {}
    for pred, st in (("confirmed", "confirmed"), ("undecided", "undecided"), ("test_only", "test_only")):
        for s, k, c in get(pred):
            status[(s, k, c)] = st
    mits: dict[tuple, list] = defaultdict(list)
    for s, k, c, w in get("mitigated"):
        status[(s, k, c)] = "mitigated"
        mits[(s, k, c)].append(w)
    asms: dict[tuple, list] = defaultdict(list)
    for s, k, c, a in get("asm"):
        asms[(s, k, c)].append(a)
    alarm_any = {(s, k, c) for s, k, c, m in get("alarm") if m == "any"}
    for s, k, c in get("cand"):
        status.setdefault((s, k, c), "mitigated")

    kills = defaultdict(set)
    for n, c, w in get("kill"):
        kills[(n, c)].add(w)
    asm_nodes = defaultdict(list)
    for n, a in get("assume_at"):
        asm_nodes[n].append(a)
    # Curated matches win the node when a learned rule matches the same span.
    src_rule = {m.node: m for m in sorted((m for m in matches if m.role == "source"), key=lambda m: m.knowledge is None)}
    sink_rule = {m.node: m for m in sorted((m for m in matches if m.role == "sink"), key=lambda m: m.knowledge is None)}
    rule_kid = {m.rule_id: m.knowledge for m in matches if m.knowledge}  # learned spec rule id -> knowledge item
    learned_sink, learned_src = defaultdict(set), defaultdict(set)
    for n, q in get("learned_sink"):
        learned_sink[n].add(q)
    for n, x in get("learned_src"):
        learned_src[n].add(x)
    stored = defaultdict(set)
    for r, key in get("stored_at"):
        stored[r].add(key)
    derivs = model.derivations()

    findings = []
    graph = _Graph(facts)
    route = {pid for _f, _n, _c, pid in facts.route_params}
    api = {p for _f, _i, p in api_sources(facts, matches)} - route
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
        for q in sorted(learned_sink.get(k, ())):
            f.learned.append({"kind": "sink", "subject": q,
                              "knowledge": [x.kid for x in kn if x.pred == "sink_api" and x.args[0] == q]})
        for x in sorted(learned_src.get(s, ())):
            f.learned.append({"kind": "source", "subject": x,
                              "knowledge": [y.kid for y in kn if y.pred in ("framework_source", "entry_source", "registrar", "source_api")
                                            and y.args[0] == x]})
        if not sm and s in api:
            f.source_kind, f.source_rule = "api", "library-api"
        if not sm and learned_src.get(s):
            f.source_kind, f.source_rule = "http", "learned-source"
        if not sm and stored.get(s):  # read back from a table / model / file that holds attacker data
            f.source_kind, f.source_rule = "stored", "stored:" + sorted(stored[s])[0]
        if k not in sink_rule and learned_sink.get(k):
            f.sink_rule = "learned:" + sorted(learned_sink[k])[0]
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
    # API input is the fallback attack surface: where a reported request (or other non-API) flow already reaches a
    # sink, the API finding there adds nothing. A library passing its own arguments to a program's argument list is
    # how libraries work, not argument injection: API input does not count for that sink.
    reached = {(f.sink, f.cls) for f in findings if f.source_kind != "api" and f.status in ("confirmed", "undecided")}
    findings = [f for f in findings if f.source_kind != "api"
                or ((f.sink, f.cls) not in reached and f.sink_rule != "spec.sink.cmdi.subprocess-argv")]
    # "Library input reaches this sink" is one issue per sink, whichever public function it enters through: keep the
    # shortest path (the entry closest to the sink).
    best: dict[tuple[int, str], Finding] = {}
    for f in findings:
        if f.source_kind == "api":
            k_ = (f.sink, f.cls)
            if k_ not in best or (len(f.path), f.source_fn) < (len(best[k_].path), best[k_].source_fn):
                best[k_] = f
    findings = [f for f in findings if f.source_kind != "api" or best.get((f.sink, f.cls)) is f]
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
    rid, pos, neg = min(derivs[atom], key=lambda d: (len(d[1]), d[0], d[1], d[2]))
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

    MAX_STATES = 2_000_000  # (node, call stack) states; beyond it no witness is shown (as when the search is exhausted)

    def _reaches(self, k: int) -> set[int]:
        """Nodes that can reach k at all (call/return matching ignored): the stack-aware search never needs others."""
        cache = self.__dict__.setdefault("_reach_cache", {})
        if k in cache:
            return cache[k]
        rev = self.__dict__.get("_rev")
        if rev is None:
            rev = defaultdict(set)
            for a, bs in self.succ.items():
                for b in bs:
                    rev[b].add(a)
            for a, uses in self.args.items():
                for c, i in uses:
                    g = self.callee.get(c)
                    p = self.params.get((g, i)) if g else None
                    if p is not None:
                        rev[p].add(a)
            for fn, rs in self.rets.items():
                for c in self.callers.get(fn, ()):
                    for r in rs:
                        rev[c].add(r)
            self._rev = rev
        seen, todo = {k}, [k]
        while todo:
            for a in rev.get(todo.pop(), ()):
                if a not in seen:
                    seen.add(a)
                    todo.append(a)
        cache[k] = seen
        return seen

    def _bfs(self, s, k, cls, kills, avoid):
        ok = self._reaches(k)
        if s not in ok:
            return None
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
                if b not in ok or (avoid and (kills.get((b, cls)) or kills.get((b, "all")))):
                    continue
                nxt = (b, st)
                if nxt not in prev:
                    prev[nxt] = cur
                    how[nxt] = kind
                    q.append(nxt)
            if len(prev) > self.MAX_STATES:
                return None  # a path that ignores call/return matching could name functions the flow never visits
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
