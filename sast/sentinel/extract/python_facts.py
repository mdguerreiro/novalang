"""Python front-end: turns source files into value-flow facts for the Datalog engine.

The extractor performs a lightweight reaching-definitions analysis per function, so
re-binding a variable (``x = int(x)``) is not conflated with its earlier tainted value.
Every value-carrying expression gets an integer node id. ``edge(a, b)`` means the value
of node ``a`` flows into node ``b``. Guards (``if not x.isdigit(): abort()``) become
*refinement nodes* that sit between the old and new definition of ``x``, so the engine
can treat a validated value exactly like a sanitized one.

Calls to project functions are not given direct argument-to-result edges. Instead the
engine composes them through summaries (``call``/``arg_in``/``param``/``ret`` facts).
Library calls that are not modelled anywhere are recorded as assumption points
(``unknown_call``): the engine assumes they propagate taint, and the neural tier can be
asked whether that assumption holds.
"""
from __future__ import annotations

import ast
import hashlib
import re
import textwrap
import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# Library calls whose result carries the taint of their inputs. These are well understood,
# so they create no assumption.
PROPAGATORS = {
    "str", "repr", "format", "list", "tuple", "set", "dict", "sorted", "reversed", "bytes",
    "bytes.fromhex", "os.path.join", "os.path.normpath", "os.path.abspath", "os.path.expanduser",
    "os.fspath", "pathlib.Path", "urllib.parse.unquote", "base64.b64decode", "json.loads",
    "json.dumps",
}
PROPAGATOR_METHODS = {
    "strip", "lstrip", "rstrip", "lower", "upper", "title", "casefold", "replace", "format",
    "encode", "decode", "split", "rsplit", "join", "get", "items", "values", "keys", "copy",
    "removeprefix", "removesuffix", "zfill", "center", "ljust", "rjust", "partition", "pop",
}
# Calls whose result never carries attacker-controlled data.
NEUTRAL = {
    "len", "bool", "isinstance", "hash", "id", "type", "range", "print", "abort",
    "flask.abort", "flask.url_for", "flask.jsonify", "flask.Flask", "logging.getLogger",
    "time.time", "uuid.uuid4", "re.compile", "sqlite3.connect", "enumerate", "zip", "min", "max",
}
NEUTRAL_METHODS = {
    "cursor", "fetchall", "fetchone", "close", "commit", "isdigit", "isalnum", "isnumeric",
    "isdecimal", "isalpha", "startswith", "endswith", "count", "index", "find",
}
# Current-user identity (object-level authorization).
IDENTITY_RE = re.compile(r"(^|\.)(current_user|current_identity)(\.|\(|$)|"
                         r"(^|\.)(get_current_user|get_jwt_identity|get_current_identity|get_user)(\(|$)|"
                         r"^flask\.(g\.user|session)(\.|\[|$)")
IDENTITY_PARAMS = {"current_user", "user_identity", "auth_user"}  # FastAPI-style `current_user: User = Depends(...)`
OWNER_FIELD_RE = re.compile(r"^(owner|user|author|created_by|account|tenant|customer|patient|member|uploader)(_id)?$")
SQL_WRITE_RE = re.compile(r"\b(?:INSERT\s+(?:OR\s+\w+\s+)?INTO|REPLACE\s+INTO|UPDATE)\s+[`\"\[]?(\w+)", re.I)
SQL_READ_RE = re.compile(r"\b(?:FROM|JOIN)\s+[`\"\[]?(\w+)", re.I)
SQL_EXEC = {"execute", "executemany", "executescript"}
SQL_FETCH = {"fetchone", "fetchall", "fetchmany", "scalars", "scalar", "first", "all", "one", "mappings"}
ORM_READ_RE = re.compile(r"^(?P<m>.+?)\.(query|objects)\.\w+")
ORM_BASE_RE = re.compile(r"(^|\.)(Model|Base|Document|DeclarativeBase|SQLModel|EmbeddedDocument)$")
LOOKUP_RE = re.compile(r"^(?P<m>.+)\.(query\.(get|get_or_404|filter_by|filter|first_or_404)|objects\.(get|filter))$")
CHA_MAX_TARGETS = 12
MUTATORS = {"append", "extend", "insert", "add", "update", "setdefault", "appendleft", "put", "push"}
NORMALIZERS = {"os.path.abspath", "os.path.realpath", "os.path.normpath", "posixpath.abspath", "posixpath.realpath",
               "posixpath.normpath", "werkzeug.security.safe_join", "flask.safe_join"}
HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")
CONFIG_BARE_RE = re.compile(r"\s*-?\s*[\"']?([A-Za-z_][\w-]*)[\"']?\s*[:=]\s*[\"']?([A-Za-z_][\w.]*)[\"']?\s*,?\s*$")
CONFIG_SUFFIXES = {".yml", ".yaml", ".json", ".toml", ".ini", ".cfg"}
CONFIG_REF_RE = re.compile(r"[\"']?([A-Za-z_][\w-]*)[\"']?\s*[:=]\s*[\"']?([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*[.:][A-Za-z_]\w*)[\"']?\s*,?\s*$")
FIXED_HOST_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/?#{}%@]+[/?#]")
EXIT_CALLS = {"abort", "flask.abort", "sys.exit", "exit", "os._exit"}
SAFE_CONVERTERS = {"int", "float", "uuid", "any"}  # werkzeug any(a, b): one of the listed literals
TEST_PATH_RE = re.compile(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$")
HOST_ATTRS = {"hostname", "netloc"}


@dataclass
class Node:
    id: int
    fn: str
    file: str
    l1: int
    c1: int
    l2: int
    c2: int
    kind: str  # use | def | param | call | expr | guard | ret | attr | sub | const
    label: str = ""
    callee: str | None = None


@dataclass
class Function:
    qname: str
    file: str
    line: int
    end_line: int
    params: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    is_entry: bool = False
    cls: str | None = None  # enclosing class for methods
    route: str | None = None


@dataclass
class Facts:
    nodes: dict[int, Node] = field(default_factory=dict)
    functions: dict[str, Function] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)  # relpath -> content
    edges: set[tuple[int, int]] = field(default_factory=set)
    calls: set[tuple[int, str]] = field(default_factory=set)  # call node -> callee qname (project fn)
    arg_in: set[tuple[int, int, int]] = field(default_factory=set)  # call, index, arg node
    params: set[tuple[str, int, int]] = field(default_factory=set)  # fn, index, param node
    rets: set[tuple[str, int]] = field(default_factory=set)  # fn, returned node
    libcalls: dict[int, str] = field(default_factory=dict)  # call node -> library callee name
    guards: set[tuple[int, str, str]] = field(default_factory=set)  # guard node, predicate, var
    typed: set[tuple[int, str]] = field(default_factory=set)  # node, type (converters, annotations)
    route_params: set[tuple[str, str, str, int]] = field(default_factory=set)  # fn, name, converter, node
    entrypoints: set[tuple[str, str]] = field(default_factory=set)
    callnames: set[tuple[int, str]] = field(default_factory=set)  # every call node -> qualified callee
    lib_args: set[tuple[int, int | str, int]] = field(default_factory=set)  # library call, position or keyword, arg node
    decorated: set[tuple[str, str]] = field(default_factory=set)  # function, resolved decorator
    classes: dict[str, list[str]] = field(default_factory=dict)  # project class -> resolved bases
    extra_sinks: set[tuple[int, str]] = field(default_factory=set)  # sinks found by the extractor (template escaping off)
    lookups: set[tuple[int, str]] = field(default_factory=set)  # call node -> project model it loads a record of
    lookup_deps: set[tuple[int, int]] = field(default_factory=set)  # lookup call -> value node used in its arguments
    user_refs: set[int] = field(default_factory=set)  # nodes reading the current user's identity
    scoped: set[int] = field(default_factory=set)  # lookup calls whose arguments mention the current user
    compares: set[tuple[int, int]] = field(default_factory=set)  # operand nodes compared with each other
    owner_fields: set[tuple[str, str]] = field(default_factory=set)  # model class, owner-like column
    fn_refs: set[tuple[int, int | str, str]] = field(default_factory=set)  # call, arg position/keyword, project fn passed
    attrnames: set[tuple[int, str]] = field(default_factory=set)  # attribute node -> resolved library name (flask.request.args)
    config_sites: dict[str, str] = field(default_factory=dict)  # config:<key> -> one example line
    skipped: list[tuple[str, str]] = field(default_factory=list)  # functions the extractor could not analyse
    ambiguous: set[tuple[int, str, int]] = field(default_factory=set)  # call, method name, candidate count
    resolved: dict[int, str] = field(default_factory=dict)  # call node -> how it was resolved (cha | self | import | ctor)
    pred_sources: dict[str, str] = field(default_factory=dict)  # predicate -> source text (for the oracle)
    # Stored data (second-order flows): what is written to / read from a table, a model or a file.
    store_writes: set[tuple[int, str, int]] = field(default_factory=set)  # write call, key (db:t | orm:M), value written
    store_reads: set[tuple[int, str]] = field(default_factory=set)  # read node, key
    file_writes: set[tuple[int, int, int]] = field(default_factory=set)  # write call, path node, content node
    file_reads: set[tuple[int, int]] = field(default_factory=set)  # open() call reading a file, path node

    def _flow_graph(self) -> tuple[dict[int, set[int]], dict[int, set[int]]]:
        """Over-approximate interprocedural value flow between nodes (intra edges, argument -> parameter,
        returned value -> call site, lookup argument -> lookup), ignoring call/return matching. Cached."""
        g = self.__dict__.get("_flow")
        if g is None:
            succ: dict[int, set[int]] = defaultdict(set)
            for a, b in self.edges:
                succ[a].add(b)
            params = defaultdict(dict)
            for f, i, p in self.params:
                params[f][i] = p
            rets = defaultdict(list)
            for f, r in self.rets:
                rets[f].append(r)
            callee = defaultdict(set)
            for k, gq in self.calls:
                callee[k].add(gq)
                for r in rets.get(gq, ()):
                    succ[r].add(k)
            for k, i, a in self.arg_in:
                for gq in callee.get(k, ()):
                    p = params.get(gq, {}).get(i)
                    if p is not None:
                        succ[a].add(p)
            for k, n in self.lookup_deps:
                succ[n].add(k)
            pred: dict[int, set[int]] = defaultdict(set)
            for a, bs in succ.items():
                for b in bs:
                    pred[b].add(a)
            g = self.__dict__["_flow"] = (succ, pred)
        return g

    def chop(self, pairs, all_callees: bool = False) -> tuple[set[str], set[int]]:
        """Functions (and heap cells) that can matter to the given (source node, sink node) findings: every
        node value-reachable from the sources, interprocedurally and through heap cells, where a function
        that holds a reached node also contributes its parameters (its summaries start there) and, with
        `all_callees`, every function it calls. A re-analysis of the slice decides those findings as the
        whole program would (checked against whole-program solves on the held-out repositories)."""
        succ, _pred = self._flow_graph()
        idx = self.__dict__.get("_fn_index")
        if idx is None:
            fparams, callees = defaultdict(list), defaultdict(set)
            for f, _i, p in self.params:
                fparams[f].append(p)
            for k, g in self.calls:
                if k in self.nodes:
                    callees[self.nodes[k].fn].add(g)
            idx = self.__dict__["_fn_index"] = (fparams, callees)
        fparams, callees = idx
        seen = {s for s, _k in pairs} | {k for _s, k in pairs}
        todo, fns = list(seen), set()

        def add_fn(f: str) -> None:
            stack = [f]
            while stack:
                g = stack.pop()
                if g in fns:
                    continue
                fns.add(g)
                for p in fparams.get(g, ()):
                    if p not in seen:
                        seen.add(p); todo.append(p)
                if all_callees:
                    stack += [h for h in callees.get(g, ()) if h not in fns]
        while todo:
            n = todo.pop()
            nd = self.nodes.get(n)
            if nd is not None and nd.kind != "heap" and nd.fn not in fns:
                add_fn(nd.fn)
            for m in succ.get(n, ()):
                if m not in seen:
                    seen.add(m); todo.append(m)
        heap = {n for n in seen if n in self.nodes and self.nodes[n].kind == "heap"}
        return fns, heap

    def slice(self, fns: set[str], extra_nodes: set[int] = frozenset()) -> "Facts":
        """The facts of `fns` (all their nodes) plus `extra_nodes`; relations are restricted to kept nodes."""
        keep = {i for i, n in self.nodes.items() if n.fn in fns} | set(extra_nodes)
        kf = set(fns)
        return Facts(
            nodes={i: self.nodes[i] for i in keep}, functions={q: f for q, f in self.functions.items() if q in kf},
            files=self.files, edges={(a, b) for a, b in self.edges if a in keep and b in keep},
            calls={(k, g) for k, g in self.calls if k in keep and g in kf},
            arg_in={x for x in self.arg_in if x[0] in keep and x[2] in keep},
            params={x for x in self.params if x[0] in kf}, rets={x for x in self.rets if x[0] in kf},
            libcalls={k: q for k, q in self.libcalls.items() if k in keep},
            guards={x for x in self.guards if x[0] in keep}, typed={x for x in self.typed if x[0] in keep},
            route_params={x for x in self.route_params if x[0] in kf},
            entrypoints={x for x in self.entrypoints if x[0] in kf},
            callnames={x for x in self.callnames if x[0] in keep},
            lib_args={x for x in self.lib_args if x[0] in keep and x[2] in keep},
            decorated={x for x in self.decorated if x[0] in kf}, classes=self.classes,
            extra_sinks={x for x in self.extra_sinks if x[0] in keep},
            lookups={x for x in self.lookups if x[0] in keep},
            lookup_deps={x for x in self.lookup_deps if x[0] in keep and x[1] in keep},
            user_refs={n for n in self.user_refs if n in keep}, scoped={n for n in self.scoped if n in keep},
            compares={x for x in self.compares if x[0] in keep and x[1] in keep}, owner_fields=self.owner_fields,
            fn_refs={x for x in self.fn_refs if x[0] in keep and x[2] in kf},
            attrnames={x for x in self.attrnames if x[0] in keep}, config_sites=self.config_sites,
            resolved={k: v for k, v in self.resolved.items() if k in keep}, pred_sources=self.pred_sources,
            store_writes={x for x in self.store_writes if x[0] in keep and x[2] in keep},
            store_reads={x for x in self.store_reads if x[0] in keep},
            file_writes={x for x in self.file_writes if x[0] in keep and x[1] in keep and x[2] in keep},
            file_reads={x for x in self.file_reads if x[0] in keep and x[1] in keep})

    def node_at(self, file: str, l1: int, c1: int, l2: int, c2: int) -> Node | None:
        """Exact span match first, then the smallest node that contains the span."""
        best = None
        for n in self.nodes.values():
            if n.file != file or n.kind in ("def", "guard", "param"):
                continue
            if (n.l1, n.c1, n.l2, n.c2) == (l1, c1, l2, c2):
                return n
            if (n.l1, n.c1) <= (l1, c1) and (n.l2, n.c2) >= (l2, c2):
                if best is None or _span_size(n) < _span_size(best):
                    best = n
        return best


def _span_size(n: Node) -> tuple[int, int]:
    return (n.l2 - n.l1, (n.c2 - n.c1) if n.l1 == n.l2 else 10_000 + n.c2)


def module_name(relpath: str) -> str:
    p = relpath[:-3] if relpath.endswith(".py") else relpath
    parts = p.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def is_test_path(relpath: str) -> bool:
    return bool(TEST_PATH_RE.search(relpath))


BUILTIN_NAMES = set(dir(__import__("builtins")))


class _Module:
    def __init__(self, relpath: str, tree: ast.Module):
        self.relpath = relpath
        self.name = module_name(relpath)
        self.package = self.name if relpath.endswith("__init__.py") else self.name.rpartition(".")[0]
        self.imports: dict[str, str] = {}
        self.local_defs: set[str] = set()
        self.global_calls: dict[str, str] = {}  # module-level `x = Something(...)`: x -> dotted callee
        self.global_names: set[str] = set()  # module-level variables (shared state between handlers)
        self.tree = tree
        for stmt in tree.body:
            self._collect(stmt)
        # Imports inside function bodies (`from PIL import ImageMath` in a handler): module-wide is a close
        # enough approximation, and never shadows a module-level import of the same name.
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for st in ast.walk(node):
                    if isinstance(st, (ast.Import, ast.ImportFrom)):
                        saved = dict(self.imports)
                        self._collect(st)
                        self.imports.update(saved)

    def _collect(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, ast.Import):
            for a in stmt.names:
                self.imports[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(stmt, ast.ImportFrom):
            base = stmt.module or ""
            if stmt.level:
                pkg = self.package.split(".") if self.package else []
                if stmt.level > 1:
                    pkg = pkg[: len(pkg) - (stmt.level - 1)]
                base = ".".join(pkg + ([base] if base else []))
            for a in stmt.names:
                self.imports[a.asname or a.name] = f"{base}.{a.name}" if base else a.name
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.local_defs.add(stmt.name)
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            for t in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]):
                if isinstance(t, ast.Name):
                    self.global_names.add(t.id)
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name) \
                and isinstance(stmt.value, ast.Call):
            callee = PythonExtractor._dotted(stmt.value.func)
            if callee:
                self.global_calls[stmt.targets[0].id] = callee


class PythonExtractor:
    def __init__(self, root: Path):
        self.root = root
        self.facts = Facts()
        self._next = 1
        self._modules: dict[str, _Module] = {}
        self._by_name: dict[str, _Module] = {}
        self._heap: dict[str, int] = {}
        self._fn_ast: dict[str, tuple] = {}
        self.pred_summary: dict[str, tuple[int, str]] = {}  # predicate function -> (param index, guard predicate)

    # ── public API ──────────────────────────────────────────────────────────
    def run(self) -> Facts:
        for path in sorted(self.root.rglob("*.py")):
            rel = path.relative_to(self.root).as_posix()
            if any(part.startswith(".") for part in rel.split("/")):
                continue
            src = path.read_text(encoding="utf-8")
            self.facts.files[rel] = src
            try:
                with warnings.catch_warnings():  # customer code: invalid escapes etc. are not our business
                    warnings.simplefilter("ignore")
                    tree = ast.parse(src, filename=rel)
            except SyntaxError:
                continue
            self._modules[rel] = _Module(rel, tree)
        self._by_name = {m.name: m for m in self._modules.values()}
        self._tops = {n.split(".")[0] for n in self._by_name}
        # Index every function first so calls can be resolved across modules.
        for rel, mod in self._modules.items():
            self._index_functions(mod, mod.tree.body, mod.name)
        for q, (mod, node) in self._fn_ast.items():
            summary = self._predicate_summary(mod, node)
            if summary:
                self.pred_summary[q] = summary
        for rel, mod in self._modules.items():
            self._walk_defs(mod, mod.tree.body, mod.name)
            self._module_registrations(mod)
        self._config_registrations()
        return self.facts

    def _config_registrations(self) -> None:
        """Handlers declared in configuration rather than code: OpenAPI `operationId: pkg.views.get_user`
        (Connexion), serverless/SAM `handler: app.main`, task routes... Every `key: dotted.name` that resolves to a
        project function becomes a function reference under the registrar `config:<key>`; whether that key
        registers request handlers is one frontier question per key."""
        for path in sorted(self.root.rglob("*")):
            if path.suffix.lower() not in CONFIG_SUFFIXES or not path.is_file() or path.stat().st_size > 1_000_000:
                continue
            rel = path.relative_to(self.root).as_posix()
            if any(part.startswith(".") or part in ("node_modules", "venv", ".venv") for part in rel.split("/")):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = text.splitlines()
            for ln, line in enumerate(lines, 1):
                refs = [(m.group(1), m.group(2).replace(":", ".")) for m in CONFIG_REF_RE.finditer(line)]
                bare = CONFIG_BARE_RE.match(line)
                if not refs and bare:
                    # Module and function on adjacent keys (`x-openapi-router-controller: vAPI` + `operationId:
                    # get_token`): combine with a nearby value that names a project module.
                    for near in lines[max(0, ln - 4): ln + 3]:
                        mm = CONFIG_BARE_RE.match(near)
                        if mm and mm.group(2) in self._by_name:
                            refs.append((bare.group(1), f"{mm.group(2)}.{bare.group(2)}"))
                            break
                for key, ref in refs:
                    target = self._config_target(ref)
                    if not target:
                        continue
                    nid = self.new_node("<config>", rel, None, "call", label=line.strip()[:80], callee=f"config:{key}",
                                        span=(ln, 1, ln, len(line) + 1))
                    self.facts.callnames.add((nid, f"config:{key}"))
                    self.facts.fn_refs.add((nid, 0, target))
                    self.facts.config_sites[f"config:{key}"] = f"{rel}:{ln}: {line.strip()[:160]}"

    def _config_target(self, ref: str) -> str | None:
        if ref in self.facts.functions:
            return ref
        hits = [q for q in self.facts.functions if q.endswith("." + ref)]  # path prefix omitted in config
        return hits[0] if len(hits) == 1 else None

    def _module_registrations(self, mod: _Module) -> None:
        """Module-level calls that hand project functions to a framework (`urlpatterns = [path("x", views.x)]`,
        `app.add_url_rule("/", view_func=index)`). Only the call and the function references are recorded."""
        for stmt in mod.tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
                continue
            for e in ast.walk(stmt):
                if not isinstance(e, ast.Call):
                    continue
                refs = []
                for key, a in [(i, x) for i, x in enumerate(e.args)] + [(k.arg, k.value) for k in e.keywords if k.arg]:
                    d = self._dotted(a) if isinstance(a, (ast.Name, ast.Attribute)) else None
                    ref = self.resolve(mod, d) if d else None
                    if ref in self.facts.functions:
                        refs.append((key, ref))
                    refs += [(key, m) for m in self.view_refs(mod, a)]
                if not refs:
                    continue
                d = self._dotted(e.func)
                qual = self.resolve(mod, d) if d else "<dynamic>"
                if d and d.split(".")[0] not in mod.imports and d.split(".")[0] not in mod.global_calls and "." in d:
                    qual = "*." + d.rsplit(".", 1)[1]
                nid = self.new_node(f"{mod.name}.<module>", mod.relpath, e, "call", label=ast.unparse(e)[:80], callee=qual)
                self.facts.callnames.add((nid, qual))
                for key, ref in refs:
                    self.facts.fn_refs.add((nid, key, ref))

    # ── function indexing ───────────────────────────────────────────────────
    def _index_functions(self, mod: _Module, body: list[ast.stmt], prefix: str) -> None:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}.{stmt.name}"
                fn = Function(q, mod.relpath, stmt.lineno, stmt.end_lineno or stmt.lineno,
                              [a.arg for a in stmt.args.posonlyargs + stmt.args.args])
                for dec in stmt.decorator_list:
                    target = dec.func if isinstance(dec, ast.Call) else dec
                    dname = self.resolve(mod, self._dotted(target) or "")
                    fn.decorators.append(dname)
                    if dname:
                        self.facts.decorated.add((q, dname))
                    if dname.split(".")[-1] in ("route", "get", "post", "put", "delete", "patch"):
                        fn.is_entry = True
                        if isinstance(dec, ast.Call) and dec.args and isinstance(dec.args[0], ast.Constant):
                            fn.route = str(dec.args[0].value)
                self.facts.functions[q] = fn
                self._fn_ast[q] = (mod, stmt)
                if fn.is_entry:
                    self.facts.entrypoints.add((q, "http_route"))
                self._index_functions(mod, stmt.body, q)
            elif isinstance(stmt, ast.ClassDef):
                cq = f"{prefix}.{stmt.name}"
                for st in stmt.body:
                    names = [t.id for t in (st.targets if isinstance(st, ast.Assign) else [st.target] if isinstance(st, ast.AnnAssign) else [])
                             if isinstance(t, ast.Name)]
                    self.facts.owner_fields.update((cq, n) for n in names if OWNER_FIELD_RE.match(n))
                self.facts.classes[cq] = [self.resolve(mod, d) for d in (self._dotted(b) for b in stmt.bases) if d]
                self._index_functions(mod, stmt.body, cq)
                for q, fn in self.facts.functions.items():
                    if q.rpartition(".")[0] == cq:
                        fn.cls = cq

    def _walk_defs(self, mod: _Module, body: list[ast.stmt], prefix: str) -> None:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}.{stmt.name}"
                try:
                    _FunctionWalker(self, mod, self.facts.functions[q], stmt).walk()
                except (RecursionError, SyntaxError, ValueError, KeyError) as e:  # one odd function never aborts a scan
                    self.facts.skipped.append((q, f"{type(e).__name__}: {e}"[:200]))
                self._walk_defs(mod, stmt.body, q)
            elif isinstance(stmt, ast.ClassDef):
                self._walk_defs(mod, stmt.body, f"{prefix}.{stmt.name}")

    # ── helpers ─────────────────────────────────────────────────────────────
    def new_node(self, fn: str, file: str, at: ast.AST | None, kind: str, label: str = "",
                 callee: str | None = None, span: tuple[int, int, int, int] | None = None) -> int:
        nid = self._next
        self._next += 1
        if span is None:
            assert at is not None
            span = (at.lineno, at.col_offset + 1, at.end_lineno or at.lineno, (at.end_col_offset or 0) + 1)
        self.facts.nodes[nid] = Node(nid, fn, file, *span, kind=kind, label=label, callee=callee)
        return nid

    @staticmethod
    def _dotted(e: ast.AST) -> str | None:
        parts = []
        while isinstance(e, ast.Attribute):
            parts.append(e.attr)
            e = e.value
        if isinstance(e, ast.Name):
            parts.append(e.id)
            return ".".join(reversed(parts))
        return None

    def resolve(self, mod: _Module, dotted: str, depth: int = 0) -> str:
        """Qualified name for a dotted expression. Module-level objects are replaced by the call that
        created them, so `http.request` in a module with `http = urllib3.PoolManager()` resolves to
        `urllib3.PoolManager().request` (also across modules: `from .db import engine`)."""
        head, _, rest = dotted.partition(".")
        tail = f".{rest}" if rest else ""
        if depth < 4 and head in mod.global_calls:
            return self.resolve(mod, mod.global_calls[head], depth + 1) + "()" + tail
        if head in mod.imports:
            base = self._localize(mod, mod.imports[head])
            owner, _, name = base.rpartition(".")
            other = self._by_name.get(owner)
            if depth < 4 and other is not None and name in other.global_calls:
                return self.resolve(other, other.global_calls[name], depth + 1) + "()" + tail
            return f"{base}{tail}"
        if head in mod.local_defs:
            return f"{mod.name}.{dotted}"
        return dotted

    def _localize(self, mod: _Module, base: str) -> str:
        """Script-style imports (`import libuser` run from the script's directory, i.e. sys.path[0]): when the
        name is not a top-level project module but a sibling of the importing module is, it means the sibling."""
        if base.split(".")[0] in self._tops or not mod.package:
            return base
        cand = f"{mod.package}.{base}"
        parts = cand.split(".")
        if any(".".join(parts[:i]) in self._by_name for i in range(len(parts), mod.package.count(".") + 1, -1)):
            return cand
        return base

    def self_attrs(self, cls: str) -> set[str]:
        if not hasattr(self, "_self_attrs"):
            self._self_attrs: dict[str, set[str]] = {}
            for mod in self._modules.values():
                for node in ast.walk(mod.tree):
                    if isinstance(node, ast.ClassDef):
                        cq = next((c for c in self.facts.classes if c.endswith("." + node.name) and
                                   c.startswith(mod.name)), None)
                        if cq:
                            self._self_attrs[cq] = {t.attr for t in ast.walk(node) if isinstance(t, ast.Attribute)
                                                    and isinstance(t.ctx, ast.Store) and isinstance(t.value, ast.Name)
                                                    and t.value.id == "self"}
        return self._self_attrs.get(cls, set())

    def _predicate_summary(self, mod: _Module, node) -> tuple[int, str] | None:
        """A project predicate that returns a recognised guard on one of its parameters:
        `return abspath(p).startswith(base)`, or `if not <guard on p>: return False ... return True`.
        Calling it then is that guard on the argument (interprocedural guard summary)."""
        params = [a.arg for a in node.args.posonlyargs + node.args.args]
        norm: dict[str, str] = {}  # local -> parameter it normalises

        def param_of(e):
            if isinstance(e, ast.Name):
                return e.id if e.id in params else norm.get(e.id)
            if isinstance(e, ast.Call) and self._normalizer_name(mod, e):
                for a in ast.walk(e):
                    if isinstance(a, ast.Name) and (a.id in params or a.id in norm):
                        return a.id if a.id in params else norm[a.id]
            return None

        def guard(test):
            if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) and \
                    test.func.attr in ("startswith", "is_relative_to"):
                pv = param_of(test.func.value)
                if pv and (test.func.value.id in norm if isinstance(test.func.value, ast.Name) else True):
                    return pv, "path_contained"
            return None

        body = [st for st in node.body if not (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant))]
        found = None
        for st in body:
            if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) and \
                    isinstance(st.value, ast.Call) and self._normalizer_name(mod, st.value):
                pv = param_of(st.value)
                if pv:
                    norm[st.targets[0].id] = pv
            elif isinstance(st, ast.Return) and st.value is not None and found is None:
                g = guard(st.value)
                if g:
                    return params.index(g[0]), g[1]
            elif isinstance(st, ast.If) and isinstance(st.test, ast.UnaryOp) and isinstance(st.test.op, ast.Not) and \
                    st.body and isinstance(st.body[-1], ast.Return) and isinstance(st.body[-1].value, ast.Constant) and \
                    st.body[-1].value.value is False:
                g = guard(st.test.operand)
                if g and found is None:
                    found = g
        last = body[-1] if body else None
        if found and isinstance(last, ast.Return) and isinstance(last.value, ast.Constant) and last.value.value is True:
            return params.index(found[0]), found[1]
        return None

    def _normalizer_name(self, mod: _Module, call: ast.Call) -> bool:
        if isinstance(call.func, ast.Attribute) and call.func.attr in ("resolve", "absolute"):
            return True
        d = self._dotted(call.func)
        return bool(d) and self.resolve(mod, d) in NORMALIZERS

    def template_files(self) -> dict[str, str]:
        if not hasattr(self, "_templates"):
            self._templates = {}
            for p in self.root.rglob("*"):
                if p.suffix in (".html", ".htm", ".jinja", ".jinja2", ".j2") and p.is_file() and p.stat().st_size < 500_000:
                    try:
                        self._templates[p.relative_to(self.root).as_posix()] = p.read_text(errors="replace")
                    except OSError:
                        pass
        return self._templates

    def heap_node(self, key: str, file: str) -> int:
        """One abstract cell per module global / class field (field-based, context-insensitive heap)."""
        if key not in self._heap:
            self._heap[key] = self.new_node("<heap>", file, None, "heap", label=key, span=(1, 1, 1, 1))
        return self._heap[key]

    def view_refs(self, mod: _Module, a: ast.expr) -> list[str]:
        """`ManageForum.as_view("manage")` (Flask MethodView, Django class-based views): the class's HTTP-verb
        methods are what the framework calls."""
        if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr == "as_view":
            d = self._dotted(a.func.value)
            cls = self.resolve(mod, d) if d else None
            if cls in self.facts.classes:
                return [m for v in HTTP_VERBS for m in [self.method(cls, v)] if m]
        return []

    def methods_named(self, name: str) -> list[str]:
        if not hasattr(self, "_by_method"):
            self._by_method: dict[str, list[str]] = {}
            for q, fn in self.facts.functions.items():
                if fn.cls and fn.params[:1] == ["self"] and not q.rsplit(".", 1)[1].startswith("__"):
                    self._by_method.setdefault(q.rsplit(".", 1)[1], []).append(q)
        return sorted(self._by_method.get(name, []))

    def method(self, cls: str, name: str, depth: int = 0) -> str | None:
        """Class-hierarchy lookup of `name` on project class `cls`: a project function, or None."""
        q = f"{cls}.{name}"
        if q in self.facts.functions:
            return q
        for b in self.facts.classes.get(cls, []) if depth < 8 else []:
            if b in self.facts.classes:
                r = self.method(b, name, depth + 1)
                if r:
                    return r
        return None

    def through_class(self, qual: str) -> str:
        """`app.User.query.filter_by` where `User(db.Model)` defines no `query`: the attribute comes from the
        (library) base class, so name it after that base, `flask_sqlalchemy.SQLAlchemy().Model.query.filter_by`.
        One question per library API instead of one per model class."""
        parts = qual.split(".")
        for i in range(len(parts) - 1, 0, -1):
            cls = ".".join(parts[:i])
            if cls in self.facts.classes:
                if self.method(cls, parts[i]):
                    return qual
                ext = [b for b in self.facts.classes[cls] if b not in self.facts.classes]
                proj = [b for b in self.facts.classes[cls] if b in self.facts.classes]
                for b in proj:  # inherited through a project base
                    r = self.through_class(".".join([b] + parts[i:]))
                    if r != ".".join([b] + parts[i:]) or not ext:
                        return r
                return ".".join([ext[0]] + parts[i:]) if ext else qual
        return qual


Env = dict[str, frozenset[int]]


def _merge(*envs: Env) -> Env:
    out: dict[str, set[int]] = {}
    for env in envs:
        for k, v in env.items():
            out.setdefault(k, set()).update(v)
    return {k: frozenset(v) for k, v in out.items()}


class _FunctionWalker:
    """Reaching-definitions walk over one function body, emitting nodes and edges."""

    def __init__(self, ex: PythonExtractor, mod: _Module, fn: Function, node: ast.FunctionDef):
        self.ex, self.mod, self.fn, self.node = ex, mod, fn, node
        self.f = ex.facts
        self.file = mod.relpath
        self.hosts: dict[str, str] = {}  # var holding urlparse(<url>).hostname -> url var
        self.types: dict[str, str] = {}  # local var -> project class (from `x = Class(...)`)
        self.aliases: dict[str, str] = {}  # local bound from shared state -> its heap cell
        self.normalized: set[str] = set()  # locals holding a normalised path (abspath/realpath/normpath/resolve)
        self.sql_cursor: dict[str, set[str]] = {}  # cursor var -> tables its last SELECT read (for fetch*())
        self.sql_read_nodes: dict[int, set[str]] = {}  # execute(SELECT ...) node -> tables (chained .fetchall())
        self.open_for_write: tuple[int, int] | None = None  # last open(path, "w") in this function: (call, path node)

    def walk(self) -> None:
        env: Env = {}
        args = self.node.args
        all_args = args.posonlyargs + args.args
        route_conv = _route_converters(self.fn.route)
        for i, a in enumerate(all_args):
            pid = self.ex.new_node(self.fn.qname, self.file, a, "param", label=a.arg)
            self.f.params.add((self.fn.qname, i, pid))
            if a.arg in IDENTITY_PARAMS:
                self.f.user_refs.add(pid)
            env[a.arg] = frozenset({pid})
            if self.fn.is_entry and a.arg in route_conv:
                conv = route_conv[a.arg]
                self.f.route_params.add((self.fn.qname, a.arg, conv, pid))
                if conv in SAFE_CONVERTERS:
                    self.f.typed.add((pid, conv))
            if a.annotation is not None:
                ann = self.ex._dotted(a.annotation) or ""
                if ann in ("int", "float", "bool", "uuid.UUID", "UUID"):
                    self.f.typed.add((pid, ann.split(".")[-1].lower()))
        self.block(self.node.body, env)

    # ── statements ──────────────────────────────────────────────────────────
    def block(self, stmts: list[ast.stmt], env: Env) -> Env:
        for s in stmts:
            env = self.stmt(s, env)
        return env

    def stmt(self, s: ast.stmt, env: Env) -> Env:
        if isinstance(s, ast.Assign):
            v = self.expr(s.value, env)
            for t in s.targets:
                if isinstance(t, ast.Name):
                    if self._is_normalizer(s.value):
                        self.normalized.add(t.id)
                    else:
                        self.normalized.discard(t.id)
                    cls = self._ctor_class(s.value)
                    if cls:
                        self.types[t.id] = cls
                    else:
                        self.types.pop(t.id, None)
            for t in s.targets:
                env = self.bind(t, v, env, s.value)
            return env
        if isinstance(s, ast.AnnAssign):
            if s.value is None:
                return env
            v = self.expr(s.value, env)
            return self.bind(s.target, v, env, s.value)
        if isinstance(s, ast.AugAssign):
            v = self.expr(s.value, env)
            old = self.expr(s.target, env) if isinstance(s.target, ast.Name) else None
            src = {x for x in (v, old) if x}
            return self.bind(s.target, src, env, s.value)
        if isinstance(s, ast.Expr):
            self.expr(s.value, env)
            return env
        if isinstance(s, ast.Return):
            if s.value is not None:
                r = self.expr(s.value, env)
                if r:
                    self.f.rets.add((self.fn.qname, r))
            return env
        if isinstance(s, ast.If):
            return self.if_stmt(s, env)
        if isinstance(s, (ast.For, ast.AsyncFor)):
            it = self.expr(s.iter, env)
            start = self.bind(s.target, it, env, s.iter)
            once = self.block(s.body, start)
            twice = self.block(s.body, _merge(start, once))
            after = _merge(env, once, twice)
            return self.block(s.orelse, after) if s.orelse else after
        if isinstance(s, ast.While):
            self.expr(s.test, env)
            once = self.block(s.body, env)
            twice = self.block(s.body, _merge(env, once))
            return _merge(env, once, twice)
        if isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                v = self.expr(item.context_expr, env)
                if item.optional_vars is not None:
                    env = self.bind(item.optional_vars, v, env, item.context_expr)
            return self.block(s.body, env)
        if isinstance(s, ast.Try):
            body = self.block(s.body, env)
            outs = [body]
            for h in s.handlers:
                outs.append(self.block(h.body, _merge(env, body)))
            merged = _merge(*outs)
            if s.orelse:
                merged = _merge(merged, self.block(s.orelse, body))
            if s.finalbody:
                merged = self.block(s.finalbody, merged)
            return merged
        if isinstance(s, ast.Assert):
            g = self.guard_info(s.test)
            if g:
                return self.refine(env, g, s)
            self.expr(s.test, env)
            return env
        return env

    def if_stmt(self, s: ast.If, env: Env) -> Env:
        self.expr(s.test, env)
        g_pos = self.guard_info(s.test)
        g_neg = self.guard_info(s.test, negate=True)
        if not g_pos and not g_neg:
            g_pos, g_neg = self._opaque_guard(s.test, env)
        body_env = self.refine(env, g_pos, s) if g_pos else env
        else_env = self.refine(env, g_neg, s) if g_neg else env
        out_body = self.block(s.body, body_env)
        out_else = self.block(s.orelse, else_env)
        body_exits = self.exits(s.body)
        else_exits = bool(s.orelse) and self.exits(s.orelse)
        if body_exits and not else_exits:
            return out_else
        if else_exits and not body_exits:
            return out_body
        return _merge(out_body, out_else)

    def exits(self, stmts: list[ast.stmt]) -> bool:
        if not stmts:
            return False
        last = stmts[-1]
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
            name = self.ex._dotted(last.value.func)
            if name and self.ex.resolve(self.mod, name) in EXIT_CALLS | {"flask.abort"}:
                return True
        if isinstance(last, ast.If):
            return self.exits(last.body) and self.exits(last.orelse)
        return False

    # ── guards ──────────────────────────────────────────────────────────────
    def guard_info(self, test: ast.expr, negate: bool = False) -> list[tuple[str, str]] | None:
        """Return [(var, predicate)] that hold when `test` evaluates to (not negate)."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.guard_info(test.operand, not negate)
        if isinstance(test, ast.BoolOp):
            parts = [self.guard_info(v, negate) for v in test.values]
            # `a and b` true => both hold; `not (a or b)` => neither... only the conjunctive case is useful.
            if isinstance(test.op, ast.And) and not negate:
                return [p for ps in parts if ps for p in ps] or None
            if isinstance(test.op, ast.Or) and negate:
                return None
            return None
        if negate:
            # `not P(x)` is only useful as a fall-through refinement when the branch exits.
            inner = self._positive_guard(test, negated_context=True)
            return inner
        return self._positive_guard(test, negated_context=False)

    def _opaque_guard(self, test: ast.expr, env: Env) -> tuple[list | None, list | None]:
        """A check the engine cannot interpret (`urlsplit(nxt).netloc != ""`, `is_safe(u)`) that inspects a
        variable through a call or attribute: both branches become unverified-validation points instead of the
        check being invisible. Truthiness/emptiness tests (`if not x`) are not validation and stay invisible."""
        inspected = set()
        for node in ast.walk(test):
            if isinstance(node, ast.Call):
                for a in list(node.args) + [k.value for k in node.keywords]:
                    inspected |= {n.id for n in ast.walk(a) if isinstance(n, ast.Name) and n.id in env}
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in env:
                    inspected.add(node.func.value.id)
        if not inspected:
            return None, None
        text = ast.get_source_segment(self.f.files[self.file], test) or ast.unparse(test)
        pred = "expr:" + " ".join(text.split())[:160]
        self.f.pred_sources[pred] = text
        self.f.pred_sources["not " + pred] = "not (" + text + ")"
        return [(v, pred) for v in sorted(inspected)], [(v, "not " + pred) for v in sorted(inspected)]

    def _positive_guard(self, test: ast.expr, negated_context: bool) -> list[tuple[str, str]] | None:
        # For negated_context we want predicates that hold when `test` is FALSE.
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op, right, left = test.ops[0], test.comparators[0], test.left
            membership_true = isinstance(op, ast.In) and not negated_context
            membership_false = isinstance(op, ast.NotIn) and negated_context
            if (membership_true or membership_false) and isinstance(left, ast.Name):
                if isinstance(right, (ast.Set, ast.List, ast.Tuple)) or (
                        isinstance(right, (ast.Name, ast.Attribute)) and (self.ex._dotted(right) or "").split(".")[-1].isupper()):
                    out = [(left.id, "in_allowlist")]
                    if left.id in self.hosts:
                        out.append((self.hosts[left.id], "host_allowlist"))
                    return out
            # `PATTERN.fullmatch(x) is not None`
            if isinstance(op, (ast.IsNot, ast.NotEq)) and isinstance(right, ast.Constant) and right.value is None and not negated_context:
                return self._positive_guard(left, negated_context)
            if isinstance(op, (ast.Is, ast.Eq)) and isinstance(right, ast.Constant) and right.value is None and negated_context:
                return self._positive_guard(left, False)
            return None
        if negated_context:
            return None
        if isinstance(test, ast.Call):
            func = test.func
            # `full = abspath(join(base, x)); if full.startswith(base_abs)`: containment of a normalised path.
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and \
                    func.attr in ("startswith", "is_relative_to") and func.value.id in self.normalized:
                return [(func.value.id, "path_contained")]
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.attr in (
                    "isdigit", "isalnum", "isnumeric", "isdecimal", "isalpha", "isidentifier"):
                pred = {"isnumeric": "isdigit", "isdecimal": "isdigit"}.get(func.attr, func.attr)
                return [(func.value.id, pred)]
            name = self.ex._dotted(func)
            if name and test.args and isinstance(test.args[-1], ast.Name):
                var = test.args[-1].id
                qual = self.ex.resolve(self.mod, name)
                if qual in ("re.fullmatch", "re.match") or name.endswith((".fullmatch", ".match")):
                    pattern = ""
                    if qual.startswith("re.") and test.args and isinstance(test.args[0], ast.Constant):
                        pattern = str(test.args[0].value)
                    pred = f"regex:{pattern}" if pattern else f"regex_obj:{name}"
                    self.f.pred_sources[pred] = ast.get_source_segment(self.f.files[self.file], test) or name
                    return [(var, pred)]
                if qual == "isinstance":
                    return None
                # Call to a (possibly user-defined) predicate function: `if is_safe_slug(x)`.
                summ = self.ex.pred_summary.get(qual)
                if summ is None and isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) \
                        and func.value.id == "self" and self.fn.cls:
                    m = self.ex.method(self.fn.cls, func.attr)
                    summ = self.ex.pred_summary.get(m) if m else None
                    if summ:
                        summ = (summ[0] - 1, summ[1])  # bound call: `self` is parameter 0
                if summ is not None and 0 <= summ[0] < len(test.args) and isinstance(test.args[summ[0]], ast.Name):
                    return [(test.args[summ[0]].id, summ[1])]
                if qual in self.f.functions or "." in qual:
                    pred = f"call:{qual}"
                    fn = self.f.functions.get(qual)
                    if fn is not None:
                        self.f.pred_sources[pred] = self._predicate_context(fn)
                    return [(var, pred)]
            if isinstance(func, ast.Name) and func.id == "isinstance" and len(test.args) == 2 and isinstance(test.args[0], ast.Name):
                t = self.ex._dotted(test.args[1]) or ""
                if t in ("int", "float", "bool"):
                    return [(test.args[0].id, f"isinstance_{t}")]
        return None

    def _predicate_context(self, fn: Function) -> str:
        """Source of a predicate function plus the module-level constants it references
        (e.g. a compiled regex), which is what a judge needs to decide what it accepts."""
        src = self.f.files[fn.file]
        lines = src.splitlines()
        body = "\n".join(lines[fn.line - 1: fn.end_line])
        mod = self.ex._modules.get(fn.file)
        try:  # methods are indented; decorators may sit above fn.line
            names = {n.id for n in ast.walk(ast.parse(textwrap.dedent(body))) if isinstance(n, ast.Name)} if body else set()
        except SyntaxError:
            names = {m for m in re.findall(r"[A-Za-z_]\w*", body)}
        consts = []
        for stmt in mod.tree.body if mod else []:
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in stmt.targets):
                consts.append(ast.get_source_segment(src, stmt) or "")
        return "\n".join(consts + [body])

    def refine(self, env: Env, guards: list[tuple[str, str]], at: ast.stmt) -> Env:
        env = dict(env)
        for var, pred in guards:
            if var not in env:
                continue
            span = (at.lineno, at.col_offset + 1, at.lineno, at.col_offset + 1 + len(self._line(at.lineno).strip()))
            gid = self.ex.new_node(self.fn.qname, self.file, None, "guard", label=f"{pred}({var})", span=span)
            for d in env[var]:
                self.f.edges.add((d, gid))
            self.f.guards.add((gid, pred, var))
            did = self.ex.new_node(self.fn.qname, self.file, None, "def", label=var, span=span)
            self.f.edges.add((gid, did))
            env[var] = frozenset({did})
        return env

    def _line(self, n: int) -> str:
        lines = self.f.files[self.file].splitlines()
        return lines[n - 1] if 0 < n <= len(lines) else ""

    # ── binding ─────────────────────────────────────────────────────────────
    def bind(self, target: ast.expr, value: int | set[int] | None, env: Env, value_expr: ast.expr | None) -> Env:
        srcs = value if isinstance(value, set) else ({value} if value else set())
        env = dict(env)
        if isinstance(target, ast.Name):
            # A host extracted from the old value of this variable says nothing about the new one.
            self.hosts = {h: u for h, u in self.hosts.items() if u != target.id}
            did = self.ex.new_node(self.fn.qname, self.file, target, "def", label=target.id)
            for v in srcs:
                self.f.edges.add((v, did))
            alias = self._heap_key(value_expr, env) if isinstance(value_expr, (ast.Name, ast.Subscript, ast.Attribute)) else None
            if alias:
                self.aliases[target.id] = alias
            else:
                self.aliases.pop(target.id, None)
            env[target.id] = frozenset({did})
            host_src = _host_of(value_expr)
            if host_src:
                self.hosts[target.id] = host_src
            else:
                self.hosts.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                env = self.bind(elt, set(srcs), env, None)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            # `self.f = v`, `obj.f = v`, `G[k] = v`, `self.items[k] = v`: the value reaches the shared cell.
            self._heap_store(self._heap_key(target, env) if isinstance(target, ast.Attribute)
                             else self._heap_key(target.value, env), srcs)
            base = target.value
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            if isinstance(base, ast.Name):
                # Weak update: the container keeps its old contents and gains the new value.
                did = self.ex.new_node(self.fn.qname, self.file, base, "def", label=base.id)
                for v in srcs | set(env.get(base.id, ())):
                    self.f.edges.add((v, did))
                env[base.id] = frozenset({did})
        elif isinstance(target, ast.Starred):
            env = self.bind(target.value, srcs, env, None)
        return env

    # ── expressions ─────────────────────────────────────────────────────────
    def expr(self, e: ast.expr | None, env: Env) -> int | None:
        if e is None:
            return None
        new = lambda kind, label="", callee=None: self.ex.new_node(self.fn.qname, self.file, e, kind, label, callee)
        if isinstance(e, ast.Constant):
            return None
        if isinstance(e, ast.Name):
            defs = env.get(e.id)
            if not defs and e.id in self.mod.global_names and e.id not in self.mod.global_calls:
                nid = new("use", e.id)  # read of a module global: whatever any function stored in it
                self.f.edges.add((self.ex.heap_node(f"{self.mod.name}.{e.id}", self.file), nid))
                return nid
            if not defs:
                if IDENTITY_RE.search(self.ex.resolve(self.mod, e.id)):
                    nid = new("use", e.id)
                    self.f.user_refs.add(nid)
                    return nid
                return None
            nid = new("use", e.id)
            for d in defs:
                self.f.edges.add((d, nid))
            return nid
        if isinstance(e, ast.Attribute):
            b = self.expr(e.value, env)
            nid = new("attr", ast.unparse(e))
            if b:
                self.f.edges.add((b, nid))
            hk = self._heap_key(e, env)
            if hk and hk.split(".")[-1] == e.attr and not hk.startswith(self.mod.name + "." + e.attr):
                self.f.edges.add((self.ex.heap_node(hk, self.file), nid))
            d = self.ex._dotted(e)
            ext_attr = self._self_attr_base(d) if d and d.startswith("self.") else None
            if ext_attr:  # `self.request.body` in a RequestHandler subclass: an inherited library attribute
                self.f.attrnames.add((nid, ext_attr))
            if d and b is None and d.split(".")[0] in self.mod.imports:  # `request.args` read from a library object
                q = self.ex.resolve(self.mod, d)
                if q.split(".")[0] not in self.ex._tops:  # project modules/classes are not library sources
                    self.f.attrnames.add((nid, q))
            if b in self.f.user_refs or (d and (IDENTITY_RE.search(self.ex.resolve(self.mod, d))
                                                or d.startswith(("request.user", "request.auth")) and "request" in env)):
                self.f.user_refs.add(nid)
            return nid
        if isinstance(e, ast.Subscript):
            b = self.expr(e.value, env)
            self.expr(e.slice, env)
            nid = new("sub", ast.unparse(e)[:80])
            if b:
                self.f.edges.add((b, nid))
            return nid
        if isinstance(e, ast.Call):
            return self.call(e, env)
        if isinstance(e, ast.Compare):
            ops = [self.expr(e.left, env)] + [self.expr(c, env) for c in e.comparators]
            for a, b in zip(ops, ops[1:]):
                if a and b:
                    self.f.compares.add((a, b))
            return None  # booleans carry no attacker-controlled data
        if isinstance(e, (ast.BinOp, ast.BoolOp, ast.JoinedStr, ast.FormattedValue, ast.IfExp,
                          ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Starred, ast.UnaryOp,
                          ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp, ast.Await)):
            if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
                self.expr(e.operand, env)
                return None
            children = self._value_children(e, env)
            nid = new("expr", ast.unparse(e)[:80])
            for c in children:
                self.f.edges.add((c, nid))
            self._mark_url_prefix(nid, _leading_literal(e))
            return nid
        if isinstance(e, ast.Lambda):
            return None
        return None

    def _value_children(self, e: ast.expr, env: Env) -> list[int]:
        if isinstance(e, ast.BinOp):
            parts = [e.left, e.right]
        elif isinstance(e, ast.BoolOp):
            parts = e.values
        elif isinstance(e, ast.JoinedStr):
            parts = e.values
        elif isinstance(e, ast.FormattedValue):
            parts = [e.value]
        elif isinstance(e, ast.IfExp):
            self.expr(e.test, env)
            parts = [e.body, e.orelse]
        elif isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            parts = e.elts
        elif isinstance(e, ast.Dict):
            parts = [v for v in e.values if v is not None] + [k for k in e.keys if k is not None]
        elif isinstance(e, (ast.Starred, ast.Await)):
            parts = [e.value]
        elif isinstance(e, ast.UnaryOp):
            parts = [e.operand]
        elif isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            inner = dict(env)
            for g in e.generators:
                it = self.expr(g.iter, inner)
                inner = self.bind(g.target, it, inner, None)
            return [x for x in [self.expr(e.elt, inner)] if x]
        elif isinstance(e, ast.DictComp):
            inner = dict(env)
            for g in e.generators:
                it = self.expr(g.iter, inner)
                inner = self.bind(g.target, it, inner, None)
            return [x for x in [self.expr(e.value, inner), self.expr(e.key, inner)] if x]
        else:
            parts = []
        return [x for x in (self.expr(p, env) for p in parts) if x]

    def _library_method(self, cls: str, name: str) -> str | None:
        """A method the project class inherits from a library base (not defined anywhere in the project chain)."""
        seen = set()
        while cls in self.f.classes and cls not in seen:
            seen.add(cls)
            if self._assigns_self_attr(cls, name):
                return None
            bases = self.f.classes[cls]
            ext = [b for b in bases if b not in self.f.classes and b not in ("object", "")]
            if ext:
                return f"{ext[0]}.{name}"
            cls = next((b for b in bases if b in self.f.classes), None)
        return None

    def _self_attr_base(self, dotted: str | None) -> str | None:
        """`self.a.m` where the method's class (and its project bases) never defines `a`: the attribute comes from
        a library base class, so name the call after it (one question per framework API)."""
        if not dotted or not self.fn.cls or not dotted.startswith("self.") or dotted.count(".") < 2:
            return None
        rest = dotted.split(".")[1:]
        cls, seen = self.fn.cls, set()
        while cls in self.f.classes and cls not in seen:
            seen.add(cls)
            if self.ex.method(cls, rest[0]) or self._assigns_self_attr(cls, rest[0]):
                return None
            bases = self.f.classes[cls]
            ext = [b for b in bases if b not in self.f.classes]
            if ext:
                return ".".join([ext[0]] + rest)
            cls = next((b for b in bases if b in self.f.classes), None)
        return None

    def _assigns_self_attr(self, cls: str, attr: str) -> bool:
        """Some method of `cls` assigns `self.attr` (then it is project state, not a library attribute)."""
        return attr in self.ex.self_attrs(cls)

    def _heap_key(self, e: ast.expr, env: Env) -> str | None:
        """Shared state a value can be stored into / read from: a module global, `self.f`, `obj.f` of a known
        project type, or anything reached through them (`posts[i]['comments']`, a loop variable over `posts`).
        Plain locals are not heap."""
        while isinstance(e, ast.Subscript) or (isinstance(e, ast.Attribute) and not self._direct_field(e)):
            e = e.value
        if isinstance(e, ast.Name) and e.id in self.aliases:
            return self.aliases[e.id]
        if isinstance(e, ast.Name) and e.id not in env and e.id in self.mod.global_names:
            if e.id in self.mod.global_calls and self.ex.resolve(self.mod, e.id) != f"{self.mod.name}.{e.id}":
                pass  # module-level library objects (`app = Flask()`) are still shared state
            return f"{self.mod.name}.{e.id}"
        if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name):
            if e.value.id == "self" and self.fn.cls and self.fn.params[:1] == ["self"]:
                return f"{self.fn.cls}.{e.attr}"
            if e.value.id in self.types:
                return f"{self.types[e.value.id]}.{e.attr}"
        return None

    def _direct_field(self, e: ast.Attribute) -> bool:
        return isinstance(e.value, ast.Name) and (e.value.id == "self" or e.value.id in self.types)

    def _heap_store(self, key: str | None, srcs) -> None:
        if key:
            h = self.ex.heap_node(key, self.file)
            for v in srcs:
                if v:
                    self.f.edges.add((v, h))

    def _template_sinks(self, e: ast.Call, qual: str, arg_nodes, kw_nodes) -> None:
        """`render_template_string(TPL, x=v)` / `render_template("t.html", x=v)` where the template turns escaping off
        for a variable (`{{ x|safe }}`, `{% autoescape false %}`): that variable's value is an XSS sink."""
        name = qual.rsplit(".", 1)[-1]
        if name not in ("render_template_string", "render_template", "render") or not kw_nodes:
            return
        tpl = self._template_text(e.args[0] if e.args else None, name)
        if not tpl:
            return
        off = "autoescape false" in tpl.replace("  ", " ").lower()
        for k, a in kw_nodes:
            if a and k and (off or re.search(r"\{\{[^}]*\b" + re.escape(k) + r"\b[^}]*\|\s*safe", tpl)
                            or re.search(r"\bfor\s+(\w+)\s+in\s+" + re.escape(k) + r"\b", tpl) and "|safe" in tpl):
                self.f.extra_sinks.add((a, "xss"))

    def _template_text(self, arg: ast.expr | None, how: str) -> str:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            if how == "render_template_string":
                return arg.value
            for rel in self.f.files and [p for p in self.ex.template_files() if p.endswith("/" + arg.value) or p == arg.value]:
                return self.ex.template_files()[rel]
            return ""
        if isinstance(arg, ast.Name) and how == "render_template_string":
            for st in self.mod.tree.body:
                if isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id == arg.id for t in st.targets) \
                        and isinstance(st.value, ast.Constant) and isinstance(st.value.value, str):
                    return st.value.value
        return ""

    def _is_normalizer(self, value: ast.expr) -> bool:
        if not isinstance(value, ast.Call):
            return False
        if isinstance(value.func, ast.Attribute) and value.func.attr in ("resolve", "absolute"):
            return True  # pathlib
        d = self.ex._dotted(value.func)
        return bool(d) and self.ex.resolve(self.mod, d) in NORMALIZERS

    def _ctor_class(self, value: ast.expr) -> str | None:
        if isinstance(value, ast.Call):
            d = self.ex._dotted(value.func)
            q = self.ex.resolve(self.mod, d) if d else None
            if q in self.f.classes:
                return q
        return None

    def _receiver_class(self, func: ast.expr) -> str | None:
        """Project class of `obj` in `obj.m(...)`: `self` in a method, or a local built by a project constructor."""
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            name = func.value.id
            if name == "self" and self.fn.cls and self.fn.params[:1] == ["self"]:
                return self.fn.cls
            return self.types.get(name)
        return None

    def _mark_url_prefix(self, nid: int, prefix: str | None) -> None:
        """A string built after a constant `scheme://host/` (or `/path`) prefix cannot choose the host it
        reaches: safe for SSRF (and open redirect) whatever follows. Path/query injection is a different class."""
        if not prefix:
            return
        if FIXED_HOST_RE.match(prefix):
            self.f.typed.add((nid, "fixed_host"))
        elif prefix.startswith("/") and not prefix.startswith(("//", "/\\")) and len(prefix) > 1:
            self.f.typed.add((nid, "relative_path"))

    def _is_model(self, cls: str | None) -> bool:
        """A project class persisted by an ORM (its bases resolve to Model / Base / Document ...)."""
        seen, todo = set(), [cls] if cls else []
        while todo:
            c = todo.pop()
            if c in seen:
                continue
            seen.add(c)
            for b in self.f.classes.get(c, []):
                if ORM_BASE_RE.search(b):
                    return True
                if b in self.f.classes:
                    todo.append(b)
        return False

    def _stored(self, e: ast.Call, func, dotted, qual: str, nid: int, receiver, arg_nodes, kw_nodes) -> None:
        """Second-order flows (RIPS): record writes to and reads from tables, ORM models and files, keyed so the
        engine can connect what an attacker stores with where it is read back."""
        method = func.attr if isinstance(func, ast.Attribute) else None
        values = [a for _, a in arg_nodes if a] + [a for _, a in kw_nodes if a]
        if method in SQL_EXEC and e.args:
            sql = _const_text(e.args[0]) or ""
            writes = {t.lower() for t in SQL_WRITE_RE.findall(sql)}
            for t in writes:
                for a in values:
                    self.f.store_writes.add((nid, f"db:{t}", a))
            if not writes and re.search(r"\bSELECT\b", sql, re.I):
                tables = {t.lower() for t in SQL_READ_RE.findall(sql)}
                if tables:
                    for t in tables:
                        self.f.store_reads.add((nid, f"db:{t}"))  # `for row in cur.execute(...)`
                    self.sql_read_nodes[nid] = tables
                    if isinstance(func.value, ast.Name):
                        self.sql_cursor[func.value.id] = tables
        elif method in SQL_FETCH:
            tables = set()
            if isinstance(func.value, ast.Name):
                tables = self.sql_cursor.get(func.value.id, set())
            elif receiver is not None:
                tables = self.sql_read_nodes.get(receiver, set())
            for t in tables:
                self.f.store_reads.add((nid, f"db:{t}"))
        # ORM: Model(...) / Model.objects.create(...) write the model; Model.query.* / Model.objects.* read it.
        target = self.ex.resolve(self.mod, dotted) if dotted else None
        cls = target if target in self.f.classes else None
        if cls is None and target and target.endswith((".objects.create", ".objects.get_or_create", ".objects.update_or_create")):
            c = target.split(".objects.")[0]
            cls = c if c in self.f.classes else None
        if cls and self._is_model(cls):
            for a in values:
                self.f.store_writes.add((nid, f"orm:{cls}", a))
        m = ORM_READ_RE.match(target or "")
        if m and m.group("m") in self.f.classes and not (target or "").endswith((".create", ".get_or_create", ".update_or_create")):
            self.f.store_reads.add((nid, f"orm:{m.group('m')}"))
        # Files: `upload.save(path)`, `open(path, "w")` + `.write(x)` write; `open(path)` reads.
        if qual == "open" and arg_nodes and arg_nodes[0][1]:
            mode = _const_text(e.args[1]) if len(e.args) > 1 else next(
                (_const_text(k.value) for k in e.keywords if k.arg == "mode"), None)
            if mode and any(ch in mode for ch in "wax"):
                self.open_for_write = (nid, arg_nodes[0][1])
            else:
                self.f.file_reads.add((nid, arg_nodes[0][1]))
        elif method == "save" and arg_nodes and arg_nodes[0][1] and receiver is not None and qual not in self.f.functions:
            self.f.file_writes.add((nid, arg_nodes[0][1], receiver))
        elif method in ("write", "writelines") and self.open_for_write and values:
            for a in values:
                self.f.file_writes.add((nid, self.open_for_write[1], a))

    def _lookup_model(self, e: ast.Call, dotted: str | None) -> str | None:
        """`Doc.query.get(x)`, `Doc.objects.get(pk=x)`, `session.get(Doc, x)`, `get_object_or_404(Doc, pk=x)`."""
        if not dotted:
            return None
        m = LOOKUP_RE.match(self.ex.resolve(self.mod, dotted))
        if m and m.group("m") in self.f.classes:
            return m.group("m")
        if dotted.rsplit(".", 1)[-1] in ("get", "get_or_404", "get_object_or_404", "one_or_404") and e.args:
            d = self.ex._dotted(e.args[0])
            q = self.ex.resolve(self.mod, d) if d else None
            if q in self.f.classes:
                return q
        return None

    def call(self, e: ast.Call, env: Env) -> int:
        first_node = self.ex._next
        func = e.func
        receiver = None
        dotted = self.ex._dotted(func)
        head = dotted.split(".")[0] if dotted else None
        offset = 0  # positional argument i binds parameter i + offset (1 for bound methods / constructors)
        how = None
        rcls = self._receiver_class(func)
        bound = self.ex.method(rcls, func.attr) if rcls and isinstance(func, ast.Attribute) else None
        inherited = self._library_method(rcls, func.attr) if rcls and not bound and isinstance(func, ast.Attribute) else None
        if inherited:  # `self.write(x)` in a tornado.web.RequestHandler subclass: the framework's method
            receiver = self.expr(func.value, env)
            qual, method, how = inherited, None, "cha-base"
        elif bound:
            receiver = self.expr(func.value, env)
            qual, method, offset, how = bound, None, 1, ("self" if head == "self" else "local-type")
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call) and \
                self._ctor_class(func.value) and self.ex.method(self._ctor_class(func.value), func.attr):
            receiver = self.expr(func.value, env)  # `Helper(x).run(y)`
            qual, method, offset, how = self.ex.method(self._ctor_class(func.value), func.attr), None, 1, "ctor"
        elif isinstance(func, ast.Attribute) and (dotted is None or head in env or (
                head not in self.mod.imports and head not in self.mod.local_defs and head not in self.mod.global_calls
                and head not in BUILTIN_NAMES and dotted.count(".") == 1)):
            # Method call on a value (`cur.execute`, `x.strip()`, `hashlib.sha256(x).hexdigest()`).
            receiver = self.expr(func.value, env)
            base_callee = None
            if isinstance(func.value, ast.Call):
                inner = self.ex._dotted(func.value.func)
                base_callee = self.ex.resolve(self.mod, inner) if inner else None
            qual = f"{base_callee}().{func.attr}" if base_callee else f"*.{func.attr}"
            method = func.attr
            ext = self._self_attr_base(dotted)
            if ext:  # `self.wfile.write` in a BaseHTTPRequestHandler subclass
                qual, method, how = ext, None, "cha-attr"
        else:
            qual = self.ex.resolve(self.mod, dotted) if dotted else "<dynamic>"
            method = None
            if dotted and head in self.mod.imports and qual != self.mod.imports[head] + dotted[len(head):]:
                how = "import"
            if qual in self.f.classes:  # constructor of a project class
                init = self.ex.method(qual, "__init__")
                qual, offset, how = (init, 1, "ctor") if init else (qual, 0, "ctor")
            elif qual not in self.f.functions:
                q2 = self.ex.through_class(qual)
                if q2 != qual:
                    qual, how = q2, "cha"

        arg_nodes: list[tuple[int, int | None]] = []
        for i, a in enumerate(e.args):
            arg_nodes.append((i, self.expr(a, env)))
        kw_nodes: list[tuple[str | None, int | None]] = [(k.arg, self.expr(k.value, env)) for k in e.keywords]
        if isinstance(func, ast.Attribute) and func.attr in MUTATORS:
            # `G.append(x)`, `self.items.add(x)`, `cache.update(d)`: x reaches the shared cell.
            self._heap_store(self._heap_key(func.value, env), [a for _, a in arg_nodes] + [a for _, a in kw_nodes])

        nid = self.ex.new_node(self.fn.qname, self.file, e, "call", label=ast.unparse(e)[:80], callee=qual)
        self.f.callnames.add((nid, qual))
        self._stored(e, func, dotted, qual, nid, receiver, arg_nodes, kw_nodes)
        if isinstance(func, ast.Attribute) and func.attr == "format" and isinstance(func.value, ast.Constant):
            self._mark_url_prefix(nid, func.value.value if isinstance(func.value.value, str) else None)
        self._template_sinks(e, qual, arg_nodes, kw_nodes)
        model = self._lookup_model(e, dotted)
        if model:
            self.f.lookups.add((nid, model))
            for x in range(first_node, nid):
                if self.f.nodes[x].kind in ("use", "attr", "sub", "call", "expr"):
                    self.f.lookup_deps.add((nid, x))
                if x in self.f.user_refs:
                    self.f.scoped.add(nid)
        if IDENTITY_RE.search(qual):
            self.f.user_refs.add(nid)

        for key, a in [(i, x) for i, x in enumerate(e.args)] + [(k.arg, k.value) for k in e.keywords if k.arg]:
            d = self.ex._dotted(a) if isinstance(a, (ast.Name, ast.Attribute)) else None
            ref = self.ex.resolve(self.mod, d) if d and d.split(".")[0] not in env else None
            if ref in self.f.functions:
                self.f.fn_refs.add((nid, key, ref))  # a function handed to a call: maybe a handler registration
            for m in self.ex.view_refs(self.mod, a):
                self.f.fn_refs.add((nid, key, m))
        if "()." in qual and qual not in self.f.functions:
            c, _, m = qual.rpartition("().")
            hit = self.ex.method(c, m) if c in self.f.classes else None
            if hit:  # module-level instance of a project class: `pkg = Helper()` ... `pkg.run(x)`
                qual, offset, how = hit, 1, "global-type"
        if how:
            self.f.resolved[nid] = how
        if qual not in self.f.functions and dotted and "." not in dotted:
            scope = self.fn.qname  # a function defined inside this (or an enclosing) function
            while "." in scope:
                if f"{scope}.{dotted}" in self.f.functions:
                    qual = f"{scope}.{dotted}"
                    break
                scope = scope.rpartition(".")[0]
        targets = [qual] if qual in self.f.functions else []
        if not targets and qual.startswith("*.") and method and method not in PROPAGATOR_METHODS | NEUTRAL_METHODS:
            # Receiver type unknown (`attack.run(handler)` with `attack` picked at runtime): class-hierarchy
            # analysis binds the call to every project method of that name. Sound over-approximation; the
            # verifier filters. Too many candidates = genuinely ambiguous: left unresolved and counted.
            cands = self.ex.methods_named(method)
            if 0 < len(cands) <= CHA_MAX_TARGETS:
                targets, offset = cands, 1
                self.f.resolved[nid] = "cha-name"
            elif cands:
                self.f.ambiguous.add((nid, method, len(cands)))
        if targets:
            if offset and receiver:
                self.f.arg_in.add((nid, 0, receiver))
            for i, a in arg_nodes:
                if a:
                    self.f.arg_in.add((nid, i + offset, a))
            for target in targets:
                self.f.calls.add((nid, target))
                params = self.f.functions[target].params
                for k, a in kw_nodes:
                    if a and k in params:
                        self.f.arg_in.add((nid, params.index(k), a))
            return nid

        # Library call: propagate argument (and receiver) taint into the result.
        for i, a in arg_nodes:
            if a:
                self.f.lib_args.add((nid, i, a))
        for k, a in kw_nodes:
            if a and k:
                self.f.lib_args.add((nid, k, a))
        incoming = [a for _, a in arg_nodes if a] + [a for _, a in kw_nodes if a]
        if receiver:
            incoming.append(receiver)
        is_neutral = qual in NEUTRAL or (method in NEUTRAL_METHODS)
        if not is_neutral:
            for a in incoming:
                self.f.edges.add((a, nid))
        # A project class without __init__ just stores its arguments: a propagator, not an unknown API.
        known = is_neutral or qual in PROPAGATORS or method in PROPAGATOR_METHODS or qual in self.f.classes
        if not known and incoming:
            self.f.libcalls[nid] = qual
        return nid


def _route_converters(route: str | None) -> dict[str, str]:
    if not route:
        return {}
    out = {}
    for m in re.finditer(r"<(?:(\w+)(?:\([^)]*\))?:)?(\w+)>", route):  # <int:id>, <any(a, b):js>
        out[m.group(2)] = m.group(1) or "string"
    return out


def _host_of(value: ast.expr | None) -> str | None:
    """`urlparse(url).hostname` -> 'url'."""
    if isinstance(value, ast.Attribute) and value.attr in HOST_ATTRS and isinstance(value.value, ast.Call):
        c = value.value
        if c.args and isinstance(c.args[0], ast.Name):
            fname = c.func.attr if isinstance(c.func, ast.Attribute) else getattr(c.func, "id", "")
            if fname in ("urlparse", "urlsplit"):
                return c.args[0].id
    return None


def _leading_literal(e: ast.expr) -> str | None:
    """The constant text a string expression starts with: `"https://h/" + x`, f"https://h/{x}", `"..%s" % x`."""
    if isinstance(e, ast.BinOp) and isinstance(e.op, (ast.Add, ast.Mod)):
        return _leading_literal(e.left)
    if isinstance(e, ast.Constant) and isinstance(e.value, str):
        return e.value
    if isinstance(e, ast.JoinedStr) and e.values and isinstance(e.values[0], ast.Constant):
        return str(e.values[0].value)
    return None


def _const_text(e: ast.expr) -> str | None:
    """The constant text of a string expression (literal parts of f-strings and concatenations, `?` for the rest)."""
    if isinstance(e, ast.Constant) and isinstance(e.value, str):
        return e.value
    if isinstance(e, ast.JoinedStr):
        return "".join(str(v.value) if isinstance(v, ast.Constant) else "?" for v in e.values)
    if isinstance(e, ast.BinOp) and isinstance(e.op, (ast.Add, ast.Mod)):
        left, right = _const_text(e.left), _const_text(e.right) if isinstance(e.op, ast.Add) else None
        return (left or "?") + (right or "?") if left or right else None
    return None


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract(root: Path) -> Facts:
    return PythonExtractor(root).run()
