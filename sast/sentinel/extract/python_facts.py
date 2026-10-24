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
EXIT_CALLS = {"abort", "flask.abort", "sys.exit", "exit", "os._exit"}
SAFE_CONVERTERS = {"int", "float", "uuid"}
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
    pred_sources: dict[str, str] = field(default_factory=dict)  # predicate -> source text (for the oracle)

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


class _Module:
    def __init__(self, relpath: str, tree: ast.Module):
        self.relpath = relpath
        self.name = module_name(relpath)
        self.package = self.name if relpath.endswith("__init__.py") else self.name.rpartition(".")[0]
        self.imports: dict[str, str] = {}
        self.local_defs: set[str] = set()
        self.tree = tree
        for stmt in tree.body:
            self._collect(stmt)

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


class PythonExtractor:
    def __init__(self, root: Path):
        self.root = root
        self.facts = Facts()
        self._next = 1
        self._modules: dict[str, _Module] = {}

    # ── public API ──────────────────────────────────────────────────────────
    def run(self) -> Facts:
        for path in sorted(self.root.rglob("*.py")):
            rel = path.relative_to(self.root).as_posix()
            if any(part.startswith(".") for part in rel.split("/")):
                continue
            src = path.read_text(encoding="utf-8")
            self.facts.files[rel] = src
            try:
                tree = ast.parse(src, filename=rel)
            except SyntaxError:
                continue
            self._modules[rel] = _Module(rel, tree)
        # Index every function first so calls can be resolved across modules.
        for rel, mod in self._modules.items():
            self._index_functions(mod, mod.tree.body, mod.name)
        for rel, mod in self._modules.items():
            self._walk_defs(mod, mod.tree.body, mod.name)
        return self.facts

    # ── function indexing ───────────────────────────────────────────────────
    def _index_functions(self, mod: _Module, body: list[ast.stmt], prefix: str) -> None:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}.{stmt.name}"
                fn = Function(q, mod.relpath, stmt.lineno, stmt.end_lineno or stmt.lineno,
                              [a.arg for a in stmt.args.posonlyargs + stmt.args.args])
                for dec in stmt.decorator_list:
                    target = dec.func if isinstance(dec, ast.Call) else dec
                    dname = self._dotted(target) or ""
                    fn.decorators.append(dname)
                    if dname.split(".")[-1] in ("route", "get", "post", "put", "delete", "patch"):
                        fn.is_entry = True
                        if isinstance(dec, ast.Call) and dec.args and isinstance(dec.args[0], ast.Constant):
                            fn.route = str(dec.args[0].value)
                self.facts.functions[q] = fn
                if fn.is_entry:
                    self.facts.entrypoints.add((q, "http_route"))
                self._index_functions(mod, stmt.body, q)
            elif isinstance(stmt, ast.ClassDef):
                self._index_functions(mod, stmt.body, f"{prefix}.{stmt.name}")

    def _walk_defs(self, mod: _Module, body: list[ast.stmt], prefix: str) -> None:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}.{stmt.name}"
                _FunctionWalker(self, mod, self.facts.functions[q], stmt).walk()
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

    def resolve(self, mod: _Module, dotted: str) -> str:
        head, _, rest = dotted.partition(".")
        if head in mod.imports:
            base = mod.imports[head]
            return f"{base}.{rest}" if rest else base
        if head in mod.local_defs:
            return f"{mod.name}.{dotted}"
        return dotted


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

    def walk(self) -> None:
        env: Env = {}
        args = self.node.args
        all_args = args.posonlyargs + args.args
        route_conv = _route_converters(self.fn.route)
        for i, a in enumerate(all_args):
            pid = self.ex.new_node(self.fn.qname, self.file, a, "param", label=a.arg)
            self.f.params.add((self.fn.qname, i, pid))
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
                if qual in self.f.functions or "." in qual:
                    pred = f"call:{qual}"
                    fn = self.f.functions.get(qual)
                    if fn is not None:
                        lines = self.f.files[fn.file].splitlines()[fn.line - 1: fn.end_line]
                        self.f.pred_sources[pred] = "\n".join(lines)
                    return [(var, pred)]
            if isinstance(func, ast.Name) and func.id == "isinstance" and len(test.args) == 2 and isinstance(test.args[0], ast.Name):
                t = self.ex._dotted(test.args[1]) or ""
                if t in ("int", "float", "bool"):
                    return [(test.args[0].id, f"isinstance_{t}")]
        return None

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
            did = self.ex.new_node(self.fn.qname, self.file, target, "def", label=target.id)
            for v in srcs:
                self.f.edges.add((v, did))
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
            if not defs:
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
            self.expr(e.left, env)
            for c in e.comparators:
                self.expr(c, env)
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

    def call(self, e: ast.Call, env: Env) -> int:
        func = e.func
        receiver = None
        dotted = self.ex._dotted(func)
        head = dotted.split(".")[0] if dotted else None
        if isinstance(func, ast.Attribute) and (dotted is None or head in env):
            # Method call on a value (`cur.execute`, `x.strip()`, `hashlib.sha256(x).hexdigest()`).
            receiver = self.expr(func.value, env)
            base_callee = None
            if isinstance(func.value, ast.Call):
                inner = self.ex._dotted(func.value.func)
                base_callee = self.ex.resolve(self.mod, inner) if inner else None
            qual = f"{base_callee}().{func.attr}" if base_callee else f"*.{func.attr}"
            method = func.attr
        else:
            qual = self.ex.resolve(self.mod, dotted) if dotted else "<dynamic>"
            method = None

        arg_nodes: list[tuple[int, int | None]] = []
        for i, a in enumerate(e.args):
            arg_nodes.append((i, self.expr(a, env)))
        kw_nodes: list[tuple[str | None, int | None]] = [(k.arg, self.expr(k.value, env)) for k in e.keywords]

        nid = self.ex.new_node(self.fn.qname, self.file, e, "call", label=ast.unparse(e)[:80], callee=qual)
        self.f.callnames.add((nid, qual))

        target = qual if qual in self.f.functions else None
        if target is None and receiver is None and method is None and dotted:
            # `self.helper(...)` and `Class.method(...)` are not resolved in the POC.
            target = None
        if target is not None:
            self.f.calls.add((nid, target))
            params = self.f.functions[target].params
            for i, a in arg_nodes:
                if a:
                    self.f.arg_in.add((nid, i, a))
            for k, a in kw_nodes:
                if a and k in params:
                    self.f.arg_in.add((nid, params.index(k), a))
            return nid

        # Library call: propagate argument (and receiver) taint into the result.
        incoming = [a for _, a in arg_nodes if a] + [a for _, a in kw_nodes if a]
        if receiver:
            incoming.append(receiver)
        is_neutral = qual in NEUTRAL or (method in NEUTRAL_METHODS)
        if not is_neutral:
            for a in incoming:
                self.f.edges.add((a, nid))
        known = is_neutral or qual in PROPAGATORS or (method in PROPAGATOR_METHODS and qual.startswith("*."))
        if not known and incoming:
            self.f.libcalls[nid] = qual
        return nid


def _route_converters(route: str | None) -> dict[str, str]:
    if not route:
        return {}
    out = {}
    for m in re.finditer(r"<(?:(\w+):)?(\w+)>", route):
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


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract(root: Path) -> Facts:
    return PythonExtractor(root).run()
