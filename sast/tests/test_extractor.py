"""Python fact extractor: reaching definitions, guards, routes, imports, library calls."""
from __future__ import annotations

from sentinel.extract.python_facts import NEUTRAL, PROPAGATORS, extract, module_name, is_test_path

from conftest import nodes_where, reachable, write_repo


def _source(facts, fn):
    [src] = [n for n in nodes_where(facts, kind="call", fn=fn) if n.callee == "flask.request.args.get"]
    return src.id


def _use_in_call(facts, fn, callee_suffix, var="x"):
    """The `use` node of `var` passed as argument to a call whose callee ends with callee_suffix."""
    calls = [n for n in nodes_where(facts, kind="call", fn=fn) if (n.callee or "").endswith(callee_suffix)]
    assert calls, f"no call to {callee_suffix} in {fn}"
    call = calls[-1]
    uses = [n for n in nodes_where(facts, kind="use", label=var, fn=fn) if n.l1 == call.l1]
    assert uses
    return uses[0].id


# ── reaching definitions ─────────────────────────────────────────────────────────────────

def test_rebinding_kills_old_definition(tmp_path):
    facts = extract(write_repo(tmp_path, {"app.py": """
        from flask import request
        import sink_mod

        def f():
            x = request.args.get("x")
            x = int(x)
            sink_mod.sink(x)
    """}))
    src = _source(facts, "app.f")
    use = _use_in_call(facts, "app.f", "sink_mod.sink")
    [cast] = [n.id for n in nodes_where(facts, kind="call", fn="app.f") if n.callee == "int"]
    assert use in reachable(facts, src)  # flows, but only through int(...)
    assert use not in reachable(facts, src, avoid={cast})


def test_branch_merge_keeps_taint(tmp_path):
    facts = extract(write_repo(tmp_path, {"app.py": """
        from flask import request
        import sink_mod

        def f(flag):
            x = request.args.get("x")
            if flag:
                x = int(x)
            sink_mod.sink(x)
    """}))
    src = _source(facts, "app.f")
    use = _use_in_call(facts, "app.f", "sink_mod.sink")
    [cast] = [n.id for n in nodes_where(facts, kind="call", fn="app.f") if n.callee == "int"]
    assert use in reachable(facts, src, avoid={cast})  # the un-cast path survives the merge


# ── guards ───────────────────────────────────────────────────────────────────────────────

def test_early_exit_isdigit_guard_refines(tmp_path):
    facts = extract(write_repo(tmp_path, {"app.py": """
        from flask import abort, request
        import sink_mod

        def f():
            x = request.args.get("x")
            if not x.isdigit():
                abort(400)
            sink_mod.sink(x)
    """}))
    guards = [(g, p, v) for g, p, v in facts.guards]
    assert [(p, v) for _, p, v in guards] == [("isdigit", "x")]
    gid = guards[0][0]
    src = _source(facts, "app.f")
    use = _use_in_call(facts, "app.f", "sink_mod.sink")
    assert use in reachable(facts, src)
    assert use not in reachable(facts, src, avoid={gid}), "every path to the sink must pass the guard node"


def test_non_exiting_negative_guard_does_not_dominate(tmp_path):
    facts = extract(write_repo(tmp_path, {"app.py": """
        from flask import request
        import sink_mod, log

        def f():
            x = request.args.get("x")
            if not x.isdigit():
                log.warn("bad")
            sink_mod.sink(x)
    """}))
    src = _source(facts, "app.f")
    use = _use_in_call(facts, "app.f", "sink_mod.sink")
    gids = {g for g, _, _ in facts.guards}
    assert use in reachable(facts, src, avoid=gids)


def test_not_in_allowlist_raise_guard(tmp_path):
    facts = extract(write_repo(tmp_path, {"app.py": """
        from flask import request
        import sink_mod

        MODES = {"a", "b"}

        def f():
            x = request.args.get("x")
            if x not in MODES:
                raise ValueError("bad mode")
            sink_mod.sink(x)
    """}))
    assert {(p, v) for _, p, v in facts.guards} == {("in_allowlist", "x")}
    gid = next(iter(facts.guards))[0]
    assert _use_in_call(facts, "app.f", "sink_mod.sink") not in reachable(facts, _source(facts, "app.f"), avoid={gid})


def test_urlparse_hostname_allowlist_refines_url_var(tmp_path):
    facts = extract(write_repo(tmp_path, {"net.py": """
        from urllib.parse import urlparse
        import requests

        ALLOWED_HOSTS = {"cdn.example"}

        def fetch_allowed(url):
            host = urlparse(url).hostname
            if host not in ALLOWED_HOSTS:
                raise ValueError("host not allowed")
            return requests.get(url)
    """}))
    assert {(p, v) for _, p, v in facts.guards} == {("in_allowlist", "host"), ("host_allowlist", "url")}


def test_regex_and_call_predicates_recorded_with_source(tmp_path):
    facts = extract(write_repo(tmp_path, {
        "validators.py": """
            import re
            SLUG_RE = re.compile(r"[a-z]+")

            def is_slug(v):
                return SLUG_RE.fullmatch(v) is not None
        """,
        "app.py": """
            import re
            from flask import abort, request
            from validators import is_slug

            def f():
                x = request.args.get("x")
                if not re.match(r"[a-z]+", x):
                    abort(400)
                if not is_slug(x):
                    abort(400)
                return x
        """}))
    preds = {p for _, p, _ in facts.guards}
    assert preds == {"regex:[a-z]+", "call:validators.is_slug"}
    # The oracle gets the predicate function *and* the module constant it relies on.
    assert "SLUG_RE = re.compile" in facts.pred_sources["call:validators.is_slug"]
    assert "re.match" in facts.pred_sources["regex:[a-z]+"]


# ── routes ───────────────────────────────────────────────────────────────────────────────

def test_route_converters_typed(tmp_path):
    facts = extract(write_repo(tmp_path, {"app.py": """
        from flask import Flask
        app = Flask(__name__)

        @app.route("/p/<int:pid>/<name>/<path:rest>")
        def page(pid, name, rest, extra=None):
            return name
    """}))
    rp = {(name, conv) for fn, name, conv, _ in facts.route_params}
    assert rp == {("pid", "int"), ("name", "string"), ("rest", "path")}
    pid_node = next(n for fn, name, conv, n in facts.route_params if name == "pid")
    typed_nodes = {n for n, _ in facts.typed}
    assert (pid_node, "int") in facts.typed
    assert typed_nodes == {pid_node}
    assert ("app.page", "http_route") in facts.entrypoints
    assert facts.functions["app.page"].route == "/p/<int:pid>/<name>/<path:rest>"


def test_int_annotation_is_typed(tmp_path):
    facts = extract(write_repo(tmp_path, {"m.py": """
        def h(a: int, b: str):
            return b
    """}))
    params = {i: p for fn, i, p in facts.params if fn == "m.h"}
    assert facts.typed == {(params[0], "int")}


# ── imports and call resolution ──────────────────────────────────────────────────────────

def test_relative_imports_resolve_to_project_functions(tmp_path):
    facts = extract(write_repo(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/b.py": """
            def helper(x):
                return x
        """,
        "pkg/a.py": """
            from .b import helper
            from . import b

            def f(v):
                helper(v)
                return b.helper(v)
        """,
        "pkg/sub/__init__.py": """
            from ..b import helper as h

            def g(v):
                return h(v)
        """,
        "pkg/sub/c.py": """
            from ..b import helper

            def k(v):
                return helper(v)
        """,
    }))
    callers = {}
    for node, target in facts.calls:
        callers.setdefault(facts.nodes[node].fn, []).append(target)
    assert callers["pkg.a.f"] == ["pkg.b.helper", "pkg.b.helper"]
    assert callers["pkg.sub.g"] == ["pkg.b.helper"]
    assert callers["pkg.sub.c.k"] == ["pkg.b.helper"]
    # Project calls compose through summaries, not libcall assumptions.
    assert not facts.libcalls
    assert {(fn, i) for fn, i, _ in facts.params} >= {("pkg.b.helper", 0)}
    assert any(fn == "pkg.b.helper" for fn, _ in facts.rets)


def test_project_call_args_and_kwargs(tmp_path):
    facts = extract(write_repo(tmp_path, {"m.py": """
        def helper(a, b):
            return b

        def f(x, y):
            return helper(x, b=y)
    """}))
    [(call, target)] = list(facts.calls)
    assert target == "m.helper"
    idx = {i for k, i, _ in facts.arg_in if k == call}
    assert idx == {0, 1}


# ── library calls ────────────────────────────────────────────────────────────────────────

def test_library_calls_classified(tmp_path):
    facts = extract(write_repo(tmp_path, {"app.py": """
        import hashlib
        import os
        import mylib

        def f(x):
            a = mylib.transform(x)
            b = os.path.join("/srv", x)
            n = len(x)
            s = x.strip()
            d = hashlib.sha256(x.encode()).hexdigest()
            c = mylib.transform("constant only")
            return a, b, n, s, d, c
    """}))
    assert "os.path.join" in PROPAGATORS and "len" in NEUTRAL
    calls = {n.callee: n for n in facts.nodes.values() if n.kind == "call"}
    libs = sorted(facts.libcalls.values())
    # unknown APIs with tainted input are assumption points; the constant-only call is not
    assert libs == ["hashlib.sha256", "hashlib.sha256().hexdigest", "mylib.transform"]
    assert sum(1 for q in facts.libcalls.values() if q == "mylib.transform") == 1
    # propagators carry taint without creating an assumption
    preds_of = {b: {a for a, bb in facts.edges if bb == b} for b in (calls["os.path.join"].id, calls["len"].id,
                                                                      calls["*.strip"].id)}
    assert preds_of[calls["os.path.join"].id], "os.path.join must propagate"
    assert preds_of[calls["*.strip"].id], "str.strip must propagate"
    assert not preds_of[calls["len"].id], "len() result never carries attacker data"
    # every call is visible to the engine by qualified name
    assert {q for _, q in facts.callnames} >= {"mylib.transform", "os.path.join", "len", "*.strip",
                                                 "hashlib.sha256().hexdigest"}


def test_module_name_and_test_paths():
    assert module_name("pkg/sub/__init__.py") == "pkg.sub"
    assert module_name("pkg/a.py") == "pkg.a"
    assert is_test_path("tests/test_x.py") and is_test_path("pkg/test_tools.py") and is_test_path("conftest.py")
    assert not is_test_path("shop/app.py") and not is_test_path("shop/contest.py")


def test_node_at_prefers_exact_then_smallest_enclosing(tmp_path):
    facts = extract(write_repo(tmp_path, {"m.py": """
        def f(x):
            return g(x + "a")
    """}))
    call = next(n for n in facts.nodes.values() if n.kind == "call")
    assert facts.node_at("m.py", call.l1, call.c1, call.l2, call.c2).id == call.id
    inner = next(n for n in facts.nodes.values() if n.kind == "expr")
    # A span strictly inside the BinOp resolves to the BinOp (or a smaller node inside it).
    got = facts.node_at("m.py", inner.l1, inner.c1 + 1, inner.l1, inner.c1 + 2)
    assert got is not None and (got.l1, got.c1) >= (inner.l1, inner.c1) and (got.l2, got.c2) <= (inner.l2, inner.c2)
