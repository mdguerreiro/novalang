"""Deterministic stand-ins for the neural tiers (no API key needed).

They are *not* oracles of truth. They imitate a careful model with a few heuristics and a small
knowledge table, and they produce the same structured, citation-bearing output as the real
client. Everything they say still has to pass the orchestrator's symbolic gates.
"""
from __future__ import annotations

import ast
import hashlib
import re

import yaml

from ..engine.analyze import CWE
from .interfaces import (AgentTools, ApiLabel, AuthzLabel, Citation, Claim, EntryLabel, GuardLabel, ProposedKnowledge, RegistrarLabel,
                         RuleContext, RuleProposal, SinkLabel, VerificationCase, Verdict)

# What a well-read model "knows" about common library APIs.
API_TABLE: dict[str, tuple[str, list[str], float, str]] = {
    "hashlib.sha256": ("propagator", [], 0.90, "Returns a hash object wrapping the input; the digest is derived from it."),
    "hashlib.sha1": ("propagator", [], 0.90, "Returns a hash object wrapping the input."),
    "hashlib.md5": ("propagator", [], 0.90, "Returns a hash object wrapping the input."),
    "hashlib.sha256().hexdigest": ("sanitizer", ["all"], 0.96, "hexdigest() returns only [0-9a-f]; no attacker-chosen characters survive."),
    "hashlib.md5().hexdigest": ("sanitizer", ["all"], 0.96, "hexdigest() returns only [0-9a-f]."),
    "slugify.slugify": ("sanitizer", ["all"], 0.93, "python-slugify output is restricted to lowercase [a-z0-9-] by default."),
    "werkzeug.utils.secure_filename": ("sanitizer", ["path"], 0.95, "Strips path separators and leading dots."),
    "bleach.clean": ("sanitizer", ["xss"], 0.92, "Allow-list based HTML sanitizer."),
    "urllib.parse.quote": ("sanitizer", ["redirect", "path"], 0.7, "Percent-encodes reserved characters."),
    "urllib.parse.urlparse": ("propagator", [], 0.95, "Parses the URL; components carry the input."),
}

# Library sinks the curated pack does not model: (argument, class) pairs.
SINK_TABLE: dict[str, tuple[list[tuple], float, str]] = {
    "subprocess.getoutput": ([(0, "cmdi")], 0.97, "Runs the string through a shell."),
    "subprocess.getstatusoutput": ([(0, "cmdi")], 0.97, "Runs the string through a shell."),
    "jinja2.Template": ([(0, "ssti")], 0.95, "Compiles the argument as template source."),
    "jinja2.Environment().from_string": ([(0, "ssti")], 0.95, "Compiles the argument as template source."),
    "lxml.etree.fromstring": ([(0, "xxe")], 0.85, "Parses XML; entity expansion depends on the parser."),
    "lxml.etree.parse": ([(0, "xxe")], 0.85, "Parses XML; entity expansion depends on the parser."),
    "pandas.read_sql": ([(0, "sqli"), ("sql", "sqli")], 0.95, "Executes the SQL string; `params` are bound safely."),
    "pandas.read_sql_query": ([(0, "sqli"), ("sql", "sqli")], 0.95, "Executes the SQL string."),
    "urllib3.PoolManager().request": ([(1, "ssrf"), ("url", "ssrf")], 0.93, "Fetches the URL given as 2nd argument."),
    "marshal.loads": ([(0, "deser")], 0.9, "Deserialises code objects from untrusted bytes."),
    "PIL.ImageMath.eval": ([(0, "code")], 0.93, "Evaluates the expression with Python eval()."),
    "dill.loads": ([(0, "deser")], 0.97, "Pickle superset; arbitrary code on load."),
    "flask.Flask().logger.info": ([], 0.9, "Logging is not a sink for the tracked classes."),
    "jinja2.Environment().from_string().render": ([], 0.9, "Template variables are data, not template source."),
}

# `.replace("'", ...)`, `.replace('\'', ...)` or `.replace("\\", ...)`: quote/backslash escaping.
ESCAPE_RE = re.compile(r"""\.replace\(\s*(?:"'"|'\\''|"\\\\")""")

PAYLOADS = {
    "sqli": ["' OR '1'='1", "1; DROP TABLE users--", "\" OR 1=1 --"],
    "cmdi": ["a; rm -rf /", "a && id", "$(id)", "`id`", "a | nc evil 1"],
    "path": ["../../etc/passwd", "/etc/passwd", "..\\..\\win.ini"],
    "xss": ["<script>alert(1)</script>", "\" onmouseover=alert(1) x=\""],
    "ssti": ["{{7*7}}", "{% for x in () %}"],
    "ssrf": ["http://169.254.169.254/", "file:///etc/passwd"],
    "redirect": ["https://evil.example", "//evil.example"],
    "code": ["__import__('os').system('id')"],
    "deser": [],
}


class MockSpecOracle:
    name = "mock-oracle-v1"

    def classify_api(self, api: str, usage: str) -> ApiLabel:
        if api in API_TABLE:
            role, classes, conf, why = API_TABLE[api]
            return ApiLabel(api, role, classes, conf, why, self.name)
        if api.endswith("().hexdigest") or api == "*.hexdigest":
            return ApiLabel(api, "sanitizer", ["all"], 0.9, "Hex digests only contain [0-9a-f].", self.name)
        return ApiLabel(api, "unknown", [], 0.4, "Unknown API. Assumption kept.", self.name)

    def classify_sink(self, api: str, args: list, usage: str) -> SinkLabel:
        if api in SINK_TABLE:
            sinks, conf, why = SINK_TABLE[api]
            return SinkLabel(api, [{"arg": a, "cls": c} for a, c in sinks], conf, why, self.name)
        return SinkLabel(api, [], 0.4, "Unknown API.", self.name)

    def classify_entry(self, fn: str, decorators: list[str], params: list[str], source: str) -> EntryLabel:
        for d in decorators:
            if re.search(r"(fastapi|starlette|aiohttp|sanic|bottle|falcon).*\.(get|post|put|patch|delete|route|api_route)$", d):
                return EntryLabel(fn, "framework", d, [], "http", 0.95, "Route decorator: parameters come from the request.", self.name)
        if params[:2] == ["event", "context"]:
            return EntryLabel(fn, "handler", None, [0], "event", 0.9, "AWS Lambda handler signature; `event` is caller input.", self.name)
        return EntryLabel(fn, "none", None, [], "", 0.6, "No sign of an entry point.", self.name)

    def classify_registrar(self, api: str, arg, usage: str) -> RegistrarLabel:
        if re.search(r"(add_route|add_url_rule|add_api_route|add_view|add_get|add_post|register_handler|django\.urls\.(path|re_path)|django\.conf\.urls\.url)$", api):
            return RegistrarLabel(api, arg, True, "http", 0.92, "Registers the function as a request handler.", self.name)
        return RegistrarLabel(api, arg, False, "", 0.8, "Not a handler registration.", self.name)

    def classify_authz(self, decorator: str, source: str) -> AuthzLabel:
        code = "\n".join(l.split("#")[0] for l in source.splitlines())  # comments are not code
        user = re.search(r"current_user|request\.user|g\.user", code)
        denies = re.search(r"abort\(\s*40[13]|raise\s+\w*(Forbidden|PermissionDenied|Unauthorized)|return\s+.*40[13]", code)
        if user and denies and re.search(r"is_admin|role|permission|has_perm|is_staff|is_superuser", code):
            return AuthzLabel(decorator, "role", 0.9, "Denies unless the user has a privileged role.", self.name)
        if user and denies and re.search(r"owner|author|user_id", code):
            return AuthzLabel(decorator, "object", 0.85, "Compares the record owner with the current user.", self.name)
        if user and denies:
            return AuthzLabel(decorator, "authn", 0.8, "Checks that a user is logged in only.", self.name)
        return AuthzLabel(decorator, "none", 0.85 if source else 0.5, "No access decision in the decorator.", self.name)

    def judge_guard(self, pred: str, source: str) -> GuardLabel:
        """Judge a validation predicate by *executing* the regex it relies on against payloads."""
        regexes = _regexes_in(source) if not pred.startswith("regex:") else [pred.split(":", 1)[1]]
        anchored = "fullmatch" in source or any(r.startswith("^") and r.endswith("$") for r in regexes)
        if not regexes:
            return GuardLabel(pred, [], 0.3, "Could not find the validation logic.", self.name)
        if not anchored:
            return GuardLabel(pred, [], 0.8, "Regex is not anchored (match/search without $). A valid prefix "
                                              "followed by a payload still passes.", self.name, {"regexes": regexes})
        safe, passing = [], {}
        for cls, payloads in PAYLOADS.items():
            hits = [p for p in payloads for r in regexes if _fullmatch(r, p)]
            if hits:
                passing[cls] = hits
            elif payloads:
                safe.append(cls)
        if not passing:
            return GuardLabel(pred, ["all"], 0.92, f"Anchored regex {regexes[0]!r} rejected all {sum(len(v) for v in PAYLOADS.values())} test payloads.", self.name,
                              {"regexes": regexes, "payloads_tested": sum(len(v) for v in PAYLOADS.values())})
        return GuardLabel(pred, safe, 0.85, f"Regex accepts payloads for {sorted(passing)}.", self.name,
                          {"regexes": regexes, "accepted": passing})


def _regexes_in(source: str) -> list[str]:
    out = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = None
    if tree is not None:
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                name = n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
                if name in ("compile", "fullmatch", "match", "search"):
                    out.append(n.args[0].value)
    return out


def _fullmatch(regex: str, s: str) -> bool:
    try:
        return re.fullmatch(regex, s) is not None
    except re.error:
        return True  # unparseable regex: assume it accepts the payload


def _cite(tools: AgentTools, file: str, l1: int, l2: int) -> Citation:
    _, sha = tools.read_span(file, l1, l2)
    return Citation(file, l1, l2, sha)


class MockVerifier:
    """Imitates a tool-using verification agent with k-sample voting."""

    name = "mock-verifier-v1"
    k = 5

    def verify(self, case: VerificationCase, tools: AgentTools) -> Verdict:
        for a in case.assumptions:
            kind, *args = a["asm"]
            if kind == "maybe_sanitizer":
                return self._judge_sanitizer(case, tools, args[0])
            if kind == "unreachable":
                return self._judge_reachability(case, tools, args[0])
            if kind == "unknown_authz":
                return self._judge_authz(case, tools, args[0])
        return Verdict(case.fingerprint, "ABSTAIN", case.cls, None, [], [], {"k": self.k, "agree": self.k},
                       0.0, "Open assumptions are about library behavior not visible in this repository.", self.name)

    # ── does decorator D authorize access to the record? ─────────────────────────────────
    def _judge_authz(self, case: VerificationCase, tools: AgentTools, dec: str) -> Verdict:
        found = tools.function_source(dec)
        if found is None:
            return self._abstain(case, f"Could not read {dec}.")
        file, l1, l2, text, _sha = found
        label = MockSpecOracle().classify_authz(dec, text)
        name = dec.rsplit(".", 1)[-1]
        if label.authorizes:
            at = next((l1 + i for i, ln in enumerate(text.splitlines()) if "abort" in ln or "raise" in ln), l1)
            claims = [Claim("c1", "guard", f"@{name} returns 403 unless {label.rationale[0].lower()}{label.rationale[1:]}",
                            _cite(tools, file, at - 1, at), {"pred": "authz_decorator", "args": [dec]})]
            return Verdict(case.fingerprint, "FALSE_POSITIVE", case.cls, "GUARDED", claims,
                           [ProposedKnowledge("authz_decorator", [dec], _scope_for(dec), f"@{name} denies unprivileged users.", ["c1"])],
                           {"k": self.k, "agree": self.k, "dissent": []}, 0.9, f"@{name} restricts the endpoint.",
                           self.name, _cost(self.k))
        claims = [Claim("c1", "context", f"@{name} makes no access decision.", _cite(tools, file, l1, l2),
                        {"pred": "not_authz_decorator", "args": [dec]})]
        return Verdict(case.fingerprint, "TRUE_POSITIVE", case.cls, "EXPLOITABLE", claims,
                       [ProposedKnowledge("not_authz_decorator", [dec], _scope_for(dec), f"@{name} does not authorize.", ["c1"])],
                       {"k": self.k, "agree": self.k, "dissent": []}, 0.88, f"@{name} does not check access.",
                       self.name, _cost(self.k))

    # ── does F neutralise this vulnerability class? ──────────────────────────────────────
    def _judge_sanitizer(self, case: VerificationCase, tools: AgentTools, fn: str) -> Verdict:
        found = tools.function_source(fn)
        if found is None:
            return self._abstain(case, f"Could not read {fn}.")
        file, l1, l2, text, _sha = found
        lines = text.splitlines()
        escapes = [i for i, ln in enumerate(lines) if ESCAPE_RE.search(ln)]
        claims: list[Claim] = []
        sink_ctx = self._sink_context(case, tools)
        if escapes and case.cls == "sqli":
            esc_l1, esc_l2 = l1 + escapes[0], l1 + escapes[-1]
            claims.append(Claim("c1", "sanitizer", f"{fn.rsplit('.', 1)[-1]}() doubles single quotes and escapes backslashes.",
                                _cite(tools, file, esc_l1, esc_l2), {"pred": "sanitizer_api", "args": [fn, "sqli"]}))
            if sink_ctx["quoted"]:
                claims.append(Claim("c2", "context", "The value is used inside a single-quoted SQL literal.",
                                    _cite(tools, sink_ctx["file"], sink_ctx["line"], sink_ctx["line"])))
                return Verdict(case.fingerprint, "FALSE_POSITIVE", case.cls, "SANITIZED", claims,
                               [ProposedKnowledge("sanitizer_api", [fn, "sqli"], _scope_for(fn),
                                                  f"{fn} escapes quotes in single-quoted SQL literals.", ["c1"])],
                               {"k": self.k, "agree": self.k, "dissent": []}, 0.93,
                               f"{fn.rsplit('.', 1)[-1]}() escapes quotes and the value is used inside quotes.",
                               self.name, _cost(self.k))
            claims.append(Claim("c2", "context", "The value is used without quotes, so quote escaping does not stop `1 OR 1=1`.",
                                _cite(tools, sink_ctx["file"], sink_ctx["line"], sink_ctx["line"])))
            return Verdict(case.fingerprint, "TRUE_POSITIVE", case.cls, "EXPLOITABLE", claims, [],
                           {"k": self.k, "agree": 4, "dissent": ["1 sample: escaping is enough"]}, 0.78,
                           "Quote escaping does not protect an unquoted value.", self.name, _cost(self.k))
        strip = [i for i, ln in enumerate(lines) if re.search(r"""\.replace\(\s*["']\.\./["']\s*,\s*["']["']\s*\)""", ln)]
        if strip and case.cls == "path":
            at = l1 + strip[0]
            claims.append(Claim("c1", "sanitizer", f"{fn.rsplit('.', 1)[-1]}() removes `../` once. `....//` becomes `../`; absolute paths pass.",
                                _cite(tools, file, at, at)))
            return Verdict(case.fingerprint, "NEEDS_HUMAN", case.cls, None, claims, [],
                           {"k": self.k, "agree": 3, "dissent": ["2 samples: the fixed directory prefix is enough"]}, 0.55,
                           "Samples split on single-pass `../` removal. Likely bypass: `....//`.", self.name, _cost(self.k))
        # F does not escape anything relevant: the "sanitizer-looking" name is misleading.
        ret_line = next((i for i, ln in enumerate(lines) if ln.strip().startswith("return")), len(lines) - 1)
        claims.append(Claim("c1", "not_sanitizer", f"{fn.rsplit('.', 1)[-1]}() concatenates its argument with no escaping or validation.",
                            _cite(tools, file, l1 + ret_line, l1 + ret_line), {"pred": "not_sanitizer", "args": [fn]}))
        return Verdict(case.fingerprint, "TRUE_POSITIVE", case.cls, "NOT_A_SANITIZER", claims,
                       [ProposedKnowledge("not_sanitizer", [fn], _scope_for(fn),
                                          f"{fn} concatenates its argument unchanged.", ["c1"])],
                       {"k": self.k, "agree": self.k, "dissent": []}, 0.9,
                       f"{fn.rsplit('.', 1)[-1]}() does not sanitize {case.cls.upper()} input.", self.name, _cost(self.k))

    def _sink_context(self, case: VerificationCase, tools: AgentTools) -> dict:
        # Find the step where the sanitized value is spliced into the query string.
        for st in case.path:
            text, _ = tools.read_span(st["file"], st["line"], st["line"])
            if "+" in text and re.search(r"""'%?\s*["']\s*\+|\+\s*["']\s*%?'""", text):
                return {"quoted": True, "file": st["file"], "line": st["line"]}
            if re.search(r"""'\{[^}]+\}'""", text):
                return {"quoted": True, "file": st["file"], "line": st["line"]}
        last = case.path[-1] if case.path else {"file": "", "line": 1}
        for st in case.path:
            text, _ = tools.read_span(st["file"], st["line"], st["line"])
            if "+" in text:
                return {"quoted": False, "file": st["file"], "line": st["line"]}
        return {"quoted": False, "file": last["file"], "line": last["line"]}

    # ── is the source function reachable at all? ─────────────────────────────────────────
    def _judge_reachability(self, case: VerificationCase, tools: AgentTools, fn: str) -> Verdict:
        short = fn.rsplit(".", 1)[-1]
        refs = [(f, ln, t) for f, ln, t in tools.grep(rf"\b{re.escape(short)}\b") if not t.lstrip().startswith("def ")]
        found = tools.function_source(fn)
        if found is None:
            return self._abstain(case, f"Could not read {fn}.")
        file, l1, l2, _text, _ = found
        if refs:
            return Verdict(case.fingerprint, "NEEDS_HUMAN", case.cls, None,
                           [Claim("c1", "reachability", f"{short} is referenced {len(refs)} time(s).", _cite(tools, refs[0][0], refs[0][1], refs[0][1]))],
                           [], {"k": self.k, "agree": 3, "dissent": ["2 samples judged it reachable"]}, 0.5,
                           "May be registered dynamically.", self.name, _cost(self.k))
        claims = [Claim("c1", "reachability", f"{short}() has no route decorator and no references in the repository.",
                        _cite(tools, file, l1, l1), {"pred": "dead_fn", "args": [fn]})]
        return Verdict(case.fingerprint, "FALSE_POSITIVE", case.cls, "UNREACHABLE", claims,
                       [ProposedKnowledge("dead_fn", [fn], "repo", f"{fn} is never routed or called.", ["c1"])],
                       {"k": self.k, "agree": self.k, "dissent": []}, 0.88,
                       f"{short}() is unreachable. Delete it.",
                       self.name, _cost(self.k))

    def _abstain(self, case: VerificationCase, why: str) -> Verdict:
        return Verdict(case.fingerprint, "ABSTAIN", case.cls, None, [], [], {"k": self.k, "agree": self.k}, 0.0, why, self.name)


# One curated sink per class, used to build the validation pair for a sanitizer rule.
SINK_SNIPPETS: dict[str, tuple[str, str]] = {
    "sqli": ("import sqlite3", "sqlite3.connect('app.db').cursor().execute(\"SELECT * FROM t WHERE c = '\" + {v} + \"'\")"),
    "cmdi": ("import os", "os.system('echo ' + {v})"),
    "path": ("", "open('/srv/data/' + {v})"),
    "xss": ("import markupsafe", "markupsafe.Markup('<p>' + {v} + '</p>')"),
    "ssti": ("from flask import render_template_string", "render_template_string('Hi ' + {v})"),
    "ssrf": ("import requests", "requests.get({v}, timeout=3)"),
    "redirect": ("from flask import redirect", "redirect({v})"),
    "code": ("", "eval({v})"),
    "deser": ("import pickle", "pickle.loads({v})"),
}


def example_app(imports: list[str], body: list[str]) -> str:
    """A tiny Flask app with one route reading `value` from the query string."""
    head = ["from flask import Flask, abort, request", *[i for i in imports if i], "", "app = Flask(__name__)", "", "",
            '@app.route("/probe")', "def probe():", '    value = request.args.get("value", "")']
    return "\n".join(head + ["    " + b for b in body] + ['    return "ok"', ""])


class MockRuleSynthesizer:
    """Template-based rule writer. Deterministic: the rule follows from the triggering decision alone.

    sink:      `target($A0, ..., $X, ...)` (and the keyword form), focused on the argument that reaches
               the wrapped sink; validated by a call with a concatenated value (vulnerable) and the
               same call behind an `isalnum()` guard (fixed).
    sanitizer: `target(...)`; validated by a curated sink of the class fed the raw value (vulnerable)
               and the value passed through `target` (fixed).
    """

    name = "mock-synth-v1"

    def propose(self, ctx: RuleContext, tools: AgentTools) -> list[RuleProposal]:
        if "(" in ctx.target or "." not in ctx.target or ctx.target.startswith("*"):
            return []  # method calls on values have no importable name to write a rule for
        module, fn = ctx.target.rsplit(".", 1)
        imp = f"from {module} import {fn}"
        if ctx.role == "sink" and ctx.param_index is not None:
            pre = "".join(f"$A{j}, " for j in range(ctx.param_index))
            either = [{"pattern": f"{ctx.target}({pre}$X, ...)"}]
            if ctx.param_name:
                either.append({"pattern": f"{ctx.target}(..., {ctx.param_name}=$X, ...)"})
            rule = {"id": f"learned.sink.{ctx.cls}.{ctx.target}", "languages": ["python"], "severity": "INFO",
                    "message": "sink", "metadata": {"sentinel": {"role": "sink", "cls": ctx.cls, "cwe": CWE.get(ctx.cls)}},
                    "patterns": [{"pattern-either": either}, {"focus-metavariable": "$X"}]}
            call = f"{fn}({'None, ' * ctx.param_index}'prefix ' + value)"
            return [RuleProposal(_dump(rule), "sink", ctx.cls,
                                 f"`{fn}` passes argument {ctx.param_index} ({ctx.param_name or '?'}) to a {ctx.cls} sink "
                                 f"(seen in {ctx.repo}); callers that cannot see its body need it modelled as a sink.",
                                 example_app([imp], [call]),
                                 example_app([imp], ["if not value.isalnum():", "    abort(400)", call]), self.name)]
        if ctx.role == "sanitizer":
            sink_cls = "sqli" if ctx.cls == "all" else ctx.cls
            if sink_cls not in SINK_SNIPPETS:
                return []
            sink_imp, sink = SINK_SNIPPETS[sink_cls]
            rule = {"id": f"learned.sanitizer.{ctx.cls}.{ctx.target}", "languages": ["python"], "severity": "INFO",
                    "message": "sanitizer", "metadata": {"sentinel": {"role": "sanitizer", "cls": ctx.cls}},
                    "pattern": f"{ctx.target}(...)"}
            return [RuleProposal(_dump(rule), "sanitizer", ctx.cls,
                                 f"`{fn}` was judged to neutralise {ctx.cls} (in {ctx.repo}); modelled as a sanitizer "
                                 "so the decision carries to every caller and to CI.",
                                 example_app([sink_imp], [sink.format(v="value")]),
                                 example_app([sink_imp, imp], [sink.format(v=f"{fn}(value)")]), self.name)]
        return []


def _dump(rule: dict) -> str:
    return yaml.safe_dump({"rules": [rule]}, sort_keys=False)


def _scope_for(fn: str) -> str:
    """Helpers in shared internal packages are org-wide knowledge; app-local ones stay repo-scoped."""
    return "org" if fn.split(".")[0].endswith("_common") or fn.split(".")[0] in ("common", "shared", "lib") else "repo"


def _cost(k: int) -> dict:
    # What the real client would report; the mock reports nominal numbers so the cost KPI is exercised.
    return {"samples": k, "tokens_in": 2400 * k, "tokens_out": 350 * k, "tool_calls": 3 * k}
