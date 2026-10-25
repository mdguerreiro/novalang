"""Orchestration of the neural tiers and the gates that keep them honest.

The LLM (or the mock) only *proposes*. The orchestrator decides, using code, never the model:
  G1 citations   every cited span must hash-match the scanned file (catches hallucinated code)
  G2 votes       FALSE_POSITIVE needs unanimity across k samples; TRUE_POSITIVE a majority
  G3 discharge   an FP is accepted only if the engine, given the agent's proposed facts, derives
                 that the finding is mitigated, i.e. it reproduces the argument symbolically. A TP
                 must leave the engine with an alarm (and, if it carries facts, they must discharge
                 the open assumptions)
  G4 policy      classes on the never-auto-suppress list always go to a human
"""
from __future__ import annotations

import ast
import hashlib
import io
import re
import tokenize
from dataclasses import dataclass, field
from typing import Callable

from ..engine.analyze import Analysis, KnowledgeFact
from ..extract.python_facts import Facts
from .interfaces import AgentTools, Verdict


def span_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Tools(AgentTools):
    """Read-only tools over one scanned repository."""

    def __init__(self, facts: Facts, analysis: Analysis, rerun: Callable[[list[KnowledgeFact]], Analysis]):
        self.facts, self.analysis, self._rerun = facts, analysis, rerun
        self.calls: list[tuple[str, tuple]] = []
        self.served: dict[str, list[tuple[int, int]]] = {}  # line ranges the agent was actually shown

    def span(self, file: str, l1: int, l2: int) -> tuple[str, str]:
        """Lines and hash, without recording a read (used by the gate)."""
        lines = self.facts.files.get(file, "").splitlines()
        text = "\n".join(lines[max(l1 - 1, 0): l2])
        return text, span_hash(text)

    def read_span(self, file: str, l1: int, l2: int) -> tuple[str, str]:
        self.calls.append(("read_span", (file, l1, l2)))
        if file in self.facts.files:
            self.served.setdefault(file, []).append((l1, l2))
        return self.span(file, l1, l2)

    def was_served(self, file: str, l1: int, l2: int) -> bool:
        """Every cited line was shown to the agent by some tool call (ranges may be merged or narrowed)."""
        shown = self.served.get(file, [])
        return l1 <= l2 and all(any(a <= n <= b for a, b in shown) for n in range(l1, l2 + 1))

    def function_source(self, qname: str):
        self.calls.append(("function_source", (qname,)))
        fn = self.facts.functions.get(qname)
        if fn is None:
            return None
        text, sha = self.read_span(fn.file, fn.line, fn.end_line)
        return fn.file, fn.line, fn.end_line, text, sha

    def grep(self, pattern: str) -> list[tuple[str, int, str]]:
        self.calls.append(("grep", (pattern,)))
        rx = re.compile(pattern)
        hits = [(f, i, ln) for f, src in sorted(self.facts.files.items())
                for i, ln in enumerate(src.splitlines(), 1) if rx.search(ln)]
        for f, i, _ in hits:
            self.served.setdefault(f, []).append((i, i))
        return hits

    def what_if(self, facts: list[dict]) -> dict:
        self.calls.append(("what_if", (tuple((f["pred"], tuple(f["args"])) for f in facts),)))
        extra = [KnowledgeFact(f"WHATIF-{i}", f["pred"], tuple(f["args"])) for i, f in enumerate(facts)]
        after = self._rerun(extra)
        before = self.analysis.by_key()
        by_fp = {f.fingerprint: f for f in after.findings}
        changed = [{"fingerprint": f.fingerprint, "from": before[f.key].status, "to": f.status}
                   for f in after.findings if f.key in before and before[f.key].status != f.status]
        return {"findings": {fp: {"status": f.status, "mitigations": f.mitigations} for fp, f in by_fp.items()},
                "changed": changed}


def strip_comments(source: str) -> str:
    """Blank out comments and docstrings, keeping every line in place (same line count and numbering)."""
    lines = source.splitlines(keepends=True)
    spans: list[tuple[tuple[int, int], tuple[int, int]]] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                spans.append((tok.start, tok.end))
        for node in ast.walk(ast.parse(source)):
            body = getattr(node, "body", None)
            if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                    and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                d = body[0]
                spans.append(((d.lineno, d.col_offset), (d.end_lineno, d.end_col_offset)))
    except (SyntaxError, tokenize.TokenError):
        return source
    out = [list(ln) for ln in lines]
    for (l1, c1), (l2, c2) in spans:
        for ln in range(l1, l2 + 1):
            row = out[ln - 1]
            a = c1 if ln == l1 else 0
            b = c2 if ln == l2 else len(row) - (1 if row and row[-1] == "\n" else 0)
            for i in range(a, min(b, len(row))):
                if row[i] != "\n":
                    row[i] = " "
    return "".join("".join(r).rstrip() + ("\n" if r and r[-1] == "\n" else "") for r in out)


class StrippedTools(AgentTools):
    """The same tools over comment- and docstring-free code. Hashes still refer to the original lines,
    so a citation made from stripped code verifies against the real file."""

    def __init__(self, inner: Tools):
        self.inner = inner
        self._cache: dict[str, list[str]] = {}

    def _stripped(self, file: str) -> list[str]:
        if file not in self._cache:
            self._cache[file] = strip_comments(self.inner.facts.files.get(file, "")).splitlines()
        return self._cache[file]

    def read_span(self, file: str, l1: int, l2: int) -> tuple[str, str]:
        _, sha = self.inner.read_span(file, l1, l2)
        return "\n".join(self._stripped(file)[max(l1 - 1, 0): l2]), sha

    def function_source(self, qname: str):
        found = self.inner.function_source(qname)
        if found is None:
            return None
        file, l1, l2, _text, sha = found
        return file, l1, l2, "\n".join(self._stripped(file)[l1 - 1: l2]), sha

    def grep(self, pattern: str) -> list[tuple[str, int, str]]:
        rx = re.compile(pattern)
        return [(f, i, ln) for f in sorted(self.inner.facts.files)
                for i, ln in enumerate(self._stripped(f), 1) if rx.search(ln)]

    def what_if(self, facts: list[dict]) -> dict:
        return self.inner.what_if(facts)


@dataclass
class GateResult:
    accepted: bool
    lane: str  # suppressed_ai | confirmed | review
    checks: list[dict] = field(default_factory=list)

    def to_json(self) -> dict:
        return {"accepted": self.accepted, "lane": self.lane, "checks": self.checks}


NEVER_AUTO_SUPPRESS: set[str] = set()


def gate(verdict: Verdict, tools: Tools, never_auto_suppress: set[str] | None = None) -> GateResult:
    checks: list[dict] = []
    never = NEVER_AUTO_SUPPRESS if never_auto_suppress is None else never_auto_suppress

    def check(name: str, ok: bool, detail: str):
        checks.append({"gate": name, "ok": ok, "detail": detail})
        return ok

    if verdict.verdict in ("ABSTAIN", "NEEDS_HUMAN"):
        check("verdict", True, f"{verdict.verdict}: sent to analyst")
        return GateResult(False, "review", checks)

    ok = True
    # G1 citations
    for c in verdict.claims:
        if c.cite is None:
            continue
        # A citation is valid when the agent was shown those exact lines (tool log) or quotes their hash.
        # The log is the stronger check: models narrow or merge ranges and then copy another range's hash.
        span = getattr(tools, "span", tools.read_span)
        _, sha = span(c.cite.file, c.cite.l1, c.cite.l2)
        seen = getattr(tools, "was_served", lambda *a: False)(c.cite.file, c.cite.l1, c.cite.l2)
        good = sha == c.cite.sha256 or seen
        ok &= check("citation", good, f"{c.id}: {c.cite.file}:{c.cite.l1}-{c.cite.l2} " +
                    ("hash matches" if sha == c.cite.sha256 else "lines were read" if seen else "lines never read"))
    # G2 votes
    k, agree = verdict.votes.get("k", 1), verdict.votes.get("agree", 0)
    if verdict.verdict == "FALSE_POSITIVE":
        ok &= check("votes", agree == k, f"{agree}/{k} agree (closing needs {k}/{k})")
    else:
        ok &= check("votes", agree * 2 > k, f"{agree}/{k} agree (confirming needs a majority)")
    # G3 symbolic discharge
    facts = [c.fact for c in verdict.claims if c.fact]
    wi = tools.what_if(facts) if facts else None
    after = wi["findings"].get(verdict.fingerprint) if wi else None
    if verdict.verdict == "FALSE_POSITIVE":
        if after is None:
            ok &= check("discharge", False, "no checkable fact in verdict")
        else:
            reproduced = after["status"] == "mitigated" and any(
                any(kid.startswith("WHATIF-") for kid in m.get("knowledge", [])) for m in after["mitigations"])
            ok &= check("discharge", reproduced,
                        "mitigation re-derived from the agent's facts" if reproduced else
                        f"not re-derived (engine status: {after['status']})")
        if ok and verdict.cls in never:
            check("policy", False, f"{verdict.cls} is never auto-closed")
            return GateResult(False, "review", checks)
        return GateResult(bool(ok), "suppressed_ai" if ok else "review", checks)
    # TRUE_POSITIVE
    current = {f.fingerprint: f for f in tools.analysis.findings}.get(verdict.fingerprint)
    has_alarm = current is not None and current.status in ("confirmed", "undecided")
    ok &= check("alarm", has_alarm, "source to sink flow exists" if has_alarm else "no flow")
    if after is not None:
        # IDOR keeps an "authorization elsewhere" assumption the verifier itself answers by reading the code.
        done = after["status"] == "confirmed" or (verdict.cls == "idor" and after["status"] == "undecided")
        ok &= check("discharge", done,
                    "all assumptions resolved" if done
                    else f"assumptions still open (status {after['status']})")
    return GateResult(bool(ok), "confirmed" if ok else "review", checks)
