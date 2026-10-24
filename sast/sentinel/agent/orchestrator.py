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

import hashlib
import re
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

    def read_span(self, file: str, l1: int, l2: int) -> tuple[str, str]:
        self.calls.append(("read_span", (file, l1, l2)))
        lines = self.facts.files.get(file, "").splitlines()
        text = "\n".join(lines[max(l1 - 1, 0): l2])
        return text, span_hash(text)

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
        return [(f, i, ln) for f, src in sorted(self.facts.files.items())
                for i, ln in enumerate(src.splitlines(), 1) if rx.search(ln)]

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
        check("verdict", True, f"agent returned {verdict.verdict}: routed to a human")
        return GateResult(False, "review", checks)

    ok = True
    # G1 citations
    for c in verdict.claims:
        if c.cite is None:
            continue
        _, sha = tools.read_span(c.cite.file, c.cite.l1, c.cite.l2)
        ok &= check("citation", sha == c.cite.sha256,
                    f"{c.id}: {c.cite.file}:{c.cite.l1}-{c.cite.l2} " + ("matches the scanned code" if sha == c.cite.sha256
                                                                       else "does NOT match the scanned code"))
    # G2 votes
    k, agree = verdict.votes.get("k", 1), verdict.votes.get("agree", 0)
    if verdict.verdict == "FALSE_POSITIVE":
        ok &= check("votes", agree == k, f"{agree}/{k} samples agree; suppression requires unanimity")
    else:
        ok &= check("votes", agree * 2 > k, f"{agree}/{k} samples agree; confirmation requires a majority")
    # G3 symbolic discharge
    facts = [c.fact for c in verdict.claims if c.fact]
    wi = tools.what_if(facts) if facts else None
    after = wi["findings"].get(verdict.fingerprint) if wi else None
    if verdict.verdict == "FALSE_POSITIVE":
        if after is None:
            ok &= check("discharge", False, "the verdict carries no checkable fact; free-text FP verdicts never suppress")
        else:
            reproduced = after["status"] == "mitigated" and any(
                any(kid.startswith("WHATIF-") for kid in m.get("knowledge", [])) for m in after["mitigations"])
            ok &= check("discharge", reproduced,
                        "engine re-derived the finding as mitigated from the agent's facts" if reproduced else
                        f"engine did not reproduce the argument (status under the agent's facts: {after['status']})")
        if ok and verdict.cls in never:
            check("policy", False, f"{verdict.cls} is on the never-auto-suppress list")
            return GateResult(False, "review", checks)
        return GateResult(bool(ok), "suppressed_ai" if ok else "review", checks)
    # TRUE_POSITIVE
    current = {f.fingerprint: f for f in tools.analysis.findings}.get(verdict.fingerprint)
    has_alarm = current is not None and current.status in ("confirmed", "undecided")
    ok &= check("alarm", has_alarm, "engine derives a source→sink flow" if has_alarm else "engine derives no flow")
    if after is not None:
        ok &= check("discharge", after["status"] == "confirmed",
                    "the agent's facts discharge every open assumption" if after["status"] == "confirmed"
                    else f"open assumptions remain (status {after['status']})")
    return GateResult(bool(ok), "confirmed" if ok else "review", checks)
