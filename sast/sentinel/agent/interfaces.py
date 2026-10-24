"""Contracts between the symbolic engine and the neural tiers.

The engine never trusts these objects. It only re-derives decisions from the *facts* they
propose (see orchestrator.py). A real LLM client (claude.py) and the deterministic mock
(mock.py) implement the same protocols.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal, Protocol

VerdictKind = Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_HUMAN", "ABSTAIN"]
ReasonCode = Literal["SANITIZED", "GUARDED", "NOT_ATTACKER_CONTROLLED", "UNREACHABLE", "TEST_CODE", "SAFE_TYPE",
                     "NOT_A_SANITIZER", "EXPLOITABLE"]


@dataclass
class Citation:
    file: str
    l1: int
    l2: int
    sha256: str  # sha256 of the cited lines exactly as returned by AgentTools.read_span


@dataclass
class Claim:
    id: str
    kind: Literal["source", "propagation", "sanitizer", "guard", "sink", "reachability", "not_sanitizer", "context"]
    statement: str
    cite: Citation | None = None
    fact: dict | None = None  # {"pred": ..., "args": [...]} that the engine can check


@dataclass
class ProposedKnowledge:
    pred: str
    args: list
    scope: Literal["repo", "org", "global"]
    rationale: str
    claim_ids: list[str] = field(default_factory=list)


@dataclass
class Verdict:
    fingerprint: str
    verdict: VerdictKind
    cls: str
    reason_code: str | None
    claims: list[Claim]
    proposed: list[ProposedKnowledge]
    votes: dict  # {"k": samples, "agree": n agreeing with the verdict, "dissent": [...]}
    confidence: float
    rationale: str
    model: str
    cost: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class ApiLabel:
    api: str
    role: Literal["propagator", "sanitizer", "source", "sink", "unknown"]
    classes: list[str]  # for sanitizers/sinks; ["all"] = every class
    confidence: float
    rationale: str
    model: str


@dataclass
class GuardLabel:
    pred: str
    safe_for: list[str]  # [] = does not validate; ["all"] = blocks every payload class
    confidence: float
    rationale: str
    model: str
    evidence: dict = field(default_factory=dict)


@dataclass
class VerificationCase:
    """Everything the verifier gets about one finding. Code is reachable only through tools."""
    fingerprint: str
    repo: str
    cls: str
    title: str
    engine_status: str
    assumptions: list[dict]
    path: list[dict]
    source_fn: str
    sink_fn: str
    proof: dict | None


class AgentTools(Protocol):
    def read_span(self, file: str, l1: int, l2: int) -> tuple[str, str]: ...
    def function_source(self, qname: str) -> tuple[str, int, int, str, str] | None: ...
    def grep(self, pattern: str) -> list[tuple[str, int, str]]: ...
    def what_if(self, facts: list[dict]) -> dict: ...


class SpecOracle(Protocol):
    name: str

    def classify_api(self, api: str, usage: str) -> ApiLabel: ...
    def judge_guard(self, pred: str, source: str) -> GuardLabel: ...


class Verifier(Protocol):
    name: str

    def verify(self, case: VerificationCase, tools: AgentTools) -> Verdict: ...
