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
class SinkLabel:
    """Frontier question: tainted data reaches arguments of an unmodelled library call. Which are sinks?"""
    api: str
    sinks: list[dict]  # [{"arg": int | str, "cls": str}]; [] = not a sink for any class we track
    confidence: float
    rationale: str
    model: str


@dataclass
class EntryLabel:
    """Frontier question: a function with no known caller (or a decorated one) passes a parameter to a sink.
    Is it an entry point that receives attacker-controlled input?"""
    fn: str
    kind: Literal["framework", "handler", "none"]  # framework: the decorator registers it (route, task, ...)
    decorator: str | None  # framework kind: which decorator makes params untrusted
    params: list[int]  # handler kind: indexes of untrusted parameters
    source_kind: str  # http | event | queue | cli
    confidence: float
    rationale: str
    model: str


@dataclass
class RegistrarLabel:
    """Frontier question: project functions are passed to `api` at argument `arg`. Does that register them as
    request handlers (so their parameters carry attacker-controlled input)?"""
    api: str
    arg: int | str
    registers: bool
    source_kind: str
    confidence: float
    rationale: str
    model: str


@dataclass
class AuthzLabel:
    """Frontier question: a decorator sits on a handler that loads a per-user record by id. Does it authorize?"""
    subject: str
    kind: Literal["object", "role", "authn", "none"]  # object/role checks authorize; authn-only and none do not
    confidence: float
    rationale: str
    model: str

    @property
    def authorizes(self) -> bool:
        return self.kind in ("object", "role")


@dataclass
class ModelLabel:
    """Frontier question: are records of this model private to the user that owns them?"""
    model: str
    private: bool
    confidence: float
    rationale: str
    model_name: str


@dataclass
class SourceLabel:
    """Frontier question: is the value of this library call / attribute attacker-controlled?"""
    api: str
    is_source: bool
    kind: str  # http | header | cookie | event | queue | cli | file
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


@dataclass
class RuleContext:
    """Why a spec rule is wanted, and the evidence for it. Built by the pipeline from a decided finding.

    role=sink:      `target` is a project helper that wraps a sink; argument `param_index` (`param_name`)
                    reaches it. A rule makes call sites visible where the helper's body is not.
    role=sanitizer: `target` was judged (by a human or a gated agent verdict) to neutralise `cls`.
    """
    role: Literal["source", "sink", "sanitizer"]
    cls: str
    target: str  # qualified callee, e.g. acme_common.shell.run_shell
    repo: str
    param_index: int | None = None
    param_name: str | None = None
    helper_source: str = ""  # body of `target` when the repository contains it (code under analysis: untrusted)
    site: dict | None = None  # {"file", "line", "code"}: where the originating finding uses `target`
    finding: dict = field(default_factory=dict)  # {"fingerprint", "source_fn", "sink_fn", "title"}


@dataclass
class RuleProposal:
    """A Semgrep spec rule plus the validation pair the patch-differential oracle runs.
    vulnerable_example / fixed_example are complete Python modules (tiny Flask apps). For a sanitizer
    rule, vulnerable = the unsanitized variant and fixed = the variant that calls the sanitizer."""
    yaml: str  # one Semgrep rule (`rules: [...]`) with metadata.sentinel {role, cls[, kind, cwe]}
    role: str
    cls: str
    rationale: str
    vulnerable_example: str
    fixed_example: str
    model: str = ""


class AgentTools(Protocol):
    def read_span(self, file: str, l1: int, l2: int) -> tuple[str, str]: ...
    def function_source(self, qname: str) -> tuple[str, int, int, str, str] | None: ...
    def grep(self, pattern: str) -> list[tuple[str, int, str]]: ...
    def what_if(self, facts: list[dict], focus: list[str] | None = None) -> dict: ...


class SpecOracle(Protocol):
    name: str

    def classify_api(self, api: str, usage: str) -> ApiLabel: ...
    def judge_guard(self, pred: str, source: str) -> GuardLabel: ...
    def classify_sink(self, api: str, args: list, usage: str) -> SinkLabel: ...
    def classify_entry(self, fn: str, decorators: list[str], params: list[str], source: str) -> EntryLabel: ...
    def classify_registrar(self, api: str, arg: int | str, usage: str) -> RegistrarLabel: ...
    def classify_authz(self, decorator: str, source: str) -> AuthzLabel: ...
    def classify_model(self, model: str, source: str) -> ModelLabel: ...
    def classify_source(self, api: str, usage: str) -> SourceLabel: ...


class Verifier(Protocol):
    name: str

    def verify(self, case: VerificationCase, tools: AgentTools) -> Verdict: ...


class RuleSynthesizer(Protocol):
    """Writes Semgrep spec rules (KNighter / Autogrep style). Proposals are never trusted: each one must
    pass the validation gate in learn/rules.py before it can affect a result."""
    name: str

    def propose(self, ctx: RuleContext, tools: AgentTools) -> list[RuleProposal]: ...
