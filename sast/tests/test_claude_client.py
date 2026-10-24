"""The real Claude verifier, driven offline by a scripted fake of the Messages API.

Checks the tool loop (tool results go back to the model, citations carry the sha256 that
read_span returned), k-sample voting, refusal handling, and that the verdict clears the same
symbolic gates as the mock.
"""
import json
from dataclasses import asdict
from types import SimpleNamespace as NS

import pytest

pytest.importorskip("anthropic")

from sentinel.agent.claude import ClaudeVerifier  # noqa: E402
from sentinel.agent.interfaces import VerificationCase  # noqa: E402
from sentinel.agent.orchestrator import Tools, gate  # noqa: E402
from sentinel.eval import fresh_scanner  # noqa: E402

QUOTE_SQL = "acme_common.db.quote_sql"


class FakeAPI:
    """Replays a script: each create() call pops the next response factory, which may inspect messages."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.beta = NS(messages=NS(create=self.create))

    def create(self, **kw):
        self.calls.append(kw)
        return self.script.pop(0)(kw)


def _usage():
    return NS(input_tokens=100, output_tokens=20)


def tool_call(name, args):
    return lambda kw: NS(stop_reason="tool_use", usage=_usage(),
                         content=[NS(type="tool_use", id=f"tu_{name}", name=name, input=args)])


def final(build):
    return lambda kw: NS(stop_reason="end_turn", usage=_usage(), content=[NS(type="text", text=json.dumps(build(kw)))])


def refusal():
    return lambda kw: NS(stop_reason="refusal", usage=_usage(), content=[])


def sha_from_last_tool_result(kw):
    last = kw["messages"][-1]["content"][0]
    return json.loads(last["content"])["sha256"]


@pytest.fixture(scope="module")
def case_and_tools():
    sc = fresh_scanner(repos=["acme-shop"])
    facts, matches = sc.inputs("acme-shop")
    a = sc.analyze_repo("acme-shop")
    f = next(x for x in a.findings if x.source_fn.endswith("order_lookup"))
    assert f.status == "undecided"
    tools = Tools(facts, a, lambda extra: sc.analyze_repo("acme-shop", extra))
    case = VerificationCase(f.fingerprint, "acme-shop", f.cls, f.title, f.status, f.assumptions,
                            [asdict(s) for s in f.path], f.source_fn, f.sink_fn, f.proof)
    return case, tools


def fp_verdict(kw):
    sha = sha_from_last_tool_result(kw)
    return {"verdict": "FALSE_POSITIVE", "reason_code": "SANITIZED", "rationale": "quote_sql escapes quotes",
            "claims": [{"id": "c1", "kind": "sanitizer", "statement": "doubles single quotes",
                        "cite": {"file": "acme_common/db.py", "l1": 11, "l2": 15, "sha256": sha},
                        "fact": {"pred": "sanitizer_api", "args": [QUOTE_SQL, "sqli"]}}],
            "proposed": [{"pred": "sanitizer_api", "args": [QUOTE_SQL, "sqli"], "scope": "org", "rationale": "x", "claim_ids": ["c1"]}]}


def test_tool_loop_citations_and_gates(case_and_tools):
    case, tools = case_and_tools
    trajectory = [tool_call("read_span", {"file": "acme_common/db.py", "l1": 11, "l2": 15}), final(fp_verdict)]
    api = FakeAPI(trajectory * 3)
    v = ClaudeVerifier(client=api).verify(case, tools)
    assert v.verdict == "FALSE_POSITIVE" and v.votes == {"k": 3, "agree": 3, "dissent": []}
    assert v.cost["tool_calls"] == 3 and v.cost["tokens_in"] == 600
    # The tool result was sent back to the model as a tool_result for the right tool_use id.
    second = api.calls[1]["messages"][-1]["content"][0]
    assert second["type"] == "tool_result" and second["tool_use_id"] == "tu_read_span"
    # Request shape: structured output schema, adaptive thinking, refusal fallbacks, no forced tool choice.
    req = api.calls[0]
    assert req["output_config"]["format"]["type"] == "json_schema" and req["thinking"] == {"type": "adaptive"}
    assert req["fallbacks"] == "default" and "tool_choice" not in req
    res = gate(v, tools)
    assert res.accepted and res.lane == "suppressed_ai", res.checks


def test_hallucinated_hash_and_split_votes_are_rejected(case_and_tools):
    case, tools = case_and_tools

    def bad(kw):
        out = fp_verdict(kw)
        out["claims"][0]["cite"]["sha256"] = "0" * 64
        return out

    traj_bad = [tool_call("read_span", {"file": "acme_common/db.py", "l1": 11, "l2": 15}), final(bad)]
    v = ClaudeVerifier(client=FakeAPI(traj_bad * 3)).verify(case, tools)
    assert not gate(v, tools).accepted

    traj_ok = [tool_call("read_span", {"file": "acme_common/db.py", "l1": 11, "l2": 15}), final(fp_verdict)]
    split = FakeAPI(traj_ok * 2 + [refusal()])
    v2 = ClaudeVerifier(client=split).verify(case, tools)
    assert v2.verdict == "FALSE_POSITIVE" and v2.votes["agree"] == 2 and v2.votes["dissent"] == ["1 sample(s): ABSTAIN"]
    assert not gate(v2, tools).accepted  # suppression needs unanimity


def test_tool_errors_are_returned_to_the_model(case_and_tools):
    case, tools = case_and_tools
    abstain = {"verdict": "ABSTAIN", "reason_code": None, "rationale": "n/a", "claims": [], "proposed": []}
    api = FakeAPI([tool_call("function_source", {"qname": "no.such.fn"}), final(lambda kw: abstain)] * 3)
    v = ClaudeVerifier(client=api).verify(case, tools)
    assert v.verdict == "ABSTAIN"
    assert json.loads(api.calls[1]["messages"][-1]["content"][0]["content"]) == {"error": "no such function"}
