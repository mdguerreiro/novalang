"""The real Claude verifier, driven offline by a scripted fake of the Messages API.

Checks the tool loop (tool results go back to the model, citations carry the sha256 that
read_span returned), k-sample voting, refusal handling, and that the verdict clears the same
symbolic gates as the mock.
"""
import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

pytest.importorskip("anthropic")

from sentinel.agent.claude import ClaudeVerifier  # noqa: E402

ClaudeVerifier.parallel = False  # the scripted fake replays responses in order
ClaudeVerifier.adaptive = False  # scripted tests exercise the full vote; adaptivity has its own test
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
    api = FakeAPI(trajectory * 4)  # 3 voting samples + 1 comment-stripped re-check
    v = ClaudeVerifier(client=api).verify(case, tools)
    assert v.verdict == "FALSE_POSITIVE" and v.votes == {"k": 3, "agree": 3, "dissent": []}
    assert v.cost["tool_calls"] == 4 and v.cost["tokens_in"] == 800 and v.cost["samples"] == 4
    # The tool result was sent back to the model as a tool_result for the right tool_use id.
    second = api.calls[1]["messages"][-1]["content"][0]
    assert second["type"] == "tool_result" and second["tool_use_id"] == "tu_read_span"
    # Request shape: structured output schema, adaptive thinking, refusal fallbacks, no forced tool choice.
    req = api.calls[0]
    assert req["output_config"]["format"]["type"] == "json_schema" and req["thinking"] == {"type": "adaptive"}
    assert req["fallbacks"] == "default" and "tool_choice" not in req
    # Caching: explicit breakpoint on the shared system prompt + automatic breakpoint on the loop prefix.
    assert req["system"][0]["cache_control"] == {"type": "ephemeral"} and req["cache_control"] == {"type": "ephemeral"}
    assert req["output_config"]["task_budget"]["total"] >= 20000 and "task-budgets-2026-03-13" in req["betas"]
    res = gate(v, tools)
    assert res.accepted and res.lane == "suppressed_ai", res.checks


def test_hallucinated_hash_and_split_votes_are_rejected(case_and_tools):
    case, tools = case_and_tools

    def bad(kw):
        out = fp_verdict(kw)
        out["claims"][0]["cite"]["sha256"] = "0" * 64
        return out

    # Cites lines it never read (the read covers other lines) with a made-up hash.
    tools.served.clear()  # the fixture is shared: earlier tests read these lines
    traj_bad = [tool_call("read_span", {"file": "acme_common/db.py", "l1": 1, "l2": 3}), final(bad)]
    v = ClaudeVerifier(client=FakeAPI(traj_bad * 4)).verify(case, tools)
    assert not gate(v, tools).accepted

    traj_ok = [tool_call("read_span", {"file": "acme_common/db.py", "l1": 11, "l2": 15}), final(fp_verdict)]
    split = FakeAPI(traj_ok * 2 + [refusal()] + traj_ok)
    v2 = ClaudeVerifier(client=split).verify(case, tools)
    assert v2.verdict == "FALSE_POSITIVE" and v2.votes["agree"] == 2 and v2.votes["dissent"] == ["1 sample(s): ABSTAIN"]
    assert not gate(v2, tools).accepted  # suppression needs unanimity


def test_tool_errors_are_returned_to_the_model(case_and_tools):
    case, tools = case_and_tools
    abstain = {"verdict": "ABSTAIN", "reason_code": None, "rationale": "n/a", "claims": [], "proposed": []}
    api = FakeAPI([tool_call("function_source", {"qname": "no.such.fn"}), final(lambda kw: abstain)] * 4)
    v = ClaudeVerifier(client=api).verify(case, tools)
    assert v.verdict == "ABSTAIN"
    assert json.loads(api.calls[1]["messages"][-1]["content"][0]["content"]) == {"error": "no such function"}


def test_comment_stripped_disagreement_goes_to_a_human(case_and_tools):
    case, tools = case_and_tools
    traj = [tool_call("read_span", {"file": "acme_common/db.py", "l1": 11, "l2": 15}), final(fp_verdict)]
    tp = {"verdict": "TRUE_POSITIVE", "reason_code": "EXPLOITABLE", "rationale": "x", "claims": [], "proposed": []}
    api = FakeAPI(traj * 3 + [final(lambda kw: tp)])
    v = ClaudeVerifier(client=api).verify(case, tools)
    assert v.verdict == "NEEDS_HUMAN" and v.proposed == []
    assert "comment-stripped re-check: TRUE_POSITIVE" in v.votes["dissent"]
    assert gate(v, tools).lane == "review"


def test_stripped_tools_hide_comments_but_keep_hashes(case_and_tools):
    from sentinel.agent.orchestrator import StrippedTools
    _, tools = case_and_tools
    text, sha = StrippedTools(tools).read_span("acme_common/db.py", 11, 15)
    orig, orig_sha = tools.read_span("acme_common/db.py", 11, 15)
    assert '"""' in orig and '"""' not in text and sha == orig_sha


def test_api_errors_become_abstentions(case_and_tools):
    import anthropic
    import httpx
    case, tools = case_and_tools

    def bad_request(kw):
        req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        raise anthropic.BadRequestError("bad", response=httpx.Response(400, request=req), body=None)

    v = ClaudeVerifier(client=FakeAPI([bad_request] * 4)).verify(case, tools)
    assert v.verdict == "ABSTAIN" and gate(v, tools).lane == "review"


def test_cross_family_voters_alternate(case_and_tools, monkeypatch):
    import sentinel.agent.claude as cl
    case, tools = case_and_tools
    monkeypatch.setattr(cl, "VOTERS", ["claude-opus-5-5", "claude-sonnet-5-5"])
    abstain = {"verdict": "ABSTAIN", "reason_code": None, "rationale": "n/a", "claims": [], "proposed": []}
    api = FakeAPI([final(lambda kw: abstain)] * 4)
    cl.ClaudeVerifier(client=api).verify(case, tools)
    assert [c["model"] for c in api.calls] == ["claude-opus-5-5", "claude-sonnet-5-5", "claude-opus-5-5", "claude-opus-5-5"]


def test_oracle_batch_maps_results_by_custom_id():
    from sentinel.agent.claude import ClaudeSpecOracle
    created = {}

    def create(requests):
        created["requests"] = requests
        return NS(id="b1", processing_status="ended")

    def msg(payload):
        return NS(stop_reason="end_turn", content=[NS(type="text", text=json.dumps(payload))])

    def results(batch_id):
        # Out of order on purpose: results must be keyed by custom_id, never by position.
        return [NS(custom_id="q1", result=NS(type="succeeded", message=msg({"safe_for": ["all"], "confidence": 0.9, "rationale": "anchored"}))),
                NS(custom_id="q0", result=NS(type="succeeded", message=msg({"role": "sanitizer", "classes": ["all"], "confidence": 0.95, "rationale": "hex"}))),
                NS(custom_id="q2", result=NS(type="errored"))]

    fake = NS(beta=NS(messages=NS(batches=NS(create=create, retrieve=None, results=results))))
    labels = ClaudeSpecOracle(client=fake).ask_many([("unknown_api", "hashlib.sha256().hexdigest", ""),
                                                     ("unknown_guard", "regex:[a-z]+", "re.fullmatch(...)"),
                                                     ("unknown_api", "x.y", "")])
    assert labels[("unknown_api", "hashlib.sha256().hexdigest")].role == "sanitizer"
    assert labels[("unknown_guard", "regex:[a-z]+")].safe_for == ["all"]
    assert labels[("unknown_api", "x.y")].role == "unknown"  # errored item: the assumption stays open
    assert all("fallbacks" not in r["params"] for r in created["requests"])  # not supported on batches


# ── rule synthesizer ─────────────────────────────────────────────────────────────────────

def _synth_ctx():
    from sentinel.agent.interfaces import RuleContext
    return RuleContext("sink", "cmdi", "acme_common.shell.run_shell", "acme-billing", 0, "command",
                       "def run_shell(command):\n    return subprocess.run(command, shell=True)",
                       {"file": "billing/app.py", "line": 56, "code": 'run_shell("tar czf /archive/" + batch)'},
                       {"fingerprint": "f", "title": "OS command injection", "source_fn": "billing.app.archive",
                        "sink_fn": "acme_common.shell.run_shell"})


def test_rule_synthesizer_request_shape_and_gate(case_and_tools):
    """The proposal parses, carries role/cls from the trigger (not the model), and passes the real gate."""
    from sentinel.agent.claude import ClaudeRuleSynthesizer
    from sentinel.agent.mock import MockRuleSynthesizer
    from sentinel.learn.rules import check_rule
    ctx = _synth_ctx()
    good = MockRuleSynthesizer().propose(ctx, None)[0]  # what a well-behaved model would write
    answer = {"rules": [{"yaml": good.yaml, "rationale": "run_shell passes its argument to a shell",
                         "vulnerable_example": good.vulnerable_example, "fixed_example": good.fixed_example}]}
    api = FakeAPI([final(lambda kw: answer)])
    [p] = ClaudeRuleSynthesizer(client=api).propose(ctx, None)
    assert (p.role, p.cls, p.yaml) == ("sink", "cmdi", good.yaml) and p.model.startswith("claude-synth:")
    assert check_rule(p.yaml, p.role, p.cls)[1] == "pass"
    req = api.calls[0]
    assert req["model"] == "claude-opus-5-5" and req["thinking"] == {"type": "adaptive"}
    assert req["output_config"]["effort"] in ("low", "medium", "high", "xhigh", "max")
    assert req["output_config"]["format"]["type"] == "json_schema"
    assert req["fallbacks"] == "default" and "server-side-fallback-2026-07-01" in req["betas"]
    assert "tool_choice" not in req and req["system"][0]["cache_control"] == {"type": "ephemeral"}
    prompt = req["messages"][0]["content"]
    assert "acme_common.shell.run_shell" in prompt and "shell=True" in prompt and '"index": 0' in prompt


def test_rule_synthesizer_failures_yield_no_proposal():
    import anthropic
    import httpx
    from sentinel.agent.claude import ClaudeRuleSynthesizer

    def overloaded(kw):
        req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        raise anthropic.InternalServerError("overloaded", response=httpx.Response(529, request=req), body=None)

    garbage = lambda kw: NS(stop_reason="end_turn", usage=_usage(), content=[NS(type="text", text="not json")])
    for script in ([overloaded], [refusal()], [garbage]):
        assert ClaudeRuleSynthesizer(client=FakeAPI(script)).propose(_synth_ctx(), None) == []


def test_rule_synthesizer_bad_rule_is_stopped_by_the_gate():
    """A model that answers with the over-broad `$F($X, ...)` gets a proposal through the API, never past the gate."""
    from sentinel.agent.claude import ClaudeRuleSynthesizer
    from sentinel.agent.mock import MockRuleSynthesizer
    from sentinel.learn.knowledge import gate_passed
    from sentinel.learn.rules import RepoView, RuleGate
    ctx = _synth_ctx()
    good = MockRuleSynthesizer().propose(ctx, None)[0]
    broad = ("rules:\n- id: learned.sink.cmdi.broad\n  languages: [python]\n  severity: INFO\n  message: sink\n"
             "  metadata: {sentinel: {role: sink, cls: cmdi}}\n  patterns:\n  - pattern: $F($X, ...)\n"
             "  - focus-metavariable: $X\n")
    answer = {"rules": [{"yaml": broad, "rationale": "x", "vulnerable_example": good.vulnerable_example,
                         "fixed_example": good.fixed_example}]}
    [p] = ClaudeRuleSynthesizer(client=FakeAPI([final(lambda kw: answer)])).propose(ctx, None)
    sc = fresh_scanner(repos=["acme-billing"])
    facts, _ = sc.inputs("acme-billing")
    item = {"id": "T-claude", "pred": "spec_rule", "scope": "org", "org_id": "acme", "repo_id": None, "origin": "agent:x",
            "payload": {"yaml": p.yaml, "role": p.role, "cls": p.cls, "rule_id": "learned.sink.cmdi.broad",
                        "vulnerable_example": p.vulnerable_example, "fixed_example": p.fixed_example,
                        "origin_repo": "acme-billing", "site": ctx.site}}
    view = RepoView(Path(sc.store.repo("acme-billing")["root"]), facts, lambda: sc.analyze_repo("acme-billing"),
                    lambda ms: sc.analyze_repo("acme-billing", extra_matches=ms))
    rep = RuleGate().gate(item, {"acme-billing": view}, set())
    assert not gate_passed(rep) and "budget" in rep["canary"], rep["canary"]


def test_one_sample_confirms_full_vote_only_to_close(case_and_tools):
    """Confirming needs one sample; a sample arguing FALSE_POSITIVE triggers the full unanimous vote."""
    case, tools = case_and_tools
    tp = {"verdict": "TRUE_POSITIVE", "reason_code": "EXPLOITABLE", "rationale": "r", "claims": [], "proposed": []}
    api = FakeAPI([final(lambda kw: tp)] * 4)
    v = ClaudeVerifier(client=api)
    v.adaptive = True
    out = v.verify(case, tools)
    assert len(api.calls) == 1 and out.verdict == "TRUE_POSITIVE" and out.votes["k"] == 1
    fp = {"verdict": "FALSE_POSITIVE", "reason_code": "SANITIZED", "rationale": "r", "claims": [], "proposed": []}
    api = FakeAPI([final(lambda kw: fp)] * 8)
    v = ClaudeVerifier(client=api)
    v.adaptive = True
    out = v.verify(case, tools)
    assert len(api.calls) == v.k + 1 and out.votes["k"] == v.k
