"""Shared fixtures and helpers for the Sentinel test suite.

Expensive inputs (Semgrep runs, demo scans, the evaluation harness) are session-scoped so each
runs once. Small inline snippets are written to tmp dirs for focused extractor/engine tests.
"""
from __future__ import annotations

import sys
import textwrap
from collections import deque
from pathlib import Path

import pytest

SAST_ROOT = Path(__file__).resolve().parents[1]
if str(SAST_ROOT) not in sys.path:
    sys.path.insert(0, str(SAST_ROOT))

from sentinel.engine.analyze import analyze  # noqa: E402
from sentinel.extract.python_facts import Facts, extract  # noqa: E402
from sentinel.extract.semgrep_specs import match_specs  # noqa: E402

DEMO = SAST_ROOT / "demo"
REPOS = ["acme-shop", "acme-billing"]


# ── helpers ──────────────────────────────────────────────────────────────────────────────

def write_repo(root: Path, files: dict[str, str]) -> Path:
    for rel, src in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src).lstrip("\n"))
    return root


def scan_dir(root: Path, knowledge=None):
    facts = extract(root)
    matches = match_specs(root, facts)
    return facts, matches, analyze(facts, matches, knowledge or [])


def short(fn: str) -> str:
    return fn.rsplit(".", 1)[-1]


def findings_for(analysis, fn_short: str, cls: str | None = None):
    return [f for f in analysis.findings if short(f.source_fn) == fn_short and (cls is None or f.cls == cls)]


def one_finding(analysis, fn_short: str, cls: str):
    fs = findings_for(analysis, fn_short, cls)
    assert len(fs) == 1, f"expected one {cls} finding in {fn_short}, got {[(f.cls, f.status) for f in analysis.findings]}"
    return fs[0]


def nodes_where(facts: Facts, **kw):
    out = []
    for n in facts.nodes.values():
        if all((n.fn.endswith(v) if k == "fn" else getattr(n, k) == v) for k, v in kw.items()):
            out.append(n)
    return out


def reachable(facts: Facts, start: int, avoid: set[int] = frozenset()) -> set[int]:
    """Intraprocedural edge reachability from `start`, never entering nodes in `avoid`."""
    succ: dict[int, list[int]] = {}
    for a, b in facts.edges:
        succ.setdefault(a, []).append(b)
    seen = {start}
    q = deque([start])
    while q:
        n = q.popleft()
        for b in succ.get(n, []):
            if b not in seen and b not in avoid:
                seen.add(b)
                q.append(b)
    return seen


# ── session fixtures ─────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def demo_inputs():
    out = {}
    for r in REPOS:
        root = DEMO / r
        facts = extract(root)
        out[r] = (facts, match_specs(root, facts))
    return out


@pytest.fixture(scope="session")
def demo_tier0(demo_inputs):
    return {r: analyze(f, m) for r, (f, m) in demo_inputs.items()}


@pytest.fixture(scope="session")
def ground_truth():
    from sentinel.eval import ground_truth as gt
    return gt()


@pytest.fixture(scope="session")
def eval_results():
    from sentinel import eval as ev
    return ev.run()
