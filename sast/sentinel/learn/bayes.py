"""Bingo-style Bayesian alarm ranking over a summarised derivation graph.

Each open finding F is the conjunction of hypotheses it was derived from:
    src(S)        the source is attacker-controlled            prior by source kind
    sink(R)       the sink spec R is right                     learned per rule from triage
    asm(A)        assumption A holds (the step does NOT neutralise taint)
    summ(G,K)     the interprocedural summary through helper G to sink K is right
Hypotheses are shared across findings (same helper, same unknown API, same source kind), so a
verdict on one finding moves the posterior of every finding that shares a derivation (Raghothaman
et al., PLDI'18). The model only *ranks*: suppression always requires direct evidence (R9).

Inference: sum-product loopy belief propagation on the factor graph (exact on trees).
"""
from __future__ import annotations

import itertools
import math
from collections import defaultdict
from dataclasses import dataclass, field

SOURCE_PRIOR = {"http": 0.95, "cookie": 0.92, "route": 0.92, "header": 0.85, "cli": 0.35, "archive": 0.5, "": 0.8}
ASM_PRIOR = {"unknown_api": 0.55, "unknown_guard": 0.45, "maybe_sanitizer": 0.5, "unreachable": 0.25, "weak_source": 0.4}
LEAK_TRUE, LEAK_FALSE = 0.97, 0.03  # P(F | all hypotheses hold), P(F | some hypothesis fails)


@dataclass
class BayesFinding:
    fid: str
    hypotheses: list[str]
    evidence: float | None = None  # likelihood that F is a TP given the observed verdict(s), or None


@dataclass
class Network:
    priors: dict[str, float] = field(default_factory=dict)
    findings: list[BayesFinding] = field(default_factory=list)

    def add_hypothesis(self, h: str, prior: float) -> None:
        self.priors.setdefault(h, prior)


def hypotheses_for(source_kind: str, source_key: str, sink_rule: str, sink_fn: str, src_fn: str,
                   assumptions: list) -> list[tuple[str, float]]:
    hs = [(f"src:{source_key}", SOURCE_PRIOR.get(source_kind, 0.8)), (f"sink:{sink_rule}", 0.95)]
    if sink_fn != src_fn:
        hs.append((f"summ:{sink_fn}", 0.97))
    for a in assumptions:
        kind = a[0] if isinstance(a, (list, tuple)) else str(a)
        key = ":".join(str(x) for x in a) if isinstance(a, (list, tuple)) else str(a)
        hs.append((f"asm:{key}", ASM_PRIOR.get(kind, 0.5)))
    return hs


def posteriors(net: Network, iterations: int = 30, damping: float = 0.3) -> dict[str, float]:
    """Return P(F is a true positive | evidence) for every finding."""
    # Factor graph: unary prior factors on hypotheses; one AND-factor per finding over (F, H1..Hn).
    # Evidence enters as a unary factor on F.
    h_msgs_to_f: dict[tuple[str, str], tuple[float, float]] = {}
    f_msgs_to_h: dict[tuple[str, str], tuple[float, float]] = {}
    for f in net.findings:
        for h in f.hypotheses:
            f_msgs_to_h[(f.fid, h)] = (0.5, 0.5)
    by_h = defaultdict(list)
    for f in net.findings:
        for h in f.hypotheses:
            by_h[h].append(f.fid)
    fmap = {f.fid: f for f in net.findings}

    def norm(a: float, b: float) -> tuple[float, float]:
        s = a + b
        return (a / s, b / s) if s > 0 else (0.5, 0.5)

    # Noisy-AND factor: P(F | all parents true) = LEAK_TRUE, otherwise LEAK_FALSE. Its messages have a closed form
    # (no 2^n enumeration), and hypothesis->factor messages use the product of all incoming messages divided by
    # the recipient's own (log space), so one iteration is linear in the number of edges.
    lt = lambda t: LEAK_TRUE * t[0] + (1 - LEAK_TRUE) * t[1]
    lf = lambda t: LEAK_FALSE * t[0] + (1 - LEAK_FALSE) * t[1]
    for _ in range(iterations):
        for h, fids in by_h.items():
            p = net.priors[h]
            lt_sum = math.log(max(p, 1e-12)) + sum(math.log(max(f_msgs_to_h[(o, h)][0], 1e-300)) for o in fids)
            lf_sum = math.log(max(1 - p, 1e-12)) + sum(math.log(max(f_msgs_to_h[(o, h)][1], 1e-300)) for o in fids)
            for fid in fids:
                mt, mf = f_msgs_to_h[(fid, h)]
                a = lt_sum - math.log(max(mt, 1e-300))
                b = lf_sum - math.log(max(mf, 1e-300))
                m = max(a, b)
                h_msgs_to_f[(h, fid)] = norm(math.exp(a - m), math.exp(b - m))
        new_msgs = {}
        for f in net.findings:
            ev = (f.evidence, 1 - f.evidence) if f.evidence is not None else (1.0, 1.0)
            hs = f.hypotheses
            ins = [h_msgs_to_f[(h, f.fid)][0] for h in hs]  # P(parent true) as seen by this factor
            allp = math.prod(ins)
            for i, h in enumerate(hs):
                others_true = allp / ins[i] if ins[i] > 0 else math.prod(x for j, x in enumerate(ins) if j != i)
                # h true: F behaves as LEAK_TRUE iff all others true; h false: always LEAK_FALSE.
                acc_t = others_true * lt(ev) + (1 - others_true) * lf(ev)
                acc_f = lf(ev)
                m = norm(acc_t, acc_f)
                old = f_msgs_to_h[(f.fid, h)]
                new_msgs[(f.fid, h)] = norm(damping * old[0] + (1 - damping) * m[0], damping * old[1] + (1 - damping) * m[1])
        f_msgs_to_h.update(new_msgs)

    out = {}
    for f in net.findings:
        ev = (f.evidence, 1 - f.evidence) if f.evidence is not None else (1.0, 1.0)
        all_true = math.prod(h_msgs_to_f[(h, f.fid)][0] for h in f.hypotheses)
        pt = all_true * LEAK_TRUE * ev[0] + (1 - all_true) * LEAK_FALSE * ev[0]
        pf_ = all_true * (1 - LEAK_TRUE) * ev[1] + (1 - all_true) * (1 - LEAK_FALSE) * ev[1]
        out[f.fid] = pt / (pt + pf_) if pt + pf_ > 0 else 0.5
    return out


def related(net: Network, fid: str) -> dict[str, list[str]]:
    """Findings that share at least one hypothesis with `fid`, grouped by the shared hypothesis."""
    mine = next((f for f in net.findings if f.fid == fid), None)
    if mine is None:
        return {}
    out: dict[str, list[str]] = {}
    for h in mine.hypotheses:
        others = [f.fid for f in net.findings if f.fid != fid and h in f.hypotheses]
        if others and not h.startswith("sink:"):
            out[h] = others
    return out
