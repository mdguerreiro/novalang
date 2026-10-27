"""Datalog evaluation with full provenance, on top of clingo.

clingo is used strictly as a stratified Datalog engine (no choice rules, no disjunction), so the
rule base stays portable to Soufflé. Provenance comes from rule instrumentation: for each rule
``H :- B1, ..., Bn, not N1, ...`` whose head predicate is in ``PROV_HEADS`` we add a twin

    fire(RuleId, H, (B1, ..., Bn), (N1, ...)) :- B1, ..., Bn, not N1, ...

so every grounded rule instance becomes an atom. Together these atoms form the derivation
hypergraph. It is used for explanations (minimal proof trees), Bingo-style Bayesian ranking,
and truth maintenance (which knowledge items a decision depends on).
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import clingo
import clingo.ast as A

MEMO_SIZE = 6  # whole-repo models are large; a scan only re-asks a handful of distinct inputs
# Above this resident size the memo keeps only the newest model: on the largest repositories a handful of whole-program
# models (with their provenance indexes) is several GB each. Eviction only costs a re-solve; results are unchanged.
MEMO_RSS_MB = int(os.environ.get("SENTINEL_MEMO_RSS_MB", "6000"))
SOLVE_STATS = {"solves": 0, "hits": 0, "seconds": 0.0, "max_seconds": 0.0}



def _rss_mb() -> float:
    try:
        with open("/proc/self/statm") as f:
            return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 2**20
    except (OSError, ValueError):
        return 0.0


RULES_DIR = Path(__file__).parent / "rules"
PROV_HEADS = {
    "cand", "alarm", "mitigated", "undecided", "confirmed", "test_only", "open", "safe",
    "mit", "asm", "p2s", "p2r", "p2s_raw", "p2r_raw", "p2k_s", "p2k_r", "p2a_s", "p2a_r",
    "kill", "assume_at", "has_asm", "reach",
}


@dataclass
class RuleInfo:
    id: int
    text: str
    head: str
    file: str
    line: int


@dataclass
class Model:
    atoms: dict[str, list[tuple]] = field(default_factory=lambda: defaultdict(list))
    fires: list[tuple[int, clingo.Symbol, tuple[clingo.Symbol, ...], tuple[clingo.Symbol, ...]]] = field(default_factory=list)
    rules: dict[int, RuleInfo] = field(default_factory=dict)

    def get(self, pred: str) -> list[tuple]:
        return self.atoms.get(pred, [])

    def all_fires(self) -> list[tuple]:
        """Every rule instance (rule id, head, premises, negated premises); a Soufflé model renders them on demand."""
        lazy = getattr(self, "_lazy", None)
        if lazy is not None:
            return lazy.all_fires()
        return [(r, str(h), tuple(map(str, p)), tuple(map(str, n))) for r, h, p, n in self.fires]

    def derivations(self) -> dict[str, list[tuple[int, list[str], list[str]]]]:
        """head atom (as string) -> [(rule id, positive premises, negated premises)]."""
        lazy = getattr(self, "_lazy", None)
        if lazy is not None:
            return lazy
        out: dict[str, list[tuple[int, list[str], list[str]]]] = defaultdict(list)
        for rid, head, pos, neg in self.fires:
            out[str(head)].append((rid, [str(p) for p in pos], [str(n) for n in neg]))
        return out


class _Rename(A.Transformer):
    """Replace anonymous variables (`_`) using a factory for the replacement term."""

    def __init__(self, make):
        self.make = make

    def visit_Variable(self, v):
        return self.make() if v.name == "_" else v

    def __call__(self, node):
        return self.visit(node)


def py(sym: clingo.Symbol):
    if sym.type == clingo.SymbolType.Number:
        return sym.number
    if sym.type == clingo.SymbolType.String:
        return sym.string
    if sym.type == clingo.SymbolType.Function:
        if not sym.arguments:
            return sym.name
        return (sym.name, *[py(a) for a in sym.arguments]) if sym.name else tuple(py(a) for a in sym.arguments)
    return str(sym)


def term(v) -> str:
    """Python value -> clingo term text."""
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, tuple):
        name, *args = v
        return f"{name}({','.join(term(a) for a in args)})"
    s = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{s}"'


def fact(pred: str, *args) -> str:
    return f"{pred}({','.join(term(a) for a in args)})." if args else f"{pred}."


class Program:
    def __init__(self, rule_files: Iterable[Path] | None = None, extra_rules: str = ""):
        files = list(rule_files) if rule_files else sorted(RULES_DIR.glob("*.lp"))
        self.rules: dict[int, RuleInfo] = {}
        self._memo: OrderedDict[str, Model] = OrderedDict()
        self._lock = threading.Lock()
        chunks = []
        for f in files:
            chunks.append(self._instrument(f.read_text(), f.name))
        if extra_rules:
            chunks.append(self._instrument(extra_rules, "<learned>"))
        self.text = "\n".join(chunks)

    def _instrument(self, source: str, fname: str) -> str:
        out: list[str] = []

        def visit(stm):
            if stm.ast_type == A.ASTType.Rule and stm.head.ast_type == A.ASTType.Literal:
                head_atom = stm.head.atom.symbol
                head_name = getattr(head_atom, "name", None)
                rid = len(self.rules) + 1
                loc = stm.location
                self.rules[rid] = RuleInfo(rid, str(stm), head_name or "?", fname, loc.begin.line)
                if head_name in PROV_HEADS and len(stm.body) > 0:
                    # Anonymous variables must be named in positive literals (so the fire head is safe)
                    # and replaced by a placeholder constant in the recorded copy of negated literals.
                    counter = iter(range(10_000))
                    named = _Rename(lambda: A.Variable(loc, f"V_anon{next(counter)}"))
                    placeholder = _Rename(lambda: A.SymbolicTerm(loc, clingo.Function("any")))
                    body, pos, neg = [], [], []
                    for lit in stm.body:
                        if lit.ast_type != A.ASTType.Literal or lit.atom.ast_type != A.ASTType.SymbolicAtom:
                            body.append(lit)
                            continue
                        if lit.sign == A.Sign.NoSign:
                            lit = named(lit)
                            pos.append(lit.atom.symbol)
                        else:
                            neg.append(placeholder(lit).atom.symbol)
                        body.append(lit)
                    fire = A.Function(loc, "fire", [
                        A.SymbolicTerm(loc, clingo.Number(rid)), head_atom,
                        A.Function(loc, "", pos, 0), A.Function(loc, "", neg, 0)], 0)
                    out.append(str(A.Rule(loc, A.Literal(loc, A.Sign.NoSign, A.SymbolicAtom(fire)), body)))
            if stm.ast_type != A.ASTType.Program:
                out.append(str(stm))

        A.parse_string(source, visit)
        return "\n".join(out)

    def solve(self, facts: Iterable[str], keep: set[str] | None = None) -> Model:
        """Solve, memoised on the exact input (models are read-only downstream). A scan re-derives the same
        program several times (gating, frontier rounds, rescans); identical inputs are solved once."""
        facts = sorted(set(facts))
        h = hashlib.blake2b(digest_size=16)
        for f in facts:
            h.update(f.encode()); h.update(b"\0")
        h.update(repr(sorted(keep) if keep is not None else None).encode())
        key = h.hexdigest()
        with self._lock:
            hit = self._memo.get(key)
            if hit is not None:
                self._memo.move_to_end(key)
                SOLVE_STATS["hits"] += 1
                return hit
        t0 = time.perf_counter()
        model = self._solve(facts, keep)
        dt = time.perf_counter() - t0
        with self._lock:
            SOLVE_STATS["solves"] += 1
            SOLVE_STATS["seconds"] += dt
            SOLVE_STATS["max_seconds"] = max(SOLVE_STATS["max_seconds"], dt)
            self._memo[key] = model
            while len(self._memo) > MEMO_SIZE or (len(self._memo) > 1 and _rss_mb() > MEMO_RSS_MB):
                self._memo.popitem(last=False)
        return model

    def _solve(self, facts: list[str], keep: set[str] | None) -> Model:
        ctl = clingo.Control(["--warn=none"])
        ctl.add("base", [], self.text)
        ctl.add("base", [], "\n".join(facts))
        ctl.ground([("base", [])])
        model = Model(rules=self.rules)

        def on_model(m: clingo.Model):
            for s in m.symbols(atoms=True):
                if s.name == "fire":
                    rid, head, pos, neg = s.arguments
                    model.fires.append((rid.number, head, tuple(pos.arguments), tuple(neg.arguments)))
                elif keep is None or s.name in keep:
                    model.atoms[s.name].append(tuple(py(a) for a in s.arguments))

        result = ctl.solve(on_model=on_model)
        if not result.satisfiable:
            raise RuntimeError("rule base is unsatisfiable (should never happen for stratified Datalog)")
        return model
