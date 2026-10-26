"""Soufflé backend for the same rule base (``SENTINEL_ENGINE=souffle``).

The .lp rules stay the single source of truth: they are parsed with clingo's own parser and translated to a Soufflé
program, compiled once to native code (cached by a hash of the rule text). Learned knowledge never changes the
program: it is input data, like the code facts.

Values. Every argument is one algebraic data type, ``T = I{n} | S{id} | C{id} | F1..F3{functor id, args}``: integers,
strings and constants (interned to integers on the Python side, so Soufflé never sees text and its output parses
without ambiguity), and function terms such as ``unknown_api(Q)``. Rule constants get ids at compile time; they are
stored next to the binary and every solve extends that table.

Provenance. For each instrumented rule (head in PROV_HEADS) the program also derives ``fire_<id>(V1, ..., Vn)``, the
variable bindings of every rule instance. Python substitutes them into the rule's head and body templates and renders
the atoms exactly as clingo prints them, so ``Model.derivations()`` and the proof trees are unchanged.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Iterable

import clingo
import clingo.ast as A

from .datalog import PROV_HEADS, RULES_DIR, Model, Program

CACHE = Path(os.environ.get("SENTINEL_SOUFFLE_CACHE", Path.home() / ".cache" / "sentinel" / "souffle"))
JOBS = int(os.environ.get("SENTINEL_SOUFFLE_JOBS", "4"))
# Below this many input facts (gate canaries, slices) clingo in-process beats a Soufflé process launch + file I/O.
SMALL = int(os.environ.get("SENTINEL_SOUFFLE_MIN_FACTS", "20000"))
ADT = ".type T = I {n: number} | S {id: number} | C {id: number} | F1 {f: number, a: T} " \
      "| F2 {f: number, a: T, b: T} | F3 {f: number, a: T, b: T, c: T}"


class Interner:
    """Strings and constants <-> integer ids (separate key spaces: "s" strings, "c" constants and functors)."""

    def __init__(self, table: list | None = None):
        self.items: list[tuple[str, str]] = [tuple(x) for x in (table or [])]
        self.ids = {x: i for i, x in enumerate(self.items)}

    def id(self, kind: str, text: str) -> int:
        key = (kind, text)
        i = self.ids.get(key)
        if i is None:
            i = self.ids[key] = len(self.items)
            self.items.append(key)
        return i

    def copy(self) -> "Interner":
        return Interner(self.items)


# ── rule translation ─────────────────────────────────────────────────────────────────────────

def _sym_t(sym: clingo.Symbol, it: Interner) -> str:
    if sym.type == clingo.SymbolType.Number:
        return f"$I({sym.number})"
    if sym.type == clingo.SymbolType.String:
        return f"$S({it.id('s', sym.string)})"
    if not sym.arguments:
        return f"$C({it.id('c', sym.name)})"
    args = [_sym_t(a, it) for a in sym.arguments]
    return f"$F{len(args)}({it.id('c', sym.name)}, {', '.join(args)})"


def _term_t(t, it: Interner) -> str:
    if t.ast_type == A.ASTType.Variable:
        return t.name
    if t.ast_type == A.ASTType.SymbolicTerm:
        return _sym_t(t.symbol, it)
    if t.ast_type == A.ASTType.Function:
        if not t.arguments:
            return f"$C({it.id('c', t.name)})"
        if len(t.arguments) > 3:
            raise ValueError(f"function term of arity {len(t.arguments)} not supported: {t}")
        return f"$F{len(t.arguments)}({it.id('c', t.name)}, {', '.join(_term_t(a, it) for a in t.arguments)})"
    raise ValueError(f"unsupported term in the Soufflé translation: {t} ({t.ast_type})")


def _atom_parts(atom):
    sym = atom.symbol
    return sym.name, list(sym.arguments)


def _vars(t, out: list):
    if t.ast_type == A.ASTType.Variable:
        if t.name != "_" and t.name not in out:
            out.append(t.name)
    elif t.ast_type == A.ASTType.Function:
        for a in t.arguments:
            _vars(a, out)


class _Anon(A.Transformer):
    """Name anonymous variables in positive literals (they become fire columns)."""

    def __init__(self):
        self.n = 0

    def visit_Variable(self, v):
        if v.name != "_":
            return v
        self.n += 1
        return A.Variable(v.location, f"V_anon{self.n}")


def translate(files: list[Path], extra_rules: str, it: Interner, outputs: set[str]):
    """-> (Soufflé source, relation arities, fire templates {rid: (vars, head, pos, neg)})."""
    arity: dict[str, int] = {}
    heads: set[str] = set()
    lines: list[str] = []
    fires: dict[int, tuple] = {}
    rid = 0

    def note(name, n):
        if arity.setdefault(name, n) != n:
            raise ValueError(f"predicate {name} used with arities {arity[name]} and {n}")

    def visit(stm):
        nonlocal rid
        if stm.ast_type != A.ASTType.Rule or stm.head.ast_type != A.ASTType.Literal:
            if stm.ast_type not in (A.ASTType.Program, getattr(A.ASTType, "Comment", A.ASTType.Program)):
                raise ValueError(f"unsupported statement for Soufflé: {stm}")
            return
        rid += 1
        hname, hargs = _atom_parts(stm.head.atom)
        note(hname, len(hargs))
        heads.add(hname)
        head_t = f"{hname}({', '.join(_term_t(a, it) for a in hargs)})" if hargs else hname
        if not stm.body:
            lines.append(head_t + ".")
            return
        body_t, pos, neg = [], [], []
        anon = _Anon()
        for lit in stm.body:
            if lit.ast_type != A.ASTType.Literal or lit.atom.ast_type != A.ASTType.SymbolicAtom:
                raise ValueError(f"unsupported body literal for Soufflé: {lit}")
            name, args = _atom_parts(lit.atom)
            note(name, len(args))
            if lit.sign == A.Sign.NoSign:
                lit = anon(lit)
                name, args = _atom_parts(lit.atom)
                pos.append((name, args))
                body_t.append(f"{name}({', '.join(_term_t(a, it) for a in args)})" if args else name)
            else:
                neg.append((name, args))
                body_t.append(f"!{name}({', '.join(_term_t(a, it) for a in args)})" if args else f"!{name}")
        lines.append(f"{head_t} :- {', '.join(body_t)}.")
        if hname in PROV_HEADS:
            vs: list[str] = []
            for _n, args in pos:
                for a in args:
                    _vars(a, vs)
            fires[rid] = (vs, (hname, hargs), pos, neg)
            body = ", ".join(body_t)
            lines.append(f"fire_{rid}({', '.join(vs)}) :- {body}." if vs else f"fire_{rid}($I(0)) :- {body}.")

    for f in files:
        A.parse_string(f.read_text(), visit)
    if extra_rules:
        A.parse_string(extra_rules, visit)
    decls = [ADT]
    for name, n in sorted(arity.items()):
        if n == 0:
            raise ValueError(f"nullary predicate {name} not supported")
        decls.append(f".decl {name}({', '.join(f'a{i}: T' for i in range(n))})")
        decls.append(f".input {name}")
        if name in outputs:
            decls.append(f".output {name}")
    for r, (vs, *_rest) in sorted(fires.items()):
        cols = ", ".join(f"a{i}: T" for i in range(max(len(vs), 1)))
        decls.append(f".decl fire_{r}({cols})")
        decls.append(f".output fire_{r}")
    return "\n".join(decls + lines) + "\n", arity, fires


# ── values in and out ────────────────────────────────────────────────────────────────────────

_FACT = re.compile(r"^([a-z_][A-Za-z0-9_]*)(?:\((.*)\))?\.$", re.S)
_ARG = re.compile(r'\s*(-?\d+|"(?:[^"\\]|\\.)*"|[a-z_][A-Za-z0-9_]*)\s*(,|$)', re.S)


def _unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")


def parse_fact(text: str):
    """'node(12,"a.b").' -> ("node", (12, "a.b")); function-term arguments go through clingo's parser."""
    m = _FACT.match(text.strip())
    if not m:
        return _parse_slow(text)
    name, body = m.group(1), m.group(2)
    if body is None:
        return name, ()
    out, pos = [], 0
    while pos < len(body):
        a = _ARG.match(body, pos)
        if not a or (a.end() < len(body) and a.group(2) != ","):
            return _parse_slow(text)
        tok = a.group(1)
        if tok[0] == '"':
            out.append(("s", _unescape(tok[1:-1])))
        elif tok[0] in "-0123456789":
            out.append(int(tok))
        else:
            out.append(("c", tok))
        pos = a.end()
        if a.group(2) == "" and pos < len(body):
            return _parse_slow(text)
    return name, tuple(out)


def _from_sym(sym: clingo.Symbol):
    if sym.type == clingo.SymbolType.Number:
        return sym.number
    if sym.type == clingo.SymbolType.String:
        return ("s", sym.string)
    if not sym.arguments:
        return ("c", sym.name)
    return ("f", sym.name, tuple(_from_sym(a) for a in sym.arguments))


def _parse_slow(text: str):
    sym = clingo.parse_term(text.strip().rstrip("."))
    return sym.name, tuple(_from_sym(a) for a in sym.arguments)


def _enc(v, it: Interner) -> str:
    if isinstance(v, int):
        return f"$I({v})"
    kind = v[0]
    if kind == "s":
        return f"$S({it.id('s', v[1])})"
    if kind == "c":
        return f"$C({it.id('c', v[1])})"
    _f, name, args = v
    return f"$F{len(args)}({it.id('c', name)}, {', '.join(_enc(a, it) for a in args)})"


_TOK = re.compile(r"\$([A-Z]\d?)\(|(-?\d+)|\)|,\s*")


def _decode_line(line: str, it: Interner, n: int) -> list:
    """One output row ($I(5)\\t$F1(7, $S(3))) -> raw values: int | ("s", text) | ("c", name) | ("f", name, args)."""
    stack: list[list] = [[]]
    kinds: list[str] = []
    for m in _TOK.finditer(line):
        if m.group(1):
            kinds.append(m.group(1))
            stack.append([])
        elif m.group(2) is not None:
            stack[-1].append(int(m.group(2)))
        elif m.group(0) == ")":
            k, vals = kinds.pop(), stack.pop()
            if k == "I":
                v = vals[0]
            elif k == "S":
                v = ("s", it.items[vals[0]][1])
            elif k == "C":
                v = ("c", it.items[vals[0]][1])
            else:
                v = ("f", it.items[vals[0]][1], tuple(vals[1:]))
            stack[-1].append(v)
    return stack[0]


def _py(v):
    """Raw value -> the Python value datalog.py's py() gives for the same clingo symbol."""
    if isinstance(v, int):
        return v
    if v[0] in ("s", "c"):
        return v[1]
    return (v[1], *[_py(a) for a in v[2]])


def _clingo_str(v) -> str:
    """Raw value -> text exactly as clingo prints the symbol."""
    if isinstance(v, int):
        return str(v)
    if v[0] == "s":
        return '"' + v[1].replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
    if v[0] == "c":
        return v[1]
    return f"{v[1]}({','.join(_clingo_str(a) for a in v[2])})"


def _render(name: str, args, env: dict) -> str:
    def term(t):
        if t.ast_type == A.ASTType.Variable:
            return "any" if t.name == "_" else _clingo_str(env[t.name])
        if t.ast_type == A.ASTType.SymbolicTerm:
            return str(t.symbol)
        if not t.arguments:
            return t.name
        return f"{t.name}({','.join(term(a) for a in t.arguments)})"
    return f"{name}({','.join(term(a) for a in args)})" if args else name


def _head_key(t, env):
    """A head argument (AST) under a binding -> raw value, comparable with a parsed atom's arguments."""
    if t.ast_type == A.ASTType.Variable:
        return env[t.name]
    if t.ast_type == A.ASTType.SymbolicTerm:
        return _from_sym(t.symbol)
    if not t.arguments:
        return ("c", t.name)
    return ("f", t.name, tuple(_head_key(a, env) for a in t.arguments))


class LazyDerivations:
    """`Model.derivations()` for Soufflé results: head atom (as clingo prints it) -> [(rule, premises, negated)].
    Large repositories derive millions of rule instances and a proof tree reads a few dozen, so rows stay undecoded
    until an atom of that predicate is asked for, and only matching instances are rendered."""

    def __init__(self, tpl: dict, raw: dict[int, list[str]], it: Interner):
        self.tpl, self.raw, self.it = tpl, raw, it
        self.by_pred: dict[str, list[int]] = defaultdict(list)
        for r, (_vs, (hname, _ha), _p, _n) in tpl.items():
            self.by_pred[hname].append(r)
        self.index: dict[str, dict] = {}

    def _pred_index(self, pred: str) -> dict:
        idx = self.index.get(pred)
        if idx is None:
            idx = defaultdict(list)
            for r in self.by_pred.get(pred, ()):
                vs, (_h, hargs), _pos, _neg = self.tpl[r]
                for ln in self.raw.get(r, ()):
                    env = dict(zip(vs, _decode_line(ln, self.it, len(vs))))
                    idx[tuple(_head_key(a, env) for a in hargs)].append((r, env))
            self.index[pred] = idx
        return idx

    def _lookup(self, atom: str):
        try:
            sym = clingo.parse_term(atom)
        except RuntimeError:
            return None
        return self._pred_index(sym.name).get(tuple(_from_sym(a) for a in sym.arguments))

    def __contains__(self, atom: str) -> bool:
        return bool(self._lookup(atom))

    def __getitem__(self, atom: str):
        hits = self._lookup(atom)
        if not hits:
            raise KeyError(atom)
        out = []
        for r, env in hits:
            _vs, _h, pos, neg = self.tpl[r]
            out.append((r, [_render(n, a, env) for n, a in pos], [_render(n, a, env) for n, a in neg]))
        return out

    def get(self, atom: str, default=None):
        return self[atom] if atom in self else default

    def all_fires(self) -> list[tuple]:
        out = []
        for r, (vs, (hname, hargs), pos, neg) in self.tpl.items():
            for ln in self.raw.get(r, ()):
                env = dict(zip(vs, _decode_line(ln, self.it, len(vs))))
                out.append((r, _render(hname, hargs, env), tuple(_render(n, a, env) for n, a in pos),
                            tuple(_render(n, a, env) for n, a in neg)))
        return out


# ── the program ──────────────────────────────────────────────────────────────────────────────

class SouffleProgram(Program):
    """Same interface as Program (solve with memo, rules for provenance), evaluated by a compiled Soufflé binary."""

    def __init__(self, rule_files: Iterable[Path] | None = None, extra_rules: str = "", outputs: Iterable[str] = ()):
        files = list(rule_files) if rule_files else sorted(RULES_DIR.glob("*.lp"))
        super().__init__(files, extra_rules)  # rule ids and texts for explanations; clingo text kept as fallback
        base = Interner()
        self.outputs = set(outputs)
        self.source, self.arity, self.fire_tpl = translate(files, extra_rules, base, self.outputs)
        self.constants = base
        digest = hashlib.sha256(self.source.encode()).hexdigest()[:16]
        self.binary = CACHE / f"sentinel-{digest}"
        if not self.binary.exists():
            self._compile()

    def _compile(self) -> None:
        CACHE.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as d:
            dl = Path(d) / "sentinel.dl"
            dl.write_text(self.source)
            out = Path(d) / "bin"
            proc = subprocess.run(["souffle", "-o", str(out), str(dl)], capture_output=True, text=True)
            if proc.returncode != 0 or not out.exists():
                raise RuntimeError(f"souffle compile failed: {proc.stderr[-2000:]}")
            tmp = self.binary.with_suffix(".tmp")
            shutil.copy(out, tmp)
            tmp.chmod(0o755)
            tmp.replace(self.binary)  # atomic: concurrent processes never run a half-written binary

    def _solve(self, facts: list[str], keep: set[str] | None) -> Model:
        if keep is None or not set(keep) <= self.outputs or len(facts) < SMALL:
            return super()._solve(facts, keep)  # small inputs, or relations not compiled as outputs: clingo
        it = self.constants.copy()
        rows: dict[str, list[str]] = defaultdict(list)
        for text in facts:
            name, args = parse_fact(text)
            if self.arity.get(name) != len(args) and not (name in self.arity and not args):
                continue  # predicates no rule reads
            rows[name].append("\t".join(_enc(a, it) for a in args) if args else "$I(0)")
        model = Model(rules=self.rules)
        with tempfile.TemporaryDirectory(prefix="sentinel-souffle-") as d:
            fin, fout = Path(d) / "in", Path(d) / "out"
            fin.mkdir()
            fout.mkdir()
            for name in self.arity:
                (fin / f"{name}.facts").write_text("\n".join(rows.get(name, [])) + ("\n" if rows.get(name) else ""))
            cmd = [str(self.binary), "-F", str(fin), "-D", str(fout), "-j", str(JOBS)]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise RuntimeError(f"souffle run failed ({proc.returncode}): {proc.stderr[-2000:]}")
            for name in set(keep) & set(self.arity):
                p = fout / f"{name}.csv"
                if p.exists():
                    model.atoms[name] = [tuple(_py(v) for v in _decode_line(ln, it, self.arity[name]))
                                         for ln in p.read_text().splitlines() if ln]
            raw = {}
            for r in self.fire_tpl:
                p = fout / f"fire_{r}.csv"
                if p.exists():
                    raw[r] = [ln for ln in p.read_text().splitlines() if ln]
            model._lazy = LazyDerivations(self.fire_tpl, raw, it)  # rendered only for atoms a proof tree visits
        return model
