"""Semgrep bridge.

1. Runs specification packs (ordinary Semgrep YAML with ``metadata.sentinel``) and lifts each
   match into a spec fact attached to the AST node with the same span.
2. Builds a *baseline* from the same specs: plain Semgrep taint-mode rules (one per class).
   That baseline is what a team gets from Semgrep OSS alone, and it is what we evaluate against.
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from .python_facts import Facts

SAST_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SPECS = [SAST_ROOT / "specs" / "python-web.yml"]


def semgrep_bin() -> str:
    env = os.environ.get("SENTINEL_SEMGREP")
    if env:
        return env
    local = SAST_ROOT / ".venv-semgrep" / "bin" / "semgrep"
    if local.exists():
        return str(local)
    found = shutil.which("semgrep")
    if not found:
        raise RuntimeError("semgrep not found: set SENTINEL_SEMGREP or install it in sast/.venv-semgrep")
    return found


@dataclass(frozen=True)
class SpecMatch:
    rule_id: str
    role: str  # source | sink | sanitizer
    cls: str | None  # vuln class or "all"
    kind: str | None  # source kind
    cwe: str | None
    file: str
    l1: int
    c1: int
    l2: int
    c2: int
    node: int | None
    knowledge: str | None = None  # id of the learned spec_rule item that produced the match (None = curated pack)


def run_semgrep_raw(config_paths: list[Path], cwd: Path, targets: list[str]) -> tuple[int, dict | None, str]:
    """Run Semgrep without raising: (exit code, parsed JSON or None, stderr tail). Used where a broken
    rule is an expected outcome (validating a proposed spec rule), not an internal error."""
    cmd = [semgrep_bin(), "--json", "--metrics=off", "--disable-version-check", "--quiet", "--no-git-ignore"]
    for c in config_paths:
        cmd += ["--config", str(c)]
    cmd += targets  # explicit targets: Semgrep's default ignores (e.g. tests/) do not apply
    env = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0", SEMGREP_SEND_METRICS="off")
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env, timeout=600)
    try:
        out = json.loads(proc.stdout) if proc.stdout.strip() else None
    except json.JSONDecodeError:
        out = None
    return proc.returncode, out, proc.stderr[-2000:]


def _run_semgrep(config_paths: list[Path], root: Path, files: list[str]) -> dict:
    if not files:
        return {"results": [], "errors": []}
    code, out, err = run_semgrep_raw(config_paths, root, files)
    if code not in (0, 1) or out is None:
        raise RuntimeError(f"semgrep failed ({code}): {err}")
    return out


def rule_meta(config_paths: list[Path]) -> dict[str, dict]:
    """rule id -> metadata.sentinel (role, cls, kind, cwe, and `knowledge` for learned rules)."""
    meta = {}
    for p in config_paths:
        for r in (yaml.safe_load(p.read_text()) or {}).get("rules", []):
            meta[r["id"]] = r.get("metadata", {}).get("sentinel", {}) | {"cwe": r.get("metadata", {}).get("sentinel", {}).get("cwe")}
    return meta


def _short_id(check_id: str, known: dict[str, dict]) -> str:
    # Semgrep prefixes rule ids with the config's directory name; recover the declared id.
    # Longest first, so a learned id never resolves to a curated id that happens to be its suffix.
    for rid in sorted(known, key=len, reverse=True):
        if check_id == rid or check_id.endswith("." + rid):
            return rid
    return check_id


def _is_literal(facts: Facts, path: str, s: dict, e: dict) -> bool:
    """The focused expression is a constant (`cur.execute("SELECT ... %s", (x,))`): it cannot carry taint."""
    lines = facts.files.get(path, "").splitlines()[s["line"] - 1: e["line"]]
    if not lines:
        return False
    if len(lines) == 1:
        text = lines[0][s["col"] - 1: e["col"] - 1]
    else:
        text = "\n".join([lines[0][s["col"] - 1:]] + lines[1:-1] + [lines[-1][: e["col"] - 1]])
    try:
        ast.literal_eval(text.strip() if not text.lstrip().startswith("(") else text.strip())
        return True
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        try:
            ast.literal_eval("(" + text.strip() + ")")  # implicitly concatenated literals over several lines
            return True
        except Exception:
            return False


def lift(results: list[dict], facts: Facts, meta: dict[str, dict], path_of=lambda r: r["path"]) -> list[SpecMatch]:
    """Semgrep results -> spec matches attached to the AST node with the same span."""
    matches = []
    for r in results:
        rid = _short_id(r["check_id"], meta)
        m = meta.get(rid, {})
        role = m.get("role")
        if role not in ("source", "sink", "sanitizer"):
            continue
        s, e = r["start"], r["end"]
        path = path_of(r)
        node = facts.node_at(path, s["line"], s["col"], e["line"], e["col"])
        if node is not None and role != "sanitizer" and \
                (node.l1, node.c1, node.l2, node.c2) != (s["line"], s["col"], e["line"], e["col"]) and \
                (m.get("knowledge") or _is_literal(facts, path, s, e)):
            # A learned sink/source focused on an expression with no node of its own (a literal) must not
            # fall back to the enclosing call: that would taint-check the call's other arguments.
            # (The curated pack keeps the original fallback; see docs/evaluation.md.)
            node = None
        matches.append(SpecMatch(rid, role, m.get("cls"), m.get("kind"), m.get("cwe"), path, s["line"], s["col"],
                                 e["line"], e["col"], node.id if node else None, m.get("knowledge")))
    return matches


def match_specs(root: Path, facts: Facts, extra_specs: list[Path] | None = None,
                include_default: bool = True) -> list[SpecMatch]:
    """`include_default=False` matches only `extra_specs` (learned rules on top of cached curated matches)."""
    configs = (DEFAULT_SPECS if include_default else []) + list(extra_specs or [])
    if not configs:
        return []
    out = _run_semgrep(configs, root, sorted(facts.files))
    return lift(out.get("results", []), facts, rule_meta(configs))


# ── baseline: Semgrep taint mode generated from the same specs ─────────────────

def _patterns_of(rule: dict) -> list[dict]:
    """Turn a spec rule body into one entry usable inside pattern-sources/sinks/sanitizers."""
    body = {k: v for k, v in rule.items() if k in ("pattern", "pattern-either", "patterns")}
    return [body]


def load_rules(config_paths: list[Path] | None = None) -> list[dict]:
    rules = []
    for p in config_paths or DEFAULT_SPECS:
        rules += (yaml.safe_load(p.read_text()) or {}).get("rules", [])
    return rules


def build_baseline_rules(config_paths: list[Path] | None = None, rules: list[dict] | None = None) -> dict:
    """Plain Semgrep taint-mode rules (one per class) generated from spec rules: what Semgrep OSS does
    with the same knowledge, and what `export-rules --format taint` hands to CI."""
    rules = rules if rules is not None else load_rules(config_paths)
    by_role: dict[str, list[dict]] = {"source": [], "sink": [], "sanitizer": []}
    for r in rules:
        m = r.get("metadata", {}).get("sentinel", {})
        if m.get("role") in by_role:
            by_role[m["role"]].append(r)
    classes = sorted({r["metadata"]["sentinel"]["cls"] for r in by_role["sink"]})
    out = []
    sources = [p for r in by_role["source"] for p in _patterns_of(r)]
    for cls in classes:
        sinks = [p for r in by_role["sink"] if r["metadata"]["sentinel"]["cls"] == cls for p in _patterns_of(r)]
        sans = [p for r in by_role["sanitizer"] if r["metadata"]["sentinel"]["cls"] in (cls, "all") for p in _patterns_of(r)]
        cwe = next((r["metadata"]["sentinel"].get("cwe") for r in by_role["sink"]
                    if r["metadata"]["sentinel"]["cls"] == cls), None)
        rule = {"id": f"baseline.{cls}", "mode": "taint", "languages": ["python"], "severity": "ERROR",
                "message": f"{cls}: untrusted input reaches a dangerous sink", "metadata": {"cls": cls, "cwe": cwe},
                "pattern-sources": sources, "pattern-sinks": sinks}
        if sans:
            rule["pattern-sanitizers"] = sans
        out.append(rule)
    return {"rules": out}


@dataclass(frozen=True)
class BaselineFinding:
    cls: str
    file: str
    line: int
    snippet: str


def run_baseline(root: Path, files: list[str], rules: list[dict] | None = None) -> list[BaselineFinding]:
    """`rules`: spec rules to generate the taint rules from (default: the curated pack)."""
    with tempfile.TemporaryDirectory() as td:
        cfg = Path(td) / "baseline.yml"
        cfg.write_text(yaml.safe_dump(build_baseline_rules(rules=rules), sort_keys=False))
        out = _run_semgrep([cfg], root, files)
    res = []
    for r in out.get("results", []):
        cls = r["check_id"].rsplit(".", 1)[-1]
        res.append(BaselineFinding(cls, r["path"], r["start"]["line"], r["extra"].get("lines", "")))
    return res
