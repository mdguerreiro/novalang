"""Semgrep bridge.

1. Runs specification packs (ordinary Semgrep YAML with ``metadata.sentinel``) and lifts each
   match into a spec fact attached to the AST node with the same span.
2. Builds a *baseline* from the same specs: plain Semgrep taint-mode rules (one per class).
   That baseline is what a team gets from Semgrep OSS alone, and it is what we evaluate against.
"""
from __future__ import annotations

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


def _run_semgrep(config_paths: list[Path], root: Path, files: list[str]) -> dict:
    if not files:
        return {"results": [], "errors": []}
    cmd = [semgrep_bin(), "--json", "--metrics=off", "--disable-version-check", "--quiet", "--no-git-ignore"]
    for c in config_paths:
        cmd += ["--config", str(c)]
    cmd += files  # explicit targets: Semgrep's default ignores (e.g. tests/) do not apply
    env = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0", SEMGREP_SEND_METRICS="off")
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, env=env, timeout=600)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"semgrep failed ({proc.returncode}): {proc.stderr[-2000:]}")
    return json.loads(proc.stdout)


def _rule_meta(config_paths: list[Path]) -> dict[str, dict]:
    meta = {}
    for p in config_paths:
        for r in (yaml.safe_load(p.read_text()) or {}).get("rules", []):
            meta[r["id"]] = r.get("metadata", {}).get("sentinel", {}) | {"cwe": r.get("metadata", {}).get("sentinel", {}).get("cwe")}
    return meta


def _short_id(check_id: str, known: dict[str, dict]) -> str:
    # Semgrep prefixes rule ids with the config's directory name; recover the declared id.
    for rid in known:
        if check_id == rid or check_id.endswith("." + rid):
            return rid
    return check_id


def match_specs(root: Path, facts: Facts, extra_specs: list[Path] | None = None) -> list[SpecMatch]:
    configs = DEFAULT_SPECS + list(extra_specs or [])
    meta = _rule_meta(configs)
    out = _run_semgrep(configs, root, sorted(facts.files))
    matches = []
    for r in out.get("results", []):
        rid = _short_id(r["check_id"], meta)
        m = meta.get(rid, {})
        role = m.get("role")
        if role not in ("source", "sink", "sanitizer"):
            continue
        s, e = r["start"], r["end"]
        node = facts.node_at(r["path"], s["line"], s["col"], e["line"], e["col"])
        matches.append(SpecMatch(rid, role, m.get("cls"), m.get("kind"), m.get("cwe"), r["path"],
                                 s["line"], s["col"], e["line"], e["col"], node.id if node else None))
    return matches


# ── baseline: Semgrep taint mode generated from the same specs ─────────────────

def _patterns_of(rule: dict) -> list[dict]:
    """Turn a spec rule body into one entry usable inside pattern-sources/sinks/sanitizers."""
    body = {k: v for k, v in rule.items() if k in ("pattern", "pattern-either", "patterns")}
    return [body]


def build_baseline_rules(config_paths: list[Path] | None = None) -> dict:
    configs = config_paths or DEFAULT_SPECS
    rules = []
    for p in configs:
        rules += (yaml.safe_load(p.read_text()) or {}).get("rules", [])
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


def run_baseline(root: Path, files: list[str]) -> list[BaselineFinding]:
    with tempfile.TemporaryDirectory() as td:
        cfg = Path(td) / "baseline.yml"
        cfg.write_text(yaml.safe_dump(build_baseline_rules(), sort_keys=False))
        out = _run_semgrep([cfg], root, files)
    res = []
    for r in out.get("results", []):
        cls = r["check_id"].rsplit(".", 1)[-1]
        res.append(BaselineFinding(cls, r["path"], r["start"]["line"], r["extra"].get("lines", "")))
    return res
