"""Finding explanations as structured data (no prose): what flows where, and which mitigations were checked."""
from __future__ import annotations

KIND = {"http": "HTTP parameter", "cookie": "Cookie", "header": "HTTP header", "route": "URL path segment",
        "cli": "CLI argument"}


def _short(fn: str) -> str:
    return fn.rsplit(".", 1)[-1] if fn else "?"


def _subject(asm: list) -> str:
    return str(asm[1]).removeprefix("call:") if len(asm) > 1 else ""


def explain(f: dict) -> dict:
    d = f["data"]
    path = d.get("path", [])
    cls = f["cls"].upper()
    summary = []
    if path:
        src, sink = path[0], path[-1]
        summary.append({"k": "Source", "v": src["label"], "loc": f"{src['file']}:{src['line']}",
                        "note": KIND.get(f["source_kind"], f["source_kind"])})
        summary.append({"k": "Sink", "v": sink["label"], "loc": f"{sink['file']}:{sink['line']}", "note": f["cwe"]})
        via = []
        for st in path:
            name = _short(st["fn"])
            if st["fn"] != f["source_fn"] and name not in via:
                via.append(name)
        summary.append({"k": "Path", "v": f"{len(path)} steps" + (f" via {', '.join(via)}" if via else ""), "loc": "", "note": ""})

    checks = []
    for m in d.get("mitigations", []):
        checks.append({"state": "applies", "text": m["label"]})
    for a in d.get("assumptions", []):
        kind, subject = a["asm"][0], _subject(a["asm"])
        checks.append({"state": "unverified", "text": {
            "maybe_sanitizer": f"{_short(subject)}: possible sanitizer, not verified",
            "unknown_api": f"{subject}: library call not modelled",
            "unknown_guard": f"{_short(subject)}: validation strength unknown",
            "unreachable": f"{_short(subject)}: no route or caller found",
            "weak_source": f"{KIND.get(subject, subject)}: may not be attacker-controlled",
        }.get(kind, a["label"])})
    for o in sorted({k for st in path for k in st.get("other_kills", [])}):
        checks.append({"state": "other_class", "text": f"{o}: does not cover {cls}"})
    if f["engine_status"] in ("confirmed", "undecided") and not any(c["state"] == "applies" for c in checks):
        checks.insert(0, {"state": "missing", "text": f"No {cls} sanitizer, validation or type cast in the flow"})

    fix = None
    first = next((a for a in d.get("assumptions", []) if a["asm"][0] in ("maybe_sanitizer", "unknown_api", "unknown_guard")), None)
    if f["engine_status"] == "undecided" and first:
        fix = {"k": "Closes if", "v": f"{_short(_subject(first['asm']))} handles {cls} input"}
    elif f["engine_status"] == "confirmed" and path:
        at = next((st for st in reversed(path) if st["fn"] == f["source_fn"]), path[-1])
        fix = {"k": "Fix at", "v": f"{at['file']}:{at['line']} in {_short(at['fn'])}()"}
    return {"summary": summary, "checks": checks, "fix": fix}
