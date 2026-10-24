"""Plain-language explanations built from the engine's evidence (never from model prose alone)."""
from __future__ import annotations

SINK_DESC = {
    "sqli": "a SQL query execution", "cmdi": "a shell command", "path": "a filesystem path", "xss": "an HTML response",
    "ssti": "a server-side template", "ssrf": "an outbound HTTP request", "deser": "a deserializer",
    "code": "dynamic code evaluation", "redirect": "a redirect target",
}
KIND_DESC = {"http": "HTTP request parameter", "cookie": "cookie", "header": "HTTP header", "route": "URL path segment",
             "cli": "command-line argument"}


def _short(fn: str) -> str:
    return fn.rsplit(".", 1)[-1] if fn else "?"


def explain(f: dict) -> dict:
    d = f["data"]
    path = d.get("path", [])
    src = path[0] if path else None
    sink = path[-1] if path else None
    helpers = []
    for st in path:
        name = _short(st["fn"])
        if st["fn"] != f["source_fn"] and name not in helpers:
            helpers.append(name)
    why = []
    if src:
        why.append(f"Untrusted input enters as a {KIND_DESC.get(f['source_kind'], 'request value')} in "
                   f"`{_short(f['source_fn'])}` ({src['file']}:{src['line']}).")
    if sink:
        hop = f" through {', '.join(f'`{h}`' for h in helpers)}" if helpers else ""
        why.append(f"It reaches {SINK_DESC.get(f['cls'], 'a dangerous sink')}{hop} at {sink['file']}:{sink['line']}"
                   f" in {len(path)} steps.")
    other = sorted({k for st in path for k in st.get("other_kills", [])})
    if f["engine_status"] in ("confirmed", "undecided"):
        why.append(f"No {f['cls'].upper()}-relevant sanitizer, validator or type conversion applies anywhere on this path.")
    why_not, counterfactual = [], None
    for o in other:
        why_not.append(f"{o[0].upper() + o[1:]} is on the path, but it does not protect against {f['title'].lower()}.")
    for a in d.get("assumptions", []):
        kind, *args = a["asm"]
        subject = args[0] if args else ""
        if kind == "maybe_sanitizer":
            why_not.append(f"`{_short(subject)}` looks like a sanitizer. The engine assumed it is not, until shown otherwise.")
            counterfactual = counterfactual or f"Proved safe if `{subject}` neutralises {f['cls'].upper()} payloads."
        elif kind == "unknown_api":
            why_not.append(f"`{subject}` is a library call the engine has no model for; it was assumed to pass the data through.")
            counterfactual = counterfactual or f"Proved safe if `{subject}` sanitizes its output for {f['cls'].upper()}."
        elif kind == "unknown_guard":
            why_not.append(f"A validation check `{subject.removeprefix('call:')}` guards this value, but its strength is unknown.")
            counterfactual = counterfactual or f"Proved safe if `{subject.removeprefix('call:')}` rejects {f['cls'].upper()} payloads."
        elif kind == "unreachable":
            why_not.append(f"`{_short(subject)}` is not reachable from any route or caller; it may be dead code.")
            counterfactual = counterfactual or f"Not exploitable if `{_short(subject)}` is never wired to a route."
        elif kind == "weak_source":
            why_not.append(f"The source is a {KIND_DESC.get(subject, subject)}, which an external attacker may not control.")
    for m in d.get("mitigations", []):
        why_not.append(f"Proved safe: {m['label']}.")
    if counterfactual is None and f["engine_status"] == "confirmed" and path:
        fix = next((st for st in reversed(path) if st["fn"] == f["source_fn"]), path[-1])
        counterfactual = (f"Safe if the value is sanitized for {f['cls'].upper()} before it leaves "
                          f"`{_short(fix['fn'])}` (best fix location: {fix['file']}:{fix['line']}).")
    return {"why": why, "why_not": why_not, "counterfactual": counterfactual}
