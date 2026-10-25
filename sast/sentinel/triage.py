"""Human triage: the second half of the flywheel.

A triage decision with a *structured reason* becomes knowledge (R10). Each reason maps to exactly
one kind of knowledge, at a default scope:

    SANITIZED     {fn}    -> sanitizer_api(fn, cls)   org if fn lives in a shared package, else repo
    GUARDED       {pred}  -> safe_pred(pred, cls)
    UNREACHABLE           -> dead_fn(source function)       repo
    NOT_EXPOSED           -> internal_only(source function) repo
    TEST_CODE / ACCEPTED_RISK / OTHER -> no correctness learning (governance only)

Before anything is committed, `preview()` shows the knowledge item, every finding it would change
across the repos in scope, and the canary result. That is the "impact preview" in the UI.
"""
from __future__ import annotations

import json
import time

from .agent.mock import _scope_for
from .pipeline import Scanner

LEARNABLE = {"SANITIZED", "GUARDED", "UNREACHABLE", "NOT_EXPOSED"}
STATES = {"confirmed", "not_exploitable", "accepted_risk", "untriaged"}


def _disp(name: str) -> str:
    """`billing.invoices.clean_filename` -> `invoices.clean_filename` (enough to recognise it)."""
    parts = name.removeprefix("call:").split(".")
    return ".".join(parts[-2:])


class Triage:
    def __init__(self, scanner: Scanner):
        self.sc = scanner
        self.store = scanner.store

    # ── suggestions shown in the reason picker ───────────────────────────────────────────
    def suggestions(self, finding: dict) -> list[dict]:
        out = []
        for a in finding["data"].get("assumptions", []):
            kind, *args = a["asm"]
            if kind == "maybe_sanitizer":
                out.append({"reason": "SANITIZED", "detail": {"fn": args[0]}, "label": f"Sanitized: {_disp(args[0])}"})
            elif kind == "unknown_api":
                out.append({"reason": "SANITIZED", "detail": {"fn": args[0]}, "label": f"Sanitized: {_disp(args[0])}"})
            elif kind == "unknown_guard":
                out.append({"reason": "GUARDED", "detail": {"pred": args[0]}, "label": f"Validated: {_disp(args[0])}"})
            elif kind == "unreachable":
                out.append({"reason": "UNREACHABLE", "detail": {}, "label": f"Dead code: {args[0].rsplit('.', 1)[-1]}()"})
        # Agent proposals that did not clear the gates are still useful hints.
        for v in self.store.q("SELECT evidence FROM verdicts WHERE finding_id=? AND kind='agent' ORDER BY id DESC LIMIT 1", finding["id"]):
            for p in v["evidence"].get("proposed", []):
                if p["pred"] == "sanitizer_api":
                    s = {"reason": "SANITIZED", "detail": {"fn": p["args"][0]}, "label": f"Sanitized: {_disp(p['args'][0])}"}
                    if s not in out:
                        out.append(s)
        out += [{"reason": "NOT_EXPOSED", "detail": {}, "label": "Not exposed externally"},
                {"reason": "TEST_CODE", "detail": {}, "label": "Test code"},
                {"reason": "ACCEPTED_RISK", "detail": {}, "label": "Risk accepted"}]
        return out

    # ── reason -> knowledge ──────────────────────────────────────────────────────────────
    def knowledge_for(self, finding: dict, reason: str, detail: dict, scope: str | None) -> dict | None:
        repo = self.store.repo(finding["repo_id"])
        if reason == "SANITIZED" and detail.get("fn"):
            fn = detail["fn"]
            return {"pred": "sanitizer_api", "args": [fn, finding["cls"]], "scope": scope or _scope_for(fn),
                    "org_id": repo["org_id"], "repo_id": repo["id"]}
        if reason == "GUARDED" and detail.get("pred"):
            pred = detail["pred"]
            default = "org" if pred.startswith("call:") and _scope_for(pred.removeprefix("call:")) == "org" else "repo"
            return {"pred": "safe_pred", "args": [pred, finding["cls"]], "scope": scope or default,
                    "org_id": repo["org_id"], "repo_id": repo["id"]}
        if reason == "UNREACHABLE":
            return {"pred": "dead_fn", "args": [finding["source_fn"]], "scope": "repo", "org_id": repo["org_id"], "repo_id": repo["id"]}
        if reason == "NOT_EXPOSED":
            return {"pred": "internal_only", "args": [finding["source_fn"]], "scope": "repo", "org_id": repo["org_id"], "repo_id": repo["id"]}
        return None

    def preview(self, finding_id: int, reason: str, detail: dict, scope: str | None = None) -> dict:
        f = self.store.one("SELECT * FROM findings WHERE id=?", finding_id)
        k = self.knowledge_for(f, reason, detail, scope)
        if k is None:
            return {"knowledge": None, "impact": [], "canary": "n/a", "learns": False}
        item = {"id": "PREVIEW", "origin": "human:preview", "status": "candidate", "corroborations": 1, **k}
        report = self.sc.preview(item)
        impact = self._enrich(report["impact"])
        return {"knowledge": k, "learns": True, "impact": impact, "canary": report["canary"],
                "sanity": report["sanity"], "conflicts": report["conflicts"], "over_budget": report["over_budget"],
                "suppresses": report["suppresses"]}

    def _enrich(self, impact: list[dict]) -> list[dict]:
        out = []
        for i in impact:
            row = self.store.one("SELECT id, repo_id, title, source_fn, file, line, lane, triage_state FROM findings "
                                 "WHERE repo_id=? AND fingerprint=?", i["repo"], i["fingerprint"])
            out.append({**i, **({"finding": row} if row else {})})
        return out

    # ── committing ───────────────────────────────────────────────────────────────────────
    def decide(self, finding_id: int, state: str, actor: str, reason: str | None = None, detail: dict | None = None,
               scope: str | None = None, note: str = "") -> dict:
        if state not in STATES:
            raise ValueError(f"unknown triage state {state}")
        f = self.store.one("SELECT * FROM findings WHERE id=?", finding_id)
        if f is None:
            raise KeyError(finding_id)
        detail = detail or {}
        verdict = {"confirmed": "TRUE_POSITIVE", "not_exploitable": "FALSE_POSITIVE",
                   "accepted_risk": "ACCEPTED_RISK", "untriaged": "REOPENED"}[state]
        vid = self.store.x("INSERT INTO verdicts(finding_id, actor, kind, verdict, reason_code, evidence, created_at) "
                           "VALUES (?,?,?,?,?,?,?)", finding_id, actor, "human", verdict, reason,
                           json.dumps({"detail": detail, "note": note, "scope": scope}), time.time())
        audit = 0 if state != "untriaged" else f["audit"]
        self.store.x("UPDATE findings SET triage_state=?, audit=?, updated_at=? WHERE id=?", state, audit, time.time(), finding_id)
        self.store.event(actor, f"triage.{state}", finding_id, None, reason=reason, detail=detail, note=note)
        result: dict = {"verdict_id": vid, "state": state, "knowledge": None, "rescanned": []}
        if state == "not_exploitable" and reason in LEARNABLE:
            k = self.knowledge_for(f, reason, detail, scope)
            if k:
                item = self.sc.ks.propose(k["pred"], k["args"], k["scope"], k["org_id"], k["repo_id"], actor, 1.0,
                                          note or f"Triage of finding #{finding_id}: {reason}", finding_id, vid)
                item = self.sc._gate_item(item["id"], approved_by=actor)
                result["knowledge"] = item
                if item["status"] == "active":
                    result["rescanned"] = self.rescan_scope(item)
        else:
            self.sc.rank(f["repo_id"])
        return result

    def bulk(self, finding_ids: list[int], state: str, actor: str, reason: str | None = None, detail: dict | None = None,
             note: str = "") -> list[dict]:
        out = []
        for fid in finding_ids:
            f = self.store.one("SELECT triage_state FROM findings WHERE id=?", fid)
            if f and f["triage_state"] == "untriaged":
                out.append(self.decide(fid, state, actor, reason, detail, None, note))
        return out

    def rescan_scope(self, item: dict) -> list[dict]:
        out = []
        for repo_id in self.sc.repos_in_scope(item):
            res = self.sc.scan(repo_id, refresh=False, trigger="knowledge")
            out.append({"repo": repo_id, **{k: v for k, v in res.items() if k in ("scan_id", "lanes")}})
        return out

    def set_knowledge(self, kid: str, status: str, actor: str) -> dict:
        item = self.store.knowledge(kid)
        if status == "active":
            report = self.sc.preview(item)
            item = self.sc.ks.apply_gate(kid, report, approved_by=actor)
            if item["status"] != "active":
                raise ValueError(f"{kid} did not pass its gates: canary={report['canary']} sanity={report['sanity']}")
        else:
            item = self.sc.ks.set_status(kid, status, actor)
        if status == "retired":
            # Truth maintenance: every finding this item suppressed is re-decided (and re-opened).
            for l in self.store.q("SELECT DISTINCT finding_id FROM knowledge_links WHERE knowledge_id=? AND finding_id IS NOT NULL", kid):
                self.store.event(actor, "finding.reopened_by_retraction", l["finding_id"], kid)
        item["rescanned"] = self.rescan_scope(item)
        return item
