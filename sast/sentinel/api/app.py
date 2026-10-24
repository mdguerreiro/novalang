"""HTTP API for the triage UI."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..explain import explain
from ..learn import bayes
from ..pipeline import Scanner
from ..store.db import Store
from ..triage import Triage

SAST_ROOT = Path(__file__).resolve().parents[2]
UI_DIST = SAST_ROOT / "ui" / "dist"
SUMMARY_COLS = ("id, repo_id, fingerprint, cls, cwe, severity, title, engine_status, lane, triage_state, source_fn, sink_fn, "
                "file, line, source_kind, posterior, group_key, shadow_by, audit, is_open, updated_at")


class TriageIn(BaseModel):
    state: str
    reason: str | None = None
    detail: dict = {}
    scope: str | None = None
    note: str = ""
    actor: str = "human:you"


class PreviewIn(BaseModel):
    reason: str
    detail: dict = {}
    scope: str | None = None


class BulkIn(BaseModel):
    ids: list[int]
    state: str
    reason: str | None = None
    detail: dict = {}
    note: str = ""
    actor: str = "human:you"


class KnowledgeIn(BaseModel):
    status: str
    actor: str = "human:you"


def create_app(store: Store | None = None, scanner: Scanner | None = None) -> FastAPI:
    store = store or Store(os.environ.get("SENTINEL_DB", str(SAST_ROOT / ".data" / "sentinel.db")))
    scanner = scanner or Scanner(store)
    triage = Triage(scanner)
    app = FastAPI(title="Sentinel", version="0.1")
    app.state.store, app.state.scanner = store, scanner

    def finding_or_404(fid: int) -> dict:
        f = store.one("SELECT * FROM findings WHERE id=?", fid)
        if f is None:
            raise HTTPException(404, "finding not found")
        return f

    def calibration(f: dict) -> dict:
        rows = store.q("SELECT triage_state FROM findings WHERE cls=? AND lane=? AND triage_state IN ('confirmed','not_exploitable')",
                       f["cls"], f["lane"])
        n = len(rows)
        conf = sum(1 for r in rows if r["triage_state"] == "confirmed")
        return {"n": n, "confirmed": conf, "rate": round(conf / n, 3) if n else None, "calibrated": n >= 5}

    @app.get("/api/overview")
    def overview():
        repos = []
        for r in store.q("SELECT * FROM repos ORDER BY id"):
            lanes = {row["lane"]: row["n"] for row in store.q(
                "SELECT lane, COUNT(*) AS n FROM findings WHERE repo_id=? AND is_open=1 GROUP BY lane", r["id"])}
            untriaged = store.one("SELECT COUNT(*) AS n FROM findings WHERE repo_id=? AND is_open=1 AND triage_state='untriaged' "
                                  "AND (lane IN ('review','confirmed') OR audit=1)", r["id"])["n"]
            last = store.one("SELECT * FROM scans WHERE repo_id=? AND finished_at IS NOT NULL ORDER BY id DESC LIMIT 1", r["id"])
            repos.append({**r, "lanes": lanes, "inbox": untriaged, "last_scan": last})
        orgs = store.q("SELECT * FROM orgs")
        knowledge = {row["status"]: row["n"] for row in store.q("SELECT status, COUNT(*) AS n FROM knowledge GROUP BY status")}
        return {"orgs": orgs, "repos": repos, "knowledge": knowledge}

    @app.get("/api/findings")
    def findings(repo: str | None = None, lane: str | None = None, state: str | None = None, audit: int | None = None,
                 include_closed: bool = False):
        where, args = ["1=1"], []
        if not include_closed:
            where.append("is_open=1")
        for col, val in (("repo_id", repo), ("lane", lane), ("triage_state", state)):
            if val:
                where.append(f"{col}=?")
                args.append(val)
        if audit is not None:
            where.append("audit=?")
            args.append(audit)
        rows = store.q(f"SELECT {SUMMARY_COLS} FROM findings WHERE {' AND '.join(where)}", *args)
        groups: dict[str, int] = {}
        for r in rows:
            groups[r["group_key"]] = groups.get(r["group_key"], 0) + 1
        for r in rows:
            r["group_size"] = groups[r["group_key"]]
        return rows

    @app.get("/api/findings/{fid}")
    def finding(fid: int):
        f = finding_or_404(fid)
        files = {}
        for st in f["data"].get("path", []):
            if st["file"] not in files:
                row = store.file(f["repo_id"], st["file"])
                files[st["file"]] = {"content": row["content"], "sha256": row["sha256"]} if row else None
        verdicts = store.q("SELECT * FROM verdicts WHERE finding_id=? ORDER BY id", fid)
        knowledge = store.q("SELECT k.*, l.relation FROM knowledge_links l JOIN knowledge k ON k.id = l.knowledge_id "
                            "WHERE l.finding_id=? ORDER BY k.id", fid)
        mit_ids = {kid for m in f["data"].get("mitigations", []) for kid in m.get("knowledge", [])}
        for kid in sorted(mit_ids - {k["id"] for k in knowledge}):
            k = store.knowledge(kid)
            if k:
                knowledge.append({**k, "relation": "suppresses"})
        if f["shadow_by"]:
            k = store.knowledge(f["shadow_by"])
            if k:
                knowledge.append({**k, "relation": "would_suppress"})
        rel = []
        net = getattr(scanner, "_net", None)
        if net is not None:
            for h, fids in bayes.related(net, str(fid)).items():
                for other in fids:
                    o = store.one(f"SELECT {SUMMARY_COLS} FROM findings WHERE id=?", int(other))
                    if o and o["repo_id"] == f["repo_id"]:
                        rel.append({"hypothesis": h, "finding": o})
        events = store.q("SELECT * FROM events WHERE finding_id=? ORDER BY id", fid)
        return {**f, "files": files, "verdicts": verdicts, "knowledge": knowledge, "related": rel, "events": events,
                "explanation": explain(f), "suggestions": triage.suggestions(f), "calibration": calibration(f)}

    @app.post("/api/findings/{fid}/preview")
    def preview(fid: int, body: PreviewIn):
        finding_or_404(fid)
        return triage.preview(fid, body.reason, body.detail, body.scope)

    @app.post("/api/findings/{fid}/triage")
    def decide(fid: int, body: TriageIn):
        finding_or_404(fid)
        try:
            res = triage.decide(fid, body.state, body.actor, body.reason, body.detail, body.scope, body.note)
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {**res, "finding": finding(fid)}

    @app.post("/api/findings/bulk")
    def bulk(body: BulkIn):
        res = triage.bulk(body.ids, body.state, body.actor, body.reason, body.detail, body.note)
        return {"count": len(res), "results": res}

    @app.get("/api/knowledge")
    def knowledge():
        rows = store.q("SELECT * FROM knowledge ORDER BY id DESC")
        for k in rows:
            links = store.q("SELECT l.relation, l.finding_id, f.repo_id, f.source_fn, f.cls, f.lane FROM knowledge_links l "
                            "LEFT JOIN findings f ON f.id = l.finding_id WHERE l.knowledge_id=?", k["id"])
            k["links"] = links
            k["support"] = scanner.ks.support(k["id"])
            k["applied_to"] = [r["id"] for r in store.q("SELECT id, data FROM findings WHERE is_open=1")
                               if any(k["id"] in m.get("knowledge", []) for m in r["data"].get("mitigations", []))]
            k["shadowing"] = [r["id"] for r in store.q("SELECT id FROM findings WHERE shadow_by=? AND is_open=1", k["id"])]
        return rows

    @app.post("/api/knowledge/{kid}")
    def set_knowledge(kid: str, body: KnowledgeIn):
        if store.knowledge(kid) is None:
            raise HTTPException(404, "knowledge item not found")
        if body.status not in ("active", "shadow", "retired"):
            raise HTTPException(400, "status must be active, shadow or retired")
        try:
            return triage.set_knowledge(kid, body.status, body.actor)
        except ValueError as e:
            raise HTTPException(409, str(e))

    @app.post("/api/knowledge/{kid}/preview")
    def preview_knowledge(kid: str):
        item = store.knowledge(kid)
        if item is None:
            raise HTTPException(404, "knowledge item not found")
        rep = scanner.preview(item)
        return {**rep, "impact": triage._enrich(rep["impact"])}

    @app.post("/api/scan/{repo_id}")
    def scan(repo_id: str):
        if store.repo(repo_id) is None:
            raise HTTPException(404, "repo not found")
        return scanner.scan(repo_id)

    @app.get("/api/insights")
    def insights():
        scans = store.q("SELECT id, repo_id, started_at, finished_at, stats FROM scans WHERE finished_at IS NOT NULL ORDER BY id")
        audited = store.q("SELECT triage_state FROM findings WHERE lane='suppressed_ai' AND triage_state IN ('confirmed','not_exploitable')")
        shown = store.q("SELECT triage_state FROM findings WHERE lane IN ('confirmed','review') AND triage_state IN ('confirmed','not_exploitable')")
        triage_counts = {r["actor_kind"]: r["n"] for r in store.q(
            "SELECT CASE WHEN actor LIKE 'human:%' THEN 'human' ELSE 'machine' END AS actor_kind, COUNT(*) AS n FROM verdicts GROUP BY actor_kind")}
        kn = store.q("SELECT origin, status, COUNT(*) AS n FROM knowledge GROUP BY origin, status")
        return {
            "scans": scans,
            "audit": {"audited": len(audited), "missed_tps": sum(1 for a in audited if a["triage_state"] == "confirmed")},
            "effective_fp": {"shown_triaged": len(shown), "fp": sum(1 for a in shown if a["triage_state"] == "not_exploitable")},
            "verdicts": triage_counts, "knowledge": kn,
        }

    @app.get("/api/events")
    def events(limit: int = 100):
        return store.q("SELECT * FROM events ORDER BY id DESC LIMIT ?", limit)

    if UI_DIST.exists():
        app.mount("/assets", StaticFiles(directory=UI_DIST / "assets"), name="assets")

        @app.get("/{path:path}")
        def spa(path: str):
            target = UI_DIST / path
            if path and target.is_file():
                return FileResponse(target)
            return FileResponse(UI_DIST / "index.html")

    return app
