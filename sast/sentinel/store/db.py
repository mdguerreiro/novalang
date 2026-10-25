"""SQLite persistence: findings, verdicts, knowledge items with provenance, audit log."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS repos (
  id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES orgs(id), name TEXT NOT NULL, root TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT, repo_id TEXT NOT NULL REFERENCES repos(id),
  started_at REAL NOT NULL, finished_at REAL, stats TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS files (
  repo_id TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, content TEXT NOT NULL,
  PRIMARY KEY (repo_id, path));
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, repo_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
  cls TEXT NOT NULL, cwe TEXT, severity TEXT, title TEXT,
  engine_status TEXT NOT NULL, lane TEXT NOT NULL, triage_state TEXT NOT NULL DEFAULT 'untriaged',
  source_fn TEXT, sink_fn TEXT, file TEXT, line INTEGER, source_kind TEXT,
  data TEXT NOT NULL DEFAULT '{}', posterior REAL, group_key TEXT, shadow_by TEXT,
  audit INTEGER NOT NULL DEFAULT 0, is_open INTEGER NOT NULL DEFAULT 1,
  first_scan INTEGER, last_scan INTEGER, updated_at REAL,
  UNIQUE (repo_id, fingerprint));
CREATE TABLE IF NOT EXISTS verdicts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL REFERENCES findings(id),
  scan_id INTEGER, actor TEXT NOT NULL, kind TEXT NOT NULL, verdict TEXT NOT NULL,
  reason_code TEXT, evidence TEXT NOT NULL DEFAULT '{}', gate TEXT NOT NULL DEFAULT '{}',
  created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS knowledge (
  id TEXT PRIMARY KEY, scope TEXT NOT NULL, org_id TEXT, repo_id TEXT,
  pred TEXT NOT NULL, args TEXT NOT NULL, status TEXT NOT NULL, origin TEXT NOT NULL,
  confidence REAL, rationale TEXT, gate TEXT NOT NULL DEFAULT '{}', corroborations INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL, updated_at REAL NOT NULL, payload TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS knowledge_links (
  knowledge_id TEXT NOT NULL, finding_id INTEGER, verdict_id INTEGER, relation TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT NOT NULL, type TEXT NOT NULL,
  finding_id INTEGER, knowledge_id TEXT, payload TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo_id, is_open);
CREATE INDEX IF NOT EXISTS idx_verdicts_finding ON verdicts(finding_id);
CREATE INDEX IF NOT EXISTS idx_links_k ON knowledge_links(knowledge_id);
"""

JSON_COLS = {"data", "stats", "evidence", "gate", "args", "payload"}


def _row(r: sqlite3.Row | None) -> dict | None:
    if r is None:
        return None
    d = dict(r)
    for k in JSON_COLS & d.keys():
        if isinstance(d[k], str):
            d[k] = json.loads(d[k])
    return d


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL" if self.path != ":memory:" else "PRAGMA journal_mode=MEMORY")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Columns added after a database may already exist (CREATE TABLE IF NOT EXISTS never adds them)."""
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(knowledge)").fetchall()}
        if "payload" not in cols:  # spec_rule items: rule YAML, examples, originating site
            self.conn.execute("ALTER TABLE knowledge ADD COLUMN payload TEXT NOT NULL DEFAULT '{}'")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self.conn.execute("BEGIN")
            try:
                yield self.conn
                self.conn.execute("COMMIT")
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise

    def q(self, sql: str, *args) -> list[dict]:
        with self._lock:
            return [_row(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql: str, *args) -> dict | None:
        with self._lock:
            return _row(self.conn.execute(sql, args).fetchone())

    def x(self, sql: str, *args) -> int:
        with self._lock:
            cur = self.conn.execute(sql, args)
            return cur.lastrowid

    # ── orgs / repos / files ─────────────────────────────────────────────────────────────
    def upsert_org(self, org_id: str, name: str) -> None:
        self.x("INSERT INTO orgs(id, name) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name", org_id, name)

    def upsert_repo(self, repo_id: str, org_id: str, name: str, root: str) -> None:
        self.x("INSERT INTO repos(id, org_id, name, root) VALUES (?,?,?,?) "
               "ON CONFLICT(id) DO UPDATE SET org_id=excluded.org_id, name=excluded.name, root=excluded.root",
               repo_id, org_id, name, root)

    def repo(self, repo_id: str) -> dict | None:
        return self.one("SELECT * FROM repos WHERE id=?", repo_id)

    def save_files(self, repo_id: str, files: dict[str, tuple[str, str]]) -> None:
        with self.tx() as c:
            for path, (sha, content) in files.items():
                c.execute("INSERT INTO files(repo_id, path, sha256, content) VALUES (?,?,?,?) "
                          "ON CONFLICT(repo_id, path) DO UPDATE SET sha256=excluded.sha256, content=excluded.content",
                          (repo_id, path, sha, content))

    def file(self, repo_id: str, path: str) -> dict | None:
        return self.one("SELECT * FROM files WHERE repo_id=? AND path=?", repo_id, path)

    # ── events ───────────────────────────────────────────────────────────────────────────
    def event(self, actor: str, type_: str, finding_id: int | None = None, knowledge_id: str | None = None,
              **payload: Any) -> int:
        return self.x("INSERT INTO events(ts, actor, type, finding_id, knowledge_id, payload) VALUES (?,?,?,?,?,?)",
                      time.time(), actor, type_, finding_id, knowledge_id, json.dumps(payload, default=str))

    # ── knowledge ────────────────────────────────────────────────────────────────────────
    def next_knowledge_id(self, prefix: str = "K") -> str:
        """K-NNN for Datalog facts, R-NNN for learned spec rules (separate sequences)."""
        r = self.one("SELECT COUNT(*) AS n FROM knowledge WHERE id LIKE ?", f"{prefix}-%")
        return f"{prefix}-{(r['n'] if r else 0) + 1:03d}"

    def knowledge(self, kid: str) -> dict | None:
        return self.one("SELECT * FROM knowledge WHERE id=?", kid)

    def find_knowledge(self, pred: str, args: list, scope: str, org_id: str | None, repo_id: str | None) -> dict | None:
        return self.one("SELECT * FROM knowledge WHERE pred=? AND args=? AND scope=? AND IFNULL(org_id,'')=IFNULL(?,'') "
                        "AND IFNULL(repo_id,'')=IFNULL(?,'') AND status != 'retired'",
                        pred, json.dumps(args), scope, org_id, repo_id)

    def knowledge_in_scope(self, org_id: str, repo_id: str, statuses: tuple[str, ...]) -> list[dict]:
        marks = ",".join("?" * len(statuses))
        return self.q(f"SELECT * FROM knowledge WHERE status IN ({marks}) AND ("
                      f"scope='global' OR (scope='org' AND org_id=?) OR (scope='repo' AND repo_id=?)) ORDER BY id",
                      *statuses, org_id, repo_id)

    def link(self, kid: str, relation: str, finding_id: int | None = None, verdict_id: int | None = None) -> None:
        exists = self.one("SELECT 1 FROM knowledge_links WHERE knowledge_id=? AND relation=? AND IFNULL(finding_id,-1)=IFNULL(?,-1) "
                          "AND IFNULL(verdict_id,-1)=IFNULL(?,-1)", kid, relation, finding_id, verdict_id)
        if not exists:
            self.x("INSERT INTO knowledge_links(knowledge_id, finding_id, verdict_id, relation, created_at) VALUES (?,?,?,?,?)",
                   kid, finding_id, verdict_id, relation, time.time())
