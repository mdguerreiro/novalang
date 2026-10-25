"""Acme Admin back office.

acme_common is an installed dependency here (see requirements.txt), not vendored: its source is not
part of this repository.
"""
import os
import shlex

from flask import Flask, request

from acme_common.db import get_db, quote_sql, run_query
from acme_common.net import fetch, fetch_allowed
from acme_common.shell import run_cmd, run_shell

from .audit import load_audit

app = Flask(__name__)


@app.route("/admin/backup")
def backup():
    database = request.args.get("db", "main")
    run_shell("pg_dump " + database + " > /backups/latest.sql")
    return {"ok": True}


@app.route("/admin/backup/safe")
def backup_safe():
    database = request.args.get("db", "main")
    run_shell("pg_dump " + shlex.quote(database) + " > /backups/latest.sql")
    return {"ok": True}


@app.route("/admin/users/search")
def user_search():
    name = request.args.get("name", "")
    return {"users": run_query("SELECT id, name FROM users WHERE name LIKE '%" + name + "%'")}


@app.route("/admin/users/by-ref")
def user_by_ref():
    ref = quote_sql(request.args.get("ref", ""))
    return {"users": run_query("SELECT id, name FROM users WHERE ref = '" + ref + "'")}


@app.route("/admin/users/lookup")
def user_lookup():
    email = quote_sql(request.args.get("email", ""))
    cur = get_db().cursor()
    cur.execute("SELECT id FROM users WHERE email = '" + email + "'")
    return {"user": cur.fetchone()}


@app.route("/admin/users/by-id")
def user_by_id():
    uid = request.args.get("id", "")
    return {"user": run_query("SELECT * FROM users WHERE id = ?", (uid,))}


@app.route("/admin/audit")
def audit_log():
    day = request.args.get("day", "")
    return {"entries": load_audit(day)}


@app.route("/admin/health")
def health_probe():
    url = request.args.get("url", "")
    return {"bytes": len(fetch(url))}


@app.route("/admin/health/cdn")
def cdn_probe():
    url = request.args.get("url", "")
    return {"bytes": len(fetch_allowed(url))}


@app.route("/admin/report")
def run_report():
    name = request.args.get("name", "")
    run_cmd(["acme-report", "--name", name])
    return {"ok": True}


@app.route("/admin/export")
def export_users():
    fmt = request.args.get("format", "csv")
    os.system("user-export --format " + fmt)
    return {"ok": True}
