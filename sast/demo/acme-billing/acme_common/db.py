"""Shared database helpers used across Acme services."""
import sqlite3

DB_PATH = "/var/lib/acme/app.db"


def get_db():
    return sqlite3.connect(DB_PATH)


def quote_sql(value):
    """Escape a value for inclusion inside a single-quoted SQL literal."""
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace("'", "''")
    return text


def run_query(sql, params=None):
    cur = get_db().cursor()
    if params is None:
        cur.execute(sql)
    else:
        cur.execute(sql, params)
    return cur.fetchall()
