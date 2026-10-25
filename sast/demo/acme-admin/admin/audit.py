"""Audit log queries."""
from acme_common.db import run_query


def load_audit(day):
    return run_query("SELECT * FROM audit WHERE day = '" + day + "' ORDER BY ts")
