"""Public reporting API (FastAPI)."""
import subprocess

from fastapi import APIRouter
from sqlalchemy import text

from .db import engine

router = APIRouter()


@router.get("/api/reports/{report_id}")
def get_report(report_id: int, fmt: str = "csv"):
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT * FROM reports WHERE id = :id"), {"id": report_id}).fetchall()
    out = subprocess.run("report-export --format " + fmt, shell=True, capture_output=True)
    return {"rows": len(rows), "export": out.returncode}


@router.get("/api/search")
def search_reports(q: str = ""):
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT * FROM reports WHERE title LIKE '%" + q + "%'")).fetchall()
    return {"rows": len(rows)}


@router.get("/api/reports/{report_id}/owner")
def report_owner(report_id: int):
    with engine.connect() as conn:
        row = conn.execute(text("SELECT owner FROM reports WHERE id = " + str(report_id))).fetchone()
    return {"owner": row[0]}
