"""ETL control API (FastAPI)."""
import shlex
import subprocess

import dill
import pandas as pd
from fastapi import APIRouter
from lxml import etree

from .db import engine

router = APIRouter()


@router.post("/jobs/preview")
def preview_job(table: str, limit: int = 10):
    df = pd.read_sql("SELECT * FROM " + table + " LIMIT " + str(limit), engine)
    return df.to_dict()


@router.post("/jobs/count")
def count_rows(table_id: int):
    df = pd.read_sql("SELECT count(*) FROM t_" + str(table_id), engine)
    return df.to_dict()


@router.post("/jobs/archive")
def archive(path: str):
    return {"out": subprocess.getoutput("tar czf /tmp/a.tgz " + shlex.quote(path))}


@router.post("/jobs/compress")
def compress(path: str):
    return {"out": subprocess.getoutput("gzip -k " + path)}


@router.post("/jobs/import")
def import_feed(body: str):
    tree = etree.fromstring(body.encode(), etree.XMLParser(resolve_entities=True))
    return {"items": len(tree)}


@router.post("/jobs/restore")
def restore(blob: bytes):
    job = dill.loads(blob)
    return {"job": str(job)}


@router.get("/jobs/{job_id}")
def job_status(job_id: str):
    df = pd.read_sql("SELECT state FROM jobs WHERE id = %(id)s", engine, params={"id": job_id})
    return df.to_dict()
