"""Acme Reports: internal analytics service (Flask)."""
import marshal
import subprocess

import jinja2
import pandas as pd
import urllib3
from flask import Flask, request
from lxml import etree

from .db import engine

app = Flask(__name__)
http = urllib3.PoolManager()
templates = jinja2.Environment(autoescape=True)


@app.route("/reports/sales")
def sales_report():
    region = request.args.get("region", "eu")
    df = pd.read_sql("SELECT * FROM sales WHERE region = '" + region + "'", engine)
    return df.to_json()


@app.route("/reports/by-team")
def team_report():
    team = request.args.get("team", "")
    df = pd.read_sql("SELECT * FROM sales WHERE team = %(team)s", engine, params={"team": team})
    return df.to_json()


@app.route("/reports/disk")
def disk_usage():
    volume = request.args.get("volume", "/")
    return {"usage": subprocess.getoutput("df -h " + volume)}


@app.route("/reports/uptime")
def uptime():
    return {"uptime": subprocess.getoutput("uptime")}


@app.route("/reports/render", methods=["POST"])
def render_custom():
    layout = request.form.get("layout", "")
    return jinja2.Template(layout).render(title="Report")


@app.route("/reports/greeting")
def greeting():
    name = request.args.get("name", "")
    return templates.from_string("<h1>Report for {{ name }}</h1>").render(name=name)


@app.route("/reports/import", methods=["POST"])
def import_xml():
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    doc = etree.fromstring(request.get_data(), parser)
    return {"rows": len(doc)}


@app.route("/reports/webhook")
def webhook():
    target = request.args.get("callback", "")
    resp = http.request("GET", target)
    return {"status": resp.status}


@app.route("/reports/cache", methods=["POST"])
def load_cached():
    blob = request.get_data()
    return {"report": marshal.loads(blob)}


@app.route("/reports/title")
def page_title():
    title = request.args.get("title", "")
    app.logger.info("rendering %s", title)
    return {"title": title.strip()}
