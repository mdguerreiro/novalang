"""Canary corpus: every flow in this file is a REAL vulnerability.

Before any learned knowledge item becomes active, Sentinel re-analyses this file with the item
applied. If a single finding here disappears, the item is too broad (e.g. "os.path.join is a
sanitizer", "any regex guard validates input") and activation is blocked.
"""
import os
import re
import subprocess

import requests
from flask import Flask, redirect, render_template_string, request, send_file

app = Flask(__name__)


def passthrough(value):
    return value.strip()


def build_query(table, needle):
    return "SELECT * FROM {} WHERE name = '{}'".format(table, needle)


@app.route("/c/sqli")
def canary_sqli():
    import sqlite3
    q = request.args.get("q", "")
    sqlite3.connect("x").cursor().execute(build_query("t", passthrough(q)))


@app.route("/c/cmdi")
def canary_cmdi():
    name = request.args.get("n", "")
    subprocess.run(f"convert {name} out.png", shell=True)


@app.route("/c/path")
def canary_path():
    name = request.args.get("f", "")
    return send_file(os.path.normpath(os.path.join("/srv", name)))


@app.route("/c/ssrf")
def canary_ssrf():
    url = request.args.get("u", "")
    return requests.get(url.lower(), timeout=3).text


@app.route("/c/ssti")
def canary_ssti():
    return render_template_string("Hi " + request.args.get("n", ""))


@app.route("/c/redirect")
def canary_redirect():
    return redirect(request.args.get("next", "/").strip())


@app.route("/c/prefix-regex")
def canary_prefix_regex():
    name = request.args.get("n", "")
    if not re.match(r"[a-z]+", name):
        return "bad"
    os.system("echo " + name)


@app.route("/c/eval")
def canary_eval():
    return str(eval(request.args.get("e", "0")))
