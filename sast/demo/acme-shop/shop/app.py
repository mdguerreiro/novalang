"""Acme Shop storefront."""
import hashlib
import os
import pickle
import subprocess

import yaml
from flask import Flask, abort, redirect, render_template_string, request, send_file, url_for
from markupsafe import escape
from slugify import slugify

from acme_common.db import get_db, quote_sql, run_query
from acme_common.net import fetch, fetch_allowed
from acme_common.shell import run_cmd

from .catalog import product_rows, search_products

app = Flask(__name__)
UPLOAD_DIR = "/srv/shop/uploads"


@app.route("/product/<int:product_id>")
def product(product_id):
    rows = run_query(f"SELECT * FROM products WHERE id = {product_id}")
    return {"product": rows}


@app.route("/search")
def search():
    term = request.args.get("q", "")
    return {"results": search_products(term)}


@app.route("/user")
def user_profile():
    user_id = request.args.get("id", "")
    if not user_id.isdigit():
        abort(400)
    cur = get_db().cursor()
    cur.execute("SELECT name, email FROM users WHERE id = " + user_id)
    return {"user": cur.fetchone()}


@app.route("/order")
def order_lookup():
    ref = quote_sql(request.args.get("ref", ""))
    rows = run_query("SELECT * FROM orders WHERE ref = '" + ref + "'")
    return {"orders": rows}


@app.route("/orders/by-customer")
def orders_by_customer():
    customer = request.args.get("customer", "")
    rows = run_query("SELECT * FROM orders WHERE customer = ?", (customer,))
    return {"orders": rows}


@app.route("/export")
def export_catalog():
    fmt = request.args.get("format", "csv")
    os.system("catalog-export --format " + fmt + " --out /tmp/export")
    return send_file("/tmp/export")


@app.route("/convert")
def convert_image():
    name = request.args.get("name", "")
    run_cmd(["convert", name, "-resize", "200x200", "/tmp/thumb.png"])
    return send_file("/tmp/thumb.png")


@app.route("/thumbnail")
def thumbnail():
    filename = os.path.basename(request.args.get("file", ""))
    return send_file(os.path.join(UPLOAD_DIR, filename))


@app.route("/download")
def download():
    path = os.path.join(UPLOAD_DIR, request.args.get("file", ""))
    return send_file(path)


@app.route("/hello")
def hello():
    name = request.args.get("name", "friend")
    return "<h1>Hello " + str(escape(name)) + "</h1>"


@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/preview")
def link_preview():
    url = request.args.get("url", "")
    return {"bytes": len(fetch(url))}


@app.route("/avatar")
def avatar():
    url = request.args.get("url", "")
    return fetch_allowed(url)


@app.route("/import", methods=["POST"])
def import_catalog():
    data = yaml.safe_load(request.get_data())
    return {"items": len(data)}


@app.route("/import/legacy", methods=["POST"])
def import_legacy():
    data = yaml.load(request.get_data(), Loader=yaml.Loader)
    return {"items": len(data)}


@app.route("/cart")
def cart():
    blob = request.cookies.get("cart", "")
    items = pickle.loads(bytes.fromhex(blob))
    return {"items": items}


@app.route("/report")
def sales_report():
    year = int(request.args.get("year", "2026"))
    rows = run_query("SELECT * FROM sales WHERE year = " + str(year))
    return {"rows": rows}


@app.route("/coupon")
def coupon():
    code = request.args.get("code", "")
    digest = hashlib.sha256(code.encode()).hexdigest()
    rows = run_query("SELECT * FROM coupons WHERE digest = '" + digest + "'")
    return {"valid": bool(rows)}


@app.route("/category")
def category():
    slug = slugify(request.args.get("c", ""))
    return {"products": product_rows("category = '" + slug + "'")}


@app.route("/login")
def login():
    target = request.args.get("next", "/")
    return redirect(target)


@app.route("/logout")
def logout():
    return redirect(url_for("search"))


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    out = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return {"ok": out.returncode == 0}


def legacy_debug_console():
    expr = request.args.get("expr", "")
    return {"result": eval(expr)}
