"""Acme Billing service."""
import os

from flask import Flask, abort, request, send_file

from acme_common.db import quote_sql, run_query
from acme_common.net import fetch
from acme_common.shell import run_shell
from acme_common.validators import is_safe_slug

from .invoices import invoice_path, invoices_for_customer, render_invoice_pdf

app = Flask(__name__)


@app.route("/invoices")
def list_invoices():
    customer = request.args.get("customer", "")
    return {"invoices": invoices_for_customer(customer)}


@app.route("/invoice/<int:invoice_id>")
def invoice(invoice_id):
    return {"invoice": run_query("SELECT * FROM invoices WHERE id = " + str(invoice_id))}


@app.route("/invoice/search")
def invoice_search():
    memo = quote_sql(request.args.get("memo", ""))
    return {"rows": run_query("SELECT * FROM invoices WHERE memo LIKE '%" + memo + "%'")}


@app.route("/invoice/by-plan")
def invoice_by_plan():
    plan = request.args.get("plan", "")
    if not is_safe_slug(plan):
        abort(400)
    return {"rows": run_query("SELECT * FROM invoices WHERE plan = '" + plan + "'")}


@app.route("/invoice/pdf")
def invoice_pdf():
    name = request.args.get("name", "")
    if not is_safe_slug(name):
        abort(400)
    render_invoice_pdf(name)
    return send_file(invoice_path(name))


@app.route("/invoice/raw")
def invoice_raw():
    name = request.args.get("name", "")
    return send_file(invoice_path(name))


@app.route("/invoice/archive")
def archive():
    batch = request.args.get("batch", "")
    run_shell("tar czf /archive/" + batch + ".tgz /srv/invoices/" + batch)
    return {"ok": True}


@app.route("/webhook/test")
def webhook_test():
    target = request.args.get("target", "")
    return {"status": len(fetch(target))}


@app.route("/statements")
def statements():
    account = request.args.get("account", "")
    if not account.isalnum():
        abort(400)
    return send_file(os.path.join("/srv/statements", account + ".pdf"))
