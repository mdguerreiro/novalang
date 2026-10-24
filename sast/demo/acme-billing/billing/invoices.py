"""Invoice data access and rendering."""
import os

from acme_common.db import run_query
from acme_common.shell import run_shell

INVOICE_DIR = "/srv/invoices"


def _customer_filter(customer):
    return "customer_ref = '" + customer + "'"


def invoices_for_customer(customer):
    return run_query("SELECT * FROM invoices WHERE " + _customer_filter(customer))


def invoice_path(name):
    return os.path.join(INVOICE_DIR, name + ".pdf")


def render_invoice_pdf(name):
    run_shell("invoice-render --template default --out " + invoice_path(name))


def clean_filename(name):
    return name.replace("../", "")
