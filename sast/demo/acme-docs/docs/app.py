"""Acme Docs: per-user documents and invoices (Flask)."""
from flask import Flask, abort, jsonify
from flask_login import current_user, login_required

from .auth import admin_required, audit_log, can_edit
from .models import Comment, Document, Invoice, Product, db

app = Flask(__name__)


@app.route("/documents/<int:doc_id>")
@login_required
def get_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    return jsonify(title=doc.title, body=doc.body)


@app.route("/documents/<int:doc_id>/safe")
@login_required
def get_document_checked(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != current_user.id:
        abort(403)
    return jsonify(title=doc.title, body=doc.body)


@app.route("/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    inv = Invoice.query.filter_by(id=invoice_id, customer_id=current_user.id).first_or_404()
    return jsonify(total=str(inv.total))


@app.route("/invoices/<int:invoice_id>/pdf")
@audit_log
def invoice_pdf(invoice_id):
    inv = Invoice.query.filter_by(id=invoice_id).first_or_404()
    return jsonify(total=str(inv.total))


@app.route("/admin/invoices/<int:invoice_id>")
@admin_required
def admin_invoice(invoice_id):
    inv = Invoice.query.get_or_404(invoice_id)
    return jsonify(total=str(inv.total))


@app.route("/comments/<int:comment_id>", methods=["DELETE"])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if not can_edit(current_user, comment):
        abort(403)
    db.session.delete(comment)
    db.session.commit()
    return "", 204


@app.route("/comments/<int:comment_id>/raw")
def comment_raw(comment_id):
    return jsonify(text=load_comment(comment_id).text)


def load_comment(cid):
    return db.session.get(Comment, cid)


@app.route("/products/<int:product_id>")
def get_product(product_id):
    p = Product.query.get_or_404(product_id)
    return jsonify(name=p.name, price=str(p.price))
