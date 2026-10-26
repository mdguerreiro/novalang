import os
import pickle
import sqlite3
from flask import Flask, request, render_template_string, escape
from markupsafe import Markup

app = Flask(__name__)
UPLOADS = "/srv/uploads"


def db():
    return sqlite3.connect("blog.db")


@app.route("/comment", methods=["POST"])
def add_comment():
    c = db().cursor()
    c.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (request.form["author"], request.form["body"]))
    return "ok"


@app.route("/comments")
def comments():
    c = db().cursor()
    c.execute("SELECT author, body FROM comments")
    rows = c.fetchall()
    html = "".join(f"<li>{body}</li>" for _a, body in rows)
    return Markup(html)  # stored XSS


@app.route("/settings")
def settings():
    c = db().cursor()
    c.execute("SELECT name, value FROM settings")  # only ever written with constants: not attacker data
    return Markup("".join(f"<b>{v}</b>" for _n, v in c.fetchall()))


def seed():
    db().execute("INSERT INTO settings (name, value) VALUES ('theme', 'dark')")


@app.route("/model", methods=["POST"])
def upload_model():
    f = request.files["model"]
    path = os.path.join(UPLOADS, os.path.basename(f.filename))
    f.save(path)
    return str(load(path))


def load(model_path):
    with open(model_path, "rb") as fh:
        return pickle.load(fh)  # uploaded file deserialized
