"""One handler per template engine, each rendering a request value raw (vulnerable) and escaped (safe)."""
import jinja2
from bottle import template as bottle_template
from django.shortcuts import render as django_render
from flask import Flask, render_template, render_template_string, request
from mako.template import Template as MakoTemplate
from tornado.template import Template as TornadoTemplate

app = Flask(__name__)
PAGE = "<h1>{{ title }}</h1>{% for c in comments %}<p>{{ c.body|safe }}</p>{% endfor %}"


@app.route("/inline")
def inline():
    q = request.args.get("q")
    return render_template_string(PAGE, title=q, comments=[{"body": q}])  # comments raw, title escaped


@app.route("/file")
def from_file():
    return render_template("profile.html", bio=request.args.get("bio"), name=request.args.get("name"))


@app.route("/jinja-direct")
def jinja_direct():
    return jinja2.Template("<p>{{ msg }}</p>").render(msg=request.args.get("msg"))  # no autoescape by default


@app.route("/jinja-env")
def jinja_env():
    env = jinja2.Environment(autoescape=True)
    return env.from_string("<p>{{ msg }}</p>").render(msg=request.args.get("msg"))  # escaped


@app.route("/django")
def django_view():
    return django_render(request, "dj.html", {"note": request.args.get("note"), "who": request.args.get("who")})


@app.route("/tornado")
def tornado_view():
    t = TornadoTemplate("{% raw blurb %} {{ safe_one }}")
    return t.generate(blurb=request.args.get("b"), safe_one=request.args.get("s"))


@app.route("/bottle")
def bottle_view():
    return bottle_template("<b>{{!raw}}</b><i>{{esc}}</i>", raw=request.args.get("r"), esc=request.args.get("e"))


@app.route("/mako")
def mako_view():
    return MakoTemplate("<p>${body}</p><p>${clean | h}</p>").render(body=request.args.get("x"), clean=request.args.get("y"))
