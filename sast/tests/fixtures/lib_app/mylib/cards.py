import pickle
import subprocess

import jinja2
import requests


class Card:
    def __init__(self, template):
        self.template = template

    def to_html(self, ctx):
        return jinja2.Environment(loader=jinja2.BaseLoader()).from_string(self.template).render(ctx)


def load(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def _private_load(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def export(path, data):
    # a file path a library writes to: not an execution sink, no API finding
    with open(path, "w") as f:
        f.write(data)


def clone(url, rev):
    subprocess.check_output(["git", "clone", url])
    subprocess.check_output(["git", "checkout", rev])


def fetch_and_run(endpoint):
    for line in requests.get(endpoint, stream=True).iter_lines():
        eval(line)


def run_fixed():
    subprocess.check_output(["git", "status"])
