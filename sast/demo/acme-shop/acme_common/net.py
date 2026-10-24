"""Outbound HTTP helpers."""
from urllib.parse import urlparse

import requests

ALLOWED_HOSTS = {"cdn.acme.example", "images.acme.example"}


def fetch(url):
    return requests.get(url, timeout=5).content


def fetch_allowed(url):
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5).content
