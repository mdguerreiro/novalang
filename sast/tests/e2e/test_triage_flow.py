"""End-to-end: the real UI teaches the engine, and the lesson transfers to another repository.

Starts a server on a fresh cold demo database, drives Chromium with the keyboard, and checks the
result through the API. Skipped when Playwright or Chromium is unavailable.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")

SAST = Path(__file__).resolve().parents[2]
CHROME = os.environ.get("SENTINEL_CHROME", "/opt/pw-browsers/chromium-1194/chrome-linux/chrome")
# Docs screenshots are refreshed only on request (SENTINEL_SCREENSHOTS=1); a normal run writes to a temp dir.
SHOTS = SAST / "docs" / "screenshots" if os.environ.get("SENTINEL_SCREENSHOTS") == "1" else \
    Path(os.environ.get("TMPDIR", "/tmp")) / "sentinel-e2e-shots"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(base: str, path: str):
    with urllib.request.urlopen(base + path, timeout=30) as r:
        return json.loads(r.read())


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    if not (SAST / "ui" / "dist" / "index.html").exists():
        pytest.skip("UI not built (cd ui && npx vite build)")
    db = tmp_path_factory.mktemp("e2e") / "sentinel.db"
    env = dict(os.environ, PYTHONPATH=str(SAST))
    subprocess.run([sys.executable, "-m", "sentinel", "--db", str(db), "demo", "--cold"], cwd=SAST, env=env,
                   check=True, capture_output=True)
    port = _free_port()
    proc = subprocess.Popen([sys.executable, "-m", "sentinel", "--db", str(db), "serve", "--port", str(port)],
                            cwd=SAST, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            _get(base, "/api/overview")
            break
        except OSError:
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("server did not start")
    yield base
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture(scope="module")
def page(server):
    with playwright.sync_playwright() as p:
        try:
            browser = p.chromium.launch(executable_path=CHROME if Path(CHROME).exists() else None)
        except Exception as e:  # pragma: no cover - environment without a browser
            pytest.skip(f"no browser: {e}")
        pg = browser.new_page(viewport={"width": 1600, "height": 1000})
        errors = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.on("console", lambda m: m.type == "error" and errors.append(m.text))
        pg.errors = errors
        yield pg
        browser.close()


def _finding(base, repo, fn, cls):
    rows = _get(base, f"/api/findings?repo={repo}")
    return next(r for r in rows if r["source_fn"].endswith("." + fn) and r["cls"] == cls)


def test_teach_engine_from_triage_transfers_to_other_repo(server, page):
    before = _finding(server, "acme-billing", "invoice_search", "sqli")
    assert before["lane"] == "suppressed_ai"  # decided by the agent on its own, not yet by the engine

    page.goto(f"{server}/#/inbox/acme-shop")
    page.click(".lane-tab:has-text('Closed by AI')")
    page.click(".q-item:has-text('order_lookup')")
    page.wait_for_selector(".f-title:has-text('SQL injection')")
    page.keyboard.press("x")
    page.wait_for_selector(".reason:has-text('Sanitized: db.quote_sql')")
    idx = page.locator(".reason").all_inner_texts().index(
        next(t for t in page.locator(".reason").all_inner_texts() if "db.quote_sql" in t))
    page.keyboard.press(str(idx + 1))
    impact = page.locator(".impact")
    impact.locator("text=closed in").wait_for(timeout=20000)
    text = impact.inner_text()
    assert "acme_common.db.quote_sql sanitizes SQLI" in text
    assert "Canaries pass" in text
    assert "in 2 repos" in text  # the shared helper is used by both services
    SHOTS.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=SHOTS / "impact-preview-dark.png")
    page.keyboard.press("Enter")
    page.locator(".toast:has-text('active: sanitizer_api')").wait_for(timeout=30000)

    # The agent had already proposed this fact (in shadow); the human decision merges into that item,
    # corroborates it and approves it, instead of creating a duplicate.
    k = [x for x in _get(server, "/api/knowledge") if x["pred"] == "sanitizer_api" and x["args"][0] == "acme_common.db.quote_sql"]
    assert len(k) == 1 and k[0]["status"] == "active" and k[0]["scope"] == "org"
    assert any(l["relation"] == "corroborated_by" and l["repo_id"] == "acme-shop" for l in k[0]["links"])
    after = _finding(server, "acme-billing", "invoice_search", "sqli")
    assert after["lane"] == "suppressed" and after["engine_status"] == "mitigated"  # now proved by the engine itself
    assert not page.errors, page.errors


def test_confirm_and_undo_with_keyboard(server, page):
    target = _finding(server, "acme-billing", "attachment", "path")
    assert target["lane"] == "review" and target["triage_state"] == "untriaged"
    page.goto(f"{server}/#/inbox/acme-billing")
    page.click(".lane-tab:has-text('Review')")
    page.click(".q-item:has-text('attachment')")
    page.wait_for_selector(".f-title:has-text('Path traversal')")
    page.keyboard.press("c")
    page.locator(".toast:has-text('True positive')").wait_for(timeout=15000)
    assert _finding(server, "acme-billing", "attachment", "path")["triage_state"] == "confirmed"
    page.keyboard.press("u")
    page.locator(".toast:has-text('Undone')").wait_for(timeout=15000)
    assert _finding(server, "acme-billing", "attachment", "path")["triage_state"] == "untriaged"
    assert not page.errors, page.errors
