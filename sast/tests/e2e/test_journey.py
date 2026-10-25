"""The full analyst journey through the UI, and the flywheel it drives (deterministic mock model).

1. Inbox: confirm a true positive whose sink sits in a shared helper. That triggers a learned sink rule (shadow).
2. Inbox: close an AI-closed finding as "Sanitized: db.quote_sql". The fact applies org-wide, so the same
   pattern in acme-billing becomes "Closed by engine".
3. Knowledge: activate a shadow fact; the finding it covers moves to "Closed by engine" with that mitigation.
4. Knowledge: open the learned rule, see its Semgrep YAML, activate it; the export contains it.
5. Onboard acme-admin (helpers installed, bodies not visible): the learned rules find its vulnerabilities.
6. Insights shows the learned facts at work. No browser errors throughout.
"""
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")

SAST = Path(__file__).resolve().parents[2]
CHROME = os.environ.get("SENTINEL_CHROME", "/opt/pw-browsers/chromium-1194/chrome-linux/chrome")


def _port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _req(base: str, path: str, method: str = "GET", body=None, raw: bool = False):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=300) as resp:
        out = resp.read()
    return out.decode() if raw else json.loads(out)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    if not (SAST / "ui" / "dist" / "index.html").exists():
        pytest.skip("UI not built")
    db = tmp_path_factory.mktemp("journey") / "sentinel.db"
    e = dict(os.environ, PYTHONPATH=str(SAST))
    e.pop("SENTINEL_LLM", None)
    subprocess.run([sys.executable, "-m", "sentinel", "--db", str(db), "demo", "--cold"], cwd=SAST, env=e, check=True,
                   capture_output=True)
    port = _port()
    proc = subprocess.Popen([sys.executable, "-m", "sentinel", "--db", str(db), "serve", "--port", str(port)], cwd=SAST,
                            env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            _req(base, "/api/overview")
            break
        except OSError:
            time.sleep(0.2)
    with playwright.sync_playwright() as p:
        try:
            browser = p.chromium.launch(executable_path=CHROME if Path(CHROME).exists() else None)
        except Exception as ex:  # pragma: no cover
            proc.terminate()
            pytest.skip(f"no browser: {ex}")
        page = browser.new_page(viewport={"width": 1600, "height": 1000})
        errors: list[str] = []
        page.on("pageerror", lambda ex: errors.append(str(ex)))
        page.on("console", lambda m: m.type == "error" and errors.append(m.text))
        yield {"base": base, "page": page, "errors": errors, "db": db}
        browser.close()
    proc.terminate()
    proc.wait(timeout=10)


def _finding(base, repo, fn, cls):
    return next(r for r in _req(base, f"/api/findings?repo={repo}") if r["source_fn"].endswith("." + fn) and r["cls"] == cls)


def _open(page, base, repo, lane, fn):
    page.goto(f"{base}/#/inbox/{repo}")
    page.click(f".lane-tab:has-text('{lane}')")
    page.click(f".q-item:has-text('{fn}')")
    page.wait_for_selector(f".f-title:has-text('{fn}')")


def test_1_confirm_tp_through_shared_helper_proposes_sink_rule(env):
    base, page = env["base"], env["page"]
    _open(page, base, "acme-shop", "Open", "search")
    page.keyboard.press("c")
    page.locator(".toast:has-text('True positive')").wait_for(timeout=60000)
    assert _finding(base, "acme-shop", "search", "sqli")["triage_state"] == "confirmed"
    rules = [k for k in _req(base, "/api/knowledge") if k["pred"] == "spec_rule" and k["args"][1] == "sink"]
    assert any("run_query" in k["args"][0] for k in rules), [k["args"] for k in rules]
    assert all(k["status"] in ("shadow", "candidate") for k in rules)  # machine-written: waits for approval


def test_2_not_exploitable_teaches_org_and_transfers(env):
    base, page = env["base"], env["page"]
    assert _finding(base, "acme-billing", "invoice_search", "sqli")["lane"] == "suppressed_ai"
    _open(page, base, "acme-shop", "Closed by AI", "order_lookup")
    page.keyboard.press("x")
    labels = page.locator(".reason").all_inner_texts()
    page.keyboard.press(str(next(i for i, t in enumerate(labels) if "db.quote_sql" in t) + 1))
    page.locator(".impact:has-text('Canaries pass')").wait_for(timeout=60000)
    page.keyboard.press("Enter")
    page.locator(".toast:has-text('active: sanitizer_api')").wait_for(timeout=60000)
    after = _finding(base, "acme-billing", "invoice_search", "sqli")
    assert after["lane"] == "suppressed" and after["engine_status"] == "mitigated"


def test_3_activate_shadow_fact_in_knowledge_ui(env):
    base, page = env["base"], env["page"]
    shadow = [k for k in _req(base, "/api/knowledge") if k["status"] == "shadow" and k["pred"] == "sanitizer_api"
              and k["args"][0] == "slugify.slugify"]
    assert shadow, "expected the oracle's slugify fact in shadow"
    kid = shadow[0]["id"]
    page.goto(f"{base}/#/knowledge")
    page.click(f".k-table tr:has-text('{kid}')")
    page.locator(".drawer").wait_for()
    page.click(".drawer-f button:has-text('Activate')")
    page.locator(f".toast:has-text('{kid} active')").wait_for(timeout=60000)
    assert next(k for k in _req(base, "/api/knowledge") if k["id"] == kid)["status"] == "active"
    cat = _finding(base, "acme-shop", "category", "sqli")
    assert cat["lane"] == "suppressed"
    detail = _req(base, f"/api/findings/{cat['id']}")
    assert any(kid in m["knowledge"] for m in detail["data"]["mitigations"])
    # The finding view shows the learned mitigation.
    _open(page, base, "acme-shop", "Closed by engine", "category")
    assert "Sanitizer: slugify.slugify" in page.locator(".checks").inner_text()


def test_4_learned_rule_yaml_activation_and_export(env):
    base, page = env["base"], env["page"]
    rule = next(k for k in _req(base, "/api/knowledge") if k["pred"] == "spec_rule" and "run_query" in k["args"][0])
    page.goto(f"{base}/#/knowledge")
    page.click(f".k-table tr:has-text('{rule['id']}')")
    yaml_block = page.locator(".drawer pre.yaml").first
    yaml_block.wait_for()
    assert "run_query" in yaml_block.inner_text() and "sentinel" in yaml_block.inner_text()
    page.click(".drawer-f button:has-text('Activate')")
    page.locator(f".toast:has-text('{rule['id']} active')").wait_for(timeout=120000)
    exported = _req(base, "/api/rules/export?org=acme", raw=True)
    assert rule["id"] in exported and "run_query" in exported
    href = page.locator("a:has-text('Export rules')").get_attribute("href")
    assert href and "/api/rules/export?org=acme" in href


def test_5_new_repo_benefits_from_learned_rules(env):
    base = env["base"]
    con = sqlite3.connect(env["db"])
    con.execute("INSERT INTO repos(id, org_id, name, root) VALUES (?,?,?,?)",
                ("acme-admin", "acme", "acme-admin", str(SAST / "demo" / "acme-admin")))
    con.commit()
    con.close()
    _req(base, "/api/scan/acme-admin", method="POST")
    search = _finding(base, "acme-admin", "user_search", "sqli")  # run_query body is not in this repo
    assert search["lane"] == "confirmed"
    detail = _req(base, f"/api/findings/{search['id']}")
    assert "spec.learned" in detail["data"]["sink_rule"]


def test_6_insights_and_no_errors(env):
    base, page = env["base"], env["page"]
    page.goto(f"{base}/#/insights")
    tile = page.locator(".kpi:has-text('Closed by learned facts') .k-value")
    tile.wait_for()
    page.click("button:has-text('Rescan')")
    page.locator(".toast:has-text('Scanned')").wait_for(timeout=180000)
    page.goto(f"{base}/#/insights")
    assert int(page.locator(".kpi:has-text('Closed by learned facts') .k-value").inner_text()) >= 2
    assert not env["errors"], env["errors"]
