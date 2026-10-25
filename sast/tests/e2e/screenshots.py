"""Capture UI screenshots of a running Sentinel server (default http://localhost:8077).

Usage: python tests/e2e/screenshots.py [base_url]
Writes PNGs to docs/screenshots/ and fails on any browser console error.
"""
import asyncio
import os
import sys
from pathlib import Path

from playwright.async_api import async_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8077"
OUT = Path(__file__).resolve().parents[2] / "docs" / "screenshots"
CHROME = os.environ.get("SENTINEL_CHROME", "/opt/pw-browsers/chromium-1194/chrome-linux/chrome")


async def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=CHROME if Path(CHROME).exists() else None)
        for theme in ("dark", "light"):
            page = await browser.new_page(viewport={"width": 1600, "height": 1000})
            page.on("console", lambda m: m.type == "error" and errors.append(f"{theme} console: {m.text}"))
            page.on("pageerror", lambda e: errors.append(f"{theme} pageerror: {e}"))
            await page.goto(f"{BASE}/#/inbox")
            await page.evaluate(f"localStorage.setItem('sentinel-theme', '{theme}')")
            await page.reload()
            await page.wait_for_selector(".q-item, .empty")
            await page.wait_for_timeout(800)
            await page.screenshot(path=OUT / f"inbox-{theme}.png")
            if theme == "light":
                continue
            await page.keyboard.press("x")
            await page.wait_for_timeout(1500)
            await page.screenshot(path=OUT / "triage-reason-dark.png")
            await page.keyboard.press("Escape")
            for lane in ("Open", "Closed by AI", "Closed by engine"):
                await page.click(f".lane-tab:has-text('{lane}')")
                await page.wait_for_timeout(900)
                await page.screenshot(path=OUT / f"lane-{lane.lower().replace(' ', '-')}-dark.png")
            await page.goto(f"{BASE}/#/knowledge")
            await page.wait_for_selector(".k-table")
            await page.wait_for_timeout(500)
            await page.screenshot(path=OUT / "knowledge-dark.png")
            await page.click(".k-table tbody tr")
            await page.wait_for_timeout(1500)
            await page.screenshot(path=OUT / "knowledge-drawer-dark.png")
            await page.goto(f"{BASE}/#/insights")
            await page.wait_for_selector(".kpis")
            await page.wait_for_timeout(500)
            await page.screenshot(path=OUT / "insights-dark.png", full_page=True)
            await page.set_viewport_size({"width": 420, "height": 900})
            await page.goto(f"{BASE}/#/inbox")
            await page.wait_for_timeout(1200)
            await page.screenshot(path=OUT / "mobile-dark.png")
        await browser.close()
    for e in errors:
        print(e)
    print(f"screenshots in {OUT}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
