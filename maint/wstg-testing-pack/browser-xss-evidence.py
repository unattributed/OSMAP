#!/usr/bin/env python3
"""Run reflected and stored XSS checks in a real headless browser."""

from __future__ import annotations

import argparse
import json
import urllib.parse
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--stored-fixture", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    marker = "osmap-wstg-browser-xss"
    payload = f'<img src=x onerror="window.__osmap_wstg_reflected_xss={marker!r}">'
    options = Options()
    options.add_argument("-headless")
    report: dict[str, object] = {"result": "failed", "checks": [], "failures": []}
    driver_path = Path.home() / ".cache" / "osmap-wstg" / "geckodriver"
    driver = webdriver.Firefox(
        options=options,
        service=Service(executable_path=str(driver_path)),
    )
    try:
        for route in ("/login?probe=", "/search?q=", "/mailbox?name="):
            url = args.base_url.rstrip("/") + route + urllib.parse.quote(payload, safe="")
            driver.get(url)
            executed = driver.execute_script("return window.__osmap_wstg_reflected_xss || null")
            reflected = payload.lower() in driver.page_source.lower()
            report["checks"].append(
                {"kind": "reflected", "route": route, "executed": bool(executed), "raw_reflection": reflected}
            )
            if executed or reflected:
                report["failures"].append(f"reflected payload remained active at {route}")

        fixture = args.stored_fixture.resolve()
        driver.get(fixture.as_uri())
        executed = driver.execute_script("return window.__osmap_wstg_stored_xss || null")
        active_nodes = driver.execute_script(
            """
            return document.querySelectorAll(
              'script,iframe,object,embed,form,[onerror],[onclick],[onload],[onfocus]'
            ).length;
            """
        )
        report["checks"].append(
            {"kind": "stored", "executed": bool(executed), "active_nodes": int(active_nodes)}
        )
        if executed or active_nodes:
            report["failures"].append("stored HTML retained executable elements or handlers")

        report["result"] = "passed" if not report["failures"] else "failed"
    finally:
        driver.quit()
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
