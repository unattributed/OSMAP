#!/usr/bin/env python3
"""Exercise the real router/forms/cookies with a bounded synthetic loopback gateway.

Authentication is a test fixture, not Dovecot/TOTP qualification. Appearance
uses the real file store. This starts no runtime gateway and sends no email.
No browser storage, session token, CSRF value or filled login form is retained.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from playwright.sync_api import sync_playwright


def start_server(root, repo, log):
    for name in ["ready.json", "stop"]:
        (root / name).unlink(missing_ok=True)
    env = dict(os.environ, OSMAP_UX_BROWSER_STATE=str(root))
    process = subprocess.Popen(["cargo", "test", "--lib", "ux_synthetic_browser_server", "--", "--ignored", "--nocapture"],
                               cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if (root / "ready.json").exists():
            data = json.loads((root / "ready.json").read_text())
            assert data["synthetic"] and data["origin"].startswith("http://127.0.0.1:")
            return process, data["origin"]
        if process.poll() is not None:
            raise RuntimeError("synthetic server exited before readiness; see fixture log")
        time.sleep(.05)
    process.terminate()
    process.wait(timeout=5)
    raise RuntimeError("synthetic server readiness timed out")


def stop_server(process, root):
    (root / "stop").touch()
    try:
        result = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=5)
        raise RuntimeError("synthetic server did not stop cleanly")
    assert result == 0, "synthetic server test failed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks = []
    with tempfile.TemporaryDirectory(prefix="osmap-ux-browser-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        browser = playwright.chromium.launch(executable_path=args.browser, headless=True)
        process, origin = start_server(root, repo, log)
        blocked = []
        context = browser.new_context(viewport={"width": 1280, "height": 900}, color_scheme="light")

        def constrain(route):
            if route.request.url.startswith(origin + "/"):
                route.continue_()
            else:
                blocked.append(route.request.resource_type)
                route.abort()

        context.route("**/*", constrain)
        page = context.new_page()

        def visit(path):
            result = page.goto(origin + path, wait_until="networkidle")
            assert result and result.ok, path
            assert page.locator("script").count() == 0

        def appearance(value):
            assert page.locator("html").get_attribute("data-appearance") == value

        def login(account, expected):
            visit("/login")
            page.get_by_label("Username or Email").fill(account + "@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            page.get_by_role("button", name="Sign In", exact=True).click()
            page.wait_for_url(origin + "/mailboxes")
            appearance(expected)

        def logout():
            page.locator(".account-menu summary").click()
            page.get_by_role("button", name="Log Out", exact=True).click()
            page.wait_for_url(origin + "/login")

        try:
            login("alice", "system")
            visit("/settings?section=appearance")
            page.get_by_label("Dark", exact=True).check()
            page.get_by_role("button", name="Save changes", exact=True).click()
            page.wait_for_url(origin + "/settings?section=appearance&appearance_updated=1")
            appearance("dark")
            for path in ["/compose", "/drafts", "/sessions", "/settings?section=appearance"]:
                visit(path)
                appearance("dark")
            page.reload(wait_until="networkidle")
            appearance("dark")
            assert page.get_by_label("Dark", exact=True).is_checked()
            checks.append("account preference persists through native form, redirect, navigation and reload")
            logout()
            appearance("dark")
            checks.append("logout retains presentation preference")
            context.add_cookies([{"name": "osmap_appearance", "value": "light", "url": origin}])
            login("alice", "dark")
            checks.append("login restores saved account choice over stale browser preference")
            logout()
            login("bob", "system")
            visit("/settings?section=appearance")
            page.emulate_media(color_scheme="dark")
            assert page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(13, 21, 38)"
            page.emulate_media(color_scheme="light")
            assert page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(245, 248, 254)"
            checks.append("system appearance follows OS change without a reload")
            page.get_by_label("Light", exact=True).check()
            page.get_by_role("button", name="Save changes", exact=True).click()
            page.wait_for_url(origin + "/settings?section=appearance&appearance_updated=1")
            appearance("light")
            page.emulate_media(color_scheme="dark")
            assert page.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(245, 248, 254)"
            logout()
            login("alice", "dark")
            checks.append("two synthetic accounts retain independent preferences")
            context.close()
            stop_server(process, root)
            process, origin = start_server(root, repo, log)
            context = browser.new_context(viewport={"width": 1280, "height": 900})
            context.route("**/*", constrain)
            page = context.new_page()
            login("alice", "dark")
            logout()
            login("bob", "light")
            checks.append("new server process restores both saved account preferences")
            assert not blocked, "synthetic application attempted outside requests"
            report = {"synthetic": True, "authentication": "test fixture; not live Dovecot/TOTP",
                      "appearance_storage": "real AppearanceStore", "browser_version": browser.version,
                      "checks": checks, "outside_requests": 0, "passed": True}
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            context.close()
            if process.poll() is None:
                stop_server(process, root)
            browser.close()
    print(json.dumps({"passed": True, "checks": len(checks), "report": str(args.output / "workflows.json")}))


if __name__ == "__main__":
    main()
