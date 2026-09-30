#!/usr/bin/env python3
"""Native sessions UI proof using temporary production SessionService storage.

Public synthetic authentication only. No tokens, CSRF values, browser storage,
session identifiers, filled login pages or external traffic are retained.
"""
import argparse
import json
from pathlib import Path
import tempfile
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server
from contrast_audit import TEXT_AUDIT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    parser.add_argument("--engine", choices=["chromium", "firefox"], default="chromium")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.chmod(0o700)
    checks, external, scripts = [], [], []
    report = {"result": "FAIL", "synthetic_authentication": True,
              "real_session_service_and_store": True, "engine": args.engine, "checks": checks}
    repo = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="osmap-sessions-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        process, origin = start_server(root, repo, log)
        browser = getattr(playwright, args.engine).launch(executable_path=args.browser, headless=True)
        report["browser_version"] = browser.version
        contexts = []

        def new_page():
            context = browser.new_context(viewport={"width": 1600, "height": 1100}, color_scheme="light", java_script_enabled=False)
            contexts.append(context)
            def route(request):
                if request.request.resource_type == "script":
                    scripts.append(True)
                if request.request.url.startswith(origin + "/"):
                    request.continue_()
                else:
                    external.append(True)
                    request.abort()
            context.route("**/*", route)
            return context.new_page()

        def visit(page, path):
            response = page.goto(origin + path, wait_until="networkidle")
            assert response.status == 200
            assert response.headers["cache-control"] == "no-store"
            assert page.locator("script").count() == 0

        def activate(page, button, keyboard=False):
            if keyboard:
                for _ in range(100):
                    page.keyboard.press("Tab")
                    if button.evaluate("el => el === document.activeElement"):
                        break
                else:
                    raise AssertionError("native control absent from keyboard focus order")
                page.screenshot(path=str(args.output / "sessions-keyboard-focus.png"), full_page=True)
            with page.expect_response(lambda response: response.request.method == "POST" and urlparse(response.url).path == "/sessions/revoke") as posted:
                with page.expect_navigation(wait_until="networkidle"):
                    if keyboard:
                        page.keyboard.press("Enter")
                    else:
                        button.click()
            assert posted.value.status == 303

        def login(page, username="alice@example.com"):
            visit(page, "/login")
            page.get_by_label("Username or Email").fill(username)
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            with page.expect_navigation(wait_until="networkidle"):
                page.get_by_role("button", name="Sign In", exact=True).click()
            visit(page, "/sessions")
            assert urlparse(page.url).path == "/sessions"
            expect(page.locator(".session-status-current")).to_have_count(1)

        def denied(page):
            visit(page, "/sessions")
            assert urlparse(page.url).path == "/login"

        def active(page, others):
            visit(page, "/sessions")
            assert urlparse(page.url).path == "/sessions"
            expect(page.locator(".session-status-current")).to_have_count(1)
            expect(page.locator(".session-status-active")).to_have_count(others)

        try:
            primary, secondary, third, foreign = new_page(), new_page(), new_page(), new_page()
            login(primary)
            login(secondary)
            login(foreign, "bob@example.com")
            active(primary, 1)
            locations = primary.locator('td[data-label="Location"]').all_text_contents()
            assert locations and all(text.strip() == "Unknown" for text in locations)
            checks.append("session location truthfully Unknown; independent authenticated contexts create separate real stored sessions")
            report["captures"] = []
            for theme in ["light", "dark"]:
                for width in [1600, 1440, 768, 360]:
                    for forced in ["none", "active"]:
                        primary.set_viewport_size({"width": width, "height": 1100})
                        primary.emulate_media(color_scheme=theme, forced_colors=forced)
                        overflow = primary.evaluate("document.documentElement.scrollWidth > innerWidth")
                        audit = primary.evaluate(TEXT_AUDIT)
                        boxes = primary.locator(".sessions-card,.sessions-card-header,.sessions-table thead,.sessions-table tbody tr,.sessions-scope-note").evaluate_all("nodes => nodes.map(n => {const b=n.getBoundingClientRect();return {element:n.tagName, class:n.className, x:b.x,y:b.y,width:b.width,height:b.height}})")
                        filename = f"sessions-{theme}-{width}-{forced}.png"
                        primary.screenshot(path=str(args.output / filename), full_page=True)
                        report["captures"].append(dict(file=filename, overflow=overflow, contrast=audit, boxes=boxes))
                        assert not overflow
                        assert not audit["failures"] and not audit["ui_failures"]
            checks.append("light/dark and both forced-colour palettes at 1600/1440/768/360: no overflow or detected text/UI contrast failures")

            primary.emulate_media(forced_colors="none", color_scheme="light")
            primary.set_viewport_size({"width": 1600, "height": 1100})
            activate(primary, primary.get_by_role("button", name="Revoke", exact=True))
            active(primary, 0)
            denied(secondary)
            active(foreign, 0)
            checks.append("pointer Revoke persists target revocation; target browser is denied and current browser remains authenticated")

            login(secondary)
            login(third)
            active(primary, 2)
            activate(primary, primary.get_by_role("button", name="Sign out all other sessions", exact=True), keyboard=True)
            active(primary, 0)
            denied(secondary)
            denied(third)
            active(foreign, 0)
            checks.append("keyboard native sign out all other sessions invalidates both other contexts and preserves current session")

            login(secondary)
            secondary.get_by_text("Session details and timeout policy", exact=True).click()
            activate(secondary, secondary.get_by_role("button", name="Revoke This Session", exact=True))
            assert urlparse(secondary.url).path == "/login"
            assert not any(cookie["name"] == "osmap_session" for cookie in secondary.context.cookies())
            denied(secondary)
            active(primary, 0)
            checks.append("current-session revoke clears browser cookie, redirects Login, denies later authenticated route and preserves another session")

            login(secondary)
            login(third)
            active(primary, 2)

            primary.get_by_text("Session details and timeout policy", exact=True).click()
            activate(primary, primary.get_by_role("button", name="Revoke All Sessions", exact=True))
            assert urlparse(primary.url).path == "/login"
            assert not any(cookie["name"] == "osmap_session" for cookie in primary.context.cookies())
            for page in [primary, secondary, third]:
                denied(page)
            active(foreign, 0)
            checks.append("foreign-account session remains authenticated after selected, others and all revocations")
            checks.append("revoke all clears current cookie and invalidates all three independent browser sessions")
            assert not external and not scripts
            checks.append("native controls work with JavaScript disabled; zero page scripts and zero external requests")
            report["result"] = "PASS"
        except Exception as error:
            # Never serialize locator/DOM dumps, response bodies or request data.
            report["failure_type"] = type(error).__name__
            raise
        finally:
            report["external_requests"] = len(external)
            report["script_requests"] = len(scripts)
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
            browser.close()
            stop_server(process, root)
    print(json.dumps({"result": report["result"], "checks": len(checks), "report": str(args.output / "workflows.json")}))


if __name__ == "__main__":
    main()
