#!/usr/bin/env python3
"""Verify coordinated native navigation using only synthetic loopback mail.

No real account, host mail, browser storage or token is retained. The router
and HTML are real; gateway bodies and credentials are public test fixtures.
"""
import argparse
import json
from pathlib import Path
import tempfile
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import sync_playwright
from browser_workflows import start_server, stop_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    parser.add_argument("--engine", choices=["chromium", "firefox"], default="chromium")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks = []
    with tempfile.TemporaryDirectory(prefix="osmap-ux-reader-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        process, origin = start_server(root, Path(__file__).resolve().parents[2], log)
        browser = getattr(playwright, args.engine).launch(executable_path=args.browser, headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 1000}, user_agent="OSMAP/ManyMessages")
        blocked = []

        def constrain(route):
            if route.request.url.startswith(origin + "/"):
                route.continue_()
            else:
                blocked.append(route.request.resource_type)
                route.abort()

        context.route("**/*", constrain)
        page = context.new_page()

        def visit(path):
            response = page.goto(origin + path, wait_until="networkidle")
            assert response and response.ok
            assert "no-store" in response.headers["cache-control"]
            assert page.locator("script").count() == 0
            assert page.locator("main").count() == 1

        def login(account):
            visit("/login")
            page.get_by_label("Username or Email").fill(account + "@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            page.get_by_role("button", name="Sign In", exact=True).click()
            page.wait_for_url(origin + "/mailboxes")

        def click(name):
            page.get_by_role("link", name=name, exact=True).click()
            page.wait_for_load_state("networkidle")

        def state(**values):
            query = parse_qs(urlsplit(page.url).query)
            for name, value in values.items():
                assert query.get(name) == [value], name

        def body(uid=125, mailbox="INBOX", account="alice"):
            pane = page.locator("#reading-pane")
            assert pane.get_by_role("heading", name=f"Message {uid:03}", exact=True).is_visible()
            assert pane.locator(".body-panel pre").inner_text() == f"Synthetic message {uid} in {mailbox} for {account}@example.com."
            assert pane.locator(".body-panel").bounding_box()["y"] < pane.locator(".reader-attachments").bounding_box()["y"]

        try:
            login("alice")
            visit("/mailbox?name=INBOX&filter=starred&sort=subject&dir=asc")
            page.get_by_role("link", name="Message 007", exact=True).focus()
            with page.expect_navigation(wait_until="networkidle"):
                page.keyboard.press("Enter")
            state(selected_uid="7", selected_mailbox="INBOX", filter="starred", sort="subject", dir="asc")
            body(7)
            assert page.locator('.message-row[data-selected="true"] .message-subject-link').inner_text() == "Message 007"
            assert page.locator(":focus").get_attribute("id") == "reading-pane"
            click("Unread")
            state(selected_uid="7", filter="unread")
            body(7)
            page.locator(".message-sort summary").click()
            click("Sort by Subject descending")
            state(selected_uid="7", sort="subject", dir="desc")
            body(7)
            checks.append("keyboard selection opens a bound reader and preserves compatible filter and sort context")

            visit("/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=125")
            body()
            click("Next page")
            state(page="2", selected_uid="125")
            body()
            assert page.get_by_role("link", name="Locate selected message on page 1", exact=True).is_visible()
            assert page.locator('.message-row[data-selected="true"]').count() == 0
            page.go_back(wait_until="networkidle")
            body()
            assert page.locator('.message-row[data-selected="true"]').count() == 1
            page.reload(wait_until="networkidle")
            body()
            checks.append("paging keeps an off-page reader with a locate link; Back and reload restore current context")

            page.locator(".mail-search-disclosure > summary").click()
            page.get_by_label("Search query", exact=True).fill("reader-fixture")
            page.get_by_role("button", name="Search", exact=True).click()
            page.wait_for_load_state("networkidle")
            state(q="reader-fixture", selected_uid="125", selected_mailbox="INBOX")
            body()
            visit("/search?q=reader-fixture&scope=all&selected_mailbox=Sent&selected_uid=125&page=3")
            body(125, "Sent")
            assert page.locator('.message-row[data-selected="true"] .message-mailbox').inner_text() == "Sent"
            page.get_by_label("Search query", exact=True).fill("reader-miss")
            page.get_by_role("button", name="Search", exact=True).click()
            page.wait_for_load_state("networkidle")
            assert page.get_by_role("heading", name="Message unavailable", exact=True).is_visible()
            assert page.locator(".body-panel").count() == 0
            checks.append("search preserves matching selection, distinguishes identical UIDs across folders, and removes an excluded body")

            page.get_by_role("link", name="Inbox", exact=True).click()
            page.wait_for_load_state("networkidle")
            assert "selected_uid" not in parse_qs(urlsplit(page.url).query)
            assert page.locator(".body-panel").count() == 0
            checks.append("folder navigation clears selection and cannot keep the previous folder body")

            selected_path = "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=125"
            visit(selected_path)
            visit("/settings")
            page.locator(".account-menu summary").click()
            page.get_by_role("button", name="Log Out", exact=True).click()
            page.wait_for_url(origin + "/login")
            login("bob")
            found_history = False
            for _ in range(7):
                if page.go_back(wait_until="networkidle") is None:
                    break
                if "selected_uid=125" in page.url:
                    body(account="bob")
                    assert "for alice@example.com." not in page.locator("main").inner_text()
                    found_history = True
                    break
            assert found_history, "selected history entry was not reached"
            visit(selected_path)
            body(account="bob")
            checks.append("logout/login and browser history rebind the reader to the current synthetic account without showing the old body")

            page.set_viewport_size({"width": 360, "height": 900})
            visit(selected_path)
            body(account="bob")
            assert not page.locator(".coordinated-list").is_visible()
            assert page.locator(".body-panel pre").bounding_box()["y"] < 900
            page.locator("#reading-pane").focus()
            page.keyboard.press("Tab")
            assert page.locator(":focus").inner_text() == "Back to list"
            with page.expect_navigation(wait_until="networkidle"):
                page.keyboard.press("Enter")
            assert page.locator(".coordinated-list").is_visible()
            assert "selected_uid" not in parse_qs(urlsplit(page.url).query)
            assert page.locator(".body-panel").count() == 0
            checks.append("narrow reader prioritizes the body and provides a working keyboard Back to list without hidden list controls in focus order")
            assert not blocked
            report = {"synthetic": True, "browser_version": browser.version, "engine": args.engine,
                      "checks": checks, "outside_requests": 0, "passed": True,
                      "scope": "real local router; public synthetic gateway, not live mail authentication"}
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            context.close()
            browser.close()
            if process.poll() is None:
                stop_server(process, root)
    print(json.dumps({"passed": True, "checks": len(checks)}))


if __name__ == "__main__":
    main()
