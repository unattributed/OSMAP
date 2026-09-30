#!/usr/bin/env python3
"""Verify native list navigation against the real router and synthetic mail.

No real authentication, mail host or mutation backend is used. All browser
requests are restricted to the disposable loopback fixture server. Output is
boolean assertions and fixture labels, never browser storage or tokens.
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
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks = []
    with tempfile.TemporaryDirectory(prefix="osmap-ux-lists-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        process, origin = start_server(root, repo, log)
        browser = playwright.chromium.launch(executable_path=args.browser, headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 900},
                                      user_agent="OSMAP/ManyMessages", color_scheme="light")
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
            assert response and response.ok, path
            assert page.locator("script").count() == 0

        def click(name):
            page.get_by_role("link", name=name, exact=True).click()
            page.wait_for_load_state("networkidle")

        def subjects():
            return page.locator(".message-subject-link").all_text_contents()

        def state(**expected):
            query = parse_qs(urlsplit(page.url).query)
            for name, value in expected.items():
                assert query.get(name) == [value], name

        try:
            visit("/login")
            page.get_by_label("Username or Email").fill("alice@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            page.get_by_role("button", name="Sign In", exact=True).click()
            page.wait_for_url(origin + "/mailboxes")
            visit("/mailbox?name=INBOX")
            assert subjects() == [f"Message {uid:03}" for uid in range(125, 75, -1)]
            click("Next page")
            assert subjects() == [f"Message {uid:03}" for uid in range(75, 25, -1)]
            click("Next page")
            assert subjects() == [f"Message {uid:03}" for uid in range(25, 0, -1)]
            assert page.get_by_role("link", name="Next page", exact=True).count() == 0
            click("Previous page")
            state(page="2", sort="received", dir="desc")
            page.go_back(wait_until="networkidle")
            state(page="3")
            checks.append("125 messages have stable non-overlapping 50/50/25 pages and browser history")
            click("Unread")
            assert subjects() == [f"Message {uid:03}" for uid in range(125, 26, -2)]
            assert "page" not in parse_qs(urlsplit(page.url).query)
            click("Next page")
            assert subjects() == [f"Message {uid:03}" for uid in range(25, 0, -2)]
            click("Starred")
            assert len(subjects()) == 17
            assert page.get_by_role("link", name="Next page", exact=True).count() == 0
            page.get_by_role("columnheader").filter(has_text="Subject").get_by_role("link").click()
            page.wait_for_load_state("networkidle")
            state(filter="starred", sort="subject", dir="asc")
            assert subjects()[0] == "Message 007"
            page.reload(wait_until="networkidle")
            assert subjects()[0] == "Message 007"
            checks.append("unread/star filters use flags, reset pages, retain sorting and survive reload")
            visit("/mailbox?name=INBOX&filter=starred&selected_mailbox=INBOX&selected_uid=7")
            assert page.locator('.message-row[data-selected="true"]').count() == 1
            visit("/mailbox?name=Sent&filter=starred&selected_mailbox=INBOX&selected_uid=7")
            assert page.locator('.message-row[data-selected="true"]').count() == 0
            checks.append("selected row requires matching mailbox and UID")
            visit("/search?q=searchsort&scope=all&field=from&filter=starred&sort=subject&dir=asc")
            assert subjects() == ["Search Zulu"]
            page.get_by_role("button", name="Search", exact=True).click()
            page.wait_for_load_state("networkidle")
            state(q="searchsort", scope="all", field="from", filter="starred", sort="subject", dir="asc")
            assert subjects() == ["Search Zulu"]
            checks.append("search form preserves query, scope, field, filter and sorting")
            visit("/search?q=manyresults&page=2")
            assert len(subjects()) == 50
            assert "Showing 51–100 of 250" in page.locator("main").inner_text()
            click("Next page")
            state(q="manyresults", page="3")
            assert len(subjects()) == 50
            checks.append("search results paginate within the existing 250-result backend limit")
            assert not blocked, "fixture attempted outside requests"
            report = {"synthetic": True, "authentication": "test fixture; not live Dovecot/TOTP",
                      "mail": "deterministic in-memory gateway; no mailbox mutation",
                      "browser_version": browser.version, "checks": checks,
                      "outside_requests": 0, "passed": True}
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            context.close()
            browser.close()
            if process.poll() is None:
                stop_server(process, root)
    print(json.dumps({"passed": True, "checks": len(checks)}))


if __name__ == "__main__":
    main()
