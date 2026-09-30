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
            page.locator(".message-sort summary").click()
            page.get_by_role("link", name="Sort by Subject ascending", exact=True).click()
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
            visit("/mailbox?name=INBOX&sort=subject&dir=asc")
            choice = page.get_by_label("Select message #7", exact=True)
            assert choice.is_visible()
            choice.focus()
            page.keyboard.press("Space")
            assert page.locator("#bulk-move-form").evaluate("e => new FormData(e).get('message_7').startsWith('7|')")
            assert page.locator("#bulk-archive-form").count() == 0
            assert page.locator("form form").count() == 0
            assert page.get_by_role("list", name="Mailbox message list", exact=True).get_by_role("listitem").count() == 50
            checks.append("visible keyboard checkboxes associate one identity-bound selection with the shared native action form")
            visit("/mailbox?name=INBOX&page=2")
            page.locator(".bulk-selection-menu summary").click()
            click("Select first 10 on this page")
            selected = page.locator('input[form="bulk-move-form"]:checked')
            assert selected.evaluate_all("es => es.map(e => e.value.split('|')[0])") == [str(uid) for uid in range(75, 65, -1)]
            assert page.locator('input[type="checkbox"]:checked').count() == 10
            state(page="2", select="move")
            page.locator(".bulk-selection-menu summary").click()
            click("Clear selection")
            assert page.locator('input[type="checkbox"]:checked').count() == 0
            page.locator(".bulk-selection-menu summary").click()
            click("Select first 10 on this page")
            click("Next page")
            assert page.locator('input[type="checkbox"]:checked').count() == 0
            checks.append("select menu checks only ten current-page identities for the shared action form; clear and page changes remove selection")
            visit("/mailbox?name=INBOX")
            previews = page.locator(".message-body-preview").all_text_contents()
            assert previews[0].startswith("<b>Untrusted synthetic preview</b>")
            assert previews[1] == "No preview available"
            assert page.locator(".message-body-preview b").count() == 0
            assert page.locator('.message-avatar[aria-hidden="true"]').count() == 50
            checks.append("untrusted preview markup stays text; unavailable previews and decorative initials are explicit")
            menu = page.locator(".global-search-menu summary")
            menu.focus()
            page.keyboard.press("Enter")
            assert page.get_by_label("Search all mail", exact=True).is_visible()
            assert page.get_by_role("navigation", name="Mail shortcuts", exact=True).get_by_role("link").count() == 7
            page.locator(".account-menu summary").click()
            assert page.locator(".global-search-menu").get_attribute("open") is None
            menu.click()
            assert page.locator(".account-menu").get_attribute("open") is None
            page.get_by_label("Search all mail", exact=True).fill("searchsort")
            page.get_by_role("button", name="Search mail", exact=True).click()
            page.wait_for_load_state("networkidle")
            state(q="searchsort", scope="all")
            assert len(subjects()) == 3
            page.locator(".global-search-menu summary").click()
            click("Open Inbox")
            state(name="INBOX")
            visit("/settings")
            assert page.locator(".global-search-menu").count() == 0
            checks.append("keyboard global search submits literal search with all-mail scope; finite shortcuts and mutually exclusive menus work")
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
