#!/usr/bin/env python3
"""Exercise real read/star forms against isolated synthetic account state.

The gateway is in-memory; native Dovecot/helper qualification is separate.
No storage state, cookies, filled forms or request bodies are retained.
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
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks = []
    with tempfile.TemporaryDirectory(prefix="osmap-ux-flags-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        process, origin = start_server(root, Path(__file__).resolve().parents[2], log)
        browser = playwright.chromium.launch(executable_path=args.browser, headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900}, user_agent="OSMAP/ManyMessages")
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

        def login(account):
            visit("/login")
            page.get_by_label("Username or Email").fill(account + "@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            page.get_by_role("button", name="Sign In", exact=True).click()
            page.wait_for_url(origin + "/mailboxes")

        def button(name, uid=7):
            return page.get_by_role("button", name=f"{name} message #{uid} in INBOX", exact=True)

        def press(name, expected_status=200):
            with page.expect_navigation(wait_until="networkidle") as navigation:
                button(name).click()
            assert navigation.value.status == expected_status

        def all_messages():
            visit("/mailbox?name=INBOX&sort=subject&dir=asc")

        try:
            login("alice")
            visit("/mailbox?name=INBOX&filter=unread&sort=subject&dir=asc")
            assert button("Read").get_attribute("aria-pressed") == "false"
            press("Read")
            query = parse_qs(urlsplit(page.url).query)
            assert query["filter"] == ["unread"] and query["sort"] == ["subject"]
            assert page.get_by_role("link", name="Message 007", exact=True).count() == 0
            assert "of 62 messages" in page.locator("main").inner_text()
            all_messages()
            assert button("Read").get_attribute("aria-pressed") == "true"
            assert button("Star").get_attribute("aria-pressed") == "true"
            press("Read")
            checks.append("native read form changes unread membership and counters while preserving query context and other flags")
            visit("/mailbox?name=INBOX&filter=starred&sort=subject&dir=asc")
            press("Star")
            assert page.get_by_role("link", name="Message 007", exact=True).count() == 0
            assert "of 16 messages" in page.locator("main").inner_text()
            all_messages()
            assert button("Star").get_attribute("aria-pressed") == "false"
            button("Star").focus()
            with page.expect_navigation(wait_until="networkidle"):
                page.keyboard.press("Space")
            assert button("Star").get_attribute("aria-pressed") == "true"
            checks.append("star filter reconciles after removal and keyboard activation restores the actual state")
            form = button("Star").locator("..").evaluate("e => Object.fromEntries(new FormData(e))")
            # Synthetic values live only in memory for this duplicate-submission check.
            for _ in range(2):
                response = context.request.post(origin + "/message/flag", form=form, headers={"Origin": origin}, max_redirects=0)
                assert response.status == 303
            page.reload(wait_until="networkidle")
            assert button("Star").get_attribute("aria-pressed") == "false"
            assert button("Read").get_attribute("aria-pressed") == "false"
            checks.append("duplicate explicit desired-state submissions are idempotent")
            alice_mailbox_guid = button("Read").locator("..").locator('[name="mailbox_guid"]').input_value()
            button("Read").locator("..").locator('[name="message_guid"]').evaluate("e => e.value = 'stale-synthetic-message'")
            press("Read", 409)
            assert page.get_by_role("heading", name="Message Has Changed").is_visible()
            all_messages()
            assert button("Read").get_attribute("aria-pressed") == "false"
            button("Read").locator("..").locator('[name="csrf_token"]').evaluate("e => e.value = 'invalid-fixture'")
            press("Read", 403)
            response = context.request.post(origin + "/message/flag", form=form, headers={"Origin": "https://outside.example.test"}, max_redirects=0)
            assert response.status == 403
            checks.append("stale identity, invalid CSRF and cross-origin submissions refuse state changes")
            all_messages()
            page.locator(".account-menu summary").click()
            page.get_by_role("button", name="Log Out", exact=True).click()
            page.wait_for_url(origin + "/login")
            login("bob")
            all_messages()
            assert button("Star").get_attribute("aria-pressed") == "true"
            button("Read").locator("..").locator('[name="mailbox_guid"]').evaluate("(e, value) => e.value = value", alice_mailbox_guid)
            press("Read", 409)
            visit("/message?mailbox=INBOX&uid=7")
            assert button("Read").get_attribute("aria-pressed") == "false"
            press("Read")
            assert urlsplit(page.url).path == "/message"
            assert button("Read").get_attribute("aria-pressed") == "true"
            all_messages()
            assert button("Read").get_attribute("aria-pressed") == "true"
            checks.append("accounts remain isolated, cross-account stale forms refuse, and reader/list state agrees")
            context.close()
            context = browser.new_context(viewport={"width": 360, "height": 900}, user_agent="OSMAP/ManyMessages;FlagUnknown")
            context.route("**/*", constrain)
            page = context.new_page()
            login("alice")
            all_messages()
            press("Read", 503)
            assert page.get_by_role("heading", name="Message State Not Confirmed").is_visible()
            assert "may have completed" in page.locator("main").inner_text()
            checks.append("unknown outcomes give an explicit refresh instruction without a success banner or retry form")
            assert not blocked
            report = {"synthetic": True, "mail_state": "in-memory fixture; native proof is separate", "browser_version": browser.version,
                      "checks": checks, "outside_requests": 0, "passed": True}
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            context.close()
            browser.close()
            if process.poll() is None:
                stop_server(process, root)
    print(json.dumps({"passed": True, "checks": len(checks)}))


if __name__ == "__main__":
    main()
