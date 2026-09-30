#!/usr/bin/env python3
"""Exercise reversible identity-bound moves against the real loopback router.

Only synthetic account/mail state is used. Form values stay in memory; evidence
contains public workflow descriptions and pass/fail, never cookies or tokens.
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
    checks, blocked = [], []
    with tempfile.TemporaryDirectory(prefix="osmap-ux-moves-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        process, origin = start_server(root, Path(__file__).resolve().parents[2], log)
        browser = getattr(playwright, args.engine).launch(executable_path=args.browser, headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 1000}, user_agent="OSMAP/ManyMessages")

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

        def login(account):
            visit("/login")
            page.get_by_label("Username or Email").fill(account + "@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            page.get_by_role("button", name="Sign In", exact=True).click()
            page.wait_for_url(origin + "/mailboxes")

        def press(name):
            with page.expect_navigation(wait_until="networkidle") as navigation:
                page.get_by_role("button", name=name, exact=True).click()
            assert navigation.value.status == 200

        def reader(uid, mailbox="INBOX", query=""):
            visit(f"/mailbox?name={mailbox}&selected_mailbox={mailbox}&selected_uid={uid}{query}")
            page.locator(".reader-more-actions summary").click()
            assert page.locator(".message-move-controls").is_visible()

        try:
            login("alice")
            reader(123, query="&filter=unread&sort=subject&dir=desc")
            old_form = page.locator(".message-move-controls").evaluate("e => Object.fromEntries(new FormData(e))")
            old_form["action"] = "archive"
            press("Archive Message")
            query = parse_qs(urlsplit(page.url).query)
            assert query["filter"] == ["unread"] and query["sort"] == ["subject"]
            assert "selected_uid" not in query and "select" not in query
            assert "of 62 messages" in page.locator("main").inner_text()
            repeated = context.request.post(origin + "/message/move", form=old_form, headers={"Origin": origin}, max_redirects=0)
            assert repeated.status == 409 and "may have completed" not in repeated.text()
            checks.append("archive uses the native form, refreshes filtered counters, clears selection and refuses replay without another mutation")

            reader(122)
            press("Move to Bin")
            visit("/mailbox?name=Trash")
            link = page.get_by_role("link", name="Message 122", exact=True).first
            trashed_uid = parse_qs(urlsplit(link.get_attribute("href")).query)["selected_uid"][0]
            assert int(trashed_uid) > 125
            reader(trashed_uid, "Trash")
            assert page.locator("#message-title").inner_text() == "Message 122"
            press("Restore to Inbox")
            visit("/mailbox?name=INBOX")
            restored = page.get_by_role("link", name="Message 122", exact=True)
            assert restored.count() == 1
            restored_uid = parse_qs(urlsplit(restored.get_attribute("href")).query)["selected_uid"][0]
            assert restored_uid != trashed_uid and int(restored_uid) > 125
            checks.append("bin and restore preserve the message while following fresh stored identities and new mailbox UIDs")

            page.locator(".bulk-selection-menu summary").click()
            page.get_by_role("link", name="Select first 10 on this page", exact=True).click()
            page.wait_for_load_state("networkidle")
            selected = page.locator('input[form="bulk-move-form"]:checked')
            assert selected.count() == 10
            chosen = selected.evaluate_all("es => es.map(e => e.name)")
            page.locator(".bulk-actions summary").click()
            press("Move Selected to Bin")
            assert "of 114 messages" in page.locator("main").inner_text()
            assert page.locator('input[type="checkbox"]:checked').count() == 0
            for name in chosen:
                assert page.locator(f'input[name="{name}"]').count() == 0
            checks.append("one visible checkbox group supports a bounded ten-message bin action and fresh counters without retaining old selection")

            # Narrow keyboard action and server-side state survive full navigation.
            page.set_viewport_size({"width": 360, "height": 900})
            reader(110)
            control = page.get_by_role("button", name="Move to Bin", exact=True)
            control.focus()
            with page.expect_navigation(wait_until="networkidle"):
                page.keyboard.press("Enter")
            assert page.locator(".coordinated-list").is_visible()
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
            checks.append("narrow keyboard bin action returns to the visible refreshed list without horizontal overflow")

            # Alice's stored generation cannot authorize Bob's corresponding UID.
            page.locator(".account-menu summary").click()
            press("Log Out")
            login("bob")
            reader(123)
            bob_form = page.locator(".message-move-controls").evaluate("e => Object.fromEntries(new FormData(e))")
            bob_form.update(action="archive", mailbox_guid=old_form["mailbox_guid"], message_guid=old_form["message_guid"])
            denied = context.request.post(origin + "/message/move", form=bob_form, headers={"Origin": origin}, max_redirects=0)
            assert denied.status == 409
            visit("/mailbox?name=INBOX")
            assert "of 125 messages" in page.locator("main").inner_text()
            checks.append("account switching cannot reuse another account's stored message generation")
            assert not blocked
            report = {"synthetic": True, "native_mail_qualification": False, "passed": len(checks), "checks": checks,
                      "engine": args.engine, "browser_version": browser.version, "external_requests": len(blocked)}
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps({"passed": len(checks), "engine": args.engine}))
        finally:
            context.close()
            browser.close()
            stop_server(process, root)


if __name__ == "__main__":
    main()
