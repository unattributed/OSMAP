#!/usr/bin/env python3
"""Check compose identity/reply workflows against an in-memory loopback sink."""
import argparse
import json
from pathlib import Path
import tempfile

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
    with tempfile.TemporaryDirectory(prefix="osmap-ux-reply-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        process, origin = start_server(root, Path(__file__).resolve().parents[2], log)
        browser = getattr(playwright, args.engine).launch(executable_path=args.browser, headless=True)

        def context(ua="OSMAP/ReplyRecipients"):
            result = browser.new_context(viewport={"width": 1440, "height": 1000}, user_agent=ua)

            def constrain(route):
                if route.request.url.startswith(origin + "/"):
                    route.continue_()
                else:
                    blocked.append(route.request.resource_type)
                    route.abort()
            result.route("**/*", constrain)
            return result

        def visit(page, path, status=200):
            response = page.goto(origin + path, wait_until="networkidle")
            assert response and response.status == status
            assert response.headers["cache-control"] == "no-store"
            assert page.locator("main").count() == 1
            assert page.locator("script, main img, main iframe, main object").count() == 0

        def login(page, account):
            visit(page, "/login")
            page.get_by_label("Username or Email").fill(account + "@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            page.get_by_role("button", name="Sign In", exact=True).click()
            page.wait_for_url(origin + "/mailboxes")

        try:
            owned = context()
            page = owned.new_page()
            login(page, "alice")
            reader = "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=9"
            visit(page, reader)
            reply = page.get_by_role("link", name="Reply all", exact=True)
            source_url = reply.get_attribute("href")
            assert "mailbox_guid=" in source_url and "message_guid=" in source_url
            reply.focus()
            with page.expect_navigation(wait_until="networkidle"):
                page.keyboard.press("Enter")
            assert page.get_by_role("heading", name="Reply all", exact=True).is_visible()
            assert page.get_by_label("From", exact=True).input_value() == "alice@example.com"
            assert page.get_by_label("From", exact=True).get_attribute("readonly") is not None
            assert page.get_by_label("To", exact=True).input_value() == "desk@example.test, other@example.test"
            assert page.get_by_label("Cc", exact=True).input_value() == "copied@example.test"
            assert page.get_by_label("Bcc", exact=True).input_value() == ""
            assert "Hello world" in page.get_by_label("Body", exact=True).input_value()
            assert page.locator("input[name=reply_message_guid]").count() == 1
            assert page.locator("input[name=in_reply_to], input[name=references]").count() == 0
            checks.append("keyboard reply-all opens identity-bound compose with canonical sender, Reply-To, deduplicated To/Cc, self excluded and empty Bcc")

            page.get_by_label("Bcc", exact=True).fill("private@example.test")
            page.get_by_label("Subject", exact=True).fill("Synthetic saved reply")
            page.get_by_role("button", name="Save Draft", exact=True).click()
            page.wait_for_url(origin + "/draft?id=*")
            draft_url = page.url.removeprefix(origin)
            assert page.get_by_role("heading", name="Resume Draft", exact=True).is_visible()
            assert page.get_by_label("Bcc", exact=True).input_value() == "private@example.test"
            assert page.locator("input[name=reply_message_guid]").count() == 0
            visit(page, "/drafts")
            assert "private@example.test" not in page.locator("main").inner_text()
            page.get_by_role("link", name="Resume", exact=True).click()
            page.wait_for_load_state("networkidle")
            assert page.get_by_label("Subject", exact=True).input_value() == "Synthetic saved reply"
            assert page.get_by_label("Cc", exact=True).input_value() == "copied@example.test"
            checks.append("save/list/resume retains edited addressing and body; persisted threading stays server owned and draft listing excludes Bcc")

            for width in [360, 768, 1440]:
                page.set_viewport_size({"width": width, "height": 1000})
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
                page.get_by_label("To", exact=True).focus()
                assert page.locator(":focus").get_attribute("id") == "compose-to"
            page.get_by_label("To", exact=True).fill('"Desk, Reply" <desk@example.test>')
            page.get_by_role("button", name="Send Message", exact=True).click()
            page.wait_for_url(origin + "/compose?sent=1")
            visit(page, draft_url, 404)
            checks.append("responsive saved compose preserves keyboard focus and accepts a quoted display name for one synthetic sink submission")

            visit(page, reader)
            page.get_by_role("link", name="Forward", exact=True).click()
            page.wait_for_load_state("networkidle")
            assert page.get_by_label("To", exact=True).input_value() == ""
            assert page.locator("input[name=reply_message_guid]").count() == 0
            assert page.locator("input[name^=include_original_attachment_]:checked").count() == 0
            checks.append("forward begins with no recipients, no reply thread and no automatically selected source attachments")

            other = context()
            other_page = other.new_page()
            login(other_page, "bob")
            visit(other_page, source_url, 409)
            assert other_page.get_by_label("Body", exact=True).count() == 0
            other.close()
            checks.append("a reader link from another account cannot expose quoted content or produce a reply")
            owned.close()
            assert not blocked
            report = {"passed": True, "synthetic_only": True, "engine": args.engine,
                      "browser_version": browser.version, "outside_requests": len(blocked), "checks": checks}
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps({"passed": True, "checks": len(checks)}))
        finally:
            browser.close()
            stop_server(process, root)


if __name__ == "__main__":
    main()
