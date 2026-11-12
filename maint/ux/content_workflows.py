#!/usr/bin/env python3
"""Exercise source, downloads and recovery using synthetic loopback mail only."""
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
    blocked = []
    with tempfile.TemporaryDirectory(prefix="osmap-ux-content-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        process, origin = start_server(root, Path(__file__).resolve().parents[2], log)
        browser = getattr(playwright, args.engine).launch(executable_path=args.browser, headless=True)

        def context(ua):
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
            ordinary = context("OSMAP/SourceLong")
            page = ordinary.new_page()
            login(page, "alice")
            reader = "/mailbox?name=INBOX&sort=subject&dir=asc&selected_mailbox=INBOX&selected_uid=9"
            visit(page, reader)
            source_link = page.get_by_role("link", name="View source", exact=True)
            source_url = source_link.get_attribute("href")
            assert "mailbox_guid=" in source_url and "message_guid=" in source_url
            source_link.focus()
            with page.expect_navigation(wait_until="networkidle"):
                page.keyboard.press("Enter")
            assert page.get_by_role("heading", name="Message source", exact=True).is_visible()
            source = page.get_by_label("Stored message source", exact=True)
            assert "<script>inert-source-marker</script>" in source.inner_text()
            assert "https://example.test/blocked" in source.inner_text()
            assert page.locator("main script, main img, main a[href^='https:']").count() == 0
            assert page.locator("main form").count() == 0
            page.get_by_role("link", name="Back to message", exact=True).click()
            page.wait_for_load_state("networkidle")
            query = parse_qs(urlsplit(page.url).query)
            assert query["selected_uid"] == ["9"] and query["sort"] == ["subject"]
            checks.append("keyboard source view escapes stored MIME text and restores the coordinated reader context")

            with page.expect_download() as download_info:
                page.locator("#reading-pane .reader-attachments").get_by_role("link", name="Download", exact=True).first.click()
            download = download_info.value
            assert download.suggested_filename == "report.pdf"
            assert Path(download.path()).read_bytes() == b"%PDF-stub%"
            download.delete()
            assert parse_qs(urlsplit(page.url).query)["selected_uid"] == ["9"]
            for name, mode in [("Reply", "reply"), ("Forward", "forward")]:
                page.get_by_role("link", name=name, exact=True).click()
                page.wait_for_load_state("networkidle")
                assert parse_qs(urlsplit(page.url).query)["mode"] == [mode]
                assert page.get_by_role("button", name="Send Message", exact=True).is_visible()
                page.go_back(wait_until="networkidle")
            checks.append("bound attachment downloads the expected filename and bytes; reply and forward open compose without submission")

            page.set_viewport_size({"width": 360, "height": 900})
            visit(page, source_url)
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
            page.get_by_label("Stored message source").focus()
            assert page.locator(":focus").get_attribute("class") == "message-source"
            checks.append("narrow source wraps long stored lines and remains keyboard focusable")

            failing = context("OSMAP/SourceUnavailable")
            error_page = failing.new_page()
            login(error_page, "alice")
            visit(error_page, source_url, 503)
            retry = error_page.get_by_role("link", name="Retry loading", exact=True)
            assert retry.get_attribute("href").startswith("/message?")
            with error_page.expect_navigation(wait_until="networkidle") as retry_response:
                retry.click()
            assert retry_response.value.status == 503
            assert error_page.locator("main form").count() == 0
            failing.close()
            checks.append("temporary source failure offers only a read-only retry and contextual return")

            bob = context("OSMAP/SourceLong")
            bob_page = bob.new_page()
            login(bob_page, "bob")
            visit(bob_page, source_url, 409)
            assert bob_page.get_by_label("Stored message source").count() == 0
            assert "inert-source-marker" not in bob_page.locator("main").inner_text()
            bob.close()
            visit(page, reader)
            page.locator(".reader-more-actions summary").click()
            page.get_by_role("button", name="Move to Bin", exact=True).click()
            page.wait_for_load_state("networkidle")
            visit(page, source_url, 404)
            assert page.get_by_label("Stored message source").count() == 0
            checks.append("another account cannot reuse a source identity; moved messages invalidate old source links")
            ordinary.close()
            assert not blocked, "message source attempted an outside request"
            report = {"passed": True, "synthetic_only": True, "engine": args.engine,
                      "browser_version": browser.version, "outside_requests": len(blocked), "checks": checks}
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps({"passed": True, "checks": len(checks)}))
        finally:
            browser.close()
            stop_server(process, root)


if __name__ == "__main__":
    main()
