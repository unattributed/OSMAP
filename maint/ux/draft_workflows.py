#!/usr/bin/env python3
"""Exercise unfinished drafts, stale forms and restart with real private storage.

Uses only the bounded synthetic loopback gateway. No email is submitted to a
mail server. Browser profiles, form tokens and synthetic draft files are erased.
"""
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
    with tempfile.TemporaryDirectory(prefix="osmap-ux-drafts-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        repo = Path(__file__).resolve().parents[2]
        process, origin = start_server(root, repo, log)
        browser = getattr(playwright, args.engine).launch(executable_path=args.browser, headless=True)

        def context():
            result = browser.new_context(viewport={"width": 1600, "height": 1100}, color_scheme="light")

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
            assert response and response.status == status, (path, response.status if response else None)
            assert response.headers["cache-control"] == "no-store"

        def click(page, name, status=200):
            with page.expect_navigation(wait_until="networkidle") as navigation:
                page.get_by_role("button", name=name, exact=True).click()
            assert navigation.value.status == status, (name, navigation.value.status)

        def login(page, who):
            visit(page, "/login")
            page.get_by_label("Username or Email").fill(who + "@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            click(page, "Sign In")

        def upload(page, filename):
            page.get_by_label("Add attachments", exact=True).set_input_files(
                {"name": filename, "mimeType": "text/plain", "buffer": b"public synthetic attachment"})

        try:
            owned = context()
            page = owned.new_page()
            login(page, "alice")
            visit(page, "/compose")
            click(page, "Save Draft")
            assert "/draft?id=" in page.url
            saved_path = page.url.removeprefix(origin)
            assert page.get_by_label("Body", exact=True).input_value() == ""
            page.get_by_label("To", exact=True).fill("  Still choosing <unfinished@")
            page.get_by_label("Body", exact=True).fill("Unfinished notes — public synthetic text")
            upload(page, "first.txt")
            click(page, "Save Draft")
            assert page.get_by_label("To", exact=True).input_value() == "  Still choosing <unfinished@"
            assert "1 stored attachment" in page.locator(".compose-attachments").inner_text()
            upload(page, "second.txt")
            click(page, "Save Draft")
            assert "2 stored attachment" in page.locator(".compose-attachments").inner_text()
            checks.append("blank and partial-address drafts save; two successive uploads retain both files")

            older = owned.new_page()
            visit(older, saved_path)
            stale_list = owned.new_page()
            visit(stale_list, "/drafts")
            page.get_by_label("Body", exact=True).fill("Newer saved version")
            click(page, "Save Draft")
            older.get_by_label("Body", exact=True).fill("Older tab unsaved text")
            upload(older, "unsaved-third.txt")
            click(older, "Save Draft", 409)
            assert older.get_by_label("Body", exact=True).input_value() == "Older tab unsaved text"
            assert "changed in another tab" in older.get_by_role("alert").inner_text()
            assert "Re-select any new uploads" in older.locator("main").inner_text()
            with older.expect_popup() as popup:
                older.get_by_role("link", name="Open saved version in a new tab", exact=True).click()
            latest = popup.value
            latest.wait_for_load_state("networkidle")
            assert latest.get_by_label("Body", exact=True).input_value() == "Newer saved version"
            assert "2 stored attachment" in latest.locator(".compose-attachments").inner_text()
            latest.close()
            click(older, "Send Message", 409)
            assert older.get_by_label("Body", exact=True).input_value() == "Older tab unsaved text"
            stale_list.locator(".draft-discard summary").click()
            click(stale_list, "Delete", 409)
            checks.append("stale Save, Send and Discard refuse; posted text remains and comparison opens separately")

            for scheme in ["light", "dark"]:
                older.emulate_media(color_scheme=scheme)
                for width in [360, 768, 1600]:
                    older.set_viewport_size({"width": width, "height": 1100})
                    older.screenshot(path=str(args.output / f"conflict-{scheme}-{width}.png"), full_page=True)
                    assert older.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
            checks.append("conflict form reflows at 360/768/1600 in light and dark")
            page.get_by_label("To", exact=True).fill("")
            click(page, "− Minimize")
            assert page.url == origin + "/drafts"
            assert page.locator(".draft-list tbody tr").count() == 1
            assert "(No subject)" in page.locator(".draft-list").inner_text()
            assert "Draft deleted." not in page.locator("main").inner_text()
            checks.append("Minimize saves incomplete text and returns to the truthful draft list")

            other = context()
            other_page = other.new_page()
            login(other_page, "bob")
            visit(other_page, saved_path, 404)
            visit(other_page, "/drafts")
            assert "No saved drafts" in other_page.locator("main").inner_text()
            other.close()
            checks.append("another account cannot resume or list the saved draft")

            owned.close()
            stop_server(process, root)
            process, origin = start_server(root, repo, log)
            owned = context()
            page = owned.new_page()
            login(page, "alice")
            visit(page, saved_path)
            assert page.get_by_label("Body", exact=True).input_value() == "Newer saved version"
            assert page.get_by_label("To", exact=True).input_value() == ""
            assert "2 stored attachment" in page.locator(".compose-attachments").inner_text()
            click(page, "Send Message", 400)
            assert page.get_by_label("Body", exact=True).input_value() == "Newer saved version"
            visit(page, "/drafts")
            assert page.locator(".draft-list tbody tr").count() == 1
            page.screenshot(path=str(args.output / "drafts-restarted-light-1600.png"), full_page=True)
            checks.append("process restart retains draft text and both files; incomplete Send refuses without deleting it")
            visit(page, "/compose")
            page.get_by_label("Body", exact=True).fill("Second draft after restart")
            click(page, "Save Draft")
            assert page.url != origin + saved_path
            visit(page, "/drafts")
            assert page.locator(".draft-list tbody tr").count() == 2
            page.locator(".draft-discard summary").first.click()
            click(page, "Delete")
            assert page.locator(".draft-list tbody tr").count() == 1
            checks.append("new draft after restart has a distinct identity; current explicit Discard removes one draft")
            owned.close()
            assert not blocked
            report = {"passed": True, "synthetic_only": True, "real_draft_store": True, "engine": args.engine,
                      "browser_version": browser.version, "outside_requests": len(blocked), "checks": checks}
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps({"passed": True, "checks": len(checks)}))
        finally:
            browser.close()
            stop_server(process, root)


if __name__ == "__main__":
    main()
