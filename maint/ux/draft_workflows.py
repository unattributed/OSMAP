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
    parser.add_argument("--no-script", action="store_true", help="exercise the complete native form fallback")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks, blocked = [], []
    with tempfile.TemporaryDirectory(prefix="osmap-ux-drafts-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as playwright:
        root = Path(temporary)
        repo = Path(__file__).resolve().parents[2]
        process, origin = start_server(root, repo, log)
        browser = getattr(playwright, args.engine).launch(executable_path=args.browser, headless=True)

        def context(ua=None):
            result = browser.new_context(viewport={"width": 1600, "height": 1100}, color_scheme="light", user_agent=ua,
                                         java_script_enabled=not args.no_script)

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
            assert page.get_by_label("Remove first.txt", exact=True).is_visible()
            assert page.get_by_label("Remove second.txt", exact=True).is_visible()
            checks.append("blank and partial-address drafts save; two successive uploads retain both files")

            older = owned.new_page()
            visit(older, saved_path)
            stale_list = owned.new_page()
            visit(stale_list, "/drafts")
            page.get_by_label("Body", exact=True).fill("Newer saved version")
            click(page, "Save Draft")
            older.get_by_label("Body", exact=True).fill("Older tab unsaved text")
            older.get_by_label("Remove first.txt", exact=True).check()
            upload(older, "unsaved-third.txt")
            click(older, "Save Draft", 409)
            assert older.get_by_label("Body", exact=True).input_value() == "Older tab unsaved text"
            assert "changed in another tab" in older.get_by_role("alert").inner_text()
            assert "Re-select any new uploads" in older.locator("main").inner_text()
            assert older.get_by_label("Remove saved file 1", exact=True).is_checked()
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
            removal = page.get_by_label("Remove first.txt", exact=True)
            removal.focus()
            removal.press("Space")
            assert removal.is_checked()
            click(page, "Send Message", 400)
            assert page.get_by_label("Body", exact=True).input_value() == "Newer saved version"
            assert page.get_by_label("Remove first.txt", exact=True).is_checked()
            assert page.get_by_label("Remove second.txt", exact=True).is_visible()
            upload(page, "replacement.txt")
            click(page, "Save Draft")
            assert page.get_by_label("Remove first.txt", exact=True).count() == 0
            assert page.get_by_label("Remove second.txt", exact=True).is_visible()
            assert page.get_by_label("Remove replacement.txt", exact=True).is_visible()
            assert page.get_by_label("Body", exact=True).input_value() == "Newer saved version"
            checks.append("keyboard removal survives refused Send; Save removes only that saved file and adds the replacement without losing text")
            for scheme in ["light", "dark"]:
                page.emulate_media(color_scheme=scheme)
                for width in [360, 768, 1600]:
                    page.set_viewport_size({"width": width, "height": 1100})
                    page.screenshot(path=str(args.output / f"saved-attachments-{scheme}-{width}.png"), full_page=True)
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
            visit(page, "/drafts")
            assert page.locator(".draft-list tbody tr").count() == 1
            page.screenshot(path=str(args.output / "drafts-restarted-light-1600.png"), full_page=True)
            checks.append("process restart retains draft text and saved files; incomplete Send refuses without deleting it")
            visit(page, "/compose")
            page.get_by_label("Subject", exact=True).fill("Alpha review")
            page.get_by_label("Body", exact=True).fill("Second draft after restart")
            click(page, "Save Draft")
            assert page.url != origin + saved_path
            alpha_path = page.url.removeprefix(origin)
            visit(page, "/drafts")
            assert page.locator(".draft-list tbody tr").count() == 2

            visit(page, "/compose")
            page.get_by_label("Subject", exact=True).fill("Zulu review")
            page.get_by_label("To", exact=True).fill("zulu@example.test")
            page.get_by_label("Body", exact=True).fill("Third public synthetic draft")
            click(page, "Save Draft")
            visit(page, "/drafts")

            def apply_view(filter_value="all", sort="subject", query=""):
                page.get_by_label("Draft filter", exact=True).select_option(filter_value)
                page.get_by_label("Draft order", exact=True).select_option(sort)
                page.get_by_label("Search drafts", exact=True).fill(query)
                click(page, "Apply")

            apply_view("attachments")
            assert page.locator(".draft-list tbody tr").count() == 1
            assert "(No subject)" in page.locator(".draft-list").inner_text()
            apply_view("no-attachments")
            assert page.locator(".draft-list tbody tr").count() == 2
            assert page.locator(".draft-subject>a").all_text_contents() == ["Alpha review", "Zulu review"]
            apply_view(query="ALPHA")
            assert page.locator(".draft-list tbody tr").count() == 1
            click(page, "Star draft")
            assert page.get_by_label("Search drafts", exact=True).input_value() == "ALPHA"
            assert page.get_by_role("button", name="Unstar draft", exact=True).get_attribute("aria-pressed") == "true"
            apply_view("starred")
            assert page.locator(".draft-subject>a").all_text_contents() == ["Alpha review"]
            apply_view(query="nothing matches this")
            assert "No drafts match these filters" in page.locator(".draft-list").inner_text()
            apply_view()
            assert "Showing 3 of 3 saved drafts" in page.locator(".draft-list-status").inner_text()
            checks.append("attachment/star filters, case-insensitive search, subject order, empty results and view-preserving Star use real saved state")
            for scheme in ["light", "dark"]:
                page.emulate_media(color_scheme=scheme)
                for width in [360, 768, 1600]:
                    page.set_viewport_size({"width": width, "height": 1100})
                    page.screenshot(path=str(args.output / f"draft-list-{scheme}-{width}.png"), full_page=True)
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
            checks.append("populated draft controls, stars and selection reflow at 360/768/1600 in light and dark")

            owned.close()
            stop_server(process, root)
            process, origin = start_server(root, repo, log)
            owned = context()
            page = owned.new_page()
            login(page, "alice")
            visit(page, saved_path)
            assert page.get_by_label("Remove first.txt", exact=True).count() == 0
            assert page.get_by_label("Remove second.txt", exact=True).is_visible()
            assert page.get_by_label("Remove replacement.txt", exact=True).is_visible()
            checks.append("attachment removal and replacement persist across a second process restart")
            visit(page, "/drafts?filter=starred&sort=subject&q=")
            assert page.locator(".draft-subject>a").all_text_contents() == ["Alpha review"]
            assert page.get_by_role("button", name="Unstar draft", exact=True).get_attribute("aria-pressed") == "true"
            checks.append("draft stars survive process restart with their saved content")
            apply_view()
            for subject in ["Alpha review", "Zulu review"]:
                page.get_by_label("Select draft: " + subject, exact=True).check()
            click(page, "Review discard")
            assert page.get_by_role("heading", name="Discard selected drafts?", exact=True).is_visible()
            assert page.locator(".draft-discard-review li").count() == 2
            page.get_by_role("link", name="Keep drafts", exact=True).click()
            page.wait_for_load_state("networkidle")
            assert page.locator(".draft-list tbody tr").count() == 3
            for subject in ["Alpha review", "Zulu review"]:
                page.get_by_label("Select draft: " + subject, exact=True).check()
            click(page, "Review discard")
            page.screenshot(path=str(args.output / "draft-discard-review-light-1600.png"), full_page=True)
            editor = owned.new_page()
            visit(editor, alpha_path)
            editor.get_by_label("Body", exact=True).fill("Changed while discard was being reviewed")
            click(editor, "Save Draft")
            editor.close()
            click(page, "Discard 2 drafts", 409)
            assert "0 of 2 selected drafts discarded" in page.locator("body").inner_text()
            page.get_by_role("link", name="Reload Drafts", exact=True).click()
            page.wait_for_load_state("networkidle")
            assert page.locator(".draft-list tbody tr").count() == 3
            for subject in ["Alpha review", "Zulu review"]:
                page.get_by_label("Select draft: " + subject, exact=True).check()
            click(page, "Review discard")
            click(page, "Discard 2 drafts")
            assert page.locator(".draft-list tbody tr").count() == 1
            assert "(No subject)" in page.locator(".draft-list").inner_text()
            checks.append("selection review is read-only, Cancel preserves drafts, stale confirmation discards none, fresh confirmation removes only the chosen pair")
            page.locator(".draft-discard summary").first.click()
            click(page, "Delete")
            assert "No saved drafts" in page.locator(".draft-list").inner_text()
            checks.append("new draft after restart has a distinct identity; current explicit Discard removes one draft")
            owned.close()
            uncertain = context("OSMAP/DraftSaveUnconfirmed")
            page = uncertain.new_page()
            login(page, "alice")
            visit(page, "/compose")
            page.get_by_label("To", exact=True).fill("still choosing")
            page.get_by_label("Body", exact=True).fill("Public notes from an unconfirmed save")
            upload(page, "uncertain.txt")
            click(page, "Save Draft", 503)
            assert "Save not confirmed" in page.get_by_role("alert").inner_text()
            assert page.get_by_label("Body", exact=True).input_value() == "Public notes from an unconfirmed save"
            for name in ["Save Draft", "Send Message", "− Minimize"]:
                assert page.get_by_role("button", name=name, exact=True).is_disabled()
            with page.expect_popup() as popup:
                page.get_by_role("link", name="Open saved version in a new tab", exact=True).click()
            recovered = popup.value
            recovered.wait_for_load_state("networkidle")
            assert recovered.get_by_label("Body", exact=True).input_value() == "Public notes from an unconfirmed save"
            assert recovered.get_by_label("Remove uncertain.txt", exact=True).is_visible()
            assert recovered.get_by_role("button", name="Save Draft", exact=True).is_enabled()
            recovered_path = recovered.url.removeprefix(origin)
            recovered.close()
            checks.append("unconfirmed Save preserves text, pauses all submission controls and opens the stored text and file in a separate comparison tab")
            for scheme in ["light", "dark"]:
                page.emulate_media(color_scheme=scheme)
                for width in [360, 768, 1600]:
                    page.set_viewport_size({"width": width, "height": 1100})
                    page.screenshot(path=str(args.output / f"save-unconfirmed-{scheme}-{width}.png"), full_page=True)
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
            uncertain.close()
            stop_server(process, root)
            process, origin = start_server(root, repo, log)
            owned = context()
            page = owned.new_page()
            login(page, "alice")
            visit(page, recovered_path)
            assert page.get_by_label("Remove uncertain.txt", exact=True).is_visible()
            page.get_by_label("Body", exact=True).fill("Reviewed after restart")
            click(page, "Save Draft")
            assert page.get_by_label("Body", exact=True).input_value() == "Reviewed after restart"
            visit(page, "/drafts")
            assert page.locator(".draft-list tbody tr").count() == 1
            checks.append("a later process reopens the unconfirmed save; editing its current revision succeeds without duplicating the draft")
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
