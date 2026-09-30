#!/usr/bin/env python3
"""Exercise private contacts and compose through real loopback forms and storage."""
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
    with tempfile.TemporaryDirectory(prefix="osmap-ux-contacts-") as temporary, \
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
            assert response and response.status == status, path
            assert response.headers["cache-control"] == "no-store"
            assert page.locator("script, main img, main iframe, main object").count() == 0

        def login(page, who):
            visit(page, "/login")
            page.get_by_label("Username or Email").fill(who + "@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            page.get_by_role("button", name="Sign In", exact=True).click()
            page.wait_for_url(origin + "/mailboxes")

        def add(page, name, address):
            visit(page, "/contacts")
            page.get_by_label("Display name (optional)").fill(name)
            page.get_by_label("Email address", exact=True).fill(address)
            page.get_by_role("button", name="Save contact", exact=True).click()
            page.wait_for_load_state("networkidle")
            assert page.get_by_role("heading", name="Saved contacts", exact=True).is_visible()
            assert address in page.locator(".contact-list").inner_text()

        try:
            owned = context()
            page = owned.new_page()
            login(page, "alice")
            add(page, "Desk <Public>", "desk@example.test")
            assert page.locator(".contact-list strong").inner_text() == "Desk <Public>"
            page.get_by_role("link", name="Edit", exact=True).click()
            page.wait_for_load_state("networkidle")
            second = owned.new_page()
            add(second, "Private recipient", "private@example.test")
            page.get_by_label("Display name (optional)").fill("Stale name")
            with page.expect_navigation() as stale:
                page.get_by_role("button", name="Save contact", exact=True).click()
            assert stale.value.status == 409
            assert page.get_by_label("Display name (optional)").input_value() == "Stale name"
            assert "Desk <Public>" in page.locator(".contact-list").inner_text()
            checks.append("contact create/escape/edit uses real storage; stale edit refuses without overwriting and retains typed values")

            visit(page, "/compose")
            page.get_by_label("To", exact=True).fill("original@example.test")
            page.get_by_label("Subject", exact=True).fill("Synthetic contact draft")
            page.get_by_label("Body", exact=True).fill("Public synthetic authoring text")
            page.locator(".compose-contacts summary").click()
            page.get_by_label("Saved contact", exact=True).select_option(index=1)
            page.get_by_label("Add contact to", exact=True).select_option("to")
            page.get_by_label("Add attachments", exact=True).set_input_files(
                {"name": "synthetic.txt", "mimeType": "text/plain", "buffer": b"synthetic attachment"})
            page.get_by_role("button", name="Add contact and save draft", exact=True).click()
            page.wait_for_url(origin + "/draft?id=*")
            assert page.get_by_label("To", exact=True).input_value() == "original@example.test, desk@example.test"
            assert "1 stored attachment" in page.locator(".compose-attachments").inner_text()
            assert page.get_by_label("Body", exact=True).input_value() == "Public synthetic authoring text"
            page.screenshot(path=str(args.output / "compose-saved-light-1600.png"), full_page=True)
            checks.append("explicit To selection saves the complete draft and uploaded attachment without submission")

            for target in ["cc", "bcc"]:
                page.locator(".compose-contacts summary").click()
                page.get_by_label("Saved contact", exact=True).select_option(index=2)
                page.get_by_label("Add contact to", exact=True).select_option(target)
                page.get_by_role("button", name="Add contact and save draft", exact=True).click()
                page.wait_for_load_state("networkidle")
                assert page.get_by_label(target.capitalize(), exact=True).input_value() == "private@example.test"
            checks.append("Cc and Bcc selections persist in their requested roles while existing uploads and text remain")

            page.locator("#compose-expanded").focus()
            page.keyboard.press("Space")
            assert page.locator("#compose-expanded").is_checked()
            assert page.locator(".compose-shell").evaluate("e => getComputedStyle(e).position") == "fixed"
            page.keyboard.press("Space")
            assert not page.locator("#compose-expanded").is_checked()
            page.get_by_role("button", name="− Minimize", exact=True).click()
            page.wait_for_url(origin + "/drafts")
            assert "Synthetic contact draft" in page.locator("main").inner_text()
            assert "private@example.test" not in page.locator("main").inner_text()
            page.screenshot(path=str(args.output / "drafts-light-1600.png"), full_page=True)
            page.locator(".draft-discard summary").click()
            page.get_by_role("link", name="Resume", exact=True).click()
            page.wait_for_load_state("networkidle")
            assert page.get_by_label("Body", exact=True).input_value() == "Public synthetic authoring text"
            checks.append("keyboard Expand/Restore keeps form values; Minimize saves then returns to Drafts; resume retains text and hides Bcc in listing")

            page.locator(".compose-contacts summary").click()
            with page.expect_popup() as popup:
                page.get_by_role("link", name="Manage contacts in a new tab", exact=True).click()
            manager = popup.value
            manager.wait_for_load_state("networkidle")
            add(manager, "New contact", "new@example.test")
            manager.close()
            page.get_by_label("Saved contact", exact=True).select_option(index=1)
            with page.expect_navigation() as stale_selection:
                page.get_by_role("button", name="Add contact and save draft", exact=True).click()
            assert stale_selection.value.status == 409
            assert "Your contacts changed" in page.get_by_role("alert").inner_text()
            assert page.get_by_label("Body", exact=True).input_value() == "Public synthetic authoring text"
            checks.append("manage-in-new-tab preserves authoring; changed contact revision refuses stale selection and retains text")

            for scheme in ["light", "dark"]:
                page.emulate_media(color_scheme=scheme)
                for width in [360, 768, 1600]:
                    page.set_viewport_size({"width": width, "height": 1100})
                    page.screenshot(path=str(args.output / f"compose-{scheme}-{width}.png"), full_page=True)
                    overflow = page.evaluate("""() => [...document.querySelectorAll('body *')].filter(e => {
                      const b=e.getBoundingClientRect(); return b.width && (b.right>innerWidth+1 || b.left < -1)
                    }).map(e=>({tag:e.tagName,classes:e.className,width:e.getBoundingClientRect().width,right:e.getBoundingClientRect().right})).slice(0,20)""")
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), (scheme, width, overflow)
            checks.append("composer reflows at 360/768/1600 in light and dark without horizontal overflow")

            other = context()
            other_page = other.new_page()
            login(other_page, "bob")
            visit(other_page, "/contacts")
            assert "No contacts saved yet" in other_page.locator("main").inner_text()
            assert "desk@example.test" not in other_page.locator("main").inner_text()
            visit(other_page, "/compose")
            assert other_page.get_by_label("Saved contact", exact=True).count() == 0
            other.close()
            checks.append("other synthetic account cannot list or select the first account's contacts")

            owned.close()
            stop_server(process, root)
            process, origin = start_server(root, repo, log)
            owned = context()
            page = owned.new_page()
            login(page, "alice")
            visit(page, "/contacts")
            assert page.locator(".contact-list li").count() == 3
            page.screenshot(path=str(args.output / "contacts-light-1600.png"), full_page=True)
            page.get_by_role("link", name="Remove", exact=True).first.click()
            page.wait_for_load_state("networkidle")
            assert page.get_by_role("heading", name="Remove this contact?", exact=True).is_visible()
            assert page.locator(".contact-list li").count() == 3
            page.get_by_role("button", name="Remove contact", exact=True).click()
            page.wait_for_load_state("networkidle")
            assert page.locator(".contact-list li").count() == 2
            checks.append("contacts survive process restart; GET confirmation is read-only and explicit POST removes only the selected entry")
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
