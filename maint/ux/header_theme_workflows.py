#!/usr/bin/env python3
"""Native account-theme and save-before-theme proof on synthetic local stores."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
import time
from urllib.parse import urlsplit, parse_qs, urlencode
from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    parser.add_argument("--engine", choices=["chromium", "firefox"], default="chromium")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.chmod(0o700)
    prior = [p for p in args.output.iterdir() if p.is_file()]
    if prior:
        archive = args.output / "prior-attempts" / str(time.time_ns())
        archive.mkdir(parents=True, mode=0o700)
        for path in prior: shutil.copy2(path, archive / path.name)
    checks, external, sends = [], [], []
    report = dict(result="FAIL", synthetic_only=True, engine=args.engine, checks=checks)
    with tempfile.TemporaryDirectory(prefix="osmap-header-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as pw:
        root = Path(temporary)
        process, origin = start_server(root, repo, log)
        browser = getattr(pw, args.engine).launch(executable_path=args.browser, headless=True)
        report["browser_version"] = browser.version

        def visit(page, path):
            response = page.goto(origin + path, wait_until="networkidle")
            assert response.status == 200
            assert response.headers["cache-control"] == "no-store"

        def submit(page, label, status=200, keyboard=False):
            button = page.get_by_role("button", name=label, exact=True)
            if keyboard: button.focus()
            with page.expect_navigation(wait_until="networkidle") as nav:
                if keyboard: page.keyboard.press("Enter")
                else: button.click()
            assert nav.value.status == status, (label, nav.value.status)

        def login(account="alice", javascript=False, marker="Header"):
            ctx = browser.new_context(java_script_enabled=javascript, user_agent="OSMAP/" + marker,
                viewport=dict(width=1600, height=1100), color_scheme="light")
            def route(r):
                if r.request.url == origin + "/send" and r.request.method == "POST": sends.append(marker)
                if r.request.url.startswith(origin + "/"): r.continue_()
                else: external.append(True); r.abort()
            ctx.route("**/*", route)
            page = ctx.new_page()
            visit(page, "/login")
            page.get_by_label("Username or Email").fill(account + "@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            submit(page, "Sign In")
            return page

        def theme(page, value):
            expect(page.locator("html")).to_have_attribute("data-appearance", value)
            for name in ("light", "dark"):
                expect(page.locator(f'[data-header-theme="{name}"]')).to_have_attribute("aria-pressed", str(name == value).lower())

        def token(page):
            return page.locator('[name="csrf_token"]').first.input_value()

        def post(page, path, fields, status=303):
            response = page.context.request.post(origin + path, data=urlencode(fields),
                headers={"Origin":origin, "Content-Type":"application/x-www-form-urlencoded"}, max_redirects=0)
            assert response.status == status

        def appearance_bytes():
            return {str(p.relative_to(root)):p.read_bytes() for p in root.rglob("*.appearance")}

        def record(page):
            ident = page.locator('[name="draft_id"]').input_value()
            metadata = next(p for p in (root / "drafts").rglob("metadata.draft") if p.parent.name == ident)
            values = dict(line.split("=", 1) for line in metadata.read_text().splitlines())
            files = {bytes.fromhex(values[f"attachment_{i}_filename_hex"]).decode():
                (metadata.parent / values[f"attachment_{i}_body_file"]).read_bytes()
                for i in range(int(values["attachment_count"]))}
            return values, files

        def disabled(page):
            for value in ("Light", "Dark"):
                expect(page.get_by_role("button", name=f"Use {value} theme", exact=True)).to_be_disabled()

        try:
            page = login()
            paths = ["/mailbox?name=INBOX&sort=subject&dir=asc&page=1&filter=all&selected_mailbox=INBOX&selected_uid=9",
                "/message?mailbox=INBOX&uid=9&return_to=%2Fmailbox%3Fname%3DINBOX",
                "/drafts?filter=all&sort=oldest&q=public"]
            for path in paths:
                visit(page, path)
                for choice in ("Dark", "Light"):
                    submit(page, f"Use {choice} theme", keyboard=choice == "Dark")
                    current, expected = urlsplit(page.url), urlsplit(path)
                    assert current.path == expected.path and parse_qs(current.query) == parse_qs(expected.query)
                    theme(page, choice.lower())
            submit(page, "Use Dark theme")
            fresh = login()
            theme(fresh, "dark")
            theme(login("bob"), "system")
            checks.append("native pointer/keyboard theme writes preserve mailbox/reader/Drafts query; fresh Alice login restores Dark and Bob remains System")

            visit(page, "/settings?section=appearance")
            disabled(page)
            page.get_by_label("System", exact=True).locator("..").click()
            submit(page, "Save changes")
            visit(page, "/mailboxes")
            theme(page, "system")
            expect(page.locator('[data-header-theme="light"]')).to_have_attribute("aria-pressed", "false")
            before = appearance_bytes()
            csrf = token(page)
            for fields, status in [
                (dict(csrf_token=csrf, appearance="dark", return_to="https://example.invalid/"), 400),
                (dict(csrf_token=csrf, appearance="dark", return_to="/logout"), 400),
                (dict(csrf_token="invalid", appearance="dark", return_to="/mailboxes"), 403),
                (dict(appearance="dark", return_to="/mailboxes"), 403),
            ]:
                post(page, "/settings/appearance", fields, status)
                assert appearance_bytes() == before
            for path in ("/settings", "/settings?section=appearance", "/settings?section=reading", "/contacts"):
                visit(page, path)
                disabled(page)
            checks.append("System remains selectable in Appearance; editing Settings/Contacts disables quick theme; invalid return/CSRF preserve appearance bytes")

            for javascript in (False, True):
                compose = login(javascript=javascript)
                visit(compose, "/compose")
                if javascript:
                    compose.get_by_role("button", name="Edit all recipients", exact=True).click()
                compose.locator('[name="to"]').fill("reader@example.test")
                compose.get_by_label("Body", exact=True).fill("Original public body")
                compose.locator("#compose-attachment").set_input_files([
                    dict(name="remove.txt", mimeType="text/plain", buffer=b"remove"),
                    dict(name="keep.txt", mimeType="text/plain", buffer=b"keep")])
                submit(compose, "Save Draft")
                old, _ = record(compose)
                compose.get_by_label("Remove remove.txt", exact=True).check()
                body = "Unsaved public <body> & 🦊\nPreserve this line"
                compose.get_by_label("Body", exact=True).fill(body)
                compose.locator("#compose-attachment").set_input_files(dict(name="new.txt", mimeType="text/plain", buffer=b"new"))
                submit(compose, "Use Dark theme", keyboard=True)
                after, files = record(compose)
                assert after["draft_id"] == old["draft_id"] and int(after["revision"]) == int(old["revision"]) + 1
                assert bytes.fromhex(after["body_hex"]).decode().replace("\r\n", "\n") == body
                expect(compose.get_by_label("Body", exact=True)).to_have_value(body)
                assert files == {"keep.txt":b"keep", "new.txt":b"new"}
                theme(compose, "dark")
                visit(compose, "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=9")
                with compose.expect_navigation(wait_until="networkidle"):
                    compose.get_by_role("link", name="Reply all", exact=True).click()
                source_body = compose.get_by_label("Body", exact=True).input_value()
                source_to = compose.locator('[name="to"]').input_value()
                submit(compose, "Use Light theme")
                reply, _ = record(compose)
                assert bytes.fromhex(reply["body_hex"]).decode().replace("\r\n", "\n") == source_body
                assert bytes.fromhex(reply["to_hex"]).decode() == source_to
                assert reply["reply_parent_hex"] and reply["reply_references_hex"]
                assert reply["body_format"] == "plain"
                theme(compose, "light")
                compose.context.close()
            assert not sends
            checks.append("with and without JS, header theme saves exact unsaved Unicode body, removes selected saved file, preserves retained/new file bytes, increments revision once and retains reply context; zero send requests")

            paused = login(marker="DraftSaveUnconfirmed")
            visit(paused, "/compose")
            paused.get_by_label("Body", exact=True).fill("Public unconfirmed draft")
            before = appearance_bytes()
            submit(paused, "Use Dark theme", 503)
            assert appearance_bytes() == before
            disabled(paused)
            checks.append("unconfirmed draft save leaves theme bytes unchanged and disables quick-theme retry")

            # Isolated synthetic recovery setup; no real submission backend.
            recovery = login(marker="SendUnconfirmed")
            visit(recovery, "/compose")
            recovery.get_by_label("To", exact=True).fill("reader@example.test")
            recovery.get_by_label("Body", exact=True).fill("Public recovery header fixture")
            submit(recovery, "Send Message", 503)
            disabled(recovery)
            assert recovery.locator('form[action="/settings/appearance"], [data-compose-theme], script').count() == 0
            assert "Keep this result page open" in recovery.locator("#header-theme-help").text_content()
            assert sends == ["SendUnconfirmed"]
            checks.append("read-only uncertain result has disabled recovery-specific theme controls and no Compose form association")

            visit(page, "/mailboxes")
            for color in ("Light", "Dark"):
                submit(page, f"Use {color} theme")
                for width in (1600, 768, 360):
                    page.set_viewport_size(dict(width=width, height=1100))
                    for section in ("general", "appearance"):
                        visit(page, "/settings?section=" + section)
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                        page.screenshot(path=str(args.output / f"header-{section}-{color.lower()}-{width}.png"), full_page=True)
                    visit(page, "/mailboxes")
                page.set_viewport_size(dict(width=1600, height=1100))
            page.emulate_media(forced_colors="active")
            for width in (1600, 768, 360):
                page.set_viewport_size(dict(width=width, height=1100))
                button = page.get_by_role("button", name="Use Light theme", exact=True)
                button.focus()
                expect(button).to_be_focused()
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                page.screenshot(path=str(args.output / f"header-focus-forced-{width}.png"), full_page=True)
            checks.append("PAGE-11/12 light/dark headers at1600/768/360 and forced-colour keyboard focus have no horizontal overflow")
            assert not external
            report["result"] = "PASS"
        except Exception as error:
            report["failure_type"] = type(error).__name__
            raise
        finally:
            report.update(external_requests=len(external), theme_workflow_send_requests=len([s for s in sends if s != "SendUnconfirmed"]), synthetic_recovery_setup_send_requests=sends.count("SendUnconfirmed"))
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
            browser.close()
            stop_server(process, root)
    print(json.dumps(dict(result=report["result"], checks=len(checks), report=str(args.output / "workflows.json"))))


if __name__ == "__main__": main()
