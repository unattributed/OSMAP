#!/usr/bin/env python3
"""Native General settings proof with durable account stores and no page JS."""
import argparse
import json
from pathlib import Path
import sys
import shutil
import time
import tempfile
from urllib.parse import urlencode

from playwright.sync_api import sync_playwright, expect


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--repo", type=Path, default=Path("/home/foo/Workspace/OSMAP"))
    parser.add_argument("--mailbox", default="Archive/2026")
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    parser.add_argument("--engine", choices=["chromium", "firefox"], default="chromium")
    args = parser.parse_args()
    sys.path.insert(0, str(args.repo / "maint/ux"))
    from browser_workflows import start_server, stop_server
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.chmod(0o700)
    previous = [args.output / name for name in ("synthetic-server.log", "workflows.json") if (args.output / name).exists()]
    if previous:
        attempt = args.output / "prior-attempts" / str(time.time_ns())
        attempt.mkdir(parents=True, mode=0o700)
        for path in previous: shutil.copy2(path, attempt / path.name)
    checks, outside, scripts, posts = [], [], [], []
    report = dict(result="FAIL", synthetic_authentication=True, real_account_stores=True,
                  checks=checks, engine=args.engine)
    with tempfile.TemporaryDirectory(prefix="osmap-general-") as tmp, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as pw:
        root = Path(tmp)
        process, origin = start_server(root, args.repo, log)
        browser = getattr(pw, args.engine).launch(executable_path=args.browser, headless=True)
        report["browser_version"] = browser.version

        def visit(page, path="/settings?section=general", status=200):
            response = page.goto(origin + path, wait_until="networkidle")
            assert response.status == status
            assert response.headers["cache-control"] == "no-store"
            if not path.startswith(("/compose", "/draft?")):
                assert page.locator("script").count() == 0
            else:
                assert page.locator("script").count() == 1
                assert page.locator("script#osmap-compose-local").text_content() == (args.repo / "src/http/compose_local.js").read_text()

        def login(account):
            ctx = browser.new_context(viewport=dict(width=1600, height=1100), java_script_enabled=False, color_scheme="light")
            def route(r):
                if r.request.resource_type == "script": scripts.append(True)
                if r.request.method == "POST": posts.append(True)
                if r.request.url.startswith(origin + "/"): r.continue_()
                else: outside.append(True); r.abort()
            ctx.route("**/*", route)
            page = ctx.new_page()
            visit(page, "/login")
            page.get_by_label("Username or Email").fill(account + "@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            with page.expect_navigation(wait_until="networkidle"):
                page.get_by_role("button", name="Sign In", exact=True).click()
            visit(page)
            return page

        def csrf(page):
            return page.locator('form[action="/settings/display"] [name="csrf_token"]').input_value()

        def post(page, path, fields):
            response = page.context.request.post(origin + path, data=urlencode(fields),
                headers={"Origin":origin, "Content-Type":"application/x-www-form-urlencoded"}, max_redirects=0)
            assert response.status == 303

        def save(page, label, status=200, keyboard=False):
            button = page.get_by_role("button", name=label, exact=True)
            if keyboard:
                for _ in range(100):
                    page.keyboard.press("Tab")
                    if button.evaluate("e => document.activeElement === e"): break
                else: raise AssertionError("Save missing from keyboard focus order")
            with page.expect_navigation(wait_until="networkidle") as navigation:
                if keyboard: page.keyboard.press("Enter")
                else: button.click()
            assert navigation.value.status == status

        def state(page, changed=True):
            visit(page)
            expect(page.get_by_label("Theme", exact=True)).to_have_value("dark" if changed else "system")
            expect(page.get_by_label("Density", exact=True)).to_have_value("compact" if changed else "comfortable")
            expect(page.get_by_label("Reader layout", exact=True)).to_have_value("stacked" if changed else "split")
            form = page.locator('form[action="/settings/display"]')
            expect(form.locator('[name="font_size"]')).to_have_value("small" if changed else "medium")
            assert form.locator('[name="show_avatars"]').count() == (0 if changed else 1)
            expect(form.locator('[name="message_preview"]')).to_have_value("1")
            expect(page.get_by_label("Archive folder", exact=True)).to_have_value(args.mailbox if changed else "")
            expect(page.locator('form[action="/settings"] [name="html_display_preference"]')).to_have_value("prefer_plain_text" if changed else "prefer_sanitized_html")
            expect(page.get_by_label("Default format", exact=True)).to_have_value("formatted" if changed else "plain")

        try:
            alice = login("alice")
            state(alice, False)
            visit(alice, "/compose")
            expect(alice.locator('[name="body_format"]')).to_have_value("plain")
            alice.get_by_label("Body", exact=True).fill("Existing **literal** draft")
            save(alice, "Save Draft")
            saved_draft = alice.url.removeprefix(origin)
            assert saved_draft.startswith("/draft?id=")
            visit(alice)
            alice.get_by_label("Default format", exact=True).select_option("formatted")
            save(alice, "Save default format", keyboard=True)
            visit(alice, "/compose")
            expect(alice.locator('[name="body_format"]')).to_have_value("formatted")
            expect(alice.get_by_label("Body", exact=True)).to_have_value("")
            visit(alice, saved_draft)
            expect(alice.locator('[name="body_format"]')).to_have_value("plain")
            expect(alice.get_by_label("Body", exact=True)).to_have_value("Existing **literal** draft")
            for label in ("Reply", "Reply all", "Forward"):
                visit(alice, "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=9")
                with alice.expect_navigation(wait_until="networkidle"):
                    alice.get_by_role("link", name=label, exact=True).click()
                expect(alice.locator('[name="body_format"]')).to_have_value("plain")
                assert "Hello world" in alice.get_by_label("Body", exact=True).input_value()
                expect(alice.get_by_text("Replies and forwards start in Plain text", exact=False)).to_be_visible()
            visit(alice)
            snapshot = {str(p.relative_to(root)):p.read_bytes() for p in (root / "settings").iterdir() if p.is_file()}
            assert any(name.endswith(".json") for name in snapshot)
            token = csrf(alice)
            for fields, status in [
                ([("csrf_token", token), ("default_body_format", "html")], 400),
                ([("csrf_token", token), ("default_body_format", "plain"), ("default_body_format", "formatted")], 400),
                ([("csrf_token", token)], 400),
                ([("default_body_format", "plain")], 403),
                ([("csrf_token", "invalid"), ("default_body_format", "plain")], 403),
            ]:
                response = alice.context.request.post(origin + "/settings/composition", data=urlencode(fields),
                    headers={"Origin":origin, "Content-Type":"application/x-www-form-urlencoded"}, max_redirects=0)
                assert response.status == status
                assert {str(p.relative_to(root)):p.read_bytes() for p in (root / "settings").iterdir() if p.is_file()} == snapshot
            checks.append("native default format applies to blank Compose; existing draft and source-backed reply/reply-all/forward stay Plain with notice; invalid/duplicate/missing values and absent/invalid CSRF leave durable bytes unchanged")
            # Establish non-default hidden fields through their actual routes.
            post(alice, "/settings/display", dict(csrf_token=csrf(alice), appearance="system", density="comfortable",
                font_size="small", reader_layout="split", message_preview="1"))
            post(alice, "/settings", dict(csrf_token=csrf(alice), html_display_preference="prefer_plain_text", archive_mailbox_name=""))
            visit(alice)
            alice.get_by_label("Theme", exact=True).select_option("dark")
            alice.get_by_label("Density", exact=True).select_option("compact")
            alice.get_by_label("Reader layout", exact=True).select_option("stacked")
            save(alice, "Save appearance", keyboard=True)
            visit(alice)
            alice.get_by_label("Archive folder", exact=True).fill(args.mailbox)
            save(alice, "Save archive folder")
            state(alice)
            alice.reload(wait_until="networkidle")
            state(alice)
            checks.append("native General appearance/archive saves preserve hidden font/avatar/snippet and existing HTML preference after reload")
            stored = {str(p.relative_to(root)):p.read_bytes() for p in root.rglob("*.settings")}
            assert stored, "fixture did not write an actual user settings record"
            alice.get_by_label("Archive folder", exact=True).fill("INBOX.DoesNotExist")
            save(alice, "Save archive folder", status=400)
            assert {str(p.relative_to(root)):p.read_bytes() for p in root.rglob("*.settings")} == stored
            state(alice)
            checks.append("missing archive mailbox is refused; durable settings bytes remain unchanged")

            before = len(posts)
            disabled = alice.locator(".settings-general-page input:disabled, .settings-general-page select:disabled, .settings-general-page button:disabled")
            assert disabled.count() >= 8
            for control in disabled.all():
                control.scroll_into_view_if_needed()
                box = control.bounding_box()
                if box: alice.mouse.click(box["x"] + box["width"]/2, box["y"] + box["height"]/2)
            assert len(posts) == before
            checks.append("unavailable controls are disabled and pointer activation sends no POST")
            disclosure = alice.locator(".general-composition-actions details")
            disclosure.locator("summary").focus()
            before_disclosure = len(posts)
            before_url = alice.url
            alice.keyboard.press("Enter")
            expect(disclosure).to_have_attribute("open", "")
            expect(disclosure.locator("p")).to_be_visible()
            scope = disclosure.inner_text()
            assert "new blank messages" in scope and "Replies and forwards use Plain text" in scope
            assert "existing drafts keep their saved format" in scope
            assert len(posts) == before_disclosure and alice.url == before_url
            alice.keyboard.press("Enter")
            expect(disclosure.locator("p")).to_be_hidden()
            checks.append("keyboard native default-format disclosure reveals scope without submitting or navigating")
            alice.get_by_role("searchbox", name="Search settings", exact=True).fill("font")
            with alice.expect_navigation(wait_until="networkidle"):
                alice.get_by_role("searchbox", name="Search settings", exact=True).press("Enter")
            expect(alice.locator(".settings-search-results").get_by_role("link", name="Font size", exact=True)).to_be_visible()
            alice.locator(".settings-search-results").get_by_role("link", name="Font size", exact=True).click()
            expect(alice.get_by_label("Font size", exact=True)).to_have_value("small")
            checks.append("keyboard Settings search finds Font size and links to its actual saved control")

            fresh = login("alice")
            state(fresh)
            bob = login("bob")
            state(bob, False)
            for context in browser.contexts: context.close()
            stop_server(process, root)
            process, origin = start_server(root, args.repo, log)
            fresh = login("alice")
            state(fresh)
            state(login("bob"), False)
            visit(fresh, "/compose")
            expect(fresh.locator('[name="body_format"]')).to_have_value("formatted")
            visit(fresh, saved_draft)
            expect(fresh.locator('[name="body_format"]')).to_have_value("plain")
            expect(fresh.get_by_label("Body", exact=True)).to_have_value("Existing **literal** draft")
            visit(fresh)
            checks.append("fresh login and server restart restore Alice durable settings; Bob remains isolated at defaults")

            # Reference geometry uses the normal text size/density. Durability
            # assertions above have already checked all non-default preferences.
            post(fresh, "/settings/display", dict(csrf_token=csrf(fresh), appearance="light", density="comfortable",
                font_size="medium", reader_layout="split", show_avatars="1", message_preview="1"))
            visit(fresh)
            for theme, width, forced in [("light",1600,False),("light",360,False),("dark",1600,False),("dark",360,False),("dark",1600,True),("dark",360,True)]:
                post(fresh, "/settings/appearance", dict(csrf_token=csrf(fresh), appearance=theme))
                visit(fresh)
                fresh.set_viewport_size(dict(width=width,height=1100))
                fresh.emulate_media(forced_colors="active" if forced else "none")
                assert fresh.evaluate("document.documentElement.scrollWidth <= innerWidth")
                fresh.screenshot(path=str(args.output / f"general-{theme}-{width}-{'forced' if forced else 'normal'}.png"), full_page=True)
                if theme == "light" and width == 1600 and not forced:
                    fresh.screenshot(path=str(args.output / "general-native-1600x1100.png"), full_page=False)
                    report["storage_y_1600"] = fresh.locator(".general-storage").bounding_box()["y"]
            assert not outside and not scripts
            checks.append("light/dark/forced General views at native 1600x1100 and 360 have no horizontal overflow; zero scripts/external requests")
            report["result"] = "PASS"
        except Exception as error:
            report["failure_type"] = type(error).__name__
            raise
        finally:
            report.update(external_requests=len(outside), script_requests=len(scripts))
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
            browser.close()
            stop_server(process, root)
    print(json.dumps({"result":report["result"], "checks":len(checks), "report":str(args.output / "workflows.json")}))


if __name__ == "__main__": main()
