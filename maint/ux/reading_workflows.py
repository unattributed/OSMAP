#!/usr/bin/env python3
"""Native Reading settings proof using private real stores and synthetic mail."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time
from urllib.parse import urlencode, urlsplit, parse_qs
from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server

SETTINGS = "/settings?section=reading"
INLINE = "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=9"
READER = "/message?mailbox=INBOX&uid=9"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    parser.add_argument("--engine", choices=["chromium", "firefox"], default="chromium")
    parser.add_argument("--captures-only", action="store_true", help="Recapture CSS after previously passing the functional workflow")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.chmod(0o700)
    prior = [p for p in args.output.iterdir() if p.is_file()]
    if prior:
        archive = args.output / "prior-attempts" / str(time.time_ns())
        archive.mkdir(parents=True, mode=0o700)
        for path in prior: shutil.copy2(path, archive / path.name)
    checks, external, scripts, post_shapes = [], [], [], []
    report = dict(result="FAIL", synthetic_only=True, real_stores=True, engine=args.engine, checks=checks)
    with tempfile.TemporaryDirectory(prefix="osmap-reading-browser-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as pw:
        root = Path(temporary)
        process, origin = start_server(root, repo, log)
        browser = getattr(pw, args.engine).launch(executable_path=args.browser, headless=True)
        report["browser_version"] = browser.version

        def visit(page, path=SETTINGS, status=200):
            response = page.goto(origin + path, wait_until="networkidle")
            assert response.status == status, (path, response.status)
            assert response.headers["cache-control"] == "no-store"
            assert page.locator("script").count() == 0
            return response

        def submit(page, name, keyboard=False):
            button = page.get_by_role("button", name=name, exact=True)
            if keyboard: button.focus()
            with page.expect_navigation(wait_until="networkidle") as nav:
                if keyboard: page.keyboard.press("Enter")
                else: button.click()
            assert nav.value.status == 200

        def login(account="alice", target="/mailboxes", forged=None):
            ctx = browser.new_context(java_script_enabled=False, viewport=dict(width=1600, height=1100), color_scheme="light")
            def route(r):
                if r.request.resource_type == "script": scripts.append(True)
                if r.request.method == "POST" and urlsplit(r.request.url).path.startswith("/settings"):
                    values = parse_qs(r.request.post_data or "", keep_blank_values=True)
                    post_shapes.append(dict(path=urlsplit(r.request.url).path, keys=sorted(values), return_section=values.get("return_section")))
                if r.request.url.startswith(origin + "/"): r.continue_()
                else: external.append(True); r.abort()
            ctx.route("**/*", route)
            if forged:
                ctx.add_cookies([dict(name="osmap_reading", value=forged, url=origin, httpOnly=True, sameSite="Strict")])
            page = ctx.new_page()
            visit(page, "/login")
            page.get_by_label("Username or Email").fill(account + "@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            submit(page, "Sign In")
            assert page.url == origin + target, ("login destination", urlsplit(page.url).path)
            return page

        def token(page):
            return page.locator('[name="csrf_token"]').first.input_value()

        def post(page, path, fields, expected=303):
            response = page.context.request.post(origin + path, data=urlencode(fields),
                headers={"Origin":origin, "Content-Type":"application/x-www-form-urlencoded"}, max_redirects=0)
            assert response.status == expected

        def state(page, start="drafts", changed=True):
            visit(page)
            expect(page.get_by_label("Default start page", exact=True)).to_have_value(start)
            expect(page.get_by_label("Conversation ordering", exact=True)).to_have_value("oldest" if changed else "newest")
            for label in ("Show source shortcut", "Attachment details"):
                assert page.get_by_label(label, exact=True).is_checked() == (not changed)

        def ordering(page, path, expected):
            visit(page, path)
            actual = [int(parse_qs(urlsplit(href).query)["selected_uid"][0]) for href in page.locator(".message-subject-link").evaluate_all("els=>els.map(e=>e.getAttribute('href'))")]
            assert actual == expected, (path, actual, expected)

        def reader(page, path, visible):
            visit(page, path)
            source = page.locator(".reader-source-shortcut")
            details = page.locator(".reader-file-details")
            assert source.count() == 1 and details.count() >= 1
            for item in [source, *details.all()]:
                if visible: expect(item).to_be_visible()
                else: expect(item).to_be_hidden()
            assert page.locator(".body-panel pre").inner_text().strip() == "Hello world"
            assert page.locator(".body-panel script, .body-panel img, .body-panel iframe").count() == 0
            expect(page.get_by_text("Message content is displayed with active content and remote images removed.", exact=True)).to_be_visible()
            download = page.get_by_role("link", name="Download", exact=True).first
            expect(download).to_be_visible()
            return source.get_attribute("href"), download.get_attribute("href")

        def captures(page):
            for color in ("light","dark"):
                visit(page)
                post(page,"/settings/appearance",dict(csrf_token=token(page),appearance=color))
                for width in ((1600,360) if args.captures_only else (1600,768,360)):
                    page.set_viewport_size(dict(width=width,height=1100))
                    visit(page)
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    gaps = page.locator(".general-card > form").evaluate_all("els=>els.map(e=>e.nextElementSibling.getBoundingClientRect().top-e.getBoundingClientRect().bottom)")
                    assert all(gap >= 8 for gap in gaps), ("form boundary spacing", gaps)
                    report.setdefault("capture_geometry", []).append(dict(color=color,width=width,height=page.evaluate("document.documentElement.scrollHeight"),form_gaps=gaps))
                    page.screenshot(path=str(args.output/f"reading-{color}-{width}.png"),full_page=True)
            page.emulate_media(forced_colors="active")
            for width in ((1600,360) if args.captures_only else (1600,768,360)):
                page.set_viewport_size(dict(width=width,height=1100))
                page.get_by_label("Default start page",exact=True).focus()
                expect(page.get_by_label("Default start page",exact=True)).to_be_focused()
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                page.screenshot(path=str(args.output/f"reading-forced-focus-{width}.png"),full_page=True)
            assert not external and not scripts
            checks.append("light/dark and forced-colour keyboard focus at requested desktop/narrow widths have no horizontal overflow; zero script/external requests")

        try:
            page = login()
            if args.captures_only:
                captures(page)
                report["result"] = "PASS"
                return
            state(page, "mailbox", False)
            ordering(page, "/mailbox?name=INBOX", [10,9])
            source_path, download_path = reader(page, INLINE, True)
            reader(page, READER, True)
            visit(page)
            page.get_by_label("Default start page", exact=True).select_option("drafts")
            page.get_by_label("Conversation ordering", exact=True).select_option("oldest")
            for label in ("Show source shortcut", "Attachment details"):
                page.get_by_label(label, exact=True).uncheck()
            submit(page, "Save reading preferences", keyboard=True)
            assert parse_qs(urlsplit(page.url).query) == {"section":["reading"], "updated":["1"]}
            expect(page.locator('[role="status"]')).to_be_visible()
            assert post_shapes[-1] == dict(path="/settings/reading", keys=["csrf_token","date_order","start_page"], return_section=None)
            state(page)
            ordering(page, "/mailbox?name=INBOX", [9,10])
            ordering(page, "/mailbox?name=INBOX&sort=received&dir=desc", [10,9])
            reader(page, INLINE, False)
            reader(page, READER, False)
            source_response = page.context.request.get(origin + source_path)
            assert source_response.status == 200
            source_csp = source_response.headers["content-security-policy"]
            assert "default-src 'none'" in source_csp and "script-src " not in source_csp
            downloaded = page.context.request.get(origin + download_path)
            assert downloaded.status == 200 and downloaded.body() == b"%PDF-stub%"
            assert downloaded.headers["content-disposition"].startswith("attachment;")
            signed_out = browser.new_context(java_script_enabled=False)
            for path in (source_path, download_path):
                refused = signed_out.request.get(origin + path, max_redirects=0)
                assert refused.status == 303 and refused.headers["location"].startswith("/login")
            signed_out.close()
            checks.append("native preference save changes actual UID order9/10, explicit URL sort wins; source/file details hide in both readers while protected body/download bytes stay unchanged and direct routes require login")

            visit(page)
            page.get_by_label("Default content", exact=True).select_option("prefer_plain_text")
            submit(page, "Save content preference")
            assert parse_qs(urlsplit(page.url).query)["section"] == ["reading"]
            assert post_shapes[-1] == dict(path="/settings", keys=["csrf_token","html_display_preference","return_section","settings_action"], return_section=["reading"])
            archive = page.get_by_label("Archive folder", exact=True)
            assert "Archive/2026" in archive.locator("option").evaluate_all("els=>els.map(e=>e.value)")
            archive.select_option("Archive/2026")
            submit(page, "Save archive folder", keyboard=True)
            assert parse_qs(urlsplit(page.url).query)["section"] == ["reading"]
            assert post_shapes[-1]["return_section"] == ["reading"]
            expect(page.get_by_label("Default content", exact=True)).to_have_value("prefer_plain_text")
            expect(page.get_by_label("Archive folder", exact=True)).to_have_value("Archive/2026")
            checks.append("native independent content/archive forms POST exact settings fields with return_section=reading; available Archive/2026 persists without losing content preference")

            path = root / "settings" / (hashlib.sha256(b"osmap-reading-preferences-v1\0alice@example.com").hexdigest() + ".json")
            saved = path.read_bytes()
            csrf = token(page)
            base = [("csrf_token",csrf),("start_page","inbox"),("date_order","newest")]
            for fields, code in [(base+[("start_page","drafts")],400), (base+[("attachment_details","0")],400),
                    (base+[("unexpected","1")],400), ([("csrf_token",csrf),("start_page","other"),("date_order","newest")],400),
                    (base[1:],403), ([("csrf_token","invalid"),*base[1:]],403)]:
                post(page,"/settings/reading",fields,code)
                assert path.read_bytes() == saved
            path.write_bytes(b'{"version":99}\n')
            visit(page, SETTINGS,503)
            assert page.locator('form[action="/settings/reading"]').count() == 0
            assert path.read_bytes() == b'{"version":99}\n'
            path.write_bytes(saved)
            checks.append("malformed/duplicate/unsupported/invalid-CSRF updates preserve record bytes; corrupt persisted record gives503 without a preference form or default overwrite")

            fresh = login(target="/drafts",forged="v1.sent.newest.1.1")
            state(fresh)
            state(login("bob",forged="v1.inbox.oldest.0.0"),"mailbox",False)
            fresh.get_by_label("Default start page", exact=True).select_option("inbox")
            submit(fresh,"Save reading preferences")
            state(login(target="/mailbox?name=INBOX",forged="v1.sent.newest.1.1"),"inbox")
            for ctx in browser.contexts: ctx.close()
            stop_server(process,root)
            process, origin = start_server(root,repo,log)
            page = login(target="/mailbox?name=INBOX",forged="v1.drafts.newest.1.1")
            state(page,"inbox")
            expect(page.get_by_label("Archive folder",exact=True)).to_have_value("Archive/2026")
            expect(page.get_by_label("Default content",exact=True)).to_have_value("prefer_plain_text")
            state(login("bob"),"mailbox",False)
            checks.append("Drafts then Inbox login redirects use stored account values despite forged cookie; restart restores reading/content/archive state; Bob remains isolated at defaults")

            captures(page)
            report["result"]="PASS"
        except Exception as error:
            report["failure_type"]=type(error).__name__
            raise
        finally:
            report.update(external_requests=len(external),script_requests=len(scripts))
            (args.output/"workflows.json").write_text(json.dumps(report,indent=2)+"\n")
            browser.close()
            stop_server(process,root)
    print(json.dumps(dict(result=report["result"],checks=len(checks),report=str(args.output/"workflows.json"))))


if __name__ == "__main__": main()
