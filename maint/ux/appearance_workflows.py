#!/usr/bin/env python3
"""Native display-preference qualification against private synthetic storage."""
import argparse
import json
import math
from pathlib import Path
import sys
import shutil
import time
import tempfile
from urllib.parse import urlencode

from playwright.sync_api import sync_playwright, expect

DEFAULTS = dict(appearance="system", density="comfortable", font_size="medium",
                reader_layout="split", show_avatars=True, message_preview=True)
CHANGED = dict(appearance="dark", density="compact", font_size="large",
               reader_layout="stacked", show_avatars=False, message_preview=False)
SETTINGS = "/settings?section=appearance"
MAIL = "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=125"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--repo", type=Path, default=Path("/home/foo/Workspace/OSMAP"))
    parser.add_argument("--engine", choices=["chromium", "firefox"], default="chromium")
    parser.add_argument("--browser", default="/usr/bin/microsoft-edge-stable")
    parser.add_argument("--preview-only", action="store_true", help="Only changed unsaved preview and save/consumer boundary")
    parser.add_argument("--zoom-only", action="store_true", help="One large-font case at witnessed native Chromium200percent page zoom")
    args = parser.parse_args()
    if args.zoom_only and (args.engine != "chromium" or args.preview_only):
        parser.error("--zoom-only requires Chromium and cannot combine with --preview-only")
    sys.path.insert(0, str(args.repo / "maint/ux"))
    from browser_workflows import start_server, stop_server
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.chmod(0o700)
    prior = [args.output / name for name in ("synthetic-server.log", "workflows.json") if (args.output / name).exists()]
    if prior:
        attempt = args.output / "prior-attempts" / str(time.time_ns())
        attempt.mkdir(parents=True, mode=0o700)
        for path in prior: shutil.copy2(path, attempt / path.name)
    checks, external, scripts = [], [], []
    report = dict(result="FAIL", synthetic_authentication=True, real_preference_store=True,
                  engine=args.engine, checks=checks)
    with tempfile.TemporaryDirectory(prefix="osmap-display-") as temporary, \
            (args.output / "synthetic-server.log").open("w") as log, sync_playwright() as pw:
        process, origin = start_server(Path(temporary), args.repo, log)
        if args.zoom_only:
            ctx, profile = None, None
            try:
                profile = tempfile.TemporaryDirectory(prefix="osmap-zoom-profile-")
                preferences = Path(profile.name) / "Default" / "Preferences"
                preferences.parent.mkdir(mode=0o700)
                preferences.write_text(json.dumps({"partition": {"default_zoom_level": {"x": math.log(2) / math.log(1.2)}}}))
                preferences.chmod(0o600)
                ctx = pw.chromium.launch_persistent_context(profile.name, executable_path=args.browser,
                    headless=True, args=["--window-size=1600,1100"], no_viewport=True,
                    java_script_enabled=False, color_scheme="light")
                report["browser_version"] = ctx.browser.version if ctx.browser else "unavailable"
                def route_zoom(route):
                    if route.request.resource_type == "script": scripts.append(True)
                    if route.request.url.startswith(origin + "/"): route.continue_()
                    else: external.append(True); route.abort()
                ctx.route("**/*", route_zoom)
                page = ctx.pages[0] if ctx.pages else ctx.new_page()
                def witness(label):
                    value = page.evaluate("""() => ({dpr:devicePixelRatio,outer:outerWidth,inner:innerWidth,
                        visualScale:visualViewport.scale,cssZoom:Number(getComputedStyle(document.documentElement).zoom),
                        overflow:document.documentElement.scrollWidth > innerWidth})""")
                    report[label] = value  # Retain actual measurements even when a witness refuses.
                    assert 1.95 <= value["dpr"] <= 2.05, "native zoom DPR witness absent"
                    assert 1.95 <= value["outer"] / value["inner"] <= 2.05, "native page zoom width witness absent"
                    assert value["visualScale"] == 1 and value["cssZoom"] == 1, "pinch/CSS zoom is not native page zoom"
                    return value
                response = page.goto(origin + "/login", wait_until="networkidle")
                assert response.status == 200
                report["native_zoom_before"] = witness("native_zoom_before")
                page.get_by_label("Username or Email").fill("alice@example.com")
                page.get_by_label("Password", exact=True).fill("correct horse battery staple")
                page.get_by_label("TOTP Code").fill("123456")
                with page.expect_navigation(wait_until="networkidle"):
                    page.get_by_role("button", name="Sign In", exact=True).click()
                response = page.goto(origin + SETTINGS, wait_until="networkidle")
                assert response.status == 200 and response.headers["cache-control"] == "no-store"
                form = page.locator('form[action="/settings/display"]')
                form.locator('[name="font_size"]').focus()
                page.keyboard.press("End")
                expect(form.locator('[name="font_size"]')).to_have_value("large")
                button = form.locator('button[type="submit"]')
                for _ in range(60):
                    page.keyboard.press("Tab")
                    if button.evaluate("e => e === document.activeElement"): break
                else: raise AssertionError("large-font Save not keyboard reachable at native200percent")
                with page.expect_navigation(wait_until="networkidle"): page.keyboard.press("Enter")
                page.reload(wait_until="networkidle")
                expect(page.locator("html")).to_have_attribute("data-font-size", "large")
                expect(page.locator('[name="font_size"]')).to_have_value("large")
                report["native_zoom_after"] = witness("native_zoom_after")
                assert not report["native_zoom_after"]["overflow"], "large-font settings overflow at native200percent"
                saved_button = page.locator('form[action="/settings/display"] button[type="submit"]')
                for _ in range(60):
                    page.keyboard.press("Tab")
                    if saved_button.evaluate("e => e === document.activeElement"): break
                else: raise AssertionError("saved large-font Save not keyboard reachable at native200percent")
                assert page.locator("script").count() == 0 and not external and not scripts
                checks.append("nativeChromium200percent witnessed DPR/outer-to-inner ratio with visual/CSS scale1; native keyboard large-font Save/reload persists with no horizontal overflow")
                report["result"] = "PASS"
                ctx.close(); ctx = None
            except Exception as error:
                report["result"] = "FAIL"
                report["failure_type"] = type(error).__name__
                raise
            finally:
                try:
                    if ctx is not None: ctx.close()
                finally:
                    try:
                        if profile is not None: profile.cleanup()
                    finally:
                        report.update(external_requests=len(external), script_requests=len(scripts),
                            scope="one native page-zoom large-font Settings case; synthetic authentication and real private preference store")
                        (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
                        stop_server(process, Path(temporary))
            return
        browser = getattr(pw, args.engine).launch(executable_path=args.browser, headless=True)
        report["browser_version"] = browser.version

        def new_page(account):
            ctx = browser.new_context(viewport=dict(width=1600, height=1100), color_scheme="light", java_script_enabled=False)
            def route(r):
                if r.request.resource_type == "script": scripts.append(True)
                if r.request.url.startswith(origin + "/"): r.continue_()
                else: external.append(True); r.abort()
            ctx.route("**/*", route)
            page = ctx.new_page()
            visit(page, "/login")
            page.get_by_label("Username or Email").fill(account + "@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            with page.expect_navigation(wait_until="networkidle"):
                page.get_by_role("button", name="Sign In", exact=True).click()
            visit(page, SETTINGS)
            return page

        def visit(page, path):
            response = page.goto(origin + path, wait_until="networkidle")
            assert response.status == 200
            assert response.headers["cache-control"] == "no-store"
            if not path.startswith(("/compose", "/draft?")):
                assert page.locator("script").count() == 0

        def state(page, values):
            form = page.locator('form[action="/settings/display"]')
            assert form.count() == 1, page.evaluate("({path:location.pathname, headings:[...document.querySelectorAll('h1,h2')].map(e=>e.textContent), forms:[...document.forms].map(f=>({action:f.getAttribute('action'),names:[...f.elements].map(e=>e.name)}))})")
            for name, value in values.items():
                field = form.locator(f'[name="{name}"]')
                if isinstance(value, bool): assert field.is_checked() == value
                elif field.first.evaluate("e => e.tagName") == "SELECT": expect(field).to_have_value(value)
                else: expect(form.locator(f'[name="{name}"][value="{value}"]')).to_be_checked()
            for name, value in values.items():
                attr = name.replace("_", "-")
                expected = str(value).lower() if isinstance(value, bool) else value
                expect(page.locator("html")).to_have_attribute("data-" + attr, expected)

        def save(page, values, keyboard=False):
            form = page.locator('form[action="/settings/display"]')
            assert form.count() == 1, page.evaluate("({path:location.pathname, headings:[...document.querySelectorAll('h1,h2')].map(e=>e.textContent), forms:[...document.forms].map(f=>({action:f.getAttribute('action'),names:[...f.elements].map(e=>e.name)}))})")
            for name, value in values.items():
                field = form.locator(f'[name="{name}"]')
                if isinstance(value, bool): field.set_checked(value)
                elif field.first.evaluate("e => e.tagName") == "SELECT": field.select_option(value)
                else: form.locator(f'label:has(input[name="{name}"][value="{value}"])').click()
            button = form.locator('button[type="submit"]')
            if keyboard:
                for _ in range(100):
                    page.keyboard.press("Tab")
                    if button.evaluate("e => e === document.activeElement"): break
                else: raise AssertionError("display Save absent from keyboard tab order")
            with page.expect_navigation(wait_until="networkidle"):
                if keyboard: page.keyboard.press("Enter")
                else: button.click()
            state(page, values)

        def metrics(page):
            visit(page, MAIL)
            return page.evaluate("""() => {
              const q = s => document.querySelector(s), css = s => getComputedStyle(q(s));
              const rect = s => { const r=q(s).getBoundingClientRect(); return {x:r.x,y:r.y,right:r.right,bottom:r.bottom}; };
              return {padding:parseFloat(css('.message-card').paddingTop)+parseFloat(css('.message-card').paddingBottom),
                font:parseFloat(css('.message-subject-link').fontSize),
                avatar:css('.message-card .message-avatar').display,
                snippet:css('.message-body-preview').display,
                list:rect('.coordinated-list'),reader:rect('#reading-pane')};
            }""")

        def preview_metrics(page):
            return page.locator(".settings-preview").evaluate("""e => {
              const q = s => e.querySelector(s), css = s => getComputedStyle(q(s));
              const rect = s => { const r=q(s).getBoundingClientRect(); return {x:r.x,y:r.y,bottom:r.bottom}; };
              return {background:getComputedStyle(e).backgroundColor,font:parseFloat(getComputedStyle(e).fontSize),
                height:q('.settings-preview-message').getBoundingClientRect().height,
                avatar:css('.settings-preview-avatar').display,snippet:css('.settings-preview-snippet').display,
                message:rect('.settings-preview-message'),reader:rect('.settings-preview-reader')};
            }""")

        def preview_boundary(page, baseline):
            visit(page, SETTINGS)
            original = preview_metrics(page)
            appearance_bytes = lambda: {str(p.relative_to(temporary)): p.read_bytes()
                for p in Path(temporary).rglob("*.appearance")}
            before = appearance_bytes()
            # Native keyboard input: no script mutates controls or submits values.
            page.locator('input[name="appearance"][value="light"]').focus()
            page.keyboard.press("ArrowRight")
            expect(page.locator('input[name="appearance"][value="dark"]')).to_be_checked()
            assert preview_metrics(page)["background"] != original["background"]
            page.locator('#settings-density').focus()
            page.keyboard.press("End")
            expect(page.locator('#settings-density')).to_have_value("compact")
            assert preview_metrics(page)["height"] < original["height"]
            page.locator('#settings-font-size').focus()
            page.keyboard.press("End")
            expect(page.locator('#settings-font-size')).to_have_value("large")
            assert preview_metrics(page)["font"] > original["font"]
            page.locator('#settings-reader-layout').focus()
            page.keyboard.press("End")
            expect(page.locator('#settings-reader-layout')).to_have_value("stacked")
            for field in ['#settings-show-avatars', '#settings-message-preview']:
                page.locator(field).focus()
                page.keyboard.press("Space")
                expect(page.locator(field)).not_to_be_checked()
            selected = preview_metrics(page)
            assert selected["reader"]["y"] >= selected["message"]["bottom"]
            assert selected["avatar"] == "none" and selected["snippet"] == "none"
            expect(page.locator('.settings-preview-saved')).to_contain_text("Saved: system, comfortable, medium")
            expect(page.locator('html')).to_have_attribute('data-appearance', 'system')
            assert appearance_bytes() == before, "unsaved preview wrote durable preferences"
            # A separate context reads the same account's still-saved defaults.
            unchanged = new_page("alice")
            state(unchanged, DEFAULTS)
            unchanged.context.close()
            assert appearance_bytes() == before
            checks.append("six native keyboard selections update computed sample only; durable appearance bytes and fresh account defaults stay unchanged before Save")
            # System follows device only inside preview before save.
            page.locator('input[name="appearance"][value="dark"]').focus()
            page.keyboard.press("ArrowRight")
            page.emulate_media(color_scheme="light")
            light = preview_metrics(page)["background"]
            page.emulate_media(color_scheme="dark")
            assert preview_metrics(page)["background"] != light
            page.keyboard.press("ArrowLeft")
            expect(page.locator('input[name="appearance"][value="dark"]')).to_be_checked()
            save(page, CHANGED, keyboard=True)
            page.reload(wait_until="networkidle")
            state(page, CHANGED)
            expect(page.locator('.settings-preview-saved')).to_contain_text("Saved: dark, compact, large")
            changed = metrics(page)
            assert changed["padding"] < baseline["padding"] and changed["font"] > baseline["font"]
            assert changed["avatar"] == "none" and changed["snippet"] == "none"
            assert changed["reader"]["y"] >= changed["list"]["bottom"] - 2
            bob = new_page("bob")
            state(bob, DEFAULTS)
            bob.context.close()
            checks.append("explicit Save/reload persists six choices and actual mailbox consumers; Bob retains defaults; System preview follows device without scripts")

        def post(page, path, values, expected):
            response = page.context.request.post(origin + path, data=urlencode(values),
                headers={"Content-Type":"application/x-www-form-urlencoded", "Origin":origin}, max_redirects=0)
            assert response.status == expected

        try:
            alice = new_page("alice")
            state(alice, DEFAULTS)
            baseline = metrics(alice)
            assert baseline["avatar"] != "none" and baseline["snippet"] != "none"
            assert baseline["reader"]["x"] > baseline["list"]["x"]
            if args.preview_only:
                preview_boundary(alice, baseline)
                assert not external and not scripts
                report["result"] = "PASS"
                return
            # Populate Drafts through its normal native form for real avatar checks.
            visit(alice, "/compose")
            alice.locator('[name="body"]').fill("Public display preference fixture")
            with alice.expect_navigation(wait_until="networkidle"):
                alice.get_by_role("button", name="Save Draft", exact=True).click()
            visit(alice, "/drafts")
            expect(alice.locator(".draft-list .sender-avatar").first).to_be_visible()
            visit(alice, SETTINGS)
            save(alice, CHANGED, keyboard=True)
            changed = metrics(alice)
            assert changed["padding"] < baseline["padding"], "density did not reduce actual row spacing"
            assert changed["font"] > baseline["font"], "font choice did not change actual message text"
            assert changed["avatar"] == "none" and changed["snippet"] == "none"
            assert changed["reader"]["y"] >= changed["list"]["bottom"] - 2
            visit(alice, "/drafts")
            expect(alice.locator(".draft-list .sender-avatar").first).to_be_hidden()
            visit(alice, SETTINGS)
            alice.reload(wait_until="networkidle")
            state(alice, CHANGED)
            checks.append("all native controls persist and change actual message spacing/fonts/avatars/snippets/reader placement; Drafts avatars respond")
            restored = new_page("alice")
            state(restored, CHANGED)
            bob = new_page("bob")
            state(bob, DEFAULTS)
            checks.append("fresh authenticated context restores all account preferences; other account retains defaults")

            token = restored.locator('form[action="/settings/display"] [name="csrf_token"]').input_value()
            post(restored, "/settings/appearance", [("csrf_token", token), ("appearance", "light")], 303)
            retained = dict(CHANGED, appearance="light")
            visit(restored, SETTINGS)
            state(restored, retained)
            values = [("csrf_token", token)] + [(k, str(v).lower()) for k,v in retained.items() if not isinstance(v, bool)]
            post(restored, "/settings/display", [(k, "unknown" if k == "density" else v) for k,v in values], 400)
            post(restored, "/settings/display", values + [("density", "comfortable")], 400)
            post(restored, "/settings/display", [(k,v) for k,v in values if k != "csrf_token"], 403)
            visit(restored, SETTINGS)
            state(restored, retained)
            checks.append("legacy theme-only update preserves remaining preferences; tampered/duplicate/no-CSRF submissions leave prior state unchanged")

            for theme, width, forced in [("light",1600,False),("dark",768,False),("system",360,False),
                                         ("system",1600,True),("system",360,True)]:
                restored.set_viewport_size(dict(width=width,height=1100))
                save(restored, dict(retained, appearance=theme))
                restored.emulate_media(color_scheme="dark" if theme == "system" else theme,
                                       forced_colors="active" if forced else "none")
                assert restored.evaluate("document.documentElement.scrollWidth <= innerWidth")
                restored.screenshot(path=str(args.output / f"appearance-{theme}-{width}-{'forced' if forced else 'normal'}.png"), full_page=True)
            restored.emulate_media(forced_colors="none", color_scheme="light")
            light = restored.evaluate("getComputedStyle(document.body).backgroundColor")
            restored.emulate_media(color_scheme="dark")
            assert restored.evaluate("getComputedStyle(document.body).backgroundColor") != light
            checks.append("light/dark/system and forced-colour widths 360/768/1600 have no overflow; system follows media change without scripts")
            assert not external and not scripts
            report["result"] = "PASS"
        except Exception as error:
            report["failure_type"] = type(error).__name__
            raise
        finally:
            report.update(external_requests=len(external), script_requests=len(scripts))
            (args.output / "workflows.json").write_text(json.dumps(report, indent=2) + "\n")
            browser.close()
            stop_server(process, Path(temporary))
    print(json.dumps({"result":report["result"], "checks":len(checks), "report":str(args.output / "workflows.json")}))


if __name__ == "__main__": main()
