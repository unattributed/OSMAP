#!/usr/bin/env python3
"""Focused responsive presentation and autosave checks on the existing fixture.

Only synthetic accounts/storage; no runtime credentials or mail submission.
Uses existing browser_workflows lifecycle and explicit checks, not a new harness.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from contextlib import ExitStack
import shutil
import tempfile

from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server, require


PAGES = [
    "/mailboxes", "/folders", "/mailbox?name=INBOX", "/mailbox?name=Sent",
    "/mailbox?name=INBOX&selected_mailbox=INBOX&selected_uid=125",
    "/mailbox?name=Archive", "/mailbox?name=Trash", "/compose", "/drafts",
    "/outbox", "/contacts", "/search?q=report", "/labels", "/notifications",
    "/settings", "/settings?section=appearance",
    "/settings?section=identity", "/settings?section=reading",
    "/settings?section=composition", "/settings?section=copies",
    "/settings?section=notifications", "/settings?section=privacy",
    "/settings?section=openpgp", "/settings?section=security", "/settings?section=authentication",
    "/settings/keys", "/settings/keys?panel=import#public-import",
    "/settings/password", "/settings/recovery", "/sessions",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--panel-controls", action="store_true", help="Only owner-requested panel controls in both styles and desktop sizes, plus touch")
    parser.add_argument("--autosave-only", action="store_true")
    parser.add_argument("--visual-only", action="store_true")
    parser.add_argument("--engine", choices=["chromium", "firefox"], default="chromium")
    parser.add_argument("--browser")
    parser.add_argument("--pages", nargs="+", choices=PAGES)
    args = parser.parse_args()
    if args.panel_controls and args.autosave_only:
        parser.error("--panel-controls cannot be combined with --autosave-only")
    if args.panel_controls:
        args.visual_only = True
        args.pages = ["/mailboxes", "/folders", "/settings", "/settings?section=reading", "/settings?section=security"]
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = dict(result="FAIL", engine=args.engine, scope="synthetic browser; real HTTP and account stores; not live authentication",
                  checks=[], captures=[], requests=[], external=0, sends=0)
    repo = Path(__file__).resolve().parents[2]
    # Existing opt-in fixture bound; the full-page sweep exceeds200 connections.
    os.environ.setdefault("OSMAP_UX_PREVIEW_MINUTES", "10")
    os.environ.setdefault("OSMAP_UX_FIXTURE_OUTBOX", "1")
    os.environ.setdefault("OSMAP_UX_FIXTURE_PASSWORD_CONTROLS", "1")
    os.environ.setdefault("OSMAP_UX_FIXTURE_RECOVERY_CONTACT", "verified")
    phase = "fixture_start"
    temp = Path(tempfile.mkdtemp(prefix="osmap-presentation-"))
    with (args.output / "server.private.log").open("w") as log, sync_playwright() as pw, ExitStack() as lifecycle:
        try:
            server, origin = start_server(temp, repo, log)
        except Exception:
            report["failure"] = dict(code="FIXTURE_START_FAILED", phase=phase,
                                     missing_observation="startup/cleanup details retained in private log")
            report["cleanup"] = "UNCONFIRMED_RETAINED"
            (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            raise
        cleanup = dict(server=False, browser=None)

        def stop_owned_server():
            try:
                stop_server(server, temp)
                cleanup["server"] = True
            finally:
                report["functional_result"] = report["result"]
                stopped = cleanup["server"] and cleanup["browser"] is not False
                report["process_cleanup"] = "PASS" if stopped else "UNCONFIRMED"
                report["cleanup"] = "FIXTURE_REMOVAL_PENDING" if stopped else "UNCONFIRMED_RETAINED"
                if "failure" not in report and report["result"] != "PASS":
                    report["failure"] = dict(code="BROWSER_SETUP_FAILED", phase=phase)
                if not stopped:
                    report["result"] = "FAIL"
                    report.setdefault("failure", dict(code="CLEANUP_UNCONFIRMED", phase=phase))
                evidence = (json.dumps(report, indent=2) + "\n").encode()
                receipt = args.output / "report.json"
                receipt.write_bytes(evidence)
                require(hashlib.sha256(receipt.read_bytes()).digest() == hashlib.sha256(evidence).digest(),
                        "durable_report_readback_failed_sources_retained")
                if stopped:
                    try:
                        shutil.rmtree(temp)
                        report["cleanup"] = "PASS"
                        receipt.write_text(json.dumps(report, indent=2) + "\n")
                    except Exception:
                        report["cleanup"] = "UNCONFIRMED_RETAINED"
                        report["result"] = "FAIL"
                        report.setdefault("failure", dict(code="OWNED_FIXTURE_REMOVAL_FAILED", phase=phase))
                        receipt.write_text(json.dumps(report, indent=2) + "\n")
                        raise

        lifecycle.callback(stop_owned_server)
        executable = args.browser or ("/usr/bin/microsoft-edge-stable" if args.engine == "chromium"
                                      else pw.firefox.executable_path)
        browser = getattr(pw, args.engine).launch(executable_path=executable, headless=True)
        report["browser_version"] = browser.version

        def close_owned_browser():
            cleanup["browser"] = False
            browser.close()
            cleanup["browser"] = True

        lifecycle.callback(close_owned_browser)
        context = browser.new_context(viewport=dict(width=1280, height=720),
                                      user_agent="KeyInventoryPractical", color_scheme="dark")
        page = context.new_page()

        def guard(route):
            url = route.request.url
            if not url.startswith(origin + "/"):
                report["external"] += 1
                route.abort()
            elif url.split("?", 1)[0] == origin + "/send":
                report["sends"] += 1
                route.abort()
            else:
                route.continue_()

        context.route("**/*", guard)

        def visit(path):
            response = page.goto(origin + path, wait_until="networkidle")
            report["requests"].append(dict(operation="page", path=path,
                                           status=response.status if response else None))
            require(response is not None and response.status == 200, "page_response_refused")
            return response

        def fits(code):
            metrics = page.evaluate("""() => ({width:innerWidth,height:innerHeight,
                documentWidth:document.documentElement.scrollWidth,
                documentHeight:document.documentElement.scrollHeight})""")
            require(metrics["documentWidth"] <= metrics["width"] + 1, code)
            return metrics

        def capture(name):
            page.screenshot(path=str(args.output / name), full_page=False)
            report["captures"].append(name)

        def panel_checks(target, path, style, touch=False):
            actual_style = target.locator("html").get_attribute("data-presentation-style")
            require(actual_style == style, "saved_presentation_style_mismatch")
            coarse = target.evaluate("matchMedia('(pointer:coarse)').matches || matchMedia('(any-pointer:coarse)').matches")
            if touch:
                require(coarse, "touch_capability_missing")
            def text_x(locator):
                return locator.evaluate("e => {const w=document.createTreeWalker(e,NodeFilter.SHOW_TEXT);let n;while(n=w.nextNode()){if(n.textContent.trim()){const r=document.createRange();r.selectNodeContents(n);return r.getBoundingClientRect().x}}return null}")
            def readable(selector):
                labels = target.locator(selector)
                require(labels.count() > 0, "panel_labels_missing")
                require(labels.evaluate_all("els => els.every(e => getComputedStyle(e).position === 'static' && e.getBoundingClientRect().width > 16)"),
                        "panel_text_labels_hidden")

            if path == "/mailboxes":
                summary = target.locator(".welcome-status-details>summary")
                reference = target.locator(".welcome-search>summary")
                signature = "e => {const s=getComputedStyle(e); return [s.fontFamily,s.fontSize,s.fontWeight,s.color,s.lineHeight]}"
                require(summary.evaluate(signature) == reference.evaluate(signature), "dashboard_link_typography_differs")
                for selector in [".welcome-browse>summary", ".welcome-search>summary", ".welcome-status-details>summary", ".welcome-activity-link", ".welcome-openpgp a", ".welcome-storage a", ".welcome-security-detail a", ".welcome-panel-heading a"]:
                    links = target.locator(selector)
                    require(links.count() > 0 and links.evaluate_all("els => els.every(e => e.textContent.trim().endsWith('→'))"),
                            "dashboard_destination_arrow_missing")
                note = target.locator(".welcome-messages>.welcome-note").first
                browse = target.locator(".welcome-browse>summary>.presentation-label")
                insets = dict(note=text_x(note), browse=text_x(browse), touch=touch, style=actual_style)
                report.setdefault("dashboard_insets", []).append(insets)
                if abs(insets["note"] - insets["browse"]) > 1:
                    target.screenshot(path=str(args.output / "dashboard-inset-failure.png"), full_page=False)
                require(abs(insets["note"] - insets["browse"]) <= 1, "dashboard_browse_inset_differs")
                # CSS empty-state probe only: native renderer/source tests cover the
                # actual empty text; this disposable DOM tests its shared CSS inset.
                target.locator(".welcome-recent").evaluate("list => {const p=document.createElement('p');p.className='welcome-empty';p.textContent='No messages were returned from Inbox.';list.before(p);list.remove()}")
                empty = target.locator(".welcome-messages>.welcome-empty")
                insets["empty"] = text_x(empty)
                require(abs(insets["note"] - insets["empty"]) <= 1, "dashboard_empty_inset_differs")
                summary.press("Space")
                require(target.locator(".welcome-status-details").get_attribute("open") is not None, "status_disclosure_keyboard_failed")
            elif path == "/folders":
                readable(".copies-details>a .presentation-label, .copies-details>.copies-secondary>summary .presentation-label")
                link = target.locator(".copies-details>a")
                require(link.get_attribute("href").startswith("/mailbox?name="), "folder_open_destination_changed")
                summary = target.locator(".copies-details>.copies-secondary>summary")
                summary.press("Space")
                require(summary.locator("..").get_attribute("open") is not None, "folder_disclosure_keyboard_failed")
            elif path == "/settings":
                readable("section[aria-labelledby=general-appearance-title] .presentation-label, section[aria-labelledby=general-composition-title] .general-card-actions>.presentation-text>.presentation-label, section[aria-labelledby=general-composition-title] summary>.presentation-label")
                for name, action in [("Save appearance", "/settings/display"), ("Save composition defaults", "/settings/composition"), ("Save signature choice", "/settings/signature")]:
                    control = target.get_by_role("button", name=name, exact=True)
                    require(control.evaluate("e => e.form.getAttribute('action')") == action, "general_form_association_changed")
            elif path.endswith("reading"):
                controls = target.locator(".reading-card-actions").first
                require(controls.locator(".presentation-label").evaluate_all("els => els.length === 3 && els.every(e => getComputedStyle(e).position === 'static')"), "reading_behaviour_labels_hidden")
                require(controls.locator("button").count() == 3, "reading_behaviour_actions_missing")
                for control in controls.locator("button").all():
                    require(control.evaluate("e => !!e.form && e.form.method === 'post' && !!e.form.querySelector('[name=csrf_token]')"), "reading_form_association_changed")
            elif path.endswith("security"):
                controls = target.locator(".security-overview-cards>.security-card").first.locator(".security-control>a")
                require(controls.count() == 5, "security_controls_missing")
                for control in controls.all():
                    expect(control.locator(".presentation-icon")).to_be_visible() if style == "icons" and not touch else None
                    label = control.locator(".presentation-label")
                    require(label.count() == 1, "security_action_label_missing")
                    if style == "text_labels" or touch:
                        require(label.evaluate("e => getComputedStyle(e).position === 'static'"), "security_text_or_touch_label_hidden")
                require(len(set(controls.evaluate_all("els => els.map(e=>e.getAttribute('href'))"))) == 5, "security_destinations_changed")
            require(target.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), "panel_control_overflow")
            report["checks"].append(dict(check="panel_controls", path=path, style=actual_style, touch=touch, coarse=coarse, result="PASS"))

        def login():
            visit("/login")
            page.get_by_label("Username or Email").fill("alice@example.com")
            page.get_by_label("Password", exact=True).fill("correct horse battery staple")
            page.get_by_label("TOTP Code").fill("123456")
            page.get_by_role("button", name="Sign In", exact=True).click()
            page.wait_for_url("**/mailboxes")

        try:
            phase = "mobile_login"
            for width, height in ([] if args.autosave_only or args.pages else [(360, 740), (390, 844)]):
                page.set_viewport_size(dict(width=width, height=height))
                visit("/login")
                metrics = fits("login_horizontal_overflow")
                footer = page.locator(".login-footer").bounding_box()
                report["checks"].append(dict(check="mobile_login", metrics=metrics, footer=footer))
                capture(f"login-{width}x{height}.png")
                require(footer is not None and footer["y"] + footer["height"] <= height + 1,
                        "login_privacy_footer_below_viewport")
            page.set_viewport_size(dict(width=1280, height=720))
            login()

            if not args.visual_only:
                phase = "autosave_preference"
                visit("/settings?section=composition")
                page.get_by_role("switch", name="Auto-save drafts", exact=True).check()
                page.get_by_label("Auto-save interval", exact=True).select_option("30")
                page.get_by_role("button", name="Save auto-save preferences", exact=True).click()
                page.wait_for_load_state("networkidle")
                page.clock.install()
                visit("/compose")
                expect(page.locator("#compose-auto-status")).to_contain_text("30 seconds")
                phase = "fresh_browser_autosave"
                page.locator("#compose-body").fill("Synthetic first automatic save.\nPublic test only.")
                with page.expect_response(lambda r: r.url == origin + "/drafts/autosave") as pending:
                    page.clock.run_for(30001)
                response = pending.value
                report["requests"].append(dict(operation="first_autosave", status=response.status,
                                               json_type=response.headers.get("content-type") == "application/json"))
                expect(page.locator("#compose-auto-status")).to_have_text("Auto-save confirmed.")
                draft = page.locator("input[name=draft_id]").input_value()
                require(page.locator("input[name=draft_revision]").input_value() == "1", "first_revision_invalid")
                phase = "existing_browser_autosave"
                page.locator("#compose-body").fill("Synthetic second automatic save 🦊\nExact persisted content.")
                with page.expect_response(lambda r: r.url == origin + "/drafts/autosave") as pending:
                    page.clock.run_for(30001)
                report["requests"].append(dict(operation="second_autosave", status=pending.value.status))
                expect(page.locator("#compose-auto-status")).to_have_text("Auto-save confirmed.")
                require(page.locator("input[name=draft_revision]").input_value() == "2", "second_revision_invalid")
                stored = context.new_page()
                stored.goto(origin + "/draft?id=" + draft, wait_until="networkidle")
                expect(stored.locator("#compose-body")).to_have_value("Synthetic second automatic save 🦊\nExact persisted content.")
                stored.close()
                report["checks"].append(dict(check="fresh_and_existing_browser_timer_and_readback", result="PASS"))
                capture("autosave-confirmed.png")

                phase = "confirmed_prewrite_refusal"
                other = context.new_page()
                other.goto(origin + "/settings?section=composition", wait_until="networkidle")
                other.get_by_role("switch", name="Auto-save drafts", exact=True).uncheck()
                other.get_by_role("button", name="Save auto-save preferences", exact=True).click()
                other.wait_for_load_state("networkidle")
                other.close()
                page.locator("#compose-body").fill("Synthetic retained manual correction.")
                saves = []
                page.on("response", lambda r: saves.append(r.status) if r.url == origin + "/drafts/autosave" else None)
                page.clock.run_for(30001)
                expect(page.locator("#compose-auto-status")).to_contain_text("saved preference is off")
                expect(page.locator("#compose-save")).to_be_enabled()
                expect(page.locator("#compose-save-status")).to_contain_text("Unsaved changes")
                count = len(saves)
                page.clock.run_for(90001)
                require(len(saves) == count and saves[-1] == 409, "known_refusal_automatically_retried")
                page.locator("#compose-save").click()
                page.wait_for_load_state("networkidle")
                expect(page.locator("#compose-body")).to_have_value("Synthetic retained manual correction.")
                require(page.locator("input[name=draft_revision]").input_value() == "3", "manual_correction_not_persisted")
                report["checks"].append(dict(check="known_prewrite_refusal_manual_correction_no_retry", result="PASS"))

                phase = "unknown_refusal"
                visit("/settings?section=composition")
                page.get_by_role("switch", name="Auto-save drafts", exact=True).check()
                page.get_by_role("button", name="Save auto-save preferences", exact=True).click()
                page.wait_for_load_state("networkidle")
                visit("/compose")
                attempts = []

                def unknown(route):
                    attempts.append(True)
                    route.fulfill(status=409, content_type="application/json",
                                  body='{"version":1,"state":"paused"}')

                page.route("**/drafts/autosave", unknown)
                page.locator("#compose-body").fill("Synthetic unknown response retained locally.")
                page.clock.run_for(30001)
                expect(page.locator("#compose-auto-status")).to_contain_text("server outcome is not confirmed")
                expect(page.locator("#compose-save")).to_be_disabled()
                page.clock.run_for(90001)
                require(len(attempts) == 1, "unknown_refusal_automatically_retried")
                expect(page.locator("#compose-body")).to_have_value("Synthetic unknown response retained locally.")
                report["checks"].append(dict(check="unknown_refusal_remains_locked_no_retry", result="PASS"))
                page.unroute("**/drafts/autosave", unknown)

            if not args.autosave_only:
                phase = "desktop_presentation"
                if not args.panel_controls:
                    visit("/compose")
                    page.locator("#compose-body").fill("Public synthetic draft for row-menu layout.")
                    page.locator("#compose-save").click()
                    page.wait_for_load_state("networkidle")
                for style in (["icons"] if args.pages and not args.panel_controls else ["icons", "text_labels"]):
                    visit("/settings?section=appearance")
                    form = page.locator('form[action="/settings/display"]')
                    form.locator('[name="presentation_style"]').select_option(style)
                    form.locator('button[type="submit"]').click()
                    page.wait_for_load_state("networkidle")
                    for width, height in ([(1280, 720)] if args.pages and not args.panel_controls else [(1280, 720), (1920, 1080)]):
                        page.set_viewport_size(dict(width=width, height=height))
                        for index, path in enumerate(args.pages or PAGES):
                            visit(path)
                            metrics = fits("active_page_horizontal_overflow")
                            report["checks"].append(dict(check="page_fit", path=path, style=style, metrics=metrics))
                            if width == 1280 and style == "icons":
                                capture(f"desktop-{index:02d}.png")
                            if args.panel_controls:
                                panel_checks(page, path, style)
                            if path == "/mailboxes" and style == "icons":
                                labels = page.locator(".welcome-page .presentation-text .presentation-label")
                                require(labels.count() >= 5, "dashboard_text_destinations_missing")
                                require(labels.evaluate_all("els => els.every(e => getComputedStyle(e).position === 'static' && e.getBoundingClientRect().width > 16)"), "dashboard_text_destinations_hidden")
                            if path == "/drafts":
                                menu = page.locator(".draft-discard").first
                                require(menu.count() == 1, "draft_menu_fixture_missing")
                                row = menu.locator("xpath=ancestor::tr")
                                before = row.bounding_box()
                                menu.locator("summary").click()
                                after = row.bounding_box()
                                panel = menu.locator(".draft-action-menu").bounding_box()
                                require(before is not None and after is not None and abs(before["height"] - after["height"]) < 1,
                                        "draft_menu_expands_row")
                                require(panel is not None and panel["x"] >= 0 and panel["x"] + panel["width"] <= width + 1,
                                        "draft_menu_clipped")
                                if style == "icons":
                                    caption = menu.locator("summary>.presentation-label").bounding_box()
                                    require(caption is not None and caption["x"] >= 0 and caption["x"] + caption["width"] <= width + 1,
                                            "draft_menu_hover_caption_clipped")
                                    menu.locator("summary").press("Shift+Tab")
                                    page.keyboard.press("Tab")
                                    caption = menu.locator("summary>.presentation-label").bounding_box()
                                    require(caption is not None and caption["x"] >= 0 and caption["x"] + caption["width"] <= width + 1,
                                            "draft_menu_focus_caption_clipped")
                                capture(f"draft-menu-{style}-{width}.png")
                                menu.locator("summary").click()
                            if path in ["/settings?section=composition", "/settings/keys?panel=import#public-import"] and style == "icons":
                                control = page.get_by_role("button", name="Save composition preferences" if path.endswith("composition") else "Import public certificate", exact=True)
                                control.scroll_into_view_if_needed()
                                control.hover()
                                label = control.locator(".presentation-label").bounding_box()
                                require(label is not None and label["x"] >= 0 and label["x"] + label["width"] <= width + 1,
                                        "action_tooltip_outside_viewport")
                if args.pages and "/mailboxes" in args.pages and not args.panel_controls:
                    phase = "cleared_activity"
                    visit("/notifications")
                    page.get_by_role("button", name="Delete all notifications", exact=True).click()
                    page.wait_for_load_state("networkidle")
                    visit("/mailboxes")
                    empty = page.locator(".welcome-activity-empty-row")
                    expect(empty).to_contain_text("No retained notices")
                    box = empty.bounding_box()
                    require(box is not None and box["width"] > 200 and box["height"] < 80,
                            "cleared_activity_not_full_width")
                    capture("cleared-activity.png")
                    report["checks"].append(dict(check="cleared_activity_full_width", result="PASS"))
                phase = "touch_presentation"
            if not args.autosave_only and args.engine == "chromium" and (not args.pages or args.panel_controls):
                if args.panel_controls:
                    visit("/settings?section=appearance")
                    form = page.locator('form[action="/settings/display"]')
                    form.locator('[name="presentation_style"]').select_option("icons")
                    form.locator('button[type="submit"]').click()
                    page.wait_for_load_state("networkidle")
                touch = browser.new_context(viewport=dict(width=768, height=1024), has_touch=True,
                                            storage_state=context.storage_state(), user_agent="KeyInventoryPractical")
                touch.route("**/*", guard)
                tp = touch.new_page()
                tp.goto(origin + "/settings?section=security", wait_until="networkidle")
                require(tp.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), "touch_overflow")
                labels = tp.locator(".settings-navigation .presentation-label")
                require(labels.count() > 0 and labels.first.is_visible(), "touch_labels_missing")
                if args.panel_controls:
                    for path in args.pages:
                        tp.goto(origin + path, wait_until="networkidle")
                        panel_checks(tp, path, "icons", touch=True)
                    tp.goto(origin + "/settings?section=security", wait_until="networkidle")
                tp.screenshot(path=str(args.output / "touch-security.png"), full_page=False)
                report["captures"].append("touch-security.png")
                if args.panel_controls:
                    require(tp.locator("html").get_attribute("data-presentation-style") == "icons" and tp.evaluate("matchMedia('(pointer:coarse)').matches || matchMedia('(any-pointer:coarse)').matches"), "touch_capture_state_mismatch")
                touch.close()
            require(report["external"] == 0 and report["sends"] == 0, "unexpected_external_or_send")
            report["result"] = "PASS"
        except Exception:
            report["failure"] = dict(code="PRESENTATION_OR_AUTOSAVE_CHECK_FAILED", phase=phase,
                                     cleanup="existing_fixture_cleanup_pending")
            if phase not in ["fixture_start", "mobile_login"] and "/login" not in page.url:
                capture("failure.png")
            raise
        finally:
            (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            lifecycle.close()
    print(json.dumps(dict(result=report["result"], checks=len(report["checks"]))))


if __name__ == "__main__":
    main()
