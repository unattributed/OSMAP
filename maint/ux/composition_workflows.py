#!/usr/bin/env python3
"""Native PAGE15/General proof; isolated synthetic accounts, no sends or page JS.

Test-driver DOM evaluation measures rendering only. Compose's existing inline
script is present but disabled. No tokens, cookies or request bodies are retained.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time
from urllib.parse import urlencode, urlsplit
from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server
from contrast_audit import TEXT_AUDIT

SETTINGS = '/settings?section=composition'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--engine', choices=['chromium', 'firefox'], default='chromium')
    parser.add_argument('--browser', default='/usr/bin/microsoft-edge-stable')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    out = args.output
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    out.chmod(0o700)
    prior = [p for p in out.iterdir() if p.is_file()]
    if prior:
        archive = out/'prior-attempts'/str(time.time_ns())
        archive.mkdir(parents=True, mode=0o700)
        for p in prior: shutil.copy2(p, archive/p.name)
    report = dict(result='FAIL', synthetic_only=True, real_stores=True, engine=args.engine,
                  checks=[], captures=[], external_requests=0, script_requests=0, send_requests=0)
    with tempfile.TemporaryDirectory(prefix='osmap-composition-browser-') as temporary, \
            (out/'synthetic-server.log').open('w') as log, sync_playwright() as pw:
        root = Path(temporary)
        process, origin = start_server(root, repo, log)
        browser = getattr(pw, args.engine).launch(executable_path=args.browser, headless=True)
        report['browser_version'] = browser.version

        def visit(p, path=SETTINGS, status=200):
            response = p.goto(origin+path, wait_until='networkidle')
            assert response.status == status, (path, response.status)
            assert response.headers['cache-control'] == 'no-store'
            if p.locator('#compose-form').count():
                assert p.locator('script:not(#osmap-compose-local)').count() == 0
                assert p.locator('.compose-recipient-editor').count() == 0
            else: assert p.locator('script').count() == 0

        def submit(p, name, status=200):
            button = p.get_by_role('button', name=name, exact=True)
            button.focus()
            with p.expect_navigation(wait_until='networkidle') as navigation:
                p.keyboard.press('Enter')
            assert navigation.value.status == status, (name, navigation.value.status)

        def login(account='alice'):
            ctx = browser.new_context(java_script_enabled=False, viewport=dict(width=1600, height=1100),
                                      color_scheme='light', user_agent='CompositionLiteralSource')
            def constrain(route):
                req = route.request
                if req.resource_type == 'script': report['script_requests'] += 1
                if urlsplit(req.url).path == '/send':
                    report['send_requests'] += 1
                    route.abort()
                elif req.url.startswith(origin+'/'): route.continue_()
                else:
                    report['external_requests'] += 1
                    route.abort()
            ctx.route('**/*', constrain)
            p = ctx.new_page()
            visit(p, '/login')
            p.get_by_label('Username or Email').fill(account+'@example.com')
            p.get_by_label('Password', exact=True).fill('correct horse battery staple')
            p.get_by_label('TOTP Code').fill('123456')
            submit(p, 'Sign In')
            return p

        def saved(p, mode='formatted', placement='below'):
            visit(p)
            expect(p.get_by_label('Format', exact=True)).to_have_value(mode)
            expect(p.get_by_label('Reply placement', exact=True)).to_have_value(placement)

        def preferences(p, mode, placement):
            visit(p)
            p.get_by_label('Format', exact=True).select_option(mode)
            p.get_by_label('Reply placement', exact=True).select_option(placement)
            submit(p, 'Save composition preferences')
            assert p.url.endswith('/settings?section=composition&updated=1')
            saved(p, mode, placement)

        def post(p, fields, expected=303):
            response = p.context.request.post(origin+'/settings/composition', data=urlencode(fields),
                headers={'Origin':origin, 'Content-Type':'application/x-www-form-urlencoded'}, max_redirects=0)
            assert response.status == expected

        def draft(p, mode):
            visit(p, '/compose')
            p.locator('#compose-to').fill('desk@example.test')
            p.locator('#compose-subject').fill('Synthetic saved '+mode)
            p.locator('#compose-body').fill('**Literal** [x](https://example.test)')
            p.locator('#compose-body-format').select_option(mode)
            submit(p, 'Save Draft')
            return p.url.removeprefix(origin)

        try:
            p = login()
            saved(p, 'plain', 'above')
            record = root/'settings'/(hashlib.sha256(b'osmap-composition-preferences-v1\0alice@example.com').hexdigest()+'.json')
            assert not record.exists()
            record.parent.mkdir(exist_ok=True, mode=0o700)
            record.parent.chmod(0o700)
            legacy = b'{"version":1,"default_body_format":"formatted"}\n'
            record.write_bytes(legacy)
            record.chmod(0o600)
            saved(p, 'formatted', 'above')
            assert record.read_bytes() == legacy
            old_plain, old_formatted = draft(p, 'plain'), draft(p, 'formatted')
            preferences(p, 'formatted', 'below')
            assert json.loads(record.read_bytes()) == dict(version=2, default_body_format='formatted', reply_placement='below')
            report['checks'].append('Absent defaults and v1 Above read without rewrite; native save upgrades private record to v2')
            visit(p, '/compose')
            expect(p.locator('#compose-body-format')).to_have_value('formatted')
            expect(p.locator('#compose-body')).to_have_value('')
            for path, mode, opposite in [(old_plain, 'plain', 'formatted'), (old_formatted, 'formatted', 'plain')]:
                preferences(p, opposite, 'below')
                visit(p, path)
                expect(p.locator('#compose-body-format')).to_have_value(mode)
                expect(p.locator('#compose-body')).to_have_value('**Literal** [x](https://example.test)')
            preferences(p, 'formatted', 'above')
            visit(p, '/compose?mode=reply&mailbox=INBOX&uid=9')
            above = p.locator('#compose-body').input_value()
            visit(p, '/compose?mode=forward&mailbox=INBOX&uid=9')
            forward = p.locator('#compose-body').input_value()
            preferences(p, 'formatted', 'below')
            for mode in ['reply', 'reply-all', 'forward']:
                visit(p, '/compose?'+urlencode(dict(mode=mode, mailbox='INBOX', uid=9)))
                expect(p.locator('#compose-body-format')).to_have_value('plain')
                body = p.locator('#compose-body').input_value()
                assert '[x](unsupported:target)' in body and '**literal**' in body
                # HTML textarea parsing strips the first leading LF from Above.
                assert above.startswith('\n') and not above.startswith('\n\n')
                assert body == (forward if mode == 'forward' else above[1:]+'\n\n')
            report['checks'].append('New blank format applies; opposite-default saved drafts retain format/source; reply/reply-all move only blank lines and preserve literal notation; forward unchanged')
            visit(p, '/settings?section=general')
            p.get_by_label('Default format', exact=True).select_option('plain')
            expect(p.get_by_label('Reply placement', exact=True)).to_have_value('below')
            submit(p, 'Save composition defaults')
            saved(p, 'plain', 'below')
            token = p.locator('[name="csrf_token"]').first.input_value()
            post(p, dict(csrf_token=token, default_body_format='formatted'))
            saved(p)
            report['checks'].append('General native format change preserves selected Below; legacy format-only POST preserves stored placement')
            saved(login('bob'), 'plain', 'above')
            for ctx in browser.contexts: ctx.close()
            stop_server(process, root)
            process, origin = start_server(root, repo, log)
            p = login()
            saved(p)
            saved(login('bob'), 'plain', 'above')
            report['checks'].append('Restart restores Alice defaults; Bob remains isolated at Plain/Above')
            original = record.read_bytes()
            visit(p)
            # Corrupt after the user has loaded a legitimate editable form.
            record.write_bytes(b'{"version":99}\n')
            submit(p, 'Save composition preferences', 503)
            expect(p.get_by_text('The preference save could not be confirmed.', exact=False)).to_be_visible()
            assert record.read_bytes() == b'{"version":99}\n'
            visit(p)
            expect(p.get_by_label('Format', exact=True)).to_be_disabled()
            expect(p.get_by_label('Reply placement', exact=True)).to_be_disabled()
            expect(p.get_by_text('Saved composition preferences are unavailable.', exact=False)).to_be_visible()
            report['checks'].append('Corrupt record rejects native save with truthful uncertainty; reload disables unavailable preferences without overwriting data')
            record.write_bytes(original)
            for scheme in ['light', 'dark']:
                for width in [1600, 768, 360]:
                    for forced in ['none', 'active']:
                        p.set_viewport_size(dict(width=width, height=1100))
                        p.emulate_media(color_scheme=scheme, forced_colors=forced)
                        visit(p)
                        assert p.evaluate('document.documentElement.scrollWidth <= innerWidth')
                        p.get_by_label('Format', exact=True).focus()
                        expect(p.get_by_label('Format', exact=True)).to_be_focused()
                        audit = p.evaluate(TEXT_AUDIT)
                        filename = f'composition-{scheme}-{width}'+('-forced' if forced=='active' else '')+'.png'
                        p.screenshot(path=str(out/filename), full_page=True)
                        report['captures'].append(dict(file=filename, overflow=False, contrast=audit, card_boxes=p.locator('.composition-settings-grid > section').evaluate_all('els=>els.map(e=>({top:e.getBoundingClientRect().top,bottom:e.getBoundingClientRect().bottom}))')))
                        assert not audit['failures'] and not audit['ui_failures'], filename
            assert report['external_requests'] == report['script_requests'] == report['send_requests'] == 0
            report['limitations'] = ['Compose retains its existing inline enhancement script, disabled by browser context; no page scripts execute.', 'Computed flat-colour audit is not full accessibility certification; native controls and forced palettes require visual review.', 'Pre-publication I/O failure and concurrent-writer guarantees rely on focused Rust store tests.']
            report['result'] = 'PASS'
        except Exception as error:
            report['failure_type'] = type(error).__name__
            raise
        finally:
            (out/'workflows.json').write_text(json.dumps(report, indent=2)+'\n')
            browser.close()
            stop_server(process, root)
    print(json.dumps(dict(result=report['result'], checks=len(report['checks']), report=str(out/'workflows.json'))))


if __name__ == '__main__': main()
