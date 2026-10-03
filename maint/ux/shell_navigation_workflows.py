#!/usr/bin/env python3
"""Synthetic native approved navigation and responsive authenticated header."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import tempfile
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright, expect
from browser_workflows import start_server, stop_server
from contrast_audit import TEXT_AUDIT

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--engine', default='chromium')
    parser.add_argument('--browser', default='/usr/bin/microsoft-edge-stable')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = dict(result='FAIL', captures=[], navigation=[], external_requests=0, post_requests=0, script_requests=0, send_requests=0)
    with tempfile.TemporaryDirectory(prefix='osmap-shell-ui-') as temp, (args.output/'server.log').open('w') as log, sync_playwright() as pw:
        root = Path(temp)
        server, origin = start_server(root, Path(__file__).resolve().parents[2], log)
        browser = getattr(pw, args.engine).launch(executable_path=args.browser, headless=True)
        report['browser_version'] = browser.version
        ctx = browser.new_context(java_script_enabled=False, viewport=dict(width=1600, height=1100))
        def bounded(route):
            req = route.request
            if not req.url.startswith(origin+'/'):
                report['external_requests'] += 1
                route.abort()
            elif urlsplit(req.url).path == '/send':
                report['send_requests'] += 1
                route.abort()
            elif req.method == 'POST' and urlsplit(req.url).path not in ('/login', '/settings'):
                report['post_requests'] += 1
                route.abort()
            else:
                if req.resource_type == 'script': report['script_requests'] += 1
                route.continue_()
        ctx.route('**/*', bounded)
        p = ctx.new_page()
        trusted_script = (Path(__file__).resolve().parents[2] / 'src/http/compose_local.js').read_bytes()
        trusted_hash = 'sha256-' + base64.b64encode(hashlib.sha256(trusted_script).digest()).decode('ascii')
        assert trusted_hash == 'sha256-kh8tYa8AQwqxy9l64g1sCx8epjT43a/Wj5pR91Smywc='
        base_csp = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        def response_boundary(response):
            assert response and response.status == 200
            assert response.headers['cache-control'] == 'no-store'
            csp = response.all_headers().get('content-security-policy')
            if urlsplit(response.url).path == '/compose':
                assert p.locator('script').count() == 1
                script = p.locator('script#osmap-compose-local')
                assert script.count() == 1
                assert script.evaluate('e => [...e.attributes].map(a => [a.name, a.value])') == [['id', 'osmap-compose-local']]
                assert script.text_content() == trusted_script.decode('utf-8')
                assert csp == base_csp + f"; connect-src 'self'; script-src '{trusted_hash}'; script-src-attr 'none'"
            else:
                assert p.locator('script').count() == 0
                assert csp == base_csp
        def visit(path):
            response = p.goto(origin+path, wait_until='networkidle')
            response_boundary(response)
        def selected_page(path, heading, current, response):
            response_boundary(response)
            assert response.request.method == 'GET'
            assert p.url == origin + path
            expect(p.get_by_role('heading', name=heading, exact=True, level=1)).to_be_visible()
            selected = p.get_by_role('navigation', name='Primary navigation').locator('[aria-current=page]')
            expect(selected).to_have_count(1)
            expect(selected).to_have_text(current)
            report['navigation'].append(dict(path=path, heading=heading, selected=current, method='GET'))
        try:
            visit('/login')
            p.get_by_label('Username or Email').fill('alice@example.com')
            p.get_by_label('Password', exact=True).fill('correct horse battery staple')
            p.get_by_label('TOTP Code').fill('123456')
            p.get_by_role('button', name='Sign In', exact=True).click()
            p.wait_for_load_state('networkidle')
            visit('/mailboxes')
            expect(p.locator('.topbar-welcome .brand-copy small')).to_be_visible()
            def rail(name, path=None, heading=None, current=None):
                nav = p.get_by_role('navigation', name='Primary navigation')
                link = nav.get_by_role('link', name=name, exact=True)
                link.focus()
                expect(link).to_be_focused()
                with p.expect_navigation(wait_until='networkidle') as navigation:
                    p.keyboard.press('Enter')
                if path is not None:
                    selected_page(path, heading, current, navigation.value)
                return nav
            for name, path, heading in [
                ('Inbox', '/mailbox?name=INBOX', 'Inbox'),
                ('Sent', '/mailbox?name=Sent', 'Sent'),
                ('Drafts', '/drafts', 'Drafts'),
                ('Compose', '/compose', 'Compose'),
                ('Mailbox', '/mailboxes', 'Welcome back.'),
                ('Search', '/search', 'Search'),
            ]:
                rail(name, path, heading, name)
            p.locator('.account-menu summary').focus()
            p.keyboard.press('Enter')
            expect(p.locator('.account-menu')).to_have_attribute('open', '')
            sessions = p.locator('.account-menu').get_by_role('link', name='Manage sessions', exact=True)
            sessions.focus()
            expect(sessions).to_be_focused()
            with p.expect_navigation(wait_until='networkidle') as navigation:
                p.keyboard.press('Enter')
            selected_page('/sessions', 'Active Sessions', 'Settings', navigation.value)
            brand = p.get_by_role('link', name='OSMAP mailboxes', exact=True)
            brand.focus()
            expect(brand).to_be_focused()
            with p.expect_navigation(wait_until='networkidle') as navigation:
                p.keyboard.press('Enter')
            selected_page('/mailboxes', 'Welcome back.', 'Mailbox', navigation.value)
            rail('Security')
            expect(p.locator('.rail-links [aria-current=page]')).to_have_text('Settings')
            rail('Settings')
            expect(p.locator('.rail-links [aria-current=page]')).to_have_text('Settings')
            rail('Archive / Bin')
            expect(p.get_by_role('heading', name='Choose Your Archive Mailbox')).to_be_visible()
            p.locator('.global-search-menu summary').press('Enter')
            p.get_by_role('link', name='Open Bin', exact=True).press('Enter')
            p.wait_for_url('**/mailbox?name=Trash**')
            expect(p.locator('.rail-links [aria-current=page]')).to_have_text('Archive / Bin')
            assert p.locator('.archive-tabs a').count() > 0
            visit('/settings?section=copies')
            p.locator('#copies-archive').select_option('INBOX.Projects')
            p.get_by_role('button', name='Save archive folder', exact=True).click()
            p.wait_for_url('**updated=1')
            rail('Archive / Bin')
            p.wait_for_url('**/mailbox?name=INBOX.Projects**')
            p.get_by_role('navigation',name='Archive and Bin').get_by_role('link',name='Bin',exact=True).press('Enter')
            p.wait_for_url('**/mailbox?name=Trash**')
            p.get_by_role('navigation',name='Archive and Bin').get_by_role('link',name='Archive',exact=True).press('Enter')
            p.wait_for_url('**/mailbox?name=INBOX.Projects**')
            for scheme in ('light', 'dark'):
                for width in (1600, 1536, 1199, 768, 360):
                    for forced in ('none', 'active'):
                        p.set_viewport_size(dict(width=width, height=1100))
                        p.emulate_media(color_scheme=scheme, forced_colors=forced)
                        visit('/settings?section=security')
                        if width <= 768:
                            expect(p.locator('.rail-storage')).to_be_hidden()
                            p.locator('.rail-disclosure summary').press('Enter')
                        expect(p.locator('.rail-storage')).to_be_visible()
                        expect(p.locator('.rail-storage')).to_have_text('StorageUsage unavailable')
                        assert p.locator('.rail-storage [role=progressbar],.rail-storage meter,.rail-storage progress').count() == 0
                        nav=p.get_by_role('navigation',name='Primary navigation')
                        expect(p.locator('.brand')).to_have_text('OSMAP')
                        assert p.locator('.brand-copy').count() == 0
                        assert nav.locator('[aria-current=page]').count()==1
                        expect(nav.locator('[aria-current=page]')).to_have_text('Settings')
                        expect(nav.get_by_role('link',name='Documents, unavailable')).to_be_disabled()
                        nav.get_by_role('link',name='Archive / Bin',exact=True).focus()
                        expect(nav.get_by_role('link',name='Archive / Bin',exact=True)).to_be_focused()
                        audit=p.evaluate(TEXT_AUDIT)
                        overflow=p.evaluate('document.documentElement.scrollWidth > innerWidth')
                        file=f'shell-{scheme}-{width}-{forced}.png'
                        p.screenshot(path=str(args.output/file),full_page=True)
                        report['captures'].append(dict(file=file,overflow=overflow,contrast=audit))
                        assert not overflow and not audit['failures'] and not audit['ui_failures'],file
            for scheme in ('light','dark'):
                for width in (1600,768,360):
                    p.set_viewport_size(dict(width=width,height=420))
                    p.emulate_media(color_scheme=scheme,forced_colors='active')
                    visit('/sessions')
                    if width <= 768: p.locator('.rail-disclosure summary').press('Enter')
                    p.locator('.rail-links').get_by_role('link',name='Search',exact=True).focus()
                    p.locator('.rail-storage').scroll_into_view_if_needed()
                    box=p.locator('.rail-storage').bounding_box()
                    assert box['y'] >= 0 and box['y']+box['height'] <= 420
                    assert p.evaluate('document.documentElement.scrollWidth <= innerWidth')
                    filename=f'shell-storage-short-{scheme}-{width}.png'
                    p.screenshot(path=str(args.output/filename))
                    report['captures'].append(dict(file=filename,overflow=False,contrast=p.evaluate(TEXT_AUDIT)))
            assert all(not c['contrast']['failures'] and not c['contrast']['ui_failures'] for c in report['captures'])
            assert report['external_requests'] == report['post_requests'] == report['script_requests'] == report['send_requests'] == 0
            report['result'] = 'PASS'
        finally:
            (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
            browser.close()
            stop_server(server, root)
    print(json.dumps(dict(result=report['result'], captures=len(report['captures']))))

if __name__ == '__main__': main()
