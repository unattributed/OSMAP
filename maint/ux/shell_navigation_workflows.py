#!/usr/bin/env python3
"""Synthetic native approved navigation and responsive authenticated header."""
import argparse
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
    report = dict(result='FAIL', captures=[], external_requests=0, post_requests=0, script_requests=0)
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
            elif req.method == 'POST' and urlsplit(req.url).path not in ('/login', '/settings'):
                report['post_requests'] += 1
                route.abort()
            else:
                if req.resource_type == 'script': report['script_requests'] += 1
                route.continue_()
        ctx.route('**/*', bounded)
        p = ctx.new_page()
        def visit(path):
            response = p.goto(origin+path, wait_until='networkidle')
            assert response.status == 200
            assert response.headers['cache-control'] == 'no-store'
        try:
            visit('/login')
            p.get_by_label('Username or Email').fill('alice@example.com')
            p.get_by_label('Password', exact=True).fill('correct horse battery staple')
            p.get_by_label('TOTP Code').fill('123456')
            p.get_by_role('button', name='Sign In', exact=True).click()
            p.wait_for_load_state('networkidle')
            visit('/mailboxes')
            expect(p.locator('.topbar-welcome .brand-copy small')).to_be_visible()
            def rail(name):
                nav = p.get_by_role('navigation', name='Primary navigation')
                link = nav.get_by_role('link', name=name, exact=True)
                link.focus()
                p.keyboard.press('Enter')
                p.wait_for_load_state('networkidle')
                return nav
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
                for width in (1536, 1199, 768, 360):
                    for forced in ('none', 'active'):
                        p.set_viewport_size(dict(width=width, height=1100))
                        p.emulate_media(color_scheme=scheme, forced_colors=forced)
                        visit('/settings?section=security')
                        if width == 360: p.locator('.rail-disclosure summary').press('Enter')
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
            assert report['external_requests'] == report['post_requests'] == report['script_requests'] == 0
            report['result'] = 'PASS'
        finally:
            (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
            browser.close()
            stop_server(server, root)
    print(json.dumps(dict(result=report['result'], captures=len(report['captures']))))

if __name__ == '__main__': main()
