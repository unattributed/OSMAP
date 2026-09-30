#!/usr/bin/env python3
"""Synthetic native Search navigation and presentation; no message mutations."""
import argparse
import json
from pathlib import Path
import tempfile
from urllib.parse import parse_qs, urlsplit
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
    with tempfile.TemporaryDirectory(prefix='osmap-search-ui-') as temp, (args.output/'server.log').open('w') as log, sync_playwright() as pw:
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
            elif req.method == 'POST' and urlsplit(req.url).path != '/login':
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
            visit('/search')
            expect(p.get_by_text('Enter keywords to search your mail.', exact=True)).to_be_visible()
            p.get_by_label('Search query', exact=True).fill('fieldfilter')
            p.locator('.search-options summary').click()
            p.locator('#search-field').select_option('subject')
            p.locator('main').get_by_role('button', name='Search', exact=True).click()
            p.wait_for_load_state('networkidle')
            expect(p.get_by_role('link', name='Subject field selected', exact=True)).to_be_visible()
            p.get_by_role('link', name='Unread', exact=True).focus()
            with p.expect_navigation(wait_until='networkidle'): p.keyboard.press('Enter')
            assert all(value in p.url for value in ('field=subject','q=fieldfilter','filter=unread'))
            p.locator('.message-sort summary').click()
            p.get_by_role('link', name='Sort by Subject ascending', exact=True).click()
            p.wait_for_load_state('networkidle')
            assert all(value in p.url for value in ('field=subject','q=fieldfilter','filter=unread','sort=subject'))
            p.get_by_label('Search query', exact=True).fill('ux-empty-fixture')
            p.locator('main').get_by_role('button', name='Search', exact=True).click()
            p.wait_for_load_state('networkidle')
            expect(p.get_by_text('No messages matched this search.', exact=False)).to_be_visible()
            visit('/search?q=ux-empty-fixture&field=subject&scope=all&filter=unread&attachment=with&after=2026-03-01')
            p.get_by_role('link', name='Clear filters', exact=True).click()
            p.wait_for_load_state('networkidle')
            cleared = parse_qs(urlsplit(p.url).query)
            assert cleared == dict(q=['ux-empty-fixture'], field=['subject'], scope=['all'])
            report['native_checks'] = ['authenticated empty landing', 'native query and field submission', 'keyboard unread retains query and field', 'sort retains filter context', 'empty results and native clear filters preserves keywords and search scope']
            for scheme in ('light', 'dark'):
                for width in (1600,360):
                    for forced in ('none','active'):
                        p.set_viewport_size(dict(width=width,height=1100))
                        p.emulate_media(color_scheme=scheme,forced_colors=forced)
                        visit('/search?q=quarterly&scope=all')
                        audit=p.evaluate(TEXT_AUDIT)
                        overflow=p.evaluate('document.documentElement.scrollWidth > innerWidth')
                        file=f'search-{scheme}-{width}-{forced}.png'
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
