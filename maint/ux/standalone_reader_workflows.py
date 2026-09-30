#!/usr/bin/env python3
"""Synthetic standalone approved reader, protected content and native actions."""
import argparse
import json
from pathlib import Path
import tempfile
from urllib.parse import urlsplit, parse_qs, urlencode
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
    with tempfile.TemporaryDirectory(prefix='osmap-reader-ui-') as temp, (args.output/'server.log').open('w') as log, sync_playwright() as pw:
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
            elif req.method == 'POST' and urlsplit(req.url).path not in ('/login', '/message/flag', '/message/move', '/settings'):
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
            visit('/message?mailbox=INBOX&uid=9')
            expect(p.locator('.body-panel pre')).to_have_text('Hello world')
            p.get_by_role('link',name='View source',exact=True).press('Enter')
            p.wait_for_load_state('networkidle')
            assert p.locator('pre.message-source').is_visible()
            assert p.locator('script').count()==0
            visit('/message?mailbox=INBOX&uid=9')
            for index in range(1):
                link=p.locator('.reader-attachments').get_by_role('link',name='Download',exact=True).nth(index)
                response=p.context.request.get(origin+link.get_attribute('href'))
                assert response.status==200 and response.headers['content-disposition'].startswith('attachment;')
                assert response.headers['x-content-type-options']=='nosniff'
                with p.expect_download() as download: link.click()
                assert Path(download.value.path()).read_bytes()==response.body()
            for name in ('Read message #9 in INBOX','Star message #9 in INBOX'):
                button=p.get_by_role('button',name=name,exact=True)
                if name.startswith('Star'): p.locator('.reader-more-actions > summary').click()
                previous=button.get_attribute('aria-pressed')
                button.press('Enter')
                p.wait_for_load_state('networkidle')
                expect(p.get_by_role('button',name=name,exact=True,include_hidden=True)).to_have_attribute('aria-pressed','false' if previous=='true' else 'true')
            p.locator('.reader-more-actions > summary').press('Enter')
            expect(p.get_by_role('button',name='Move to Bin',exact=True)).to_be_visible()
            assert p.get_by_label('Destination Mailbox').locator('option').count()>0
            p.locator('.reader-more-actions > summary').press('Enter')
            for name in ('Reply to message','Reply','Reply all','Forward'):
                p.get_by_role('link',name=name,exact=True).click()
                p.wait_for_load_state('networkidle')
                expect(p.locator('#compose-body')).to_contain_text('Hello world')
                visit('/message?mailbox=INBOX&uid=9')
            for scheme in ('light', 'dark'):
                for width in (1600,360):
                    for forced in ('none','active'):
                        p.set_viewport_size(dict(width=width,height=1100))
                        p.emulate_media(color_scheme=scheme,forced_colors=forced)
                        visit('/message?mailbox=INBOX&uid=9')
                        audit=p.evaluate(TEXT_AUDIT)
                        overflow=p.evaluate('document.documentElement.scrollWidth > innerWidth')
                        file=f'reader-{scheme}-{width}-{forced}.png'
                        p.screenshot(path=str(args.output/file),full_page=True)
                        report['captures'].append(dict(file=file,overflow=overflow,contrast=audit,boxes=p.locator('.reader-toolbar,.message-heading,.reader-status,.reader-boundary-note,.body-panel,.reader-attachments,.reader-primary-actions').evaluate_all('els=>els.map(e=>({class:e.className,top:e.getBoundingClientRect().top,bottom:e.getBoundingClientRect().bottom}))')))
                        assert not overflow and not audit['failures'] and not audit['ui_failures'],file
            p.set_viewport_size(dict(width=1600,height=1100))
            visit('/settings?section=copies')
            p.locator('#copies-archive').select_option('INBOX.Projects')
            p.get_by_role('button',name='Save archive folder',exact=True).click();p.wait_for_load_state('networkidle')
            visit('/message?mailbox=INBOX&uid=123')
            p.get_by_role('button',name='Archive message',exact=True).click();p.wait_for_load_state('networkidle')
            visit('/mailbox?name=INBOX.Projects')
            p.locator('.message-subject-link, .archive-subject').filter(has_text='Message 123').first.click();p.wait_for_load_state('networkidle')
            if urlsplit(p.url).path != '/message':
                selected=parse_qs(urlsplit(p.url).query)
                visit('/message?'+urlencode(dict(mailbox=selected['selected_mailbox'][0],uid=selected['selected_uid'][0])))
            p.get_by_role('button',name='Move message to Bin',exact=True).click();p.wait_for_load_state('networkidle')
            visit('/mailbox?name=Trash')
            p.locator('.message-subject-link, .archive-subject').filter(has_text='Message 123').first.click();p.wait_for_load_state('networkidle')
            if urlsplit(p.url).path != '/message':
                selected=parse_qs(urlsplit(p.url).query)
                visit('/message?'+urlencode(dict(mailbox=selected['selected_mailbox'][0],uid=selected['selected_uid'][0])))
            p.get_by_role('button',name='Restore message to Inbox',exact=True).click();p.wait_for_load_state('networkidle')
            visit('/mailbox?name=INBOX')
            expect(p.locator('.message-subject-link').filter(has_text='Message 123')).to_be_visible()
            report['functional_checks']=['Bounded source view','Native PDF download matches returned bytes; second surfaced file lacks a downloadable fixture','Read/star persist after native POST','Native top Archive, Bin and Restore return owned message to Inbox','Reply/reply-all/forward quote source; no sends']
            assert report['external_requests'] == report['post_requests'] == report['script_requests'] == 0
            report['result'] = 'PASS'
        finally:
            (args.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
            browser.close()
            stop_server(server, root)
    print(json.dumps(dict(result=report['result'], captures=len(report['captures']))))

if __name__ == '__main__': main()
