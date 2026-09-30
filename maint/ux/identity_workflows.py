#!/usr/bin/env python3
"""Native PAGE13 profile persistence, isolation, stale and invalid form recovery."""
import argparse
import json
from pathlib import Path
import tempfile
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
    report = dict(result='FAIL', checks=[], captures=[], external=0, scripts=0, sends=0)
    with tempfile.TemporaryDirectory(prefix='osmap-identity-ui-') as temp, (args.output/'server.log').open('w') as log, sync_playwright() as pw:
        root = Path(temp)
        server, origin = start_server(root, Path(__file__).resolve().parents[2], log)
        browser = getattr(pw, args.engine).launch(executable_path=args.browser, headless=True)
        report['browser'] = browser.version
        def login(account):
            context = browser.new_context(java_script_enabled=False, user_agent='OSMAP/SentCopyUnconfirmed', viewport=dict(width=1600, height=1100))
            def bounded(route):
                req = route.request
                if req.resource_type == 'script': report['scripts'] += 1
                if req.url.split('?')[0] == origin+'/send':
                    report['sends'] += 1
                    route.continue_()
                elif req.url.startswith(origin+'/'): route.continue_()
                else:
                    report['external'] += 1
                    route.abort()
            context.route('**/*', bounded)
            p = context.new_page()
            p.goto(origin+'/login')
            p.get_by_label('Username or Email').fill(account+'@example.com')
            p.get_by_label('Password', exact=True).fill('correct horse battery staple')
            p.get_by_label('TOTP Code').fill('123456')
            p.get_by_role('button', name='Sign In', exact=True).click()
            p.wait_for_url('**/mailboxes')
            return p
        def visit(p):
            r = p.goto(origin+'/settings?section=identity', wait_until='networkidle')
            assert r.status == 200
            assert r.headers['cache-control'] == 'no-store'
        def submit(p, status=200):
            with p.expect_navigation(wait_until='networkidle') as navigation:
                p.get_by_role('button', name='Save identity', exact=True).press('Enter')
            assert navigation.value.status == status
        def fields(p, name, reply):
            p.get_by_label('Display name', exact=True).fill(name)
            p.get_by_label('Reply-to', exact=True).fill(reply)
        try:
            p = login('alice')
            p.goto(origin+'/settings')
            p.get_by_role('navigation', name='Settings sections').get_by_role('link', name='Identity', exact=True).click()
            p.wait_for_url('**section=identity')
            expect(p.get_by_label('Email address', exact=True)).to_have_value('alice@example.com')
            assert p.get_by_label('Email address', exact=True).get_attribute('readonly') is not None
            expect(p.get_by_label('Display name', exact=True)).to_have_value('')
            fields(p, 'Alice Example', 'reply@example.test')
            submit(p)
            visit(p)
            expect(p.get_by_label('Display name', exact=True)).to_have_value('Alice Example')
            expect(p.get_by_label('Reply-to', exact=True)).to_have_value('reply@example.test')
            compose = p.context.new_page()
            compose.goto(origin+'/compose', wait_until='networkidle')
            expect(compose.locator('.compose-sender-chip')).to_have_text('Alice Example')
            compose.locator('[name=to]').fill('bob@example.com')
            compose.get_by_label('Subject', exact=True).fill('Captured identity fixture')
            compose.get_by_label('Body', exact=True).fill('Synthetic exact body 🦊')
            compose.get_by_role('button', name='Save Draft', exact=True).click()
            compose.wait_for_url('**/draft?**')
            draft_url = compose.url
            response = p.goto(origin+'/settings', wait_until='networkidle')
            assert response.status == 200
            expect(p.get_by_label('Display name', exact=True)).to_have_value('Alice Example')
            expect(p.get_by_label('Reply-to address', exact=True)).to_have_value('reply@example.test')
            assert p.get_by_label('Display name', exact=True).get_attribute('readonly') is not None
            p.get_by_role('link', name='Edit in Identity', exact=True).press('Enter')
            p.wait_for_url('**section=identity')
            bob = login('bob')
            visit(bob)
            expect(bob.get_by_label('Display name', exact=True)).to_have_value('')
            expect(bob.get_by_label('Reply-to', exact=True)).to_have_value('')
            bob.goto(origin+'/settings', wait_until='networkidle')
            expect(bob.get_by_label('Display name', exact=True)).to_have_value('')
            expect(bob.get_by_label('Reply-to address', exact=True)).to_have_value('bob@example.com')
            visit(bob)
            report['checks'].append('Native save/reload persists Alice profile; Bob starts isolated; canonical address is readonly')
            report['checks'].append('General shows the owned saved profile and default reply address; keyboard Edit in Identity navigation works')
            stale = p.context.new_page()
            visit(stale)
            fields(p, 'Alice Current', '')
            submit(p)
            fields(stale, 'Alice Stale', 'stale@example.test')
            submit(stale, 409)
            expect(stale.get_by_label('Display name', exact=True)).to_have_value('Alice Stale')
            expect(stale.get_by_label('Reply-to', exact=True)).to_have_value('stale@example.test')
            visit(p)
            expect(p.get_by_label('Display name', exact=True)).to_have_value('Alice Current')
            expect(p.get_by_label('Reply-to', exact=True)).to_have_value('')
            report['checks'].append('Concurrent stale revision refused409, entered values retained, newer stored profile unchanged')
            fields(p, 'Alice <literal>', 'two@example.test, second@example.test')
            submit(p, 400)
            expect(p.get_by_label('Display name', exact=True)).to_have_value('Alice <literal>')
            expect(p.get_by_label('Reply-to', exact=True)).to_have_value('two@example.test, second@example.test')
            assert p.locator('script').count() == 0
            visit(p)
            expect(p.get_by_label('Display name', exact=True)).to_have_value('Alice Current')
            report['checks'].append('Invalid multi-address Reply-to refused400, literal entered fields retained, storage unchanged')
            compose.goto(draft_url, wait_until='networkidle')
            expect(compose.locator('.compose-sender-chip')).to_have_text('Alice Example')
            compose.get_by_text('Sender details', exact=True).click()
            expect(compose.locator('#sender-policy')).to_contain_text('reply@example.test')
            expect(compose.locator('#sender-policy')).to_contain_text('keeps its captured identity')
            compose.get_by_role('button', name='Save Draft', exact=True).click()
            compose.wait_for_url('**/draft?**')
            expect(compose.locator('.compose-sender-chip')).to_have_text('Alice Example')
            draft_url = compose.url
            fresh = p.context.new_page()
            fresh.goto(origin+'/compose', wait_until='networkidle')
            expect(fresh.locator('.compose-sender-chip')).to_have_text('Alice Current')
            bob.goto(origin+'/compose', wait_until='networkidle')
            expect(bob.locator('.compose-sender-chip')).to_have_text('B')
            report['checks'].append('Fresh capture survives profile change, reopen and native resave; fresh Compose shows current profile; Bob remains isolated')
            for scheme in ('light','dark'):
                for width in (1600,360):
                    for forced in ('none','active'):
                        compose.set_viewport_size(dict(width=width,height=1100))
                        compose.emulate_media(color_scheme=scheme,forced_colors=forced)
                        compose.goto(draft_url, wait_until='networkidle')
                        file=f'captured-compose-{scheme}-{width}-{forced}.png'
                        compose.screenshot(path=str(args.output/file),full_page=True)
                        overflow=compose.evaluate('document.documentElement.scrollWidth > innerWidth')
                        audit=compose.evaluate(TEXT_AUDIT)
                        assert not overflow and not audit['failures'] and not audit['ui_failures']
                        report['captures'].append(dict(file=file,overflow=overflow,contrast=audit))
            compose.get_by_role('button', name='Send Message', exact=True).click()
            expect(compose.get_by_role('heading',name='Message accepted for submission',exact=True)).to_be_visible()
            with compose.expect_popup() as popup:
                compose.get_by_role('link',name='Check this attempt’s receipt (opens in a new tab)',exact=True).click()
            receipt=popup.value
            receipt.wait_for_load_state('networkidle')
            expect(receipt.locator('[data-sender-name]')).to_have_text('Alice Example')
            expect(receipt.locator('[data-sender-reply]')).to_have_text('reply@example.test')
            assert receipt.locator('form[action="/send"], form[action="/drafts/save"]').count()==0
            for width in (1600,360):
                receipt.set_viewport_size(dict(width=width,height=1100))
                file=f'captured-receipt-{width}.png'
                receipt.screenshot(path=str(args.output/file),full_page=True)
                overflow=receipt.evaluate('document.documentElement.scrollWidth > innerWidth')
                assert not overflow
                report['captures'].append(dict(file=file,overflow=overflow))
            report['checks'].append('One synthetic Sent-copy-unconfirmed action exposes immutable captured identity in readonly verified receipt; no real submission backend')
            for scheme in ('light','dark'):
                for width in (1600,360):
                    for forced in ('none','active'):
                        p.set_viewport_size(dict(width=width,height=1100))
                        p.emulate_media(color_scheme=scheme,forced_colors=forced)
                        visit(p)
                        p.get_by_label('Display name',exact=True).focus()
                        expect(p.get_by_label('Display name',exact=True)).to_be_focused()
                        overflow = p.evaluate('document.documentElement.scrollWidth > innerWidth')
                        audit = p.evaluate(TEXT_AUDIT)
                        file = f'identity-{scheme}-{width}-{forced}.png'
                        p.screenshot(path=str(args.output/file),full_page=True)
                        report['captures'].append(dict(file=file,overflow=overflow,contrast=audit,boxes=p.locator('.identity-card').evaluate_all('els=>els.map(e=>({top:e.getBoundingClientRect().top,bottom:e.getBoundingClientRect().bottom}))')))
                        assert not overflow and not audit['failures'] and not audit['ui_failures'], file
            p.get_by_label('Display name', exact=True).fill('é' * 128)
            p.get_by_role('button', name='Save identity', exact=True).click()
            p.wait_for_load_state('networkidle')
            fresh.goto(origin+'/compose', wait_until='networkidle')
            expect(fresh.locator('.compose-sender-chip')).to_have_text('é' * 128)
            for width in (1600,360):
                fresh.set_viewport_size(dict(width=width,height=1100))
                fresh.emulate_media(color_scheme='dark')
                overflow=fresh.evaluate('document.documentElement.scrollWidth > innerWidth')
                audit=fresh.evaluate(TEXT_AUDIT)
                file=f'maximum-sender-{width}.png'
                fresh.screenshot(path=str(args.output/file),full_page=True)
                report['captures'].append(dict(file=file,overflow=overflow,contrast=audit))
                assert not overflow and not audit['failures'] and not audit['ui_failures']
            report['checks'].append('Maximum 128-character/256-byte Unicode sender remains visible without horizontal overflow')
            assert report['external'] == report['scripts'] == 0
            assert report['sends'] == 1
            report['result'] = 'PASS'
        finally:
            (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
            browser.close()
            stop_server(server, root)
    print(json.dumps(dict(result=report['result'],checks=len(report['checks']),captures=len(report['captures']))))

if __name__ == '__main__': main()
