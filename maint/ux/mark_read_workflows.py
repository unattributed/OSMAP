#!/usr/bin/env python3
"""Actual native mark-read interactions in the owned 180-second loopback fixture.

Synthetic authentication and mailbox flags only; no live authentication, native
mail host, Send, private cryptography, or operator mailbox is exercised.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import sync_playwright
from contrast_audit import TEXT_AUDIT

REPO = Path(__file__).resolve().parents[2]
SPRINT = Path('/home/foo/Downloads/osmap-ux-s02/revalidation-20261003')
FIXTURE = 'http::tests::ux_browser_server::ux_synthetic_browser_server'
ALLOWED_POSTS = {'/login', '/settings/mark-read', '/message/open'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--browser', default='/usr/bin/microsoft-edge-stable')
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(SPRINT.resolve()) or output == SPRINT.resolve():
        parser.error('--output must be a dedicated directory under the S02 sprint root')
    executable = args.executable.resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        parser.error('--executable must be the compiled synthetic test binary')
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.chmod(0o700)
    report = dict(
        scope='synthetic loopback actual router, stores, opening and flag gateway; no live qualification',
        javascript_enabled=False, passed=False, checks=[], captures=[],
        outside_requests=0, send_requests=0, unexpected_posts=0, opening_posts=[],
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        cleanup=dict(server_reaped=False, fixture_removed=False),
    )
    step = 'fixture_start'
    server = None
    temporary = None
    browser = None
    try:
        with tempfile.TemporaryDirectory(prefix='osmap-mark-read-') as tmp, \
                (output / 'synthetic-server.log').open('w') as log, sync_playwright() as pw:
            temporary = Path(tmp)
            temporary.chmod(0o700)
            (output / 'synthetic-server.log').chmod(0o600)
            env = dict(os.environ, OSMAP_UX_BROWSER_STATE=str(temporary))
            env.pop('OSMAP_UX_PREVIEW_MINUTES', None)
            env.pop('OSMAP_UX_FIXTURE_OPENPGP', None)
            server = subprocess.Popen(
                [str(executable), FIXTURE, '--exact', '--ignored', '--nocapture'],
                cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + 15
            while not (temporary / 'ready.json').exists():
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('fixture readiness')
                time.sleep(.05)
            ready = json.loads((temporary / 'ready.json').read_text())
            origin = ready['origin']
            parsed = urlsplit(origin)
            assert ready['synthetic'] and ready['deadline_seconds'] == 180
            assert parsed.scheme == 'http' and ipaddress.ip_address(parsed.hostname).is_loopback
            assert parsed.port and not parsed.path and not parsed.query and not parsed.fragment
            browser = pw.chromium.launch(executable_path=args.browser, headless=True)
            report['browser_version'] = browser.version
            try:
                def new_context(agent):
                    context = browser.new_context(java_script_enabled=False, user_agent=agent,
                                                  viewport=dict(width=1440, height=1000))

                    def guard(route):
                        request = route.request
                        path = urlsplit(request.url).path
                        if not request.url.startswith(origin + '/'):
                            report['outside_requests'] += 1
                            route.abort()
                        elif path == '/send':
                            report['send_requests'] += 1
                            route.abort()
                        elif request.method not in {'GET', 'POST'} or (
                                request.method == 'POST' and path not in ALLOWED_POSTS):
                            report['unexpected_posts'] += 1
                            route.abort()
                        else:
                            if request.method == 'POST' and path == '/message/open':
                                fields = parse_qs(request.post_data or '', strict_parsing=True)
                                assert set(fields) == {'csrf_token', 'mailbox', 'uid', 'mailbox_guid', 'message_guid', 'return_to'}
                                assert all(len(value) == 1 for value in fields.values())
                                report['opening_posts'].append(dict(mailbox=fields['mailbox'][0], uid=int(fields['uid'][0])))
                            route.continue_()

                    context.route('**/*', guard)
                    page = context.new_page()
                    page.set_default_timeout(8000)
                    visit(page, '/login')
                    page.get_by_label('Username or Email').fill('alice@example.com')
                    page.get_by_label('Password', exact=True).fill('correct horse battery staple')
                    page.get_by_label('TOTP Code').fill('123456')
                    page.get_by_role('button', name='Sign In', exact=True).click()
                    page.wait_for_url(origin + '/mailboxes')
                    return context, page

                def visit(page, path, status=200):
                    response = page.goto(origin + path, wait_until='networkidle')
                    assert response and response.status == status
                    assert 'no-store' in response.headers.get('cache-control', '')
                    assert page.locator('script').count() == 0
                    return response

                def submit(page, locator, status=200):
                    locator.focus()
                    with page.expect_navigation(wait_until='networkidle') as navigation:
                        locator.press('Enter')
                    assert navigation.value and navigation.value.status == status
                    assert page.locator('script').count() == 0

                def body(page, uid, mailbox='INBOX'):
                    pane = page.locator('#reading-pane')
                    assert pane.is_visible()
                    assert pane.get_by_role('heading', name=f'Message {uid:03}', exact=True).is_visible()
                    assert pane.locator('.body-panel pre').inner_text() == f'Synthetic message {uid} in {mailbox} for alice@example.com.'

                def query(page):
                    return parse_qs(urlsplit(page.url).query)

                def opening_identity(button):
                    form = button.locator('xpath=..')
                    assert form.get_attribute('action') == '/message/open'
                    assert form.get_attribute('method') == 'post'
                    assert form.locator('input[type=hidden]').count() == 6
                    return (form.locator('[name=mailbox]').input_value(), int(form.locator('[name=uid]').input_value()))

                context, page = new_context('OSMAP/ManyMessages')
                try:
                    step = 'settings_manual_mirror'
                    visit(page, '/settings?section=general')
                    assert page.locator('#general-mark-read').input_value() == 'manual'
                    page.locator('#general-mark-read').select_option('manual')
                    submit(page, page.locator('button[form=general-mark-read-form]'))
                    visit(page, '/settings?section=reading')
                    assert page.locator('#reading-mark-read').input_value() == 'manual'
                    report['checks'].append('General native Manual save reloads in Reading mirror')

                    step = 'manual_get_readonly'
                    unread = '/mailbox?name=INBOX&filter=unread&sort=subject&dir=asc'
                    visit(page, unread)
                    submit(page, page.get_by_role('link', name='Message 009', exact=True))
                    body(page, 9)
                    assert page.locator('.message-row[data-selected=true]').count() == 1
                    page.reload(wait_until='networkidle')
                    body(page, 9)
                    submit(page, page.get_by_role('link', name='Back to list', exact=True))
                    assert page.get_by_role('link', name='Message 009', exact=True).count() == 1
                    assert not report['opening_posts']
                    report['checks'].append('Manual subject GET, reload and Back retain unread row without opening POST')

                    step = 'settings_on_open_and_stale_cas'
                    stale = context.new_page()
                    visit(stale, '/settings?section=general')
                    visit(page, '/settings?section=reading')
                    page.locator('#reading-mark-read').select_option('on_open')
                    submit(page, page.locator('button[form=reading-mark-read-form]'))
                    visit(page, '/settings?section=general')
                    assert page.locator('#general-mark-read').input_value() == 'on_open'
                    stale.locator('#general-mark-read').select_option('manual')
                    submit(stale, stale.locator('button[form=general-mark-read-form]'), 409)
                    stale.close()
                    visit(page, '/settings?section=reading')
                    assert page.locator('#reading-mark-read').input_value() == 'on_open'
                    report['checks'].append('Reading OnOpen persists in General; stale native old-tab save returns409 without reset')

                    step = 'inbox_unread_native_open'
                    visit(page, unread)
                    target = page.get_by_role('button', name='Message 009', exact=True)
                    assert opening_identity(target) == ('INBOX', 9)
                    before = len(report['opening_posts'])
                    submit(page, target)
                    body(page, 9)
                    assert len(report['opening_posts']) == before + 1
                    assert query(page)['opened_read'] == ['1']
                    assert page.locator('.message-row .message-subject-link').filter(has_text='Message 009').count() == 0
                    page.reload(wait_until='networkidle')
                    body(page, 9)
                    assert len(report['opening_posts']) == before + 1
                    report['checks'].append('Unread UID9 opening posts exact identity, confirms Seen, excludes actual row and preserves reader on read-only reload')

                    step = 'keyboard_next_unread'
                    target = page.get_by_role('button', name='Next message', exact=True)
                    assert opening_identity(target) == ('INBOX', 11)
                    submit(page, target)
                    body(page, 11)
                    assert report['opening_posts'][-1] == dict(mailbox='INBOX', uid=11)
                    assert page.locator('.message-row .message-subject-link').filter(has_text='Message 011').count() == 0
                    submit(page, page.get_by_role('link', name='Back to list', exact=True))
                    assert page.locator('#reading-pane').count() == 0
                    for uid in [9, 11]:
                        assert page.get_by_role('button', name=f'Message {uid:03}', exact=True).count() == 0
                    assert page.get_by_role('button', name='Message 013', exact=True).count() == 1
                    report['checks'].append('Keyboard Next opens only next unread UID11; Back is GET and preserves other unread rows')

                    step = 'search_distinct_folder_openings'
                    search = '/search?q=reader-fixture&field=subject&scope=all&sort=subject&dir=asc'
                    visit(page, search)
                    target = page.get_by_role('button', name='Message 001', exact=True).first
                    assert opening_identity(target) == ('INBOX', 1)
                    submit(page, target)
                    body(page, 1)
                    target = page.get_by_role('button', name='Next message', exact=True)
                    assert opening_identity(target) == ('Sent', 1)
                    submit(page, target)
                    body(page, 1, 'Sent')
                    assert query(page)['scope'] == ['all'] and query(page)['field'] == ['subject']
                    target = page.get_by_role('button', name='Previous message', exact=True)
                    assert opening_identity(target) == ('INBOX', 1)
                    report['checks'].append('All-scope Subject search and keyboard arrow POST bind distinct INBOX/Sent identities sharing UID1')

                    step = 'visual_focus_contrast'
                    for width in [1440, 360]:
                        for scheme in ['light', 'dark']:
                            page.set_viewport_size(dict(width=width, height=1000))
                            page.emulate_media(color_scheme=scheme)
                            target = page.get_by_role('button', name='Previous message', exact=True)
                            target.focus()
                            assert page.locator(':focus').get_attribute('aria-label') == 'Previous message'
                            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                            audit = page.evaluate(TEXT_AUDIT)
                            assert not audit['failures'] and not audit['ui_failures']
                            filename = f'mark-read-{width}-{scheme}-synthetic.png'
                            page.screenshot(path=str(output / filename), full_page=True)
                            report['captures'].append(dict(file=filename, width=width, scheme=scheme,
                                                           overflow=False, focused=True,
                                                           flat_text_failures=0, ui_token_failures=0))

                    step = 'archive_and_welcome_openings'
                    visit(page, '/mailbox?name=Trash&sort=subject&dir=asc')
                    target = page.locator('.archive-subject').first
                    identity = opening_identity(target)
                    assert identity == ('Trash', 1)
                    submit(page, target)
                    body(page, 1, 'Trash')
                    visit(page, '/mailboxes')
                    target = page.locator('.welcome-recent-link').first
                    assert opening_identity(target)[0] == 'INBOX'
                    submit(page, target)
                    assert page.locator('#reading-pane .body-panel').count() == 1
                    report['checks'].append('Archive and Welcome rendered native forms execute actual opening routes')
                finally:
                    context.close()

                step = 'missing_guid_disabled'
                context, page = new_context('OSMAP/LegacyMetadata')
                try:
                    visit(page, '/mailbox?name=INBOX')
                    assert page.locator('.message-subject-link').count() > 0
                    assert page.locator('button.message-subject-link:disabled').count() == page.locator('.message-subject-link').count()
                    assert page.locator('form[action="/message/open"]').count() == 0
                    assert page.locator('a.message-subject-link').count() == 0
                    report['checks'].append('OnOpen missing metadata disables subjects without a GET fallback')
                finally:
                    context.close()
                assert report['outside_requests'] == report['send_requests'] == report['unexpected_posts'] == 0
                assert len(report['opening_posts']) == 6
                report['passed'] = True
            finally:
                browser.close()
                browser = None
                (temporary / 'stop').touch()
                try:
                    report['server_exit_code'] = server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.terminate()
                    try:
                        report['server_exit_code'] = server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        report['server_exit_code'] = server.wait(timeout=5)
                report['cleanup']['server_reaped'] = server.poll() is not None
                assert report['server_exit_code'] == 0
    except Exception as error:
        report['passed'] = False
        report['error'] = dict(class_name=type(error).__name__, step=step)
    finally:
        if browser:
            browser.close()
        if server and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        report['cleanup']['server_reaped'] = bool(server and server.poll() is not None)
        report['cleanup']['fixture_removed'] = bool(temporary and not temporary.exists())
        report['passed'] = report['passed'] and all(report['cleanup'].values())
        path = output / 'report.json'
        path.write_text(json.dumps(report, indent=2) + '\n')
        path.chmod(0o600)
        print(json.dumps(dict(passed=report['passed'], checks=len(report['checks']),
                              error=report.get('error'), cleanup=report['cleanup'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
