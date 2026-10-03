#!/usr/bin/env python3
"""Actual no-script conversation defaults and navigation in a disposable fixture.

Synthetic authentication and public three-message data only. No mail host,
operator account, Send, private cryptography or live Seen mutation is exercised.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urlsplit

from playwright.sync_api import sync_playwright
from contrast_audit import TEXT_AUDIT

REPO = Path(__file__).resolve().parents[2]
SPRINT = Path('/home/foo/Downloads/osmap-ux-s02/revalidation-20261003')
FIXTURE = 'http::tests::ux_browser_server::ux_synthetic_browser_server'
ALLOWED_POSTS = {'/login', '/settings/reading'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--browser', default='/usr/bin/microsoft-edge-stable')
    args = parser.parse_args()
    output = args.output.resolve()
    if output == SPRINT.resolve() or not output.is_relative_to(SPRINT.resolve()):
        parser.error('--output must be a dedicated directory under the S02 sprint root')
    executable = args.executable.resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        parser.error('--executable must be the compiled synthetic fixture test binary')
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.chmod(0o700)
    report = dict(passed=False,
                  scope='synthetic loopback actual BrowserApp, saved Reading store and owned public threading fixture; no live qualification',
                  javascript_enabled=False, checks=[], captures=[],
                  send_requests=0, opening_requests=0, flag_requests=0,
                  outside_requests=0, unexpected_posts=0, settings_posts=0,
                  executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
                  cleanup=dict(server_reaped=False, fixture_removed=False))
    step = 'fixture_start'
    server = None
    temporary = None
    browser = None
    try:
        with tempfile.TemporaryDirectory(prefix='osmap-conversation-') as tmp, \
                (output / 'synthetic-server.log').open('w') as log, sync_playwright() as pw:
            temporary = Path(tmp)
            temporary.chmod(0o700)
            (output / 'synthetic-server.log').chmod(0o600)
            env = dict(os.environ, OSMAP_UX_BROWSER_STATE=str(temporary),
                       OSMAP_UX_FIXTURE_CONVERSATION='1')
            env.pop('OSMAP_UX_PREVIEW_MINUTES', None)
            env.pop('OSMAP_UX_FIXTURE_OPENPGP', None)
            server = subprocess.Popen([str(executable), FIXTURE, '--exact', '--ignored', '--nocapture'],
                                      cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT)
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
                context = browser.new_context(java_script_enabled=False,
                                              user_agent='OSMAP/ConversationFixture',
                                              viewport=dict(width=1440, height=1000))
                try:
                    def guard(route):
                        request = route.request
                        url = urlsplit(request.url)
                        if url.path == '/send':
                            report['send_requests'] += 1
                        if url.path == '/message/open' and request.method == 'POST':
                            report['opening_requests'] += 1
                        if url.path == '/message/flag' and request.method == 'POST':
                            report['flag_requests'] += 1
                        if url.scheme + '://' + url.netloc != origin:
                            report['outside_requests'] += 1
                            route.abort()
                        elif url.path == '/send' or request.method not in {'GET', 'POST'}:
                            report['unexpected_posts'] += 1
                            route.abort()
                        elif request.method == 'POST' and url.path not in ALLOWED_POSTS:
                            report['unexpected_posts'] += 1
                            route.abort()
                        else:
                            if request.method == 'POST' and url.path == '/settings/reading':
                                fields = parse_qs(request.post_data or '', strict_parsing=True)
                                assert {'csrf_token', 'start_page', 'date_order'} <= set(fields)
                                assert set(fields) <= {'csrf_token', 'start_page', 'date_order',
                                                       'show_source_shortcut', 'attachment_details'}
                                assert all(len(values) == 1 for values in fields.values())
                                assert fields['date_order'][0] in {'newest', 'oldest'}
                                report['settings_posts'] += 1
                            route.continue_()

                    context.route('**/*', guard)
                    page = context.new_page()
                    page.set_default_timeout(8000)

                    def visit(path):
                        response = page.goto(origin + path, wait_until='networkidle')
                        assert response and response.status == 200
                        assert 'no-store' in response.headers.get('cache-control', '')
                        assert page.locator('script').count() == 0

                    def activate(locator):
                        locator.focus()
                        with page.expect_navigation(wait_until='networkidle') as navigation:
                            locator.press('Enter')
                        assert navigation.value and navigation.value.status == 200
                        assert page.locator('script').count() == 0

                    def query():
                        return parse_qs(urlsplit(page.url).query)

                    def order():
                        result = []
                        for row in page.locator('.message-card, .search-result-row').all():
                            label = row.locator('summary[aria-label^="More for message #"]').get_attribute('aria-label')
                            match = re.fullmatch(r'More for message #(\d+) in INBOX', label or '')
                            assert match
                            result.append(int(match[1]))
                        return result

                    def row(uid):
                        return page.locator('.message-card, .search-result-row').filter(
                            has=page.locator(f'summary[aria-label="More for message #{uid} in INBOX"]'))

                    def body(uid):
                        assert query()['selected_uid'] == [str(uid)]
                        assert query()['selected_mailbox'] == ['INBOX']
                        assert query()['selected_mailbox_guid'] and query()['selected_message_guid']
                        pane = page.locator('#reading-pane')
                        assert pane.is_visible()
                        assert pane.locator('.body-panel pre').inner_text() == f'Synthetic message {uid} in INBOX for alice@example.com.'

                    def save(ordering):
                        visit('/settings?section=reading')
                        choice = page.locator('#reading-date-order')
                        assert choice.evaluate('(e) => e.form.id') == 'reading-preferences-form'
                        assert choice.get_attribute('name') == 'date_order' and not choice.is_disabled()
                        choice.select_option(ordering)
                        page.locator('#reading-start-page').select_option('inbox')
                        activate(page.locator('button[form=reading-preferences-form]'))
                        visit('/settings?section=reading')
                        assert page.locator('#reading-date-order').input_value() == ordering
                        assert page.locator('#reading-start-page').input_value() == 'inbox'
                        visit('/settings?section=general')
                        assert page.locator('#general-start-page').input_value() == 'inbox'

                    step = 'synthetic_login'
                    visit('/login')
                    page.get_by_label('Username or Email').fill('alice@example.com')
                    page.get_by_label('Password', exact=True).fill('correct horse battery staple')
                    page.get_by_label('TOTP Code').fill('123456')
                    activate(page.get_by_role('button', name='Sign In', exact=True))
                    assert urlsplit(page.url).path == '/mailboxes'

                    step = 'saved_newest_flat_list'
                    save('newest')
                    visit('/mailbox?name=INBOX')
                    assert order() == [3, 1, 2]
                    assert page.locator('.message-subject-link').all_text_contents() == ['Shared public subject'] * 3
                    activate(row(3).locator('a.message-subject-link'))
                    body(3)
                    assert 'sort' not in query() and 'dir' not in query()
                    activate(page.locator('#reading-pane').get_by_role('link', name='Next message', exact=True))
                    body(1)
                    activate(page.locator('#reading-pane').get_by_role('link', name='Next message', exact=True))
                    body(2)
                    report['checks'].append('Native Reading Newest save persists and General start-page mirror reloads; real parent/reply are contiguous while unrelated same-subject UID2 remains separate; existing keyboard Next follows3→1→2')

                    step = 'saved_oldest_and_explicit_precedence'
                    save('oldest')
                    visit('/mailbox?name=INBOX')
                    assert order() == [1, 3, 2]
                    activate(row(1).locator('a.message-subject-link'))
                    body(1)
                    activate(page.locator('#reading-pane').get_by_role('link', name='Next message', exact=True))
                    body(3)
                    visit('/mailbox?name=INBOX&sort=received&dir=asc')
                    assert order() == [1, 2, 3]
                    activate(row(1).locator('a.message-subject-link'))
                    activate(page.locator('#reading-pane').get_by_role('link', name='Next message', exact=True))
                    body(2)
                    assert query()['sort'] == ['received'] and query()['dir'] == ['asc']
                    report['checks'].append('Native Oldest save reverses actual members and arrows1→3; explicit Received asc retains ordinary1→2→3 and reader Next1→2')

                    step = 'filtered_search_context'
                    save('newest')
                    search = '/search?q=Shared%20public%20subject&field=subject&scope=all&from=sender%40example.test&pgp=unknown&after=2026-10-03&before=2026-10-03'
                    visit(search)
                    assert order() == [3, 1, 2]
                    activate(row(3).locator('a.message-subject-link'))
                    body(3)
                    activate(page.locator('#reading-pane').get_by_role('link', name='Next message', exact=True))
                    body(1)
                    for key, value in [('q', 'Shared public subject'), ('field', 'subject'), ('scope', 'all'),
                                       ('from', 'sender@example.test'), ('pgp', 'unknown'),
                                       ('after', '2026-10-03'), ('before', '2026-10-03')]:
                        assert query()[key] == [value]
                    assert 'sort' not in query() and 'dir' not in query()
                    report['checks'].append('Actual Subject Search retains account/folder/query/sender/MIME/date predicates through grouped flat order and existing Next; no implicit sort materialized')

                    step = 'visual_focus'
                    for width in [1440, 360]:
                        for scheme in ['light', 'dark']:
                            page.set_viewport_size(dict(width=width, height=1000))
                            page.emulate_media(color_scheme=scheme)
                            target = page.locator('#reading-pane').get_by_role('link', name='Next message', exact=True)
                            target.focus()
                            assert page.locator(':focus').get_attribute('aria-label') == 'Next message'
                            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                            audit = page.evaluate(TEXT_AUDIT)
                            assert not audit['failures'] and not audit['ui_failures']
                            filename = f'conversation-{width}-{scheme}-synthetic.png'
                            page.screenshot(path=str(output / filename), full_page=True)
                            report['captures'].append(dict(file=filename, width=width, scheme=scheme,
                                                           overflow=False, focused=True,
                                                           flat_text_failures=0, ui_token_failures=0))

                    step = 'stale_guid_and_filter_exclusion'
                    selected = urlsplit(page.url)
                    fields = {key: values[0] for key, values in query().items()}
                    fields['selected_message_guid'] = 'stale-conversation-browser'
                    visit(selected.path + '?' + urlencode(fields))
                    assert page.locator('#reading-unavailable').count() == 1
                    assert page.locator('#reading-pane .body-panel').count() == 0
                    fields = {key: values[0] for key, values in parse_qs(selected.query).items()}
                    fields['filter'] = 'starred'
                    visit(selected.path + '?' + urlencode(fields))
                    assert order() == [] and page.locator('#reading-pane .body-panel').count() == 0
                    visit(search)
                    activate(row(3).locator('a.message-subject-link'))
                    activate(page.get_by_role('link', name='Back to list', exact=True))
                    assert 'selected_uid' not in query() and page.locator('#reading-pane').count() == 0
                    assert order() == [3, 1, 2] and query()['q'] == ['Shared public subject']
                    report['checks'].append('Stale GUID and real Starred exclusion refuse the reader; native Back retains filtered Search without a fabricated thread panel or mailbox fallback')
                    assert report['settings_posts'] == 3
                    assert all(report[key] == 0 for key in ['send_requests', 'opening_requests', 'flag_requests',
                                                          'outside_requests', 'unexpected_posts'])
                    report['passed'] = True
                finally:
                    context.close()
            finally:
                try:
                    browser.close()
                finally:
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
    except Exception as error:
        report['passed'] = False
        report['error'] = dict(class_name=type(error).__name__, step=step)
    finally:
        if browser:
            try:
                browser.close()
            except Exception:
                report['passed'] = False
        if server:
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
        report['cleanup']['fixture_removed'] = bool(temporary and not temporary.exists())
        report['passed'] = report['passed'] and all(report['cleanup'].values()) and report.get('server_exit_code') == 0
        path = output / 'report.json'
        path.write_text(json.dumps(report, indent=2) + '\n')
        path.chmod(0o600)
        print(json.dumps(dict(passed=report['passed'], checks=len(report['checks']),
                              error=report.get('error'), cleanup=report['cleanup'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
