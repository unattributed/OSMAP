#!/usr/bin/env python3
"""Measure native originating-row Back focus, using owned loopback data only."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urlsplit

from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[2]
ROOT = Path('/home/foo/Downloads/osmap-ux-s02/revalidation-20261003/back-focus')
FIXTURE = 'http::tests::ux_browser_server::ux_synthetic_browser_server'
CONTROL = '''<!doctype html><html><head><title>Owned native focus control</title>
<style>body{font:18px sans-serif}a{display:block}#native-target{margin-top:80px}
#native-target:focus{outline:3px solid #124ca4;outline-offset:3px}</style></head>
<body><a id="native-jump" href="#native-target">Native fragment positive control</a>
<div id="native-target" tabindex="-1">Owned native focus target</div></body></html>'''
FOCUS = '''() => {
 const e=document.activeElement;
 const r=e?.closest('.message-card,.search-result-row');
 const label=r?.querySelector('summary[aria-label^="More for message #"]')?.getAttribute('aria-label')||null;
 const b=e?.getBoundingClientRect(),s=e?getComputedStyle(e):null;
 return {tag:e?.tagName||null,id:e?.id||null,row:label,
   width:b?.width||0,height:b?.height||0,outline_width:s?.outlineWidth||null,
   outline_style:s?.outlineStyle||null,focus_visible:e?.matches(':focus-visible')||false};
}'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--executable', required=True, type=Path)
    parser.add_argument('--color-scheme', choices=['light', 'dark'], default='light')
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or not output.is_relative_to(ROOT):
        parser.error('output must be a dedicated child of the back-focus root')
    if output.exists():
        parser.error('output must not replace prior evidence')
    executable = args.executable.resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        parser.error('compiled fixture executable required')
    output.mkdir(mode=0o700, parents=True)
    output.chmod(0o700)
    report = dict(scope='synthetic actual BrowserApp, no JavaScript in application; login-only POST; no host, Send or real mailbox data',
                  passed=False, color_scheme=args.color_scheme, positive_controls=[], cases=[], failures=[],
                  outside_requests=0, send_requests=0, unexpected_posts=0,
                  login_posts=0, cleanup=dict(server_reaped=False, fixture_removed=False),
                  executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest())
    step = 'fixture_prepare'
    server = None
    temporary = None
    browser = None
    try:
        with tempfile.TemporaryDirectory(prefix='osmap-back-focus-') as scratch, \
                (output / 'synthetic-server.log').open('w') as log, sync_playwright() as pw:
            temporary = Path(scratch)
            temporary.chmod(0o700)
            (output / 'synthetic-server.log').chmod(0o600)
            copied = temporary / 'fixture-binary'
            shutil.copyfile(executable, copied)
            copied.chmod(0o500)
            assert hashlib.sha256(copied.read_bytes()).hexdigest() == report['executable_sha256']
            state = temporary / 'state'
            state.mkdir(mode=0o700)
            env = dict(os.environ, OSMAP_UX_BROWSER_STATE=str(state), OSMAP_UX_FIXTURE_BACK_FOCUS='1')
            env.pop('OSMAP_UX_FIXTURE_CONVERSATION', None)
            env.pop('OSMAP_UX_PREVIEW_MINUTES', None)
            env.pop('OSMAP_UX_FIXTURE_OPENPGP', None)
            server = subprocess.Popen([str(copied), FIXTURE, '--exact', '--ignored', '--nocapture'],
                                      cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 15
            while not (state / 'ready.json').exists():
                if server.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('fixture readiness')
                time.sleep(.05)
            ready = json.loads((state / 'ready.json').read_text())
            origin = ready['origin']
            url = urlsplit(origin)
            assert ready['synthetic'] and ready['deadline_seconds'] == 180
            assert ready['back_focus_fixture'] is True
            report['isolated_back_focus_fixture'] = True
            assert url.scheme == 'http' and ipaddress.ip_address(url.hostname).is_loopback
            assert url.port and not url.path and not url.query and not url.fragment
            browser = pw.chromium.launch(executable_path='/usr/bin/microsoft-edge-stable', headless=True)
            report['browser_version'] = browser.version
            context = browser.new_context(java_script_enabled=False, color_scheme=args.color_scheme,
                                          user_agent='OSMAP/BackFocusFixture',
                                          viewport=dict(width=1440, height=1000))
            try:
                def guard(route):
                    request = route.request
                    u = urlsplit(request.url)
                    if u.path == '/send':
                        report['send_requests'] += 1
                    if u.scheme + '://' + u.netloc != origin:
                        report['outside_requests'] += 1
                        route.abort()
                    elif request.method != 'GET' and not (request.method == 'POST' and u.path == '/login'):
                        report['unexpected_posts'] += 1
                        route.abort()
                    elif u.path == '/send':
                        route.abort()
                    elif u.path == '/__owned-native-focus-control':
                        route.fulfill(status=200, content_type='text/html', body=CONTROL)
                    else:
                        if request.method == 'POST':
                            report['login_posts'] += 1
                        route.continue_()
                context.route('**/*', guard)
                page = context.new_page()
                page.set_default_timeout(8000)

                def visit(path):
                    response = page.goto(origin + path, wait_until='networkidle')
                    assert response and response.status == 200
                    assert page.locator('script').count() == 0
                    return response

                def activate(control):
                    control.focus()
                    with page.expect_navigation(wait_until='networkidle') as nav:
                        control.press('Enter')
                    assert nav.value and nav.value.status == 200
                    assert page.locator('script').count() == 0

                step = 'native_fragment_positive_control'
                for width in [1440, 360]:
                    page.set_viewport_size(dict(width=width, height=1000))
                    visit('/__owned-native-focus-control')
                    jump = page.locator('#native-jump')
                    jump.focus()
                    jump.press('Enter')
                    page.wait_for_url(origin + '/__owned-native-focus-control#native-target')
                    focus = page.evaluate(FOCUS)
                    assert focus['id'] == 'native-target' and focus['focus_visible']
                    assert float(focus['outline_width'].removesuffix('px')) >= 3
                    report['positive_controls'].append(dict(width=width, passed=True, focus=focus,
                        instrumented_static_page=True, application_qualification=False))

                step = 'synthetic_login'
                visit('/login')
                page.get_by_label('Username or Email').fill('alice@example.com')
                page.get_by_label('Password', exact=True).fill('correct horse battery staple')
                page.get_by_label('TOTP Code').fill('123456')
                activate(page.get_by_role('button', name='Sign In', exact=True))
                assert urlsplit(page.url).path == '/mailboxes'

                selected_targets = {}
                equal_uid_ids = {}
                for width in [1440, 360]:
                    page.set_viewport_size(dict(width=width, height=1000))
                    for surface, uid, mailbox, base in [
                        ('mailbox', 3, 'INBOX', '/mailbox?name=INBOX&filter=unread&from=sender%40example.test&pgp=unknown&after=2026-10-03&before=2026-10-03&sort=subject&dir=asc'),
                        ('search', 1, 'INBOX', '/search?q=Shared%20public%20subject&field=subject&scope=all&filter=unread&from=sender%40example.test&pgp=unknown&after=2026-10-03&before=2026-10-03'),
                        ('mailbox_page2', 53, 'INBOX', '/mailbox?name=INBOX&sort=received&dir=asc&page=2'),
                        ('search_page2', 53, 'INBOX', '/search?q=Shared%20public%20subject&field=subject&scope=all&sort=received&dir=asc&page=2'),
                        ('equal_uid_inbox', 3, 'INBOX', '/search?q=Shared%20public%20subject&field=subject&scope=all&from=sender%40example.test&sort=received&dir=asc'),
                        ('equal_uid_sent', 3, 'Sent', '/search?q=Shared%20public%20subject&field=subject&scope=all&from=sender%40example.test&sort=received&dir=asc'),
                    ]:
                        step = f'{surface}_{width}_native_back'
                        visit(base)
                        baseline = parse_qs(urlsplit(page.url).query)
                        identity = f'More for message #{uid} in {mailbox}'
                        row = page.locator('.message-card,.search-result-row').filter(
                            has=page.locator(f'summary[aria-label="{identity}"]'))
                        assert row.count() == 1
                        subject = row.locator('a.message-subject-link')
                        selected = parse_qs(urlsplit(subject.get_attribute('href')).query)
                        assert selected['selected_mailbox'] == [mailbox] and selected['selected_uid'] == [str(uid)]
                        assert selected['selected_mailbox_guid'] and selected['selected_message_guid']
                        selected_targets[surface] = subject.get_attribute('href')
                        activate(subject)
                        selected_url = page.url
                        assert page.locator('#reading-pane .body-panel pre').inner_text() == f'Synthetic message {uid} in {mailbox} for alice@example.com.'
                        activate(page.locator('#reading-pane').get_by_role('link', name='Back to list', exact=True))
                        assert page.locator('#reading-pane').count() == 0
                        assert parse_qs(urlsplit(page.url).query) == baseline
                        assert page.locator('.coordinated-list').is_visible()
                        row = page.locator('.message-card,.search-result-row').filter(
                            has=page.locator(f'summary[aria-label="{identity}"]'))
                        assert row.count() == 1
                        focus = page.evaluate(FOCUS)
                        exact_focus = focus['row'] == identity
                        visible_focus = (focus['focus_visible'] and focus['width'] > 0 and focus['height'] > 0
                                         and focus['outline_style'] not in {'none', 'hidden'}
                                         and float((focus['outline_width'] or '0px').removesuffix('px')) > 0)
                        screenshot = f'back-focus-{surface}-{width}-synthetic.png'
                        page.screenshot(path=str(output / screenshot), full_page=True)
                        outcome = dict(surface=surface, width=width, originating_uid=uid,
                            originating_mailbox=mailbox, context_preserved=True, pane_closed=True, current_row_present=True,
                            exact_originating_row_focus=exact_focus, visible_focus=visible_focus,
                            focus=focus, fragment=urlsplit(page.url).fragment, screenshot=screenshot)
                        if not exact_focus or not visible_focus:
                            report['failures'].append(dict(surface=surface,width=width,
                                reason='originating_current_row_keyboard_focus_not_restored'))
                        step = f'{surface}_{width}_browser_history_control'
                        response = page.go_back(wait_until='networkidle')
                        assert response and response.status == 200 and page.url == selected_url
                        assert page.locator('#reading-pane .body-panel pre').inner_text() == f'Synthetic message {uid} in {mailbox} for alice@example.com.'
                        response = page.go_forward(wait_until='networkidle')
                        assert response and response.status == 200
                        assert page.locator('#reading-pane').count() == 0
                        assert parse_qs(urlsplit(page.url).query) == baseline
                        outcome['browser_history_selected_body_and_list_context'] = True
                        report['cases'].append(outcome)
                        if surface.startswith('equal_uid_'):
                            assert focus['id'], 'current identity needs a bounded focus target'
                            equal_uid_ids[(width, mailbox)] = focus['id']
                for width in [1440, 360]:
                    assert equal_uid_ids[(width, 'INBOX')] != equal_uid_ids[(width, 'Sent')]
                report['equal_uid_folder_targets_distinct'] = True

                # Presentation-only negative controls: a current owned selected
                # row on another page, a stale expected version, and a missing
                # current row must never focus a different row or expose a body.
                page.set_viewport_size(dict(width=1440, height=1000))
                report['negative_cases'] = []
                for surface in ['mailbox', 'search']:
                    target = urlsplit(selected_targets[surface + '_page2'])
                    initial = {key: values[0] for key, values in parse_qs(target.query).items()}
                    for kind in ['off_page', 'stale_guid', 'missing_row']:
                        step = f'{surface}_{kind}_safe_back'
                        fields = dict(initial)
                        if kind == 'off_page':
                            fields['page'] = '1'
                        elif kind == 'stale_guid':
                            fields['selected_message_guid'] = 'valid-but-stale-fixture-guid'
                        else:
                            fields['selected_uid'] = '999'
                            fields['selected_message_guid'] = 'missing-fixture-guid'
                        visit(target.path + '?' + urlencode(fields) + '#reading-pane')
                        pane = page.locator('#reading-pane')
                        step = f'{surface}_{kind}_pane_present'
                        assert pane.count() == 1
                        if kind == 'off_page':
                            step = f'{surface}_{kind}_current_owned_body'
                            assert pane.locator('.body-panel pre').inner_text() == 'Synthetic message 53 in INBOX for alice@example.com.'
                            step = f'{surface}_{kind}_locate_page2'
                            assert page.get_by_role('link', name='Locate selected message on page 2', exact=True).count() == 1
                            step = f'{surface}_{kind}_current_row_absent_from_page1'
                            assert page.locator('.message-card,.search-result-row').filter(
                                has=page.locator('summary[aria-label="More for message #53 in INBOX"]')).count() == 0
                        else:
                            step = f'{surface}_{kind}_unavailable_pane_without_body'
                            assert pane.get_by_role('heading', name='Message unavailable', exact=True).count() == 1
                            assert pane.locator('.body-panel').count() == 0
                        back = pane.get_by_role('link', name='Back to list', exact=True)
                        href = urlsplit(back.get_attribute('href'))
                        step = f'{surface}_{kind}_no_back_fragment'
                        assert not href.fragment, 'missing/current-version mismatch must not get a focus target'
                        expected = dict(fields)
                        for key in ['selected_mailbox','selected_uid','selected_mailbox_guid','selected_message_guid','opened_read']:
                            expected.pop(key, None)
                        # The shared list_navigation_href omits default page 1;
                        # omission and page=1 express the same preserved page.
                        if expected.get('page') == '1':
                            expected.pop('page')
                        step = f'{surface}_{kind}_canonical_back_context'
                        assert {key: values[0] for key, values in parse_qs(href.query).items()} == expected
                        step = f'{surface}_{kind}_activate_safe_back'
                        activate(back)
                        assert page.locator('#reading-pane').count() == 0
                        assert not urlsplit(page.url).fragment
                        assert page.evaluate(FOCUS)['row'] is None
                        report['negative_cases'].append(dict(surface=surface, kind=kind,
                            context_preserved=True, no_wrong_row_focus=True,
                            no_fragment_fallback=True, canonical_page=expected.get('page', '1'),
                            missing_or_stale_body_refused=kind != 'off_page'))
                assert len(report['negative_cases']) == 6
                assert report['outside_requests'] == report['send_requests'] == report['unexpected_posts'] == 0
                assert report['login_posts'] == 1 and len(report['cases']) == 12
                report['passed'] = not report['failures']
            finally:
                context.close()
                browser.close()
                browser = None
                (state / 'stop').touch()
                try:
                    status = server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.terminate()
                    try:
                        status = server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        status = server.wait(timeout=5)
                report['server_exit_code'] = status
                report['cleanup']['server_reaped'] = server.poll() is not None
    except Exception as exc:
        report['error'] = dict(step=step, error_class=type(exc).__name__)
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
            report['cleanup']['server_reaped'] = True
        report['cleanup']['fixture_removed'] = temporary is not None and not temporary.exists()
        report['passed'] = (report['passed'] and not report.get('error') and all(report['cleanup'].values()) and report.get('server_exit_code') == 0)
        target = output / 'report.json'
        target.write_text(json.dumps(report, indent=2) + '\n')
        target.chmod(0o600)
    print(json.dumps({k:report[k] for k in ['passed','failures','cleanup']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
