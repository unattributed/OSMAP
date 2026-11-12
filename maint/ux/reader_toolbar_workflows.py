#!/usr/bin/env python3
"""Measure real standalone/coordinated toolbar ink, controls and keyboard focus.

Owned synthetic loopback fixture only, no script in the application. Login is
the sole allowed POST. No operator account, host, Send or mail mutation is used.
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
from urllib.parse import parse_qs, urlencode, urlsplit

from playwright.sync_api import sync_playwright

REPO = Path(__file__).resolve().parents[2]
SPRINT = Path('/home/foo/Downloads/osmap-ux-s02/revalidation-20261003')
FIXTURE = 'http::tests::ux_browser_server::ux_synthetic_browser_server'

# Geometry and computed painted edges test the actual icon construction. Text
# contrast audits cannot detect an empty span/pseudo-element with no drawing.
MEASURE = r'''(toolbar) => {
  const number = value => Number.parseFloat(value) || 0;
  const nontransparent = value => value !== 'transparent' &&
    !/^rgba\(.*,[\s]*0(?:\.0+)?\)$/.test(value);
  const painted = style => {
    if (style.display === 'none' || style.visibility !== 'visible' || number(style.opacity) === 0)
      return false;
    const w = number(style.width), h = number(style.height);
    const border = ['Top', 'Right', 'Bottom', 'Left'].some(side =>
      number(style['border' + side + 'Width']) > 0 &&
      !['none', 'hidden'].includes(style['border' + side + 'Style']) &&
      nontransparent(style['border' + side + 'Color']));
    return border && (w > 0 || h > 0);
  };
  const icons = Array.from(toolbar.querySelectorAll('.reader-line-icon')).map(icon => {
    const box = icon.getBoundingClientRect();
    const before = getComputedStyle(icon, '::before'), after = getComputedStyle(icon, '::after');
    const child = icon.querySelector('i');
    const beforeInk = !['none', 'normal'].includes(before.content) && painted(before);
    const afterInk = !['none', 'normal'].includes(after.content) && painted(after);
    const childInk = !!child && painted(getComputedStyle(child));
    return {class_name: icon.className, width: box.width, height: box.height,
      ink: {before: beforeInk, after: afterInk, i: childInk},
      geometry_ok: Math.abs(box.width - 16) < .1 && Math.abs(box.height - 16) < .1,
      painted: beforeInk || afterInk || childInk};
  });
  const relevant = element => !!element.querySelector(':scope > .reader-line-icon') ||
    ['Previous message', 'Next message'].includes(element.getAttribute('aria-label'));
  const allControls = Array.from(toolbar.querySelectorAll('a,button,summary')).filter(element => {
    const box = element.getBoundingClientRect();
    return box.width > 0 && box.height > 0 && getComputedStyle(element).visibility === 'visible' &&
      element.checkVisibility({checkOpacity: true, checkVisibilityCSS: true});
  }).map(element => {
    const box = element.getBoundingClientRect(), style = getComputedStyle(element);
    return {top_row_control: relevant(element), tag: element.tagName, label: element.getAttribute('aria-label') ||
      element.getAttribute('title') || element.textContent.trim(), width: box.width, height: box.height,
      enabled: !element.disabled && element.getAttribute('aria-disabled') !== 'true',
      compact: box.width >= 32 && box.width <= 40 && box.height >= 32 && box.height <= 40,
      inside_viewport: box.left >= -.5 && box.right <= innerWidth + .5,
      border_visible: ['Top', 'Right', 'Bottom', 'Left'].some(side =>
        number(style['border' + side + 'Width']) > 0 &&
        !['none', 'hidden'].includes(style['border' + side + 'Style']))};
  });
  // Text actions and help disclosure inside Labels/More do not have the icon
  // row's compact dimensions. Retain their measurements as diagnostics only.
  const controls = allControls.filter(control => control.top_row_control);
  const secondary_controls = allControls.filter(control => !control.top_row_control);
  return {icons, controls, secondary_controls,
    overflow: document.documentElement.scrollWidth > innerWidth};
}'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--browser', default='/usr/bin/microsoft-edge-stable')
    parser.add_argument('--forced-colors', action='store_true',
                        help='run six system forced-colors checks instead of the default twelve theme checks')
    args = parser.parse_args()
    output = args.output.resolve()
    if output == SPRINT.resolve() or not output.is_relative_to(SPRINT.resolve()):
        parser.error('--output must be a dedicated directory under the existing S02 sprint root')
    executable = args.executable.resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        parser.error('--executable must be the compiled owned synthetic fixture test binary')
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.chmod(0o700)
    report = dict(passed=False, scope='actual no-script synthetic loopback reader toolbar geometry; no live qualification',
                  executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
                  javascript_enabled=False, forced_colors='active' if args.forced_colors else 'none',
                  observations=[], failures=[],
                  outside_requests=0, send_requests=0, mutation_requests=0, login_posts=0,
                  cleanup=dict(server_reaped=False, fixture_removed=False))
    server = None
    browser = None
    temporary = None
    step = 'fixture_start'
    try:
        with tempfile.TemporaryDirectory(prefix='osmap-reader-toolbar-') as tmp, \
                (output / 'synthetic-server.log').open('w') as log, sync_playwright() as pw:
            temporary = Path(tmp)
            temporary.chmod(0o700)
            (output / 'synthetic-server.log').chmod(0o600)
            env = dict(os.environ, OSMAP_UX_BROWSER_STATE=str(temporary), OSMAP_UX_FIXTURE_CONVERSATION='1')
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
                                              user_agent='OSMAP/ReaderToolbarFixture',
                                              viewport=dict(width=1440, height=1000))
                try:
                    def guard(route):
                        request = route.request
                        url = urlsplit(request.url)
                        if url.path == '/send':
                            report['send_requests'] += 1
                        if url.scheme + '://' + url.netloc != origin:
                            report['outside_requests'] += 1
                            route.abort()
                        elif url.path == '/send' or request.method not in {'GET', 'POST'}:
                            report['mutation_requests'] += 1
                            route.abort()
                        elif request.method == 'POST' and url.path != '/login':
                            report['mutation_requests'] += 1
                            route.abort()
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
                        assert 'no-store' in response.headers.get('cache-control', '')
                        assert page.locator('script').count() == 0

                    step = 'synthetic_login'
                    visit('/login')
                    page.get_by_label('Username or Email').fill('alice@example.com')
                    page.get_by_label('Password', exact=True).fill('correct horse battery staple')
                    page.get_by_label('TOTP Code').fill('123456')
                    page.get_by_role('button', name='Sign In', exact=True).press('Enter')
                    page.wait_for_url(origin + '/mailboxes')
                    visit('/settings?section=reading')
                    assert page.locator('#reading-mark-read').input_value() == 'manual'

                    def selected_target(origin_path):
                        visit(origin_path)
                        row = page.locator('.message-card, .search-result-row').filter(
                            has=page.locator('summary[aria-label="More for message #3 in INBOX"]'))
                        link = row.locator('a.message-subject-link')
                        assert link.count() == 1
                        href = link.get_attribute('href')
                        parsed = urlsplit(href)
                        assert not parsed.scheme and not parsed.netloc
                        fields = parse_qs(parsed.query)
                        assert fields['selected_uid'] == ['3'] and fields['selected_mailbox'] == ['INBOX']
                        assert fields['selected_mailbox_guid'] and fields['selected_message_guid']
                        return parsed.path + '?' + parsed.query, fields

                    mailbox, identity = selected_target('/mailbox?name=INBOX')
                    search, _ = selected_target('/search?q=Shared%20public%20subject&field=subject&scope=all')
                    standalone = '/message?' + urlencode(dict(mailbox='INBOX', uid='3',
                        mailbox_guid=identity['selected_mailbox_guid'][0],
                        message_guid=identity['selected_message_guid'][0],
                        return_to='/mailbox?name=INBOX'))
                    for surface, path in [('standalone', standalone), ('mailbox', mailbox), ('search', search)]:
                        for width in [1440, 360]:
                            for scheme in ['light'] if args.forced_colors else ['light', 'dark']:
                                step = f'{surface}_{width}_{scheme}'
                                page.set_viewport_size(dict(width=width, height=1000))
                                page.emulate_media(color_scheme=scheme,
                                                   forced_colors='active' if args.forced_colors else 'none')
                                visit(path)
                                toolbar = page.locator('.reader-icon-toolbar')
                                assert toolbar.count() == 1 and toolbar.is_visible()
                                toolbar.scroll_into_view_if_needed()
                                assert page.locator('.body-panel pre').inner_text() == 'Synthetic message 3 in INBOX for alice@example.com.'
                                if args.forced_colors:
                                    assert page.evaluate("matchMedia('(forced-colors: active)').matches")
                                measurement = toolbar.evaluate(MEASURE)
                                issues = []
                                names = {icon['class_name'].split('reader-line-')[-1] for icon in measurement['icons']}
                                if not {'back', 'reply', 'archive', 'bin', 'read', 'clock', 'label', 'more'} <= names:
                                    issues.append('missing_expected_icon_span')
                                if any(not icon['geometry_ok'] for icon in measurement['icons']):
                                    issues.append('icon_span_not_16px')
                                if any(not icon['painted'] for icon in measurement['icons']):
                                    issues.append('icon_has_no_painted_before_after_or_i_edge')
                                if len(measurement['controls']) != 10 or any(not control['compact'] for control in measurement['controls']):
                                    issues.append('visible_control_not_compact_32_to_40px')
                                if any(not control['inside_viewport'] or not control['border_visible'] for control in measurement['controls']):
                                    issues.append('control_border_or_viewport_failure')
                                if measurement['overflow']:
                                    issues.append('document_horizontal_overflow')
                                enabled = [control for control in toolbar.locator('a,button,summary').all()
                                           if control.is_visible() and not control.is_disabled()
                                           and control.get_attribute('aria-disabled') != 'true']
                                assert len(enabled) >= 3
                                enabled[0].focus()
                                keyboard_ok = True
                                for index in range(min(len(enabled) - 1, 5)):
                                    enabled[index].press('Tab')
                                    if not enabled[index + 1].evaluate('(e) => document.activeElement === e'):
                                        keyboard_ok = False
                                        break
                                if not keyboard_ok:
                                    issues.append('enabled_toolbar_keyboard_tab_order_failure')
                                mode = 'forced-colors-' if args.forced_colors else ''
                                filename = f'reader-toolbar-{mode}{surface}-{width}-{scheme}-synthetic.png'
                                page.screenshot(path=str(output / filename), full_page=True)
                                observation = dict(surface=surface, width=width, scheme=scheme,
                                                   capture=filename, keyboard_tab_pass=keyboard_ok,
                                                   passed=not issues, issues=issues, **measurement)
                                report['observations'].append(observation)
                                if issues:
                                    report['failures'].append(dict(surface=surface, width=width, scheme=scheme, issues=issues))
                    report['standalone_positive_control'] = all(item['passed'] for item in report['observations'] if item['surface'] == 'standalone')
                    report['coordinated_mailbox_pass'] = all(item['passed'] for item in report['observations'] if item['surface'] == 'mailbox')
                    report['coordinated_search_pass'] = all(item['passed'] for item in report['observations'] if item['surface'] == 'search')
                    expected_observations = 6 if args.forced_colors else 12
                    assert len(report['observations']) == expected_observations and report['login_posts'] == 1
                    assert report['send_requests'] == report['outside_requests'] == report['mutation_requests'] == 0
                    report['passed'] = not report['failures']
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
        if server and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        report['cleanup']['server_reaped'] = bool(server and server.poll() is not None)
        report['cleanup']['fixture_removed'] = bool(temporary and not temporary.exists())
        report['passed'] = report['passed'] and all(report['cleanup'].values()) and report.get('server_exit_code') == 0
        result = output / 'report.json'
        result.write_text(json.dumps(report, indent=2) + '\n')
        result.chmod(0o600)
        print(json.dumps(dict(passed=report['passed'], observations=len(report['observations']),
                              standalone_positive_control=report.get('standalone_positive_control'),
                              failures=report['failures'], error=report.get('error'), cleanup=report['cleanup'])))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
