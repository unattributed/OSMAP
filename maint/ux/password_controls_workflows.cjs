// S04-02 T01 only: actual owned headless browser, synthetic account/router.
// No Runtime backend, operator profile, installed host or credential change.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');
const {chromium} = require('playwright');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function state(root) {
  const result = {};
  function visit(dir) {
    for (const name of fs.readdirSync(dir)) {
      const leaf = path.join(dir, name); const info = fs.lstatSync(leaf);
      assert(!info.isSymbolicLink(), 'fixture state unexpectedly linked');
      if (info.isDirectory()) visit(leaf);
      else { assert(info.isFile()); result[path.relative(root, leaf)] = sha(fs.readFileSync(leaf)); }
    }
  }
  visit(root); return result;
}
async function main() {
  const out = path.resolve(process.argv[2]);
  const binary = path.resolve(process.argv[3]);
  assert(fs.lstatSync(binary).isFile() && !fs.lstatSync(binary).isSymbolicLink());
  fs.mkdirSync(out, {recursive: true, mode: 0o700}); fs.chmodSync(out, 0o700);
  const repo = path.resolve(__dirname, '../..');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'osmap-password-controls-'));
  fs.chmodSync(root, 0o700);
  const log = fs.openSync(path.join(out, 'server.log'), 'wx', 0o600);
  const child = spawn(binary, ['--exact', 'http::tests::ux_browser_server::ux_synthetic_browser_server', '--ignored', '--nocapture'], {
    cwd: repo, env: {...process.env, OSMAP_UX_BROWSER_STATE: root, OSMAP_UX_FIXTURE_PASSWORD_CONTROLS: '1'}, stdio: ['ignore', log, log]
  });
  let terminal = null;
  const exited = new Promise(resolve => child.once('exit', (code, signal) => {terminal = {code, signal}; resolve(terminal);}));
  let browser; let success = false; let cleaned = false; let report;
  const requests = []; const blocked = []; const checks = [];
  try {
    const until = performance.now() + 45000;
    while (!fs.existsSync(path.join(root, 'ready.json')) && performance.now() < until && terminal === null) await sleep(25);
    assert(fs.existsSync(path.join(root, 'ready.json')), 'owned synthetic server readiness missing');
    const info = JSON.parse(fs.readFileSync(path.join(root, 'ready.json'), 'utf8'));
    assert.equal(info.synthetic, true); assert.equal(info.password_controls_fixture, true); assert.equal(info.deadline_seconds, 180);
    assert(/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(info.origin));
    const origin = info.origin;
    // No X11/Wayland connection. Ozone headless uses its browser-owned clipboard;
    // only public synthetic data is seeded by the separate automation page.
    const environment = {...process.env}; delete environment.DISPLAY; delete environment.WAYLAND_DISPLAY;
    browser = await chromium.launch({executablePath: '/usr/bin/microsoft-edge-stable', headless: true, args: ['--ozone-platform=headless'], env: environment});
    const context = await browser.newContext({permissions: ['clipboard-read', 'clipboard-write']});
    await context.route('**/*', route => {
      const r = route.request();
      if (r.url().startsWith(origin + '/')) {requests.push({method: r.method(), path: new URL(r.url()).pathname}); return route.continue();}
      blocked.push(r.resourceType()); return route.abort();
    });
    const page = await context.newPage(); page.setDefaultTimeout(5000);
    await page.goto(origin + '/login');
    await page.getByLabel('Username or Email').fill('alice@example.com');
    await page.getByLabel('Password', {exact: true}).fill('correct horse battery staple');
    await page.getByLabel('TOTP Code').fill('123456');
    await Promise.all([page.waitForURL('**/mailboxes'), page.getByRole('button', {name: 'Sign In', exact: true}).click()]);
    const seeder = await context.newPage(); await seeder.goto(origin + '/login');
    const sideEffects = [];
    await page.exposeBinding('__osmapT01SideEffect', (_, kind) => {
      assert(['submit', 'clipboard', 'storage', 'network'].includes(kind)); sideEffects.push(kind);
    });
    await page.addInitScript(() => {
      const counters = {submit: 0, clipboard: 0, storage: 0, network: 0, paste: 0, trustedPaste: 0};
      Object.defineProperty(window, '__osmapPasswordT01', {value: counters});
      const record = kind => {counters[kind]++; void window.__osmapT01SideEffect(kind);};
      const refuse = kind => function () {record(kind); throw new Error('T01 forbidden side effect');};
      for (const name of ['submit', 'requestSubmit']) HTMLFormElement.prototype[name] = refuse('submit');
      document.addEventListener('submit', () => {record('submit');}, true);
      document.addEventListener('paste', event => {counters.paste++; if (event.isTrusted) counters.trustedPaste++;}, true);
      for (const name of ['read', 'readText', 'write', 'writeText']) if (navigator.clipboard && name in navigator.clipboard) navigator.clipboard[name] = refuse('clipboard');
      for (const name of ['setItem', 'removeItem', 'clear']) Storage.prototype[name] = refuse('storage');
      if (window.indexedDB) for (const name of ['open', 'deleteDatabase']) indexedDB[name] = refuse('storage');
      window.fetch = refuse('network'); window.XMLHttpRequest = refuse('network'); window.WebSocket = refuse('network'); navigator.sendBeacon = refuse('network');
    });
    await page.goto(origin + '/settings?section=security');
    await page.getByRole('link', {name: 'Change password', exact: true}).click();
    await page.waitForURL('**/settings/password');
    const spyControl = await page.evaluate(() => {
      const form = document.getElementById('password-change-form');
      for (const invoke of [() => form.submit(), () => form.requestSubmit(),
        () => navigator.clipboard.readText(), () => navigator.clipboard.writeText('public'),
        () => navigator.clipboard.read(), () => navigator.clipboard.write([]),
        () => localStorage.setItem('public', 'public'), () => localStorage.removeItem('public'),
        () => localStorage.clear(), () => indexedDB.open('public'), () => indexedDB.deleteDatabase('public'),
        () => fetch('/blocked'), () => new XMLHttpRequest(), () => new WebSocket('ws://blocked'), () => navigator.sendBeacon('/blocked')]) {
        try {invoke();} catch (_) {}
      }
      const result = {...window.__osmapPasswordT01};
      for (const name of Object.keys(window.__osmapPasswordT01)) window.__osmapPasswordT01[name] = 0;
      return result;
    });
    assert.deepEqual(spyControl, {submit: 2, clipboard: 4, storage: 5, network: 4, paste: 0, trustedPaste: 0});
    assert.deepEqual(sideEffects.sort(), ['submit','submit', ...Array(4).fill('clipboard'), ...Array(5).fill('storage'), ...Array(4).fill('network')].sort());
    sideEffects.length = 0;
    const initial = state(root); const cookieBefore = await context.cookies();
    requests.length = 0;
    const names = ['current_password', 'new_password', 'confirmation'];
    const labels = ['Current password', 'New password', 'Confirm new password'];
    const values = ['Public current passphrase', 'Public new passphrase', 'Public confirmation passphrase'];
    async function snapshot() {return page.evaluate(() => ['current_password','new_password','confirmation'].map(name => {const input = document.getElementById(name); return {type: input.type, value: input.value};}));}
    for (let i = 0; i < names.length; i++) await page.getByLabel(labels[i], {exact: true}).fill(values[i]);
    for (let i = 0; i < names.length; i++) {
      const field = page.getByLabel(labels[i], {exact: true});
      const button = page.getByRole('button', {name: 'Show or hide ' + labels[i], exact: true});
      assert(await button.isVisible()); assert.equal(await button.getAttribute('type'), 'button');
      assert.equal(await button.getAttribute('aria-controls'), names[i]); assert.equal(await button.getAttribute('aria-pressed'), 'false');
      await field.focus(); await page.keyboard.press('Tab'); assert(await button.evaluate(el => el === document.activeElement));
      await page.keyboard.press('Enter');
      assert.equal(await button.innerText(), 'Hide'); assert.equal(await button.getAttribute('aria-pressed'), 'true');
      assert.deepEqual(await snapshot(), names.map((_, j) => ({type: i === j ? 'text' : 'password', value: values[j]})));
      await page.keyboard.press('Space');
      assert.equal(await button.innerText(), 'Show'); assert.equal(await button.getAttribute('aria-pressed'), 'false');
      assert.deepEqual(await snapshot(), names.map((_, j) => ({type: 'password', value: values[j]})));
    }
    checks.push('three actual independent controls; keyboard Tab/Enter/Space; accessible labels/controls/pressed state; other fields preserved');
    for (let i = 0; i < names.length; i++) {
      values[i] = 'Public paste ' + names[i] + ' 🦊';
      await seeder.bringToFront(); await seeder.evaluate(text => navigator.clipboard.writeText(text), values[i]); await page.bringToFront();
      await page.getByLabel(labels[i], {exact: true}).focus(); await page.keyboard.press('Control+a'); await page.keyboard.press('Control+v');
      assert.deepEqual(await snapshot(), names.map((_, j) => ({type: 'password', value: values[j]})));
    }
    const metrics = await page.evaluate(() => ({...window.__osmapPasswordT01}));
    assert.deepEqual(metrics, {submit: 0, clipboard: 0, storage: 0, network: 0, paste: 3, trustedPaste: 3});
    checks.push('three trusted native Ctrl+V pastes preserve Unicode without application Clipboard API calls');
    assert.equal(requests.length, 0, 'local controls unexpectedly requested network');
    await Promise.all([page.waitForURL('**/settings?section=security'), page.getByRole('link', {name: 'Cancel', exact: true}).click()]);
    assert(requests.length === 1 && requests[0].method === 'GET' && requests[0].path === '/settings');
    assert.deepEqual(state(root), initial); assert.deepEqual(await context.cookies(), cookieBefore);
    checks.push('populated Cancel emits one settings GET; no POST; synthetic account/session/file state preserved');
    await page.goto(origin + '/settings?section=authentication');
    await page.getByRole('link', {name: 'Change password', exact: true}).click(); await page.waitForURL('**/settings/password');
    await page.getByLabel('Current password', {exact: true}).fill('Public populated breadcrumb'); requests.length = 0;
    await Promise.all([page.waitForURL('**/settings?section=security'), page.getByRole('navigation', {name: 'Breadcrumb'}).getByRole('link', {name: 'Security', exact: true}).click()]);
    assert.deepEqual(requests, [{method: 'GET', path: '/settings'}]);
    assert.deepEqual(state(root), initial); assert.deepEqual(await context.cookies(), cookieBefore); assert.equal(blocked.length, 0); assert.deepEqual(sideEffects, [], 'local controls/navigation attempted a forbidden API');
    checks.push('Authentication and Recovery entry plus populated breadcrumb navigation use GET only with no account changes');
    report = {status: 'PASS', scope: 'S04-02-T01 source-owned real headless browser with synthetic gateway', engine: browser.version(), javascript: true, checks, interaction_metrics: metrics, external_requests: blocked.length, password_POSTs: requests.filter(r => r.method !== 'GET').length, fixture_state_preserved: true, forbidden_side_effects_across_navigation: sideEffects.length, observer_positive_control: '15 forbidden calls intercepted before checks', browser_clipboard: 'public synthetic seed in Ozone headless; no display server', binary_sha256: sha(fs.readFileSync(binary)), password_script_sha256: sha(fs.readFileSync(path.join(repo, 'src/http/password_local.js'))), not_qualified: ['real authentication or password mutation', 'native backend/Runtime capability', 'installed T06', 'owner acceptance']};
    success = true;
  } catch (error) {
    fs.writeFileSync(path.join(out, 'failure.json'), JSON.stringify({status: 'FAIL', type: error.name}, null, 2) + '\n', {mode: 0o600});
    throw error;
  } finally {
    let browserCloseFailed = false;
    if (browser) {try {await browser.close();} catch (_) {browserCloseFailed = true;}}
    fs.writeFileSync(path.join(root, 'stop'), '', {mode: 0o600});
    const outcome = terminal || await Promise.race([exited, sleep(5000).then(() => null)]);
    if (!outcome && terminal === null) {child.kill('SIGTERM'); await Promise.race([exited, sleep(5000)]);}
    else cleaned = outcome.code === 0 && outcome.signal === null;
    fs.closeSync(log);
    if (cleaned) fs.rmSync(root, {recursive: true});
    assert(cleaned, 'owned synthetic server cleanup not confirmed');
    assert(!browserCloseFailed, 'owned browser cleanup not confirmed');
    if (success) fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify({...report, owned_server_exit: 0, owned_root_removed: true}, null, 2) + '\n', {mode: 0o600});
  }
}
main().catch(error => {process.stderr.write(error.name + '\n'); process.exitCode = 1;});
