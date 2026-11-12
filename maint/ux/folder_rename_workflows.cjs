// Finite synthetic browser journey. Only a fresh owned loopback fixture is used.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {chromium, firefox} = require('playwright');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function main() {
  const out = path.resolve(process.argv[2]);
  const engine = process.argv[3] || 'chromium';
  assert(['chromium', 'firefox'].includes(engine));
  fs.mkdirSync(out, {recursive: true, mode: 0o700});
  fs.chmodSync(out, 0o700);
  const repo = path.resolve(__dirname, '../..');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'osmap-folder-rename-'));
  const log = fs.openSync(path.join(out, 'server.log'), 'w', 0o600);
  const child = spawn('cargo', ['test', '--lib', 'ux_synthetic_browser_server', '--', '--ignored', '--nocapture'], {
    cwd: repo, env: {...process.env, OSMAP_UX_BROWSER_STATE: root, OSMAP_UX_FIXTURE_FOLDER_RENAME: '1'}, stdio: ['ignore', log, log]
  });
  const exited = new Promise(resolve => child.once('exit', (code, signal) => resolve({code, signal})));
  let browser;
  let page;
  let cleanup = false;
  let successEvidence;
  const blocked = [];
  try {
    const until = performance.now() + 45000;
    const ready = path.join(root, 'ready.json');
    while (!fs.existsSync(ready) && performance.now() < until && child.exitCode === null) await sleep(50);
    assert(fs.existsSync(ready), 'synthetic readiness not confirmed');
    const info = JSON.parse(fs.readFileSync(ready, 'utf8'));
    assert.equal(info.synthetic, true);
    assert.equal(info.deadline_seconds, 180);
    assert(/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(info.origin));
    const origin = info.origin;
    const browserPath = engine === 'chromium' ? '/usr/bin/microsoft-edge-stable' : '/home/foo/.cache/ms-playwright/firefox-1543/firefox/firefox';
    assert(fs.existsSync(browserPath), 'installed browser unavailable');
    browser = await (engine === 'chromium' ? chromium : firefox).launch({executablePath: browserPath, headless: true});
    const auditSource = fs.readFileSync(path.join(repo, 'maint/ux/contrast_audit.py'), 'utf8').match(/TEXT_AUDIT\s*=\s*r"""([\s\S]*?)"""/)[1];
    async function context(agent) {
      const ctx = await browser.newContext({javaScriptEnabled: false, viewport: {width: 1600, height: 1100}, userAgent: agent});
      await ctx.route('**/*', route => {
        const url = route.request().url();
        if (url.startsWith(origin + '/') && !url.includes('/send')) return route.continue();
        blocked.push(route.request().resourceType()); return route.abort();
      });
      return ctx;
    }
    async function login(ctx, account) {
      const p = await ctx.newPage(); p.setDefaultTimeout(10000);
      await p.goto(origin + '/login');
      await p.getByLabel('Username').fill(account);
      await p.getByLabel('Password', {exact: true}).fill('correct horse battery staple');
      await p.getByLabel('TOTP code').fill('123456');
      await p.getByRole('button', {name: 'Sign In', exact: true}).click();
      await p.waitForURL('**/mailboxes'); return p;
    }
    async function create(p, leaf) {
      await p.goto(origin + '/settings?section=copies&folder=INBOX');
      await p.getByRole('link', {name: 'New subfolder', exact: true}).click();
      await p.getByLabel('Subfolder name').fill(leaf);
      await p.getByRole('button', {name: 'Review creation', exact: true}).click();
      await p.getByRole('button', {name: 'Confirm create folder', exact: true}).click();
      await p.waitForURL(url => url.searchParams.get('folder') === 'INBOX.' + leaf);
    }
    const ctx = await context('FolderCreateValid');
    page = await login(ctx, 'alice@example.com');
    await page.goto(origin + '/settings?section=copies&folder=INBOX');
    assert(await page.getByRole('button', {name: 'Rename', exact: true}).isDisabled());
    await create(page, 'Rename source');
    await page.getByRole('link', {name: 'Rename', exact: true}).focus();
    await page.keyboard.press('Enter');
    await page.getByLabel('Folder name', {exact: true}).fill('Élodie & Office');
    await page.getByRole('button', {name: 'Review rename', exact: true}).click();
    assert(await page.getByRole('heading', {name: 'Review rename', exact: true}).isVisible());
    const guid = await page.locator('[name="source_guid"]').inputValue();
    for (const scheme of ['light', 'dark']) for (const width of [1600, 360]) for (const forced of ['none', 'active']) {
      await page.setViewportSize({width, height: 1100}); await page.emulateMedia({colorScheme: scheme, forcedColors: forced});
      const audit = await page.evaluate("(" + auditSource + ")()");
      assert.equal(audit.failures.length, 0); assert.equal(audit.ui_failures.length, 0);
      assert(await page.evaluate('document.documentElement.scrollWidth <= innerWidth'));
      await page.screenshot({path: path.join(out, `review-${scheme}-${width}-${forced}.png`), fullPage: true});
    }
    await page.getByRole('button', {name: 'Confirm rename folder', exact: true}).click();
    await page.waitForURL(url => url.searchParams.get('folder') === 'INBOX.Élodie & Office');
    assert.equal(await page.locator('.copies-details h3').last().innerText(), 'INBOX.Élodie & Office');
    await page.getByRole('link', {name: 'Rename', exact: true}).click();
    assert.equal(await page.locator('[name="source_guid"]').inputValue(), guid);
    await ctx.close();
    // The helper committed but its response was lost: only current proof clears pending.
    const committed = await context('FolderCreateRenameUnknownCommitted');
    page = await login(committed, 'alice@example.com');
    await page.goto(origin + '/settings/folders/rename?source=' + encodeURIComponent('INBOX.Élodie & Office'));
    await page.getByLabel('Folder name', {exact: true}).fill('Confirmed by check');
    await page.getByRole('button', {name: 'Review rename', exact: true}).click();
    let response = await Promise.all([page.waitForNavigation(), page.getByRole('button', {name: 'Confirm rename folder', exact: true}).click()]);
    assert.equal(response[0].status(), 503);
    assert.equal(await page.locator('form[action="/settings/folders/rename"]').count(), 0);
    await page.getByRole('link', {name: 'Check rename result', exact: true}).click();
    await page.getByRole('button', {name: 'Check current result', exact: true}).click();
    await page.waitForURL(url => url.searchParams.get('folder') === 'INBOX.Confirmed by check');
    await committed.close();
    // A lost settled pre-dispatch refusal has a durable original-action witness.
    const refused = await context('FolderCreateRenameRefusedLost');
    page = await login(refused, 'alice@example.com');
    await page.goto(origin + '/settings/folders/rename?source=' + encodeURIComponent('INBOX.Confirmed by check'));
    await page.getByLabel('Folder name', {exact: true}).fill('Not dispatched');
    await page.getByRole('button', {name: 'Review rename', exact: true}).click();
    response = await Promise.all([page.waitForNavigation(), page.getByRole('button', {name: 'Confirm rename folder', exact: true}).click()]);
    assert.equal(response[0].status(), 503);
    await page.getByRole('link', {name: 'Check rename result', exact: true}).click();
    response = await Promise.all([page.waitForNavigation(), page.getByRole('button', {name: 'Check current result', exact: true}).click()]);
    assert.equal(response[0].status(), 200);
    assert(await page.getByText('finished without attempting a rename', {exact: false}).isVisible());
    await page.screenshot({path: path.join(out, 'settled-refusal.png'), fullPage: true});
    await page.getByRole('link', {name: 'Inspect Copies & Folders', exact: true}).click();
    await page.goto(origin + '/settings?section=copies&folder=' + encodeURIComponent('INBOX.Confirmed by check'));
    assert(await page.getByRole('link', {name: 'Rename', exact: true}).isVisible());
    await refused.close();
    // An unchanged result stays pending; no rename retry or invented child proof.
    const uncertain = await context('FolderCreateRenameUnknown');
    page = await login(uncertain, 'alice@example.com');
    await page.goto(origin + '/settings/folders/rename?source=' + encodeURIComponent('INBOX.Confirmed by check'));
    await page.getByLabel('Folder name', {exact: true}).fill('Uncertain');
    await page.getByRole('button', {name: 'Review rename', exact: true}).click();
    response = await Promise.all([page.waitForNavigation(), page.getByRole('button', {name: 'Confirm rename folder', exact: true}).click()]);
    assert.equal(response[0].status(), 503);
    await page.getByRole('link', {name: 'Check rename result', exact: true}).click();
    response = await Promise.all([page.waitForNavigation(), page.getByRole('button', {name: 'Check current result', exact: true}).click()]);
    assert.equal(response[0].status(), 409);
    assert(await page.getByText('A proven settled helper result is required', {exact: false}).isVisible());
    await page.screenshot({path: path.join(out, 'unknown-result.png'), fullPage: true});
    await page.getByRole('link', {name: 'Inspect Copies & Folders', exact: true}).click();
    assert(await page.getByRole('button', {name: 'Rename', exact: true}).isDisabled());
    assert(await page.getByRole('link', {name: 'Check rename result', exact: true}).isVisible());
    await uncertain.close();
    const bob = await context('FolderCreateValid');
    page = await login(bob, 'bob@example.com');
    await page.goto(origin + '/settings?section=copies&folder=INBOX');
    assert.equal(await page.locator('.copies-tree').getByText('INBOX.Confirmed by check', {exact: true}).count(), 0);
    await bob.close();
    assert.equal(blocked.length, 0);
    successEvidence = {status: 'PASS', engine, javascript: false, external_requests: 0, checked: ['keyboard review', 'GUID continuity', 'confirmed read-only result', 'unchanged pending result', 'settled no-op recovery', 'account isolation', 'contrast/overflow'], not_qualified: ['Dovecot', 'OpenBSD native', 'human UAT']};
  } catch (error) {
    if (page && !page.isClosed() && page.url().includes('/settings')) await page.screenshot({path: path.join(out, 'failure.png'), fullPage: true}).catch(() => {});
    fs.writeFileSync(path.join(out, 'failure.json'), JSON.stringify({status: 'FAIL', error: error.name, message: String(error.message).slice(0, 500)}, null, 2) + '\n', {mode: 0o600});
    throw error;
  } finally {
    if (browser) await browser.close();
    fs.writeFileSync(path.join(root, 'stop'), '');
    const outcome = await Promise.race([exited, sleep(5000).then(() => null)]);
    if (!outcome) { child.kill('SIGTERM'); await Promise.race([exited, sleep(5000)]); }
    else cleanup = outcome.code === 0 && outcome.signal === null;
    fs.closeSync(log);
    if (cleanup) fs.rmSync(root, {recursive: true});
    assert(cleanup, 'owned synthetic server cleanup not confirmed');
    if (successEvidence) fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify({...successEvidence, owned_server_exit: 0, owned_root_removed: true}, null, 2) + '\n', {mode: 0o600});
  }
}
main().catch(error => { process.stderr.write(error.stack + '\n'); process.exitCode = 1; });
