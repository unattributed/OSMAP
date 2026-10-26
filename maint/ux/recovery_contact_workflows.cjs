// S04-03 presentation QA only. Public synthetic fixtures; no native mail claim.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {chromium} = require('playwright');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function main() {
  const out = path.resolve(process.argv[2]);
  const binary = path.resolve(process.argv[3]);
  fs.mkdirSync(out, {recursive:true, mode:0o700});
  const result = {scope:'synthetic actual-browser presentation; no native or delivery qualification', states:[], requests:[], externalRequests:0};
  const environment = {...process.env}; delete environment.DISPLAY; delete environment.WAYLAND_DISPLAY;
  const browser = await chromium.launch({executablePath:'/usr/bin/microsoft-edge-stable',headless:true,env:environment});
  try {
    for (const mode of ['empty','verified','pending','uncertain','unavailable']) {
      const root = fs.mkdtempSync(path.join(os.tmpdir(),'osmap-recovery-ui-'));
      const child = spawn(binary, ['--exact','http::tests::ux_browser_server::ux_synthetic_browser_server','--ignored','--nocapture'], {
        env:{...process.env,OSMAP_UX_BROWSER_STATE:root,OSMAP_UX_FIXTURE_RECOVERY_CONTACT:mode},stdio:['ignore','ignore','ignore']
      });
      const exited = new Promise(resolve => child.once('exit',resolve));
      const context = await browser.newContext();
      try {
        const until = Date.now()+20000;
        while (!fs.existsSync(path.join(root,'ready.json')) && Date.now()<until && child.exitCode===null) await sleep(25);
        assert(fs.existsSync(path.join(root,'ready.json')),'fixture did not become ready');
        const ready=JSON.parse(fs.readFileSync(path.join(root,'ready.json')));
        assert.equal(ready.recovery_contact_fixture,mode); assert.equal(ready.synthetic,true);
        assert(/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(ready.origin));
        await context.route('**/*',route=>{
          const url=new URL(route.request().url());
          if(url.origin!==ready.origin){ result.externalRequests++; return route.abort(); }
          result.requests.push({method:route.request().method(),path:url.pathname}); return route.continue();
        });
        const page=await context.newPage(); page.setDefaultTimeout(5000);
        await page.goto(ready.origin+'/login');
        await page.getByLabel('Username or Email').fill('alice@example.com');
        await page.getByLabel('Password',{exact:true}).fill('correct horse battery staple');
        await page.getByLabel('TOTP Code').fill('123456');
        await Promise.all([page.waitForURL('**/mailboxes'),page.getByRole('button',{name:'Sign In',exact:true}).click()]);
        await page.goto(ready.origin+'/settings/recovery');
        await page.getByRole('heading',{name:'Recovery Contact',exact:true}).waitFor();
        assert.equal(await page.locator('input[type=password]').count(),2+(mode==='pending'?1:0));
        assert(await page.locator('input[type=password]').evaluateAll(nodes=>nodes.every(n=>n.value==='')));
        assert.equal(await page.locator('#recovery-proof').count(),mode==='pending'?1:0);
        if(mode==='uncertain') await page.getByRole('alert').filter({hasText:'An earlier previous-contact notification remains unconfirmed'}).waitFor();
        if(mode==='unavailable') assert.equal(await page.locator('fieldset[disabled]').count(),2);
        for(const [width,scheme] of [[1440,'light'],[1440,'dark'],[360,'light']]) {
          await page.setViewportSize({width,height:1000}); await page.emulateMedia({colorScheme:scheme});
          assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'horizontal overflow');
          await page.screenshot({path:path.join(out,mode+'-'+width+'-'+scheme+'.png'),fullPage:true});
        }
        if(mode==='verified') {
          await page.getByRole('link',{name:'Change contact',exact:true}).click();
          assert.equal(new URL(page.url()).hash,'#recovery-change');
          await page.getByLabel('New email',{exact:true}).fill('public-fixture@example.test');
          await page.locator('#change-password').fill('Public fixture field value');
          await page.locator('#change-totp').fill('123456');
          const before=result.requests.filter(r=>r.method==='POST'&&r.path==='/settings/recovery').length;
          await page.getByRole('link',{name:'Cancel',exact:true}).click();
          await page.getByRole('link',{name:'Manage recovery contact',exact:true}).click();
          assert.equal(await page.getByLabel('New email',{exact:true}).inputValue(),'');
          assert.equal(await page.locator('#change-password').inputValue(),'');
          assert.equal(result.requests.filter(r=>r.method==='POST'&&r.path==='/settings/recovery').length,before);
          await page.keyboard.press('Tab');
          assert(await page.evaluate(()=>document.activeElement!==document.body));
        }
        result.states.push({mode,passed:true,emptySecrets:true,responsive:true});
      } finally {
        await context.close(); fs.writeFileSync(path.join(root,'stop'),'');
        await Promise.race([exited,sleep(3000)]);
        if(child.exitCode===null){child.kill('SIGTERM');await Promise.race([exited,sleep(3000)]);}
        assert.notEqual(child.exitCode,null,'owned fixture did not stop');
        fs.rmSync(root,{recursive:true});
      }
    }
    assert.equal(result.externalRequests,0); result.passed=true;
  } finally {
    await browser.close();fs.writeFileSync(path.join(out,'result.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});
  }
  process.stdout.write('Recovery contact browser presentation PASS\n');
}
main().catch(error=>{process.stderr.write(error.message+'\n');process.exitCode=1;});
