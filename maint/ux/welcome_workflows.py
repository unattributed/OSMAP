import argparse,json,tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT
parser=argparse.ArgumentParser(description='Approved Welcome native workflows against isolated synthetic stores.')
parser.add_argument('output',type=Path)
parser.add_argument('--engine',choices=['chromium','firefox'],default='chromium')
parser.add_argument('--browser',default='/usr/bin/microsoft-edge-stable')
args=parser.parse_args()
repo=Path(__file__).resolve().parents[2]
out=args.output;out.mkdir(parents=True,exist_ok=True,mode=0o700)
report={'status':'FAIL','scope':'Isolated Welcome data proposal; synthetic loopback; no sends','captures':[],'checks':[],'external':[],'scripts':[],'send_requests':0}
with tempfile.TemporaryDirectory(prefix='osmap-welcome-browser-') as tmp,(out/'server.log').open('w') as log,sync_playwright() as pw:
    process,origin=start_server(Path(tmp),repo,log)
    browser=getattr(pw,args.engine).launch(executable_path=args.browser,headless=True)
    report['browser']=browser.version
    def page(ua='WelcomeBrowser', account='alice@example.com'):
        ctx=browser.new_context(viewport={'width':1536,'height':1024},color_scheme='light',java_script_enabled=False,user_agent=ua)
        def constrained(r):
            if r.request.url.split('?')[0] == origin+'/send': report['send_requests'] += 1
            if r.request.resource_type=='script': report['scripts'].append(r.request.url.split('?')[0].replace(origin,''))
            if r.request.url.startswith(origin+'/'):r.continue_()
            else:report['external'].append(True);r.abort()
        ctx.route('**/*',constrained);p=ctx.new_page();p.goto(origin+'/login')
        p.get_by_label('Username or Email').fill(account);p.get_by_label('Password',exact=True).fill('correct horse battery staple');p.get_by_label('TOTP Code').fill('123456')
        p.get_by_role('button',name='Sign In',exact=True).click();p.wait_for_url('**/mailboxes');return p
    def capture(p,name,**metadata):
        audit=p.evaluate(TEXT_AUDIT)
        p.screenshot(path=str(out/name),full_page=True)
        report['captures'].append(dict(file=name,contrast=audit,**metadata))
        assert not audit['failures'] and not audit['ui_failures'], (name,audit)
    try:
        p=page()
        metric=p.locator('.welcome-metric[href="/mailbox?name=Sent"]');expect(metric).to_have_attribute('aria-label','Sent · loaded messages: 2; open list');metric.press('Enter');p.wait_for_url('**/mailbox?name=Sent');p.goto(origin+'/mailboxes')
        bad=page('WelcomeSent/wrong-owner');expect(bad.locator('.welcome-metric[href="/mailbox?name=Sent"]')).to_contain_text('Unknown')
        bob=page(account='bob@example.com');expect(bob.locator('.welcome-metric[href="/mailbox?name=Sent"]')).to_have_attribute('aria-label','Sent · loaded messages: 2; open list');expect(bob.locator('.welcome-account')).to_contain_text('bob@example.com')
        report['checks'].append('Native Sent metric opens owned list; loaded-set scope; foreign result refused; Bob account isolated')
        activity=p.locator('.welcome-activity-rows time');assert 1<=activity.count()<=5;assert all('UTC' in text for text in activity.all_text_contents());expect(p.locator('.welcome-activity-scope')).to_contain_text('Key and recovery events are unavailable');report['checks'].append('Owned retained sign-ins show UTC/device, with explicit non-audit-history scope')
        assert p.locator('.welcome-recent-link').count()==2
        p.locator('.welcome-recent-link').first.press('Enter');p.wait_for_url('**/message?**')
        assert p.locator('h1').count()>0
        p.goto(origin+'/mailboxes');p.locator('.welcome-panel-heading').get_by_role('link',name='Open Inbox').click();p.wait_for_url('**/mailbox?name=INBOX')
        p.goto(origin+'/mailboxes');report['checks'].append('Real newest summary link opens authenticated reader; View all opens Inbox')
        for width in [1536,360]:
            for scheme in ['light','dark']:
                for forced in ['none','active']:
                    p.set_viewport_size({'width':width,'height':1024});p.emulate_media(color_scheme=scheme,forced_colors=forced)
                    p.goto(origin+'/mailboxes');assert p.locator('script').count()==0
                    dimensions=p.evaluate('({scroll:document.documentElement.scrollWidth,viewport:innerWidth})')
                    assert dimensions['scroll']<=dimensions['viewport'],dimensions
                    name=f'welcome-{scheme}-{width}'+('-forced' if forced=='active' else '')+'.png'
                    capture(p,name,width=width,scheme=scheme,forced=forced,overflow=False)
        p.set_viewport_size({'width':1536,'height':1024});p.emulate_media(color_scheme='light',forced_colors='none')
        def home():p.goto(origin+'/mailboxes')
        home();button=p.locator('.welcome-shortcuts').get_by_role('link',name='Compose New message')
        for _ in range(70):
            p.keyboard.press('Tab')
            if button.evaluate('e=>e===document.activeElement'):break
        else:raise AssertionError('Compose not reachable using Tab')
        p.keyboard.press('Enter');p.wait_for_url('**/compose');report['checks'].append('Keyboard Tab/Enter opens Compose; no submission')
        home();p.locator('.welcome-browse summary').press('Enter');p.locator('.welcome-folder-scroll').get_by_role('link',name='INBOX Open mailbox').click();p.wait_for_url('**/mailbox?name=INBOX');report['checks'].append('Actual mailbox link opens INBOX')
        home();p.locator('.welcome-search summary').press('Enter');p.locator('#mailbox-global-search').fill('quarterly report');p.locator('#search-field').select_option('subject');p.locator('.welcome-search button').click();p.wait_for_url('**/search?**');assert p.locator('h1').count()>0;assert 'field=subject' in p.url;report['checks'].append('Native all-mailbox search submits query and selected field')
        home();p.locator('.welcome-shortcut-menu summary').press('Enter');expect(p.get_by_role('link',name='Open configured Archive')).to_be_visible();p.get_by_role('link',name='Open configured Archive').click();assert '/mailbox/shortcut' in p.url or '/mailbox?' in p.url;report['checks'].append('Archive menu resolves existing native route')
        home();p.locator('.welcome-shortcut-menu summary').click();p.get_by_role('link',name='Open Bin',exact=True).click();p.wait_for_url('**/mailbox?name=Trash');report['checks'].append('Bin opens actual Trash mailbox')
        for label,target in [('Settings Account & preferences','/settings'),('Security Account protection','/settings?section=security')]:
            home();p.locator('.welcome-shortcuts').get_by_role('link',name=label).click();p.wait_for_url('**'+target);report['checks'].append(label+' navigation')
        missing=page('WelcomeMissing');missing.set_viewport_size({'width':360,'height':1024});missing.goto(origin+'/mailboxes')
        expect(missing.locator('.welcome-shortcuts').get_by_text('Mailbox unavailable',exact=True)).to_be_visible()
        assert missing.locator('.welcome-page a[href="/mailbox?name=INBOX"]').count()==0
        missing.locator('.welcome-shortcut-menu summary').click();expect(missing.get_by_text('Bin mailbox unavailable',exact=True)).to_be_visible();assert missing.locator('.welcome-page a[href="/mailbox?name=Trash"]').count()==0
        assert missing.locator('.welcome-page img').count()==0
        missing.locator('.welcome-browse summary').click()
        assert '<img src=x> & synthetic' in missing.locator('.welcome-folder-scroll').inner_text()
        assert missing.evaluate('document.documentElement.scrollWidth<=innerWidth')
        capture(missing,'welcome-missing-escaped-360.png',overflow=False)
        report['checks'].append('Missing INBOX/Trash do not produce enabled Welcome mailbox links; long escaped name is literal and fits')
        many=page('Firefox/ManyMailboxes');many.locator('.welcome-browse summary').click();assert many.locator('.welcome-folder-scroll a').count()==1024;expect(many.get_by_text('Mailbox list display limit reached:',exact=False)).to_be_visible();report['checks'].append('Large mailbox list remains capped at 1024 real links')
        dense=page('WelcomeData/rows');assert dense.locator('.welcome-recent-link').count()==5
        for width,scheme in [(1536,'light'),(360,'dark')]:
            dense.set_viewport_size({'width':width,'height':1024});dense.emulate_media(color_scheme=scheme)
            assert dense.evaluate('document.documentElement.scrollWidth<=innerWidth')
            capture(dense,f'welcome-five-{scheme}-{width}.png',overflow=False)
        report['checks'].append('More than five actual summaries show newest five; dense rows have no overflow')
        assert not report['external'];assert report['scripts']==[];assert report['send_requests']==0;report['status']='PASS'
    finally:
        (out/'report.json').write_text(json.dumps(report,indent=2));browser.close();stop_server(process,Path(tmp))
