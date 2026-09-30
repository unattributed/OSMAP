"""PAGE27 native empty/error journeys, synthetic loopback only."""
import argparse,json,tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT
p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('--engine',default='chromium');p.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True,mode=0o700)
r=dict(status='FAIL',captures=[],checks=[],external=0,mutations=0)
with tempfile.TemporaryDirectory() as tmp,(a.output/'server.log').open('w') as log,sync_playwright() as pw:
 process,origin=start_server(Path(tmp),Path(__file__).resolve().parents[2],log);b=getattr(pw,a.engine).launch(executable_path=a.browser,headless=True)
 try:
  cases=[('empty','WelcomeData/empty','/mailbox?name=INBOX',200,'No messages','Compose'),('failure','WelcomeData/failure','/mailbox?name=INBOX&filter=unread&attachment=with&after=2026-01-01&page=2',503,'Failed load','Retry'),('search','OSMAP/State','/search?mailbox=INBOX&q=ux-empty-fixture&field=subject&filter=unread',200,'Empty search','Clear filters'),('search-all','OSMAP/State','/search?scope=all&q=ux-empty-fixture&attachment=with',200,'Empty search','Clear filters'),('search-failure','OSMAP/StateFailure','/search?scope=all&q=retained&field=subject&filter=unread&before=2026-09-30',503,'Failed load','Retry')]
  for name,ua,path,status,title,action in cases:
   c=b.new_context(java_script_enabled=False,user_agent=ua,viewport=dict(width=1600,height=1100));page=c.new_page()
   def guard(route):
    if not route.request.url.startswith(origin+'/'):r['external']+=1;route.abort();return
    if route.request.method=='POST' and not route.request.url.endswith('/login'):r['mutations']+=1;route.abort();return
    route.continue_()
   c.route('**/*',guard);page.goto(origin+'/login');page.get_by_label('Username or Email').fill('alice@example.com');page.get_by_label('Password',exact=True).fill('correct horse battery staple');page.get_by_label('TOTP Code').fill('123456');page.get_by_role('button',name='Sign In',exact=True).click()
   assert page.goto(origin+path).status==status;assert page.get_by_role('heading',name=title,exact=True).count()==1;assert page.locator('script').count()==0
   if status==503:
    assert page.locator('main form').count()==0
    assert page.get_by_role('navigation',name='Primary navigation').locator('[aria-current=page]').inner_text()==('Search' if name=='search-failure' else 'Inbox')
   href=page.locator('.mail-state-card').get_by_role('link',name=action,exact=True).get_attribute('href')
   for width,scheme,forced in [(1600,'light','none'),(360,'dark','none'),(360,'light','active')]:
    page.set_viewport_size(dict(width=width,height=1100));page.emulate_media(color_scheme=scheme,forced_colors=forced);assert page.evaluate('document.documentElement.scrollWidth<=innerWidth');audit=page.evaluate(TEXT_AUDIT);file=f'{name}-{width}-{scheme}-{forced}.png';page.screenshot(path=str(a.output/file),full_page=True);r['captures'].append(dict(file=file,contrast=audit));assert not audit['failures'] and not audit['ui_failures']
   page.locator('.mail-state-card').get_by_role('link',name=action,exact=True).press('Enter')
   if action=='Retry':
    from urllib.parse import parse_qs,urlsplit
    assert parse_qs(urlsplit(page.url).query)==parse_qs(urlsplit(origin+path).query) or all(parse_qs(urlsplit(page.url).query).get(k)==v for k,v in parse_qs(urlsplit(origin+path).query).items())
    assert page.get_by_role('heading',name='Failed load',exact=True).count()==1
   elif action=='Clear filters':assert page.url==origin+('/search?scope=all' if name=='search-all' else '/search?mailbox=INBOX');assert page.get_by_text('Enter keywords to search your mail.',exact=True).count()==1;assert page.locator('input[name=q]').last.input_value()==''
   else:assert '/compose' in page.url;assert page.locator('textarea[name=body]').count()==1
   r['checks'].append(name+' native keyboard action preserves finite context');c.close()
  assert r['external']==r['mutations']==0;r['status']='PASS'
 finally:
  (a.output/'report.json').write_text(json.dumps(r,indent=2));b.close();stop_server(process,Path(tmp))
