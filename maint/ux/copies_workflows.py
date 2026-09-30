import argparse,json,tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT
parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);parser.add_argument('--engine',default='chromium',choices=['chromium','firefox']);parser.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');args=parser.parse_args()
out=args.output;out.mkdir(parents=True,exist_ok=True,mode=0o700)
report={'result':'FAIL','checks':[],'captures':[],'external':0,'scripts':0,'sends':0}
with tempfile.TemporaryDirectory() as t,(out/'server.log').open('w') as log,sync_playwright() as pw:
 root=Path(t);process,origin=start_server(root,Path(__file__).resolve().parents[2],log);browser=getattr(pw,args.engine).launch(executable_path=args.browser,headless=True);report['browser']=browser.version
 def login(ua='CopiesBrowser',account='alice'):
  ctx=browser.new_context(java_script_enabled=False,user_agent=ua,viewport={'width':1600,'height':1100})
  def route(r):
   if r.request.resource_type=='script':report['scripts']+=1
   if r.request.url.split('?')[0]==origin+'/send':report['sends']+=1;r.abort()
   elif r.request.url.startswith(origin+'/'):r.continue_()
   else:report['external']+=1;r.abort()
  ctx.route('**/*',route);p=ctx.new_page();p.goto(origin+'/login');p.get_by_label('Username or Email').fill(account+'@example.com');p.get_by_label('Password',exact=True).fill('correct horse battery staple');p.get_by_label('TOTP Code').fill('123456');p.get_by_role('button',name='Sign In',exact=True).click();p.wait_for_url('**/mailboxes');return p
 try:
  p=login();p.goto(origin+'/settings?section=reading');p.get_by_label('Default content',exact=True).select_option('prefer_plain_text');p.get_by_role('button',name='Save content preference',exact=True).click();p.wait_for_url('**updated=1')
  p.goto(origin+'/settings?section=copies');assert p.locator('[name="html_display_preference"]').count()==0;other=p.context.new_page();other.goto(origin+'/settings?section=reading');other.get_by_label('Default content',exact=True).select_option('prefer_sanitized_html');other.get_by_role('button',name='Save content preference',exact=True).click();other.wait_for_url('**updated=1');p.locator('#copies-archive').select_option('INBOX.Projects');p.get_by_role('button',name='Save archive folder',exact=True).press('Enter');p.wait_for_url('**section=copies&updated=1');expect(p.locator('#copies-archive')).to_have_value('INBOX.Projects');other.goto(origin+'/settings?section=reading');expect(other.get_by_label('Default content',exact=True)).to_have_value('prefer_sanitized_html')
  report['checks'].append('Native stale Copies tab save preserves newer Protected HTML saved from another tab')
  p.get_by_role('link',name='Open folder',exact=True).click();p.wait_for_url('**/mailbox?name=INBOX.Projects')
  missing=login('WelcomeMissing');missing.goto(origin+'/settings?section=copies');expect(missing.locator('#copies-archive')).to_have_value('INBOX.Projects');assert '(unavailable)' in missing.locator('#copies-archive option:checked').inner_text();assert missing.locator('.settings-copies-page a[href="/mailbox?name=Sent"]').count()==0
  bad=login('CopiesWrongOwner');bad.goto(origin+'/settings?section=copies');expect(bad.get_by_role('button',name='Save archive folder',exact=True)).to_be_disabled()
  bob=login(account='bob');bob.goto(origin+'/settings?section=copies');expect(bob.locator('#copies-archive')).to_have_value('')
  report['checks'].append('Missing stored Archive stays selected; wrong-owner listing disables save; Bob remains isolated')
  for scheme in ['light','dark']:
   for width in [1600,768,360]:
    for forced in ['none','active']:
     p.set_viewport_size({'width':width,'height':1100});p.emulate_media(color_scheme=scheme,forced_colors=forced);p.goto(origin+'/settings?section=copies');assert p.locator('script').count()==0;assert p.evaluate('document.documentElement.scrollWidth<=innerWidth');p.locator('#copies-archive').focus();expect(p.locator('#copies-archive')).to_be_focused();audit=p.evaluate(TEXT_AUDIT);assert not audit['failures'] and not audit['ui_failures'];name=f'copies-{scheme}-{width}-{forced}.png';p.screenshot(path=str(out/name),full_page=True);report['captures'].append({'file':name,'contrast':audit,'overflow':False})
  privacy=login('PrivacyBrowser');privacy.goto(origin+'/settings?section=privacy');assert privacy.locator('.privacy-preference').count()==0;expect(privacy.get_by_label('Allow per-message exceptions',exact=True)).to_be_disabled()
  for section in ['reading']:
   privacy.locator('.privacy-notes a').click();privacy.wait_for_url('**section=reading#html-display-prefer-sanitized')
   privacy.goto(origin+'/settings?section='+section);other.goto(origin+'/settings?section=copies');other.locator('#copies-archive').select_option('INBOX');other.get_by_role('button',name='Save archive folder',exact=True).click();other.wait_for_url('**updated=1');privacy.get_by_label('Default content',exact=True).select_option('prefer_plain_text');privacy.get_by_role('button',name='Save content preference',exact=True).press('Enter');privacy.wait_for_url('**updated=1');other.reload();expect(other.locator('#copies-archive')).to_have_value('INBOX');privacy.goto(origin+'/message?mailbox=INBOX&uid=9');expect(privacy.locator('main')).to_contain_text('Synthetic plain part');assert privacy.locator('.message-html strong').count()==0
   privacy.goto(origin+'/settings?section='+section);privacy.get_by_label('Default content',exact=True).select_option('prefer_sanitized_html');privacy.get_by_role('button',name='Save content preference',exact=True).click();privacy.wait_for_url('**updated=1');privacy.goto(origin+'/message?mailbox=INBOX&uid=9');expect(privacy.locator('.message-html strong')).to_have_text('protected part');assert privacy.locator('img[src*="external.invalid"]').count()==0
  privacy.goto(origin+'/settings?section=reading');privacy.get_by_label('Default content',exact=True).select_option('prefer_plain_text');privacy.get_by_role('button',name='Save content preference',exact=True).click();privacy.wait_for_url('**updated=1');bob.goto(origin+'/settings?section=reading');expect(bob.get_by_label('Default content',exact=True)).to_have_value('prefer_sanitized_html');privacy.reload();expect(privacy.get_by_label('Default content',exact=True)).to_have_value('prefer_plain_text')
  report['checks'].append('Privacy link and stale Reading form preserve newer Archive; native real renderer switches plain/protected parts; remote image stripped; reload persists; Bob isolated')
  for scheme in ['light','dark']:
   for width in [1600,768,360]:
    for forced in ['none','active']:
     privacy.set_viewport_size({'width':width,'height':1100});privacy.emulate_media(color_scheme=scheme,forced_colors=forced);privacy.goto(origin+'/settings?section=privacy');assert privacy.locator('script').count()==0;assert privacy.evaluate('document.documentElement.scrollWidth<=innerWidth');privacy.locator('.privacy-notes a').focus();expect(privacy.locator('.privacy-notes a')).to_be_focused();geometry=privacy.locator('.privacy-cards').bounding_box();assert width!=1600 or abs(geometry['y']+geometry['height']-391)<=5;audit=privacy.evaluate(TEXT_AUDIT);name=f'privacy-{scheme}-{width}'+('-forced' if forced=='active' else '')+'.png';privacy.screenshot(path=str(out/name),full_page=True);report['captures'].append({'file':name,'contrast':audit,'overflow':False,'forced':forced});assert not audit['failures'] and not audit['ui_failures'],name
  assert report['external']==report['scripts']==report['sends']==0;report['result']='PASS'
 finally:
  (out/'report.json').write_text(json.dumps(report,indent=2));browser.close();stop_server(process,root)
