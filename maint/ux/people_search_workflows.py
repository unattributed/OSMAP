#!/usr/bin/env python3
"""Native account-private saved-contact search, using disposable real stores."""
import argparse,json,tempfile
from urllib.parse import parse_qs,urlsplit
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT

def main():
 p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('--engine',default='chromium');p.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True,mode=0o700)
 report=dict(result='FAIL',captures=[],external=0,scripts=0,checks=[])
 with tempfile.TemporaryDirectory(prefix='osmap-people-') as temp,(a.output/'server.log').open('w') as log,sync_playwright() as pw:
  root=Path(temp);repo=Path(__file__).resolve().parents[2];server,origin=start_server(root,repo,log);browser=getattr(pw,a.engine).launch(executable_path=a.browser,headless=True)
  def context():
   c=browser.new_context(java_script_enabled=False,viewport=dict(width=1600,height=1100))
   def bounded(route):
    if not route.request.url.startswith(origin+'/'):report['external']+=1;route.abort()
    elif route.request.resource_type=='script':report['scripts']+=1;route.abort()
    else:route.continue_()
   c.route('**/*',bounded);return c
  def visit(page,path,status=200):
   r=page.goto(origin+path,wait_until='networkidle');assert r.status==status;assert r.headers['cache-control']=='no-store';assert page.locator('script').count()==0
   if 'category=people' in path: assert page.locator('main img,main svg').count()==0
  def login(page,who):
   visit(page,'/login');page.get_by_label('Username or Email').fill(who+'@example.com');page.get_by_label('Password',exact=True).fill('correct horse battery staple');page.get_by_label('TOTP Code').fill('123456');page.get_by_role('button',name='Sign In',exact=True).click();page.wait_for_load_state('networkidle')
  try:
   alice=context();page=alice.new_page();login(page,'alice')
   for n in range(21):
    visit(page,'/contacts');page.get_by_label('Display name (optional)').fill(f'Person {n:02} <Public>');page.get_by_label('Email address',exact=True).fill(f'person{n:02}@example.test');page.get_by_role('button',name='Save contact',exact=True).click();page.wait_for_load_state('networkidle')
   visit(page,'/search');page.get_by_role('link',name='People',exact=True).press('Enter');page.wait_for_load_state('networkidle');page.get_by_label('Search query',exact=True).fill('PERSON');page.locator('.people-search button[type=submit]').press('Enter');page.wait_for_load_state('networkidle');assert page.locator('.people-type').count()==20
   page.get_by_role('link',name='Next page',exact=True).press('Enter');page.wait_for_load_state('networkidle');assert page.locator('.people-type').count()==1
   expected_query=parse_qs(urlsplit(page.url).query)
   for choice in ['Dark','Light']:
    page.get_by_role('button',name=f'Use {choice} theme',exact=True).press('Enter');page.wait_for_load_state('networkidle');assert urlsplit(page.url).path=='/search';assert parse_qs(urlsplit(page.url).query)==expected_query;expect(page.locator('html')).to_have_attribute('data-appearance',choice.lower());assert page.locator('.people-type').count()==1
   report['checks'].append('Native header theme preserves People category, query and second-page results')
   page.get_by_role('link',name='Edit contact person20@example.test',exact=True).press('Enter');page.wait_for_load_state('networkidle');expect(page.get_by_label('Display name (optional)')).to_have_value('Person 20 <Public>');page.get_by_label('Display name (optional)').fill('Edited <Person>');page.get_by_role('button',name='Save contact',exact=True).click();page.wait_for_load_state('networkidle')
   visit(page,'/search?category=people&q=EDITED');expect(page.locator('.message-subject-link')).to_have_text('Edited <Person>');page.get_by_role('link',name='Messages',exact=True).press('Enter');page.wait_for_load_state('networkidle');assert 'scope=all' in page.url and 'q=EDITED' in page.url
   report['checks'].append('Native create, case-insensitive search, page, revision-bound edit, query-preserving Messages link')
   bob=context();other=bob.new_page();login(other,'bob');visit(other,'/search?category=people&q=Person');expect(other.get_by_text('No saved contacts match.',exact=True)).to_be_visible();assert other.locator('.people-type').count()==0;bob.close()
   for path in ['/search?category=other','/search?category=people&page=0','/search?category=people&q='+'x'*257]:visit(page,path,400)
   report['checks'].append('Bob isolation and finite invalid category/page/query refusal')
   visit(page,'/settings?section=appearance');page.get_by_label('System',exact=True).locator('..').click();page.get_by_role('button',name='Save changes',exact=True).click();page.wait_for_load_state('networkidle')
   for scheme in ['light','dark']:
    for width in [1600,360]:
     for forced in ['none','active']:
      page.set_viewport_size(dict(width=width,height=1100));page.emulate_media(color_scheme=scheme,forced_colors=forced);visit(page,'/search?category=people&q=Person');assert page.locator('#people-query').bounding_box()['width'] >= 150;audit=page.evaluate(TEXT_AUDIT);overflow=page.evaluate('document.documentElement.scrollWidth>innerWidth');name=f'people-{scheme}-{width}-{forced}.png';page.screenshot(path=str(a.output/name),full_page=True);report['captures'].append(dict(file=name,contrast=audit,overflow=overflow));assert not overflow and not audit['failures'] and not audit['ui_failures']
   alice.close();stop_server(server,root);server,origin=start_server(root,repo,log);alice=context();page=alice.new_page();login(page,'alice');visit(page,'/search?category=people&q=edited');expect(page.locator('.message-subject-link')).to_have_text('Edited <Person>')
   files=list((root/'settings/contacts-v1').glob('*.json'));assert len(files)==1;original=files[0].read_bytes();files[0].write_bytes(b'corrupt');visit(page,'/search?category=people&q=Person',503);expect(page.get_by_text('People search unavailable',exact=True)).to_be_visible();assert page.locator('.people-type').count()==0;files[0].write_bytes(original);visit(page,'/search?category=people&q=edited');assert page.locator('.people-type').count()==1
   report['checks'].append('Restart persistence; corrupt store returns unavailable without empty-result claim; restored store readable')
   assert report['external']==report['scripts']==0;report['result']='PASS'
  finally:
   (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');browser.close();stop_server(server,root)
 print(json.dumps(dict(result=report['result'],captures=len(report['captures']))))
if __name__=='__main__':main()
