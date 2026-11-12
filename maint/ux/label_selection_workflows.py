#!/usr/bin/env python3
"""Native bounded two-message label changes against a private synthetic real store."""
import argparse,json,tempfile
from pathlib import Path
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT

def main():
 a=argparse.ArgumentParser();a.add_argument('output',type=Path);a.add_argument('--engine',default='chromium');a.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');args=a.parse_args();args.output.mkdir(mode=0o700,parents=True,exist_ok=True)
 report=dict(result='FAIL',captures=[],external=0,scripts=0,mail_mutations=0)
 with tempfile.TemporaryDirectory(prefix='osmap-selected-labels-') as temp,(args.output/'server.log').open('w') as log,sync_playwright() as pw:
  root=Path(temp);server,origin=start_server(root,Path(__file__).resolve().parents[2],log);browser=getattr(pw,args.engine).launch(executable_path=args.browser,headless=True);ctx=browser.new_context(java_script_enabled=False,viewport=dict(width=1600,height=1100));report['browser']=browser.version
  def guard(route):
   r=route.request
   if not r.url.startswith(origin+'/'):report['external']+=1;route.abort()
   elif r.resource_type=='script':report['scripts']+=1;route.abort()
   elif r.method=='POST' and urlsplit(r.url).path not in ['/login','/labels/change','/messages/labels/review','/messages/labels/apply']:report['mail_mutations']+=1;route.abort()
   else:route.continue_()
  ctx.route('**/*',guard);p=ctx.new_page()
  def go(page,path):
   r=page.goto(origin+path,wait_until='networkidle');assert r.status==200;assert r.headers['cache-control']=='no-store'
  def login(page,who):
   go(page,'/login');page.get_by_label('Username or Email').fill(who+'@example.com');page.get_by_label('Password',exact=True).fill('correct horse battery staple');page.get_by_label('TOTP Code').fill('123456');page.get_by_role('button',name='Sign In',exact=True).click();page.wait_for_load_state('networkidle')
  def click(page,name):
   with page.expect_navigation(wait_until='networkidle') as nav:page.get_by_role('button',name=name,exact=True).click()
   return nav.value.status
  def review(page):
   go(page,'/mailbox?name=INBOX&sort=uid&direction=asc');page.locator('.bulk-row-choice input').nth(0).check();page.locator('.bulk-row-choice input').nth(1).check();page.locator('details.bulk-actions > summary').click();assert click(page,'Review labels for selected')==200;expect(page.get_by_role('heading',name='2 selected messages',exact=True)).to_be_visible()
  def apply(page,label,action='attach',status=200):
   page.get_by_label('Existing label',exact=True).select_option(label=label);page.get_by_label('Change',exact=True).select_option(action);page.get_by_label('Confirm this label change',exact=False).check();assert click(page,'Apply label change')==status;expect(page.get_by_role('button',name='Apply label change',exact=True)).to_be_disabled()
  def create(name):
   go(p,'/labels');p.get_by_label('Label name',exact=True).fill(name);assert click(p,'Create label')==200
  def assigned(uid,label,value):
   go(p,f'/message?mailbox=INBOX&uid={uid}');p.locator('.reader-labels summary').click();p.get_by_role('link',name='Edit message labels',exact=True).click();p.wait_for_load_state('networkidle');row=p.locator('.label-item').filter(has=p.get_by_role('heading',name=label,exact=True));expect(row.get_by_text(value,exact=True)).to_be_visible()
  try:
   login(p,'alice');create('Project <Aurora>');review(p)
   ids=[i.get_attribute('name').removeprefix('message_') for i in p.locator('form[action="/messages/labels/apply"] input[name^="message_"]').all()];assert len(ids)==2
   for scheme in ['light','dark']:
    for width in [1600,360]:
     for forced in ['none','active']:
      p.set_viewport_size(dict(width=width,height=1100));p.emulate_media(color_scheme=scheme,forced_colors=forced);p.get_by_label('Existing label',exact=True).select_option(label='Project <Aurora>');p.get_by_label('Change',exact=True).focus();p.keyboard.press('Tab');audit=p.evaluate(TEXT_AUDIT);overflow=p.evaluate('document.documentElement.scrollWidth>innerWidth');file=f'selected-labels-{scheme}-{width}-{forced}.png';p.screenshot(path=str(args.output/file),full_page=True);report['captures'].append(dict(file=file,overflow=overflow,contrast=audit));assert not overflow and not audit['failures'] and not audit['ui_failures']
   p.emulate_media(color_scheme='light',forced_colors='none');p.set_viewport_size(dict(width=1600,height=1100));apply(p,'Project <Aurora>')
   for uid in ids:assigned(uid,'Project <Aurora>','Assigned')
   review(p);apply(p,'Project <Aurora>','detach')
   for uid in ids:assigned(uid,'Project <Aurora>','Not assigned')
   stale=ctx.new_page();review(stale);old=stale.locator('input[name=revision]').input_value();chosen=stale.get_by_label('Existing label',exact=True).locator('option').filter(has_text='Project <Aurora>').get_attribute('value');create('Parallel edit');apply(stale,'Project <Aurora>',status=409);assert stale.locator('input[name=revision]').input_value()==old;expect(stale.get_by_label('Existing label',exact=True)).to_have_value(chosen);assert click(stale,'Reload selection')==200;expect(stale.get_by_role('button',name='Apply label change',exact=True)).to_be_enabled();stale.close()
   # Exercise actual per-message capacity without forging browser storage or fixture state.
   for i in range(7):create(f'Capacity {i}')
   for name in ['Project <Aurora>','Parallel edit']+[f'Capacity {i}' for i in range(6)]:review(p);apply(p,name)
   review(p);apply(p,'Capacity 6',status=409);expect(p.get_by_text('None of its label assignments were saved.',exact=False)).to_be_visible()
   for uid in ids:assigned(uid,'Capacity 6','Not assigned')
   bob=browser.new_context(java_script_enabled=False);bob.route('**/*',guard);bp=bob.new_page();login(bp,'bob');go(bp,'/labels');expect(bp.get_by_text('No labels yet. Create one above to begin.',exact=True)).to_be_visible();review(bp);expect(bp.get_by_role('button',name='Apply label change',exact=True)).to_be_disabled();bob.close()
   report['checks']=['native selection2 review is not a move','escaped label and actual selected subjects','atomic attach then both assigned','atomic detach then both not assigned','stale409 retains revision and disabled choice; explicit reload','8 labels per message capacity409, neither extra assignment','Bob private store isolation and empty-label disabled action']
   assert report['external']==report['scripts']==report['mail_mutations']==0;report['result']='PASS'
  except Exception:
   p.screenshot(path=str(args.output/'failure.png'),full_page=True)
   report['visible_labels']=p.locator('label').all_text_contents()
   raise
  finally:
   (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');browser.close();stop_server(server,root)
 print(json.dumps(dict(result=report['result'],captures=len(report['captures']))))
if __name__=='__main__':main()
