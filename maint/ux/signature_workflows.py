#!/usr/bin/env python3
"""Native ordinary-footer settings and one-time composer insertion, synthetic only."""
import argparse,hashlib,json,tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT

def main():
 a=argparse.ArgumentParser();a.add_argument('output',type=Path);a.add_argument('--engine',default='chromium');a.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');args=a.parse_args();args.output.mkdir(mode=0o700,parents=True,exist_ok=True);report=dict(result='FAIL',captures=[],external=0,script_executions=0,sends=0)
 with tempfile.TemporaryDirectory(prefix='osmap-signature-ui-') as temp,(args.output/'server.log').open('w') as log,sync_playwright() as pw:
  root=Path(temp);repo=Path(__file__).resolve().parents[2];server,origin=start_server(root,repo,log);b=getattr(pw,args.engine).launch(executable_path=args.browser,headless=True);report['browser']=b.version
  def guard(route):
   req=route.request
   if not req.url.startswith(origin+'/'):report['external']+=1;route.abort()
   elif req.url.split('?')[0]==origin+'/send':report['sends']+=1;route.abort()
   elif req.resource_type=='script':report['script_executions']+=1;route.abort()
   else:route.continue_()
  def login(who='alice'):
   c=b.new_context(java_script_enabled=False,viewport=dict(width=1600,height=1100));c.route('**/*',guard);p=c.new_page();p.goto(origin+'/login');p.get_by_label('Username or Email').fill(who+'@example.com');p.get_by_label('Password',exact=True).fill('correct horse battery staple');p.get_by_label('TOTP Code').fill('123456');p.get_by_role('button',name='Sign In',exact=True).click();p.wait_for_load_state('networkidle');return p
  def go(p,path='/settings?section=identity',status=200):
   r=p.goto(origin+path,wait_until='networkidle');assert r.status==status;assert r.headers['cache-control']=='no-store'
  def click(p,label,status=200):
   with p.expect_navigation(wait_until='networkidle') as nav:p.get_by_role('button',name=label,exact=True).click()
   assert nav.value.status==status
  def edit(p,text):
   p.locator('.signature-editor summary').click();p.get_by_label('Default signature text',exact=True).fill(text)
  try:
   p=login();go(p);expect(p.get_by_label('Signature',exact=True)).to_have_value('none')
   p.get_by_label('Signature',exact=True).select_option('default');click(p,'Save signature choice',400);expect(p.get_by_role('button',name='Save signature',exact=True)).to_be_enabled()
   go(p);p.get_by_label('Display name',exact=True).fill('Synthetic Name');click(p,'Save identity');go(p)
   old='\nRegards,\nSynthetic <Aurora> 🦊';edit(p,old);click(p,'Save signature text');p.get_by_label('Signature',exact=True).select_option('default');click(p,'Save signature choice');expect(p.get_by_label('Display name',exact=True)).to_have_value('Synthetic Name')
   go(p,'/settings?section=composition');expect(p.get_by_role('switch',name='Include signature',exact=True)).to_be_checked();p.get_by_label('Reply placement',exact=True).select_option('below');click(p,'Save composition preferences')
   go(p,'/compose');body=p.locator('#compose-body').input_value();assert body.count(old)==1;p.locator('#compose-to').fill('desk@example.test');p.locator('#compose-subject').fill('Original footer draft');click(p,'Save Draft');draft=p.url.removeprefix(origin)
   stale=p.context.new_page();go(stale);edit(stale,'Stale footer');revision=stale.locator('.signature-editor input[name=signature_revision]').input_value()
   go(p);edit(p,'New footer');click(p,'Save signature text');click(stale,'Save signature text',409);expect(stale.locator('textarea')).to_have_value('Stale footer');expect(stale.get_by_role('button',name='Save signature',exact=True)).to_be_disabled();assert stale.locator('input[name=signature_revision]').input_value()==revision;stale.close()
   go(p,draft);expect(p.locator('#compose-body')).to_have_value(body)
   for mode in ['reply','reply-all','forward']:
    go(p,f'/compose?mode={mode}&mailbox=INBOX&uid=9');assert p.locator('#compose-body').input_value().count('New footer')==1
   go(p,'/settings?section=composition');p.get_by_role('switch',name='Include signature',exact=True).uncheck();click(p,'Save signature choice');expect(p.get_by_label('Reply placement',exact=True)).to_have_value('below');go(p);expect(p.get_by_label('Signature',exact=True)).to_have_value('none');edit(p,'New footer');expect(p.get_by_label('Default signature text',exact=True)).to_have_value('New footer')
   go(p,'/compose');expect(p.locator('#compose-body')).to_have_value('')
   go(p);edit(p,'x'*2001);click(p,'Save signature text',400);expect(p.locator('textarea')).to_have_value('x'*2001);expect(p.get_by_role('button',name='Save signature',exact=True)).to_be_enabled()
   go(p);p.get_by_label('Signature',exact=True).select_option('default');click(p,'Save signature choice');go(p,'/settings?section=composition');p.get_by_label('Format',exact=True).select_option('formatted');click(p,'Save composition preferences');go(p,'/compose');expect(p.locator('#compose-body-format')).to_have_value('formatted');assert p.locator('#compose-body').input_value().count('New footer')==1
   go(p);edit(p,'**Not literal**');click(p,'Save signature text');go(p,'/compose');expect(p.locator('#compose-body')).to_have_value('');expect(p.get_by_text('Signature not inserted for Formatted text:',exact=False)).to_be_visible()
   go(p);edit(p,'New footer');click(p,'Save signature text');p.get_by_label('Signature',exact=True).select_option('none');click(p,'Save signature choice')
   for section in ['identity','composition']:
    for scheme in ['light','dark']:
     for width,forced in [(1600,'none'),(360,'none'),(360,'active')]:
      p.set_viewport_size(dict(width=width,height=1100));p.emulate_media(color_scheme=scheme,forced_colors=forced);go(p,'/settings?section='+section)
      if width==360:p.locator('.signature-editor summary').focus();p.keyboard.press('Enter');expect(p.get_by_label('Default signature text',exact=True)).to_be_visible()
      audit=p.evaluate(TEXT_AUDIT);overflow=p.evaluate('document.documentElement.scrollWidth>innerWidth');file=f'signature-{section}-{scheme}-{width}-{forced}.png';p.screenshot(path=str(args.output/file),full_page=True);report['captures'].append(dict(file=file,overflow=overflow,contrast=audit));assert not overflow and not audit['failures'] and not audit['ui_failures']
   bob=login('bob');go(bob);expect(bob.get_by_label('Signature',exact=True)).to_have_value('none');bob.locator('.signature-editor summary').click();expect(bob.get_by_label('Default signature text',exact=True)).to_have_value('');bob.context.close()
   stop_server(server,root);server,origin=start_server(root,repo,log);fresh=login();go(fresh);fresh.locator('.signature-editor summary').click();expect(fresh.get_by_label('Default signature text',exact=True)).to_have_value('New footer')
   record=root/'settings'/(hashlib.sha256(b'osmap-signature-v1\0alice@example.com').hexdigest()+'.json');assert record.exists();record.write_text('corrupt');go(fresh);expect(fresh.get_by_label('Signature',exact=True)).to_be_disabled();expect(fresh.get_by_text('Saved signature preferences are unavailable.',exact=False)).to_be_visible();assert fresh.get_by_role('button',name='Save signature choice',exact=True).count()==0
   assert report['external']==report['script_executions']==report['sends']==0;report['result']='PASS'
  except Exception:
   p.screenshot(path=str(args.output/'failure.png'),full_page=True);raise
  finally:
   (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');b.close();stop_server(server,root)
 print(json.dumps(dict(result=report['result'],captures=len(report['captures']))))
if __name__=='__main__':main()
