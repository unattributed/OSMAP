#!/usr/bin/env python3
"""Synthetic delayed automatic draft saving; no sends or external requests."""
import argparse,json,tempfile,threading
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server
from contrast_audit import TEXT_AUDIT

def main():
 a=argparse.ArgumentParser();a.add_argument('output',type=Path);a.add_argument('--engine',default='chromium');a.add_argument('--headed',action='store_true');a.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');args=a.parse_args();args.output.mkdir(parents=True,exist_ok=True,mode=0o700);report=dict(result='FAIL',saves=0,external=0,sends=0,captures=[])
 with tempfile.TemporaryDirectory(prefix='osmap-autosave-') as temp,(args.output/'server.log').open('w') as log,sync_playwright() as pw:
  root=Path(temp);repo=Path(__file__).resolve().parents[2];server,origin=start_server(root,repo,log);b=getattr(pw,args.engine).launch(executable_path=args.browser,headless=not args.headed);ctx=b.new_context(viewport=dict(width=1600,height=1100));p=ctx.new_page();held=[];fault=[False]
  def guard(route):
   r=route.request
   if not r.url.startswith(origin+'/'):report['external']+=1;route.abort()
   elif r.url==origin+'/send':report['sends']+=1;route.abort()
   elif r.url==origin+'/drafts/autosave':
    report['saves']+=1
    if fault[0]:route.abort()
    elif report['saves']==1:held.append(route)
    else:route.continue_()
   else:route.continue_()
  ctx.route('**/*',guard)
  def go(path):p.goto(origin+path,wait_until='networkidle')
  def login(page):
   page.goto(origin+'/login');page.get_by_label('Username or Email').fill('alice@example.com');page.get_by_label('Password',exact=True).fill('correct horse battery staple');page.get_by_label('TOTP Code').fill('123456');page.get_by_role('button',name='Sign In',exact=True).click();page.wait_for_load_state('networkidle')
  try:
   login(p);go('/settings?section=composition');p.get_by_role('switch',name='Auto-save drafts',exact=True).check();p.get_by_label('Auto-save interval',exact=True).select_option('30');p.get_by_role('button',name='Save auto-save preferences',exact=True).click();p.wait_for_load_state('networkidle')
   for width,scheme,forced in [(1600,'light','none'),(360,'dark','active')]:
    p.set_viewport_size(dict(width=width,height=1100));p.emulate_media(color_scheme=scheme,forced_colors=forced);audit=p.evaluate(TEXT_AUDIT);overflow=p.evaluate('document.documentElement.scrollWidth>innerWidth');file=f'autosave-settings-{width}-{forced}.png';p.screenshot(path=str(args.output/file),full_page=True);report['captures'].append(dict(file=file,contrast=audit,overflow=overflow));assert not overflow and not audit['failures'] and not audit['ui_failures']
   p.emulate_media(color_scheme='light',forced_colors='none');p.set_viewport_size(dict(width=1600,height=1100));p.clock.install();go('/compose');expect(p.locator('#compose-auto-status')).to_contain_text('30 seconds');p.locator('#compose-body').fill('First <literal> 🦊');p.clock.run_for(30001);p.wait_for_timeout(100);assert len(held)==1
   expect(p.locator('#compose-save')).to_be_disabled();before=p.url;p.get_by_role('link',name='Inbox',exact=True).click();assert p.url==before;p.locator('#compose-body').fill('Newer text stays visible');p.clock.run_for(5000);assert report['saves']==1;held.pop().continue_();expect(p.locator('#compose-auto-status')).to_contain_text('Newer changes remain unsaved');expect(p.locator('#compose-body')).to_have_value('Newer text stays visible');expect(p.locator('#compose-save-status')).to_contain_text('Unsaved');draft=p.locator('input[name=draft_id]').input_value()
   stored=ctx.new_page();stored.goto(origin+'/draft?id='+draft,wait_until='networkidle');expect(stored.locator('#compose-body')).to_have_value('First <literal> 🦊');stored.close()
   p.clock.run_for(30001);expect(p.locator('#compose-auto-status')).to_have_text('Auto-save confirmed.');count=report['saves'];p.clock.run_for(120001);assert report['saves']==count
   p.locator('#compose-body').fill('Hidden edit');p.locator('.compose-more summary').click()
   with ctx.expect_page() as opened:p.get_by_role('link',name='Manage contacts',exact=True).click()
   cover=opened.value;cover.wait_for_load_state('networkidle');cover.bring_to_front();report['hidden_page_observed']=p.evaluate('document.visibilityState')=='hidden'
   if report['hidden_page_observed']:
    p.clock.run_for(30001);assert report['saves']==count
   else:report['visibility_limit']='Automation kept the background tab visible; hidden-page dispatch remains unqualified in this engine.'
   cover.close();p.bring_to_front();p.locator('#compose-body').fill('Newer text stays visible')
   # Pending files cannot be claimed saved; native save remains available.
   p.locator('#compose-attachment').set_input_files(dict(name='public.txt',mimeType='text/plain',buffer=b'public synthetic'));p.clock.run_for(30001);expect(p.locator('#compose-auto-status')).to_contain_text('pending files');assert report['saves']==count;p.locator('#compose-attachment').set_input_files([])
   # Another tab advances the real revision; the first tab must pause.
   other=ctx.new_page();other.goto(origin+'/draft?id='+draft,wait_until='networkidle');other.locator('#compose-body').fill('Other tab');other.locator('#compose-save').click();other.wait_for_load_state('networkidle');other.close();p.locator('#compose-body').fill('Local conflict retained');p.clock.run_for(30001);expect(p.locator('#compose-auto-status')).to_contain_text('no automatic retry');expect(p.locator('#compose-body')).to_have_value('Local conflict retained');expect(p.locator('#compose-save')).to_be_disabled();count=report['saves'];p.clock.run_for(120001);assert report['saves']==count
   for scheme,width,forced in [('light',1600,'none'),('dark',360,'none'),('dark',360,'active')]:
    p.set_viewport_size(dict(width=width,height=1100));p.emulate_media(color_scheme=scheme,forced_colors=forced);audit=p.evaluate(TEXT_AUDIT);overflow=p.evaluate('document.documentElement.scrollWidth>innerWidth');file=f'autosave-paused-{scheme}-{width}-{forced}.png';p.screenshot(path=str(args.output/file),full_page=True);report['captures'].append(dict(file=file,contrast=audit,overflow=overflow));assert not overflow and not audit['failures'] and not audit['ui_failures']
   p.on('dialog',lambda d:d.accept());go('/compose');expect(p.locator('#compose-auto-status')).to_contain_text('enabled');fault[0]=True;p.locator('#compose-body').fill('Abort retained');p.clock.run_for(30001);expect(p.locator('#compose-auto-status')).to_contain_text('no automatic retry');count=report['saves'];p.clock.run_for(90001);assert count==report['saves'];fault[0]=False
   native=b.new_context(java_script_enabled=False);native.route('**/*',guard);np=native.new_page();login(np);np.goto(origin+'/compose');np.locator('#compose-body').fill('Native fallback');np.locator('#compose-save').click();np.wait_for_load_state('networkidle');expect(np.locator('#compose-body')).to_have_value('Native fallback');native.close()
   assert report['external']==report['sends']==0;report['result']='PASS'
  except Exception:
   p.screenshot(path=str(args.output/'failure.png'),full_page=True);raise
  finally:
   (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');b.close();stop_server(server,root)
 print(json.dumps(dict(result=report['result'],saves=report['saves'])))
if __name__=='__main__':main()
