#!/usr/bin/env python3
"""Focused native regressions for autosave navigation, old previews and API fallback."""
import argparse,json,tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright,expect
from browser_workflows import start_server,stop_server

def main():
 a=argparse.ArgumentParser();a.add_argument('output',type=Path);a.add_argument('--engine',default='chromium');a.add_argument('--browser',default='/usr/bin/microsoft-edge-stable');args=a.parse_args();args.output.mkdir(mode=0o700,parents=True,exist_ok=True);report=dict(result='FAIL',external=0,sends=0,saves=0,checks=[])
 with tempfile.TemporaryDirectory(prefix='osmap-autosave-review-') as t,(args.output/'server.log').open('w') as log,sync_playwright() as pw:
  root=Path(t);server,origin=start_server(root,Path(__file__).resolve().parents[2],log);b=getattr(pw,args.engine).launch(executable_path=args.browser,headless=True);ctx=b.new_context(viewport=dict(width=1600,height=1100));p=ctx.new_page();fault=[False];dialogs=[]
  def guard(route):
   r=route.request
   if not r.url.startswith(origin+'/'):report['external']+=1;route.abort()
   elif r.url==origin+'/send':report['sends']+=1;route.abort()
   elif r.url==origin+'/drafts/autosave':
    report['saves']+=1
    if fault[0]:route.abort()
    else:route.continue_()
   else:route.continue_()
  ctx.route('**/*',guard)
  def login(page):
   page.goto(origin+'/login');page.get_by_label('Username or Email').fill('alice@example.com');page.get_by_label('Password',exact=True).fill('correct horse battery staple');page.get_by_label('TOTP Code').fill('123456');page.get_by_role('button',name='Sign In',exact=True).click();page.wait_for_load_state('networkidle')
  def dismissed(d):dialogs.append(d.type);d.dismiss()
  def search_retains(text):
   before=p.url;count=len(dialogs);p.get_by_label('Search all mail',exact=True).fill('Synthetic');p.get_by_role('button',name='Search mail',exact=True).click();assert dialogs[count:]==['beforeunload'];assert p.url==before;expect(p.locator('#compose-body')).to_have_value(text)
  try:
   login(p);p.on('dialog',dismissed);p.goto(origin+'/compose',wait_until='networkidle');expect(p.locator('#compose-auto-status')).to_contain_text('off');p.locator('#compose-body').fill('Original preview text');search_retains('Original preview text');report['checks'].append('Off: native header Search prompts; dismiss retains exact local text')
   p.locator('#compose-save').click();p.wait_for_load_state('networkidle');draft=p.url
   p.goto(origin+'/settings?section=composition',wait_until='networkidle');p.get_by_role('switch',name='Auto-save drafts',exact=True).check();p.get_by_role('button',name='Save auto-save preferences',exact=True).click();p.wait_for_load_state('networkidle')
   p.clock.install();p.goto(draft+'&preview=1&preflight=1',wait_until='networkidle');expect(p.locator('.compose-preview')).to_have_count(2);expect(p.locator('#compose-auto-status')).to_contain_text('enabled');p.locator('#compose-body').fill('New confirmed draft text');p.clock.run_for(30001);expect(p.locator('#compose-auto-status')).to_have_text('Auto-save confirmed.');expect(p.locator('#compose-save-status')).to_have_text('Saved draft.')
   for panel in p.locator('.compose-preview').all():expect(panel).to_have_attribute('data-stale','true');expect(panel.locator('.compose-stale-preview')).to_be_visible()
   expect(p.get_by_role('region',name='Message preview',exact=True)).to_contain_text('Original preview text');p.screenshot(path=str(args.output/'old-preview-remains-stale.png'),full_page=True);report['checks'].append('Confirmed autosave advances saved baseline but retains stale render-time preview and preflight warnings')
   fault[0]=True;p.locator('#compose-body').fill('Paused local text');p.clock.run_for(30001);expect(p.locator('#compose-auto-status')).to_contain_text('no automatic retry');search_retains('Paused local text');report['checks'].append('Paused: native header Search still prompts and preserves local text');fault[0]=False
   unsupported=b.new_context();unsupported.route('**/*',guard);unsupported.add_init_script('Object.defineProperty(window, "AbortController", {value: undefined});');up=unsupported.new_page();login(up);up.goto(origin+'/compose',wait_until='networkidle');expect(up.locator('#compose-auto-status')).to_contain_text('unsupported');expect(up.locator('#compose-save')).to_be_enabled();before=report['saves'];up.locator('#compose-body').fill('Native unsupported fallback');up.locator('#compose-save').click();up.wait_for_load_state('networkidle');expect(up.locator('#compose-body')).to_have_value('Native unsupported fallback');assert report['saves']==before;unsupported.close();report['checks'].append('Absent AbortController performs no automatic POST and native Save remains usable')
   assert report['external']==report['sends']==0;report['result']='PASS'
  finally:
   (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');b.close();stop_server(server,root)
 print(report['result'])
if __name__=='__main__':main()
