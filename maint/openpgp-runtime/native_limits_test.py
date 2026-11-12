import pathlib,tempfile,subprocess,socket,os,json,hashlib,time
assert socket.gethostname()=='obsd1.blackbagsecurity.com'
SOURCE=pathlib.Path(__file__).with_name('inventory.c').read_text()
os.umask(0o077)
started=time.monotonic()
with tempfile.TemporaryDirectory(prefix='osmap-public-limits-') as d:
 root=pathlib.Path(d);homes=[]
 def home(n):
  p=root/n;p.mkdir(mode=0o700);homes.append(p);return p
 def run(args,data=b'',timeout=20):
  assert time.monotonic()-started<300,'overall budget'
  return subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,env={'PATH':'/usr/bin:/bin:/usr/local/bin','LC_ALL':'C','GNUPGHOME':str(root/'NEVER_DEFAULT')})
 def gpg(h,args,data=b''):
  r=run(['/usr/local/bin/gpg','--no-options','--homedir',str(h),'--batch','--pinentry-mode','loopback','--passphrase','']+args,data);assert r.returncode==0,'synthetic GPG operation failed';return r.stdout
 def manifest(h):return {str(p.relative_to(h)):(p.lstat().st_mode,hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None) for p in h.rglob('*')}
 def inv(h,binary,expected):
  before=manifest(h);r=run([str(binary),str(h)]);result=json.loads(r.stdout)
  assert result['ok']==expected and (r.returncode==0)==expected
  assert before==manifest(h),'inventory mutated home'
  assert not (root/'NEVER_DEFAULT').exists()
  return result,len(r.stdout)
 try:
  worker=root/'worker';diagnostic=root/'diagnostic'
  for name,source in [('worker',SOURCE),('diagnostic',SOURCE.replace('#define LIMIT 65536','#define LIMIT 131072'))]:
   p=root/(name+'.c');p.write_text(source)
   c=run(['/usr/bin/cc','-std=c99','-Wall','-Wextra','-Werror','-I/usr/local/include',str(p),'-L/usr/local/lib','-lgpgme','-lgpg-error','-o',str(root/name)]);assert c.returncode==0,'compile failed'
  secret=home('fixture-generation');count=home('public-count');meta=home('public-metadata');fps=[]
  for n in range(32):
   gpg(secret,['--quick-generate-key',f'Synthetic Limit {n} <limit{n}@fixture.test>','ed25519','cert,sign','0'])
  listing=gpg(secret,['--with-colons','--list-keys']).decode();fps=[l.split(':')[9] for l in listing.splitlines() if l.startswith('fpr:')];assert len(fps)==32
  gpg(count,['--import'],gpg(secret,['--export']))
  result,size=inv(count,worker,True);assert len(result['keys'])==32
  print(json.dumps({'case':'32primary_success','bytes':size}),flush=True)
  gpg(secret,['--quick-generate-key','Synthetic Extra <extra@fixture.test>','ed25519','cert,sign','0'])
  gpg(count,['--import'],gpg(secret,['--export']))
  inv(count,worker,False);raw=gpg(count,['--with-colons','--list-keys']).decode();assert sum(l.startswith('pub:') for l in raw.splitlines())==33
  print(json.dumps({'case':'33primary_refused','count':33}),flush=True)
  previous=0;overflow=False
  for subs in range(1,9):
   for fp in fps:gpg(secret,['--quick-add-key',fp,'ed25519','sign','0'])
   gpg(meta,['--import'],gpg(secret,['--export']+fps))
   diagnostic_result,fullsize=inv(meta,diagnostic,True)
   assert len(diagnostic_result['keys'])==32 and all(len(k['subkeys'])==subs for k in diagnostic_result['keys'])
   if fullsize<=65535:
    actual,size=inv(meta,worker,True);assert size==fullsize;previous=size
    print(json.dumps({'case':'metadata_success','primaries':32,'subkeys_each':subs,'bytes':size}),flush=True)
   else:
    inv(meta,worker,False);overflow=True
    print(json.dumps({'case':'metadata_overflow_refused','primaries':32,'subkeys_each':subs,'diagnostic_bytes':fullsize,'last_legal_bytes':previous,'only_diagnostic_difference':'LIMIT 131072'}),flush=True);break
  assert overflow and previous>0
  print('all_home_manifests_unchanged=PASS default_home_absent=PASS',flush=True)
 finally:
  for h in homes:
   subprocess.run(['/usr/local/bin/gpgconf','--homedir',str(h),'--kill','gpg-agent'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
print('fixture_agents_stopped=PASS private_fixture_cleanup=PASS',flush=True)
