"""Actual private peer/pipe/group source controls; no native SSH/mail/password."""
from pathlib import Path
import hashlib,hmac,json,os,signal,socket,subprocess,sys,threading,time,unittest
from unittest.mock import patch
import mutation_relay as relay
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'account-runtime'))
import test_guarded_mutation_worker as gf
import test_account_mutation_worker as f
from account_mutation_continuity import signed,verify
from account_mutation_codec import response,verify_request

class RelayTests(unittest.TestCase):
 def raw(self,millis=1000,unicode=False):
  sent=int(time.time()*1000);now=sent//1000
  args=dict(issued=now,expires=now+300)
  if unicode:args.update(current='old public unicode é🙂',new='new public unicode é🙂',confirmation='new public unicode é🙂')
  raw=gf.guarded(f.frame(**args),sent=sent,deadline=sent+millis)
  value=json.loads(raw);p=value['session_proof'];p['session_expires']=now+500;p['idle_expires']=now+400
  p['signature']=hmac.new(gf.SESSION_KEY,gf.payload(p),hashlib.sha256).hexdigest()
  return gf.encoded(value)
 def exchange(self,mode='good',*,raw=None,uid=None,ack_mode='good',cleanup_failure=False):
  if cleanup_failure:mode='trailing' # Enter original failure cleanup path.
  server,client=socket.socketpair();r=relay._Relay(os.getuid() if uid is None else uid);errors=[]
  program=str(Path(__file__).with_name('mutation_relay_fixture.py'))
  def work():
   try:
    with patch.object(r,'_command',return_value=(sys.executable,'-I',program,mode)):
     if cleanup_failure:
      with patch.object(r,'_cleanup',side_effect=relay.Unavailable('public cleanup uncertainty')):r.connection(server)
     else:r.connection(server)
   except BaseException as e:errors.append(type(e))
   finally:server.close()
  t=threading.Thread(target=work);t.start();raw=self.raw() if raw is None else raw
  challenge=reply=None;client.settimeout(2)
  def exact(n):
   out=bytearray()
   while len(out)<n:
    p=client.recv(n-len(out))
    if not p:raise EOFError
    out.extend(p)
   return bytes(out)
  def framed(limit):
   n=int.from_bytes(exact(4),'big');self.assertLessEqual(n,limit);return exact(n)
  try:
   client.sendall(len(raw).to_bytes(4,'big')+raw)
   if mode not in ('wait','oversize'):
    first=framed(4096);challenge=verify(first,f.KEY,'challenge')
    self.assertEqual(challenge['frame_sha256'],hashlib.sha256(raw).hexdigest())
    ack=dict(challenge,phase='ack');ack.pop('signature');payload=signed(ack,f.KEY)
    if ack_mode=='tamper':payload=payload.replace(b'"ack"',b'"bad"')
    client.sendall(len(payload).to_bytes(4,'big')+payload+(b'X' if ack_mode=='trailing' else b''))
    client.shutdown(socket.SHUT_WR)
   reply=framed(4096)
   self.assertEqual(client.recv(1),b'')
  except (EOFError,ConnectionResetError,BrokenPipeError):reply=None
  finally:client.close();t.join(timeout=2)
  self.assertFalse(t.is_alive())
  if cleanup_failure:
   for child in r._retained:
    self.assertIsNone(child.returncode)
    try:os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    child.wait(timeout=1)
    for pipe in (child.stdin,child.stdout):
     if not pipe.closed:pipe.close()
  return r,raw,reply,challenge,errors
 def test_fixed_pinned_dedicated_purpose_never_reuses_multiplex_authority(self):
  a=relay.ssh_argv();self.assertEqual(a[-2:],('_osmap@216.128.179.75','osmap-account-mutation'))
  self.assertIn('/var/lib/osmap-bridge/keys/mutation',a)
  for option in ('ControlMaster=no','ControlPersist=no','ControlPath=none','StrictHostKeyChecking=yes','IdentityAgent=none','ConnectionAttempts=1','ClearAllForwardings=yes'):
   self.assertIn(option,a)
  self.assertNotIn('-L',a);self.assertNotIn('-R',a)
 def test_native_refuses_before_ssh_material_or_listener(self):
  with patch('mutation_relay._material',side_effect=AssertionError),patch('mutation_relay.socket.socket',side_effect=AssertionError):
   with self.assertRaises(relay.Unavailable):relay.serve_native()
 def test_actual_duplex_exact_unicode_guarded_frame_ack_and_signed_terminal(self):
  r,raw,reply,challenge,errors=self.exchange(raw=self.raw(unicode=True))
  self.assertEqual(errors,[]);self.assertFalse(r._contained)
  value=json.loads(reply);inner=bytes.fromhex(json.loads(raw)['budget']['request_hex'])
  request=verify_request(inner,f.KEY,value['responded_at'])
  self.assertEqual(reply,response(request,value['outcome'],f.KEY,value['responded_at']))
  self.assertEqual(value['outcome']['status'],'changed');self.assertEqual(challenge['account'],f.ACCOUNT)
 def test_wrong_actual_peer_and_malformed_future_expired_overlong_budget_never_spawn(self):
  raw=self.raw();value=json.loads(raw);sent=value['budget']['sent_millis']
  bad=[b'{}',b'{"budget":{},"budget":{}}']
  for start,end in [(sent+10000,sent+11000),(sent-2000,sent-1000),(sent,sent+60001)]:
   copy=json.loads(raw);copy['budget'].update(sent_millis=start,deadline_millis=end)
   copy['session_proof'].update(checked_millis=start,deadline_millis=end);bad.append(json.dumps(copy).encode())
  with patch('mutation_relay.subprocess.Popen',side_effect=AssertionError):
   self.assertIsNone(self.exchange(uid=os.getuid()+1)[2])
   for raw in bad:self.assertIsNone(self.exchange(raw=raw)[2])
 def test_tampered_end_to_end_account_source_action_epoch_bindings_never_get_terminal(self):
  raw=self.raw()
  for field,replacement in [('account','bob@example.test'),('source','192.0.2.1'),
    ('epoch',1),('action','other_action')]:
   outer=json.loads(raw);inner=json.loads(bytes.fromhex(outer['budget']['request_hex']))
   inner[field]=replacement
   outer['budget']['request_hex']=json.dumps(inner).encode().hex()
   with self.subTest(field=field):
    r,_,reply,_,errors=self.exchange(raw=json.dumps(outer).encode())
    self.assertIsNone(reply);self.assertEqual(errors,[relay.Unavailable])
 def test_actual_original_budget_timeout_kills_owned_ssh_fixture_without_terminal(self):
  began=time.monotonic();r,_,reply,_,errors=self.exchange('wait',raw=self.raw(300))
  self.assertLess(time.monotonic()-began,.65);self.assertIsNone(reply)
  self.assertFalse(r._contained);self.assertEqual(errors,[relay.Unavailable])
 def test_actual_ack_tamper_or_trailing_never_gets_terminal(self):
  for mode in ('tamper','trailing'):
   with self.subTest(mode=mode):self.assertIsNone(self.exchange(ack_mode=mode)[2])
 def test_nonzero_exit_trailing_remote_or_oversize_never_publishes_terminal(self):
  for mode in ('badexit','trailing','oversize'):
   with self.subTest(mode=mode):self.assertIsNone(self.exchange(mode)[2])
 def test_unconfirmed_local_cleanup_latches_and_withholds_terminal(self):
  r,_,reply,_,errors=self.exchange(cleanup_failure=True)
  self.assertIsNone(reply);self.assertTrue(r._contained)
  self.assertEqual(errors,[relay.Unavailable]);self.assertEqual(len(r._retained),1)
 def test_public_parsed_budget_is_not_authority_and_cannot_renew_cap(self):
  raw=self.raw();value=json.loads(raw);value['budget']['signature']='0'*64
  now=relay._millis();began=time.monotonic()
  d=relay._Deadline(json.dumps(value).encode(),began,now,began+.2)
  self.assertLessEqual(d.remaining(),.2)
  with patch('mutation_relay._millis',return_value=now-1):
   with self.assertRaises(relay.Unavailable):d.remaining()

 def test_eof_before_delayed_clean_exit_reaps_without_success_kill(self):
  instance,_,reply,_,errors=self.exchange('lateexit')
  self.assertIsNotNone(reply);self.assertEqual(errors,[]);self.assertFalse(instance._contained)

 def test_already_reaped_surviving_group_never_gets_a_signal(self):
  from types import SimpleNamespace
  child=SimpleNamespace(pid=12345,returncode=0)
  budget=SimpleNamespace(remaining=lambda:1,resource_remaining=lambda:1)
  with patch.object(relay.os,'killpg')as probe:
   with self.assertRaises(relay.Unavailable):relay._Relay._cleanup(child,budget)
   probe.assert_called_once_with(child.pid,0)


 def test_rc_stop_closes_owned_listener_and_cancels_io_with_original_cleanup_budget(self):
  import tempfile
  with tempfile.TemporaryDirectory(prefix='osmap-mutation-stop-')as name:
   path=Path(name)/'mutation.sock';actual=socket.socket(socket.AF_UNIX);handlers={};events=[]
   instance=relay._Relay(os.getuid())
   def install(number,handler):
    previous=handlers.get(number,signal.SIG_DFL);handlers[number]=handler;events.append((number,handler));return previous
   class Listener:
    def bind(self,chosen):actual.bind(chosen)
    def listen(self,count):actual.listen(count)
    def settimeout(self,seconds):actual.settimeout(seconds)
    def accept(inner):
     self.assertIn(signal.SIGTERM,handlers,'rc stop has no source-owned graceful handler')
     self.assertIn(signal.SIGINT,handlers)
     handlers[signal.SIGTERM](signal.SIGTERM,None)
     raise socket.timeout()
    def close(self):actual.close()
   # Intercept signals/native constructor only; execute actual service body on
   # one owned local listener, without activating native flags/material/SSH.
   with patch.object(relay._Relay,'native',return_value=instance),patch.object(relay,'LISTEN',path), \
     patch.object(relay.socket,'socket',return_value=Listener()),patch.object(relay.signal,'signal',side_effect=install):
    relay.serve_native()
   self.assertFalse(path.exists());self.assertTrue(instance._stop.is_set())
   self.assertEqual(handlers,{signal.SIGTERM:signal.SIG_DFL,signal.SIGINT:signal.SIG_DFL})
   self.assertEqual(len(events),4)
  instance._stop.clear();start=time.monotonic();wall=relay._millis()
  deadline=relay._Deadline(self.raw(2000),start,wall,start+2,instance._stop)
  a,b=socket.socketpair();child=None
  try:
   # Stop arrives while receive is waiting, not before the call.
   timer=threading.Timer(.02,instance._stop.set);timer.start()
   try:
    with self.assertRaises(relay.Unavailable):relay._Relay._socket_exact(a,1,deadline.io)
   finally:timer.join(timeout=1)
   self.assertGreater(deadline.resource_remaining(),.1)
   # Backpressure holds forward IO; stop must interrupt without restarting a
   # frame or turning cancellation into deadline renewal.
   instance._stop.clear();a.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,1024);a.setblocking(False)
   while True:
    try:a.send(b'x'*4096)
    except BlockingIOError:break
   timer=threading.Timer(.02,instance._stop.set);timer.start()
   try:
    with self.assertRaises(relay.Unavailable):relay._Relay._send(a,b'public',deadline)
   finally:timer.join(timeout=1)
   self.assertGreater(deadline.resource_remaining(),.1)
   # Direct test-owned synthetic process: only local disposition, no native
   # authentication. Cancellation cannot suppress original-budget kill/reap.
   child=subprocess.Popen((sys.executable,'-I','-c','import time;time.sleep(5)'),
    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
   relay._Relay._cleanup(child,deadline);self.assertIsNotNone(child.returncode)
   self.assertFalse(instance._contained)
   with patch.object(relay.subprocess,'Popen',side_effect=AssertionError)as spawn:
    with self.assertRaises(relay.Unavailable):instance.connection(a)
    spawn.assert_not_called()
   with patch.object(relay.time,'monotonic',return_value=start+2):
    with self.assertRaises(relay.Unavailable):deadline.resource_remaining()
  finally:
   a.close();b.close()
   if child is not None and child.returncode is None:
    try:os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    child.wait(timeout=1)

if __name__=='__main__':unittest.main()
