"""Finite source transport controls with real public HMAC bytes/owned children.

Local Linux peer/group/process evidence is not native SSH or Toronto authority.
"""
from pathlib import Path
import hashlib,hmac,json,os,signal,socket,sys,threading,time,unittest
from unittest.mock import patch
import admission_relay as relay
KEY=bytes([23])*32
SCHEMA='osmap-account-admission-v1'
def encoded(value):return json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
class RelayTests(unittest.TestCase):
 def raw(self,admit=False):
  now=int(time.time());op={'operation':'admit','epoch':4}if admit else{'operation':'authenticate','password':'public unicode é🙂'}
  value=dict(schema=SCHEMA,account='alice@example.test',operation=op,issued=now,expires=now+35,nonce='b'*32)
  value['signature']=hmac.new(KEY,encoded([SCHEMA,'request',value['account'],op,now,now+35,value['nonce']]),hashlib.sha256).hexdigest()
  # Whitespace deliberately differs from compact canonical MAC payload.
  return json.dumps(value,ensure_ascii=False,indent=1).encode()
 def exchange(self,mode='good',raw=None,uid=None,seconds=30,uncertain=False):
  if uncertain:mode='trailing' # Failure cleanup, distinct from successful reap.
  server,client=socket.socketpair();instance=relay._Relay(os.getuid()if uid is None else uid);errors=[]
  raw=self.raw()if raw is None else raw;program=Path(__file__).with_name('admission_relay_fixture.py')
  def work():
   try:
    with patch.object(instance,'_command',return_value=(sys.executable,'-I','-B',str(program),mode,hashlib.sha256(raw).hexdigest())),patch.object(relay,'ORIGINAL_SECONDS',seconds):
     if uncertain:
      with patch.object(instance,'_cleanup',side_effect=relay.Unavailable('public cleanup uncertainty')):instance.connection(server)
     else:instance.connection(server)
   except BaseException as error:errors.append(type(error))
   finally:server.close()
  worker=threading.Thread(target=work);worker.start();client.settimeout(2);reply=None
  try:
   client.sendall(len(raw).to_bytes(4,'big')+raw)
   # No local SHUT_WR: matches actual Rust Client write-frame/read-frame.
   def exact(n):
    out=bytearray()
    while len(out)<n:
     part=client.recv(n-len(out))
     if not part:raise EOFError
     out.extend(part)
    return bytes(out)
   size=int.from_bytes(exact(4),'big');self.assertLessEqual(size,4096);reply=exact(size)
   self.assertEqual(client.recv(1),b'')
  except(EOFError,ConnectionResetError,BrokenPipeError):reply=None
  finally:client.close();worker.join(timeout=2)
  self.assertFalse(worker.is_alive())
  if uncertain:
   for child in instance._retained:
    self.assertIsNone(child.returncode)
    try:os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    child.wait(timeout=1)
    for pipe in(child.stdin,child.stdout):
     if not pipe.closed:pipe.close()
  return instance,reply,errors
 def test_fixed_distinct_pinned_purpose_and_disabled_before_material(self):
  args=relay.ssh_argv();self.assertEqual(args[-2:],('_osmap@216.128.179.75','osmap-account-admission'))
  self.assertIn('/var/lib/osmap-bridge/keys/admission',args)
  for value in('StrictHostKeyChecking=yes','IdentityAgent=none','ControlMaster=no','ControlPath=none','ControlPersist=no','ConnectionAttempts=1','ClearAllForwardings=yes'):self.assertIn(value,args)
  with patch.object(relay,'_material',side_effect=AssertionError),patch.object(relay.socket,'socket',side_effect=AssertionError):
   with self.assertRaises(relay.Unavailable):relay.serve_native()
 def test_real_opaque_unicode_and_admit_reply_MAC_without_local_EOF(self):
  for admit in(False,True):
   instance,reply,errors=self.exchange(raw=self.raw(admit));self.assertEqual(errors,[]);self.assertFalse(instance._contained)
   value=json.loads(reply);payload=encoded([SCHEMA,'response',value['account'],value['nonce'],'active',4])
   self.assertEqual(value['signature'],hmac.new(KEY,payload,hashlib.sha256).hexdigest());self.assertEqual(value['epoch'],4)
 def test_wrong_peer_duplicate_expired_future_window_never_spawns(self):
  value=json.loads(self.raw());bad=[b'{}',b'{"schema":1,"schema":2}']
  for issued,expires in((value['issued']+100,value['expires']+100),(value['issued']-100,value['expires']-100),(value['issued'],value['expires']+1)):
   copy=dict(value,issued=issued,expires=expires);bad.append(encoded(copy))
  with patch.object(relay.subprocess,'Popen',side_effect=AssertionError)as spawn:
   self.assertIsNone(self.exchange(uid=os.getuid()+1)[1])
   for raw in bad:self.assertIsNone(self.exchange(raw=raw)[1])
   spawn.assert_not_called()
 def test_remote_MAC_rejection_is_not_replaced_by_relay_authority(self):
  value=json.loads(self.raw());value['account']='bob@example.test'
  self.assertIsNone(self.exchange(raw=encoded(value))[1])
 def test_remote_trailing_oversize_nonzero_withhold_reply(self):
  for mode in('trailing','oversize','badexit'):
   with self.subTest(mode=mode):
    instance,reply,errors=self.exchange(mode);self.assertIsNone(reply);self.assertEqual(errors,[relay.Unavailable]);self.assertFalse(instance._contained)
 def test_original_shortened_budget_reaps_once_and_never_returns_reply(self):
  start=time.monotonic();instance,reply,errors=self.exchange('wait',seconds=.3)
  self.assertLess(time.monotonic()-start,.7);self.assertIsNone(reply);self.assertEqual(errors,[relay.Unavailable]);self.assertFalse(instance._contained)
 def test_cleanup_uncertainty_latches_and_prevents_later_dispatch(self):
  instance,reply,errors=self.exchange(uncertain=True);self.assertIsNone(reply);self.assertTrue(instance._contained);self.assertEqual(len(instance._retained),1)
  a,b=socket.socketpair()
  try:
   with patch.object(relay.subprocess,'Popen',side_effect=AssertionError):
    with self.assertRaises(relay.Unavailable):instance.connection(a)
  finally:a.close();b.close()
 def test_unsigned_window_only_shortens_and_clock_regression_refuses(self):
  start=time.monotonic();wall=relay._millis();stop=threading.Event();deadline=relay._Deadline(self.raw(),start,wall,start+.2,stop)
  self.assertLessEqual(deadline.remaining(),.2)
  with patch.object(relay,'_millis',return_value=wall-1):
   with self.assertRaises(relay.Unavailable):deadline.remaining()
 def test_eof_before_delayed_clean_exit_reaps_without_success_kill(self):
  instance,reply,errors=self.exchange('lateexit')
  self.assertIsNotNone(reply);self.assertEqual(errors,[]);self.assertFalse(instance._contained)

 def test_already_reaped_surviving_group_never_gets_a_signal(self):
  from types import SimpleNamespace
  child=SimpleNamespace(pid=12345,returncode=0)
  budget=SimpleNamespace(remaining=lambda:1,resource_remaining=lambda:1)
  with patch.object(relay.os,'killpg')as probe:
   with self.assertRaises(relay.Unavailable):relay._Relay._cleanup(child,budget)
   probe.assert_called_once_with(child.pid,0)

if __name__=='__main__':unittest.main()
