"""Primary DAC/public custody; real local peer, native UID/kernel projected."""
import contextlib,os,socket,stat,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R))
import account_primary_identity as q,account_hash_identity as h,test_hash_identity as helper_source
from account_mutation_supervisor import _peer
from authoritative_password import Refused
from operation_budget import OperationBudget
PASS=helper_source.PASS.replace(b'_osmaphash',b'_osmapprimary')
GROUP=helper_source.GROUP.replace(b'_osmaphash',b'_osmapprimary')
class PrimaryIdentityTests(unittest.TestCase):
 def setUp(self):
  millis=int(time.time()*1000);self.b=OperationBudget.from_original_deadline((millis+60000)//1000,received_mono=time.monotonic(),received_millis=millis,sent_millis=millis,deadline_millis=millis+12000,wall_millis=lambda:int(time.time()*1000));self.end=time.monotonic()+10
 def fixture(self):
  real_binding_uid=os.getuid()
  tmp=tempfile.TemporaryDirectory(prefix='osmap-primary-source-');self.addCleanup(tmp.cleanup);helper=helper_source.IdentityTests();helper.b=self.b;helper.end=self.end
  stack,p,g,null,observed=helper.fixture(tmp.name);stack.__enter__();self.addCleanup(stack.close);p.write_bytes(PASS);g.write_bytes(GROUP)
  endpoint=Path(tmp.name)/'private-auth';server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(endpoint));server.listen(32);server.settimeout(.1);self.addCleanup(server.close);endpoint.chmod(0o660);actual_lstat=Path.lstat;real=observed
  def project(path):
   value=real(path)
   if path==endpoint:return helper.project(value,st_uid=q.SERVER_UID,st_gid=12346)
   return value
  local_platform='linux'
  def peer(stream):
   with patch.object(sys,'platform',local_platform):return _peer(stream)
  chosen=real_binding_uid;extra=contextlib.ExitStack();extra.enter_context(patch.object(q,'SOCKET',endpoint));extra.enter_context(patch.object(q,'PEER_BIND_UID',chosen));extra.enter_context(patch.object(Path,'lstat',project));extra.enter_context(patch.object(q,'_peer',side_effect=peer));extra.__enter__();self.addCleanup(extra.close)
  return p,g,null,endpoint,server,extra,project
 def drain(self,server,expected):
  count=0
  while True:
   try:child,_=server.accept()
   except TimeoutError:break
   with child:self.assertEqual(child.recv(1),b'')
   count+=1
  self.assertEqual(count,expected)
 def test_fixed_private_listener_original0600_and_no_caller_profile(self):
  self.assertEqual((q.NAME,str(q.SOCKET),q.SERVER_UID,q.PEER_BIND_UID),('_osmapprimary','/var/dovecot/osmap-account-auth-client',518,None))
  self.assertNotEqual(str(q.SOCKET),'/var/dovecot/auth-client')
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(h.os,'open',side_effect=AssertionError),patch.object(q.socket,'socket',side_effect=AssertionError):
   with self.assertRaises(Refused):q.PrimaryChildIdentity.native(self.b,self.end)
  for args in ((),({'uid':518,'socket':'/caller/path'},),('caller',)):
   with self.assertRaises(Refused):q.PrimaryChildIdentity(*args)
  with self.assertRaises(TypeError):q.PrimaryChildIdentity.native(self.b,self.end,uid=12345)
 def test_public_private_UID_GID_inert_unique_and_no_server_reuse(self):
  self.assertEqual(q._selected(PASS,GROUP),(12345,12346))
  for users,groups in ((PASS.replace(b'12345',b'518'),GROUP),(PASS.replace(b'12346',b'1003'),GROUP),(PASS.replace(b'/sbin/nologin',b'/bin/ksh'),GROUP),(PASS,GROUP.replace(b'_osmapprimary:*:12346:',b'_osmapprimary:*:12346:fixture')),(PASS+b'other:*:12345:777:opaque:/var/empty:/sbin/nologin\n',GROUP),(PASS,GROUP+b'other:*:888:_osmapprimary\n')):
   with self.assertRaises(Refused):q._selected(users,groups)
  self.assertEqual(q._selected(PASS.replace(b'root:*:0:0:root',b'opaque-\xff:placeholder:0:0:utf8-\xc3\xa9'),GROUP.replace(b'wheel:*:',b'opaque-\xff:placeholder:')),(12345,12346))
 def test_genuine_local_socket_native_metadata_projection_and_zero_protocol_peer(self):
  p,g,null,endpoint,server,extra,project=self.fixture();value=q.PrimaryChildIdentity.native(self.b,self.end);self.assertEqual((value._uid,value._gid),(12345,12346));value.recheck(self.b,self.end);self.drain(server,3)
 def test_original600_wrong_socket_owner_group_mode_links_refuse_before_connect(self):
  p,g,null,endpoint,server,extra,project=self.fixture()
  for changed in ({'st_mode':stat.S_IFSOCK|0o600,'st_gid':0},{'st_uid':0},{'st_gid':12347},{'st_mode':stat.S_IFSOCK|0o666},{'st_mode':stat.S_IFREG|0o660},{'st_nlink':2}):
   def altered(path,change=changed):
    old=project(path)
    if path==endpoint:return NS(**{**vars(old),**change})
    return old
   with patch.object(Path,'lstat',altered),patch.object(q.socket,'socket',side_effect=AssertionError('DAC precedes connect')):
    with self.assertRaises(Refused):q._socket(12345,12346,self.b,self.end)
  self.drain(server,0)
 def test_actual_linux_peer_identity_differs_from_projected_file_owner(self):
  p,g,null,endpoint,server,extra,project=self.fixture()
  # Actual peer is local socket binding UID; a projected filesystem owner does
  # not change it. No native518 peer is manufactured by this actual countercase.
  with patch.object(q,'PEER_BIND_UID',518):
   with self.assertRaises(Refused):q._socket(12345,12346,self.b,self.end)
  self.drain(server,1)
 def test_actual_socket_inode_replacement_at_peer_check_refuses_and_closes(self):
  p,g,null,endpoint,server,extra,project=self.fixture();replacement=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.addCleanup(replacement.close);other=endpoint.with_name('replacement');replacement.bind(str(other));replacement.listen(1);other.chmod(0o660);before=set(os.listdir('/proc/self/fd'));ordinary=q._peer
  def swap(stream):
   result=ordinary(stream);os.replace(other,endpoint);return result
  with patch.object(q,'_peer',side_effect=swap):
   with self.assertRaises(Refused):q._socket(12345,12346,self.b,self.end)
  self.assertEqual(set(os.listdir('/proc/self/fd')),before);self.drain(server,1)
 def test_original_receipt_phase_and_public_custody_changes_refuse(self):
  p,g,null,endpoint,server,extra,project=self.fixture();value=q.PrimaryChildIdentity.native(self.b,self.end)
  generic=OperationBudget(int(time.time())+8,maximum_seconds=8)
  with patch.object(generic,'inherited_group',return_value=True),patch.object(q.socket,'socket',side_effect=AssertionError):
   with self.assertRaises(Refused):q._socket(12345,12346,generic,self.end)
   with self.assertRaises(Refused):q._socket(12345,12346,self.b,time.monotonic()-1)
  p.write_bytes(PASS+b'compatible:*:888:889:opaque:/var/empty:/sbin/nologin\n')
  with patch.object(q.socket,'socket',side_effect=AssertionError):
   with self.assertRaises(Refused):value.recheck(self.b,self.end)
  self.drain(server,2)
 def test_closed_saved_identity_drop_order_and_every_id_group_refusal(self):
  p,g,null,endpoint,server,extra,project=self.fixture();value=q.PrimaryChildIdentity.native(self.b,self.end);state={'uid':0,'gid':0,'groups':[0]};calls=[]
  def groups(v):calls.append(('groups',v));state['groups']=list(v)
  def gids(*v):calls.append(('gid',v));state['gid']=v[0]
  def uids(*v):calls.append(('uid',v));state['uid']=v[0]
  with patch.object(q.os,'getuid',side_effect=lambda:state['uid']),patch.object(q.os,'geteuid',side_effect=lambda:state['uid']),patch.object(q.os,'getgid',side_effect=lambda:state['gid']),patch.object(q.os,'getegid',side_effect=lambda:state['gid']),patch.object(q.os,'getgroups',side_effect=lambda:state['groups']),patch.object(q.os,'getresgid',side_effect=lambda:(state['gid'],)*3),patch.object(q.os,'getresuid',side_effect=lambda:(state['uid'],)*3),patch.object(q.os,'setgroups',side_effect=groups),patch.object(q.os,'setresgid',side_effect=gids),patch.object(q.os,'setresuid',side_effect=uids),patch.object(q.os,'chdir',side_effect=lambda path:calls.append(('cwd',path))):
   value.drop(self.b,self.end)
  self.assertEqual(calls,[('cwd','/'),('groups',()),('gid',(12346,)*3),('uid',(12345,)*3)]);self.assertEqual(state,{'uid':12345,'gid':12346,'groups':[]});self.drain(server,3)
  for field,observed in (('getgroups',[12346]),('getresgid',(12346,12346,0)),('getresuid',(12345,12345,0)),('getgid',0),('getegid',0),('getuid',0),('geteuid',0)):
   with patch.object(value,'recheck',return_value=None),patch.object(q.os,'chdir',return_value=None),patch.object(q.os,'setgroups',return_value=None),patch.object(q.os,'setresgid',return_value=None),patch.object(q.os,'setresuid',return_value=None),patch.object(q.os,'getgroups',return_value=[]),patch.object(q.os,'getresgid',return_value=(12346,)*3),patch.object(q.os,'getresuid',return_value=(12345,)*3),patch.object(q.os,'getgid',return_value=12346),patch.object(q.os,'getegid',return_value=12346),patch.object(q.os,'getuid',side_effect=[0,12345]),patch.object(q.os,'geteuid',side_effect=[0,12345]):
    # Privileged-entry check and postdrop getters are separate. This loop's
    # observed failure is injected only at the final source-owned readback.
    if field in ('getuid','geteuid'):
     injected=patch.object(q.os,field,side_effect=[0,observed])
    else:injected=patch.object(q.os,field,return_value=observed)
    with injected:
     with self.assertRaises(Refused):value.drop(self.b,self.end)
if __name__=='__main__':unittest.main(verbosity=2)
