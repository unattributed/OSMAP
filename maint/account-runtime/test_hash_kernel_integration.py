"""Mandatory future hash-only typed identity before locked guard, profiles empty."""
import os,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R/'source' if (R/'source').is_dir() else R))
import account_command_kernel as k
import account_hash_identity as h
from authoritative_password import Refused,AuthoritativePasswordAdapter as A
from operation_budget import OperationBudget
from account_native_material import NativeMaterial
import test_hash_identity as fixtures
class HashKernelTests(unittest.TestCase):
 def setUp(self):self.b=OperationBudget(int(time.time())+8,maximum_seconds=8);self.end=time.monotonic()+7
 def make(self,role='hash',budget=None):
  b=budget or self.b;program,args=(A.HASH_PROGRAM,A.HASH_ARGS) if role=='hash' else (A.SQL_PROGRAM,A.SQL_ARGS)
  with patch.object(b,'inherited_group',return_value=True):return k.CommandKernelSeal._fixture(program,args,None,b,(('/fixed/public-program',b'rx'),),b'stdio rpath wpath cpath prot_exec exec')
 def test_empty_native_graph_still_refuses_before_identity_or_files_or_spawn(self):
  material=object.__new__(NativeMaterial)
  self.assertEqual(k._PROFILES,())
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(h.HashChildIdentity,'native',side_effect=AssertionError),patch.object(k.os,'open',side_effect=AssertionError),patch.object(k.subprocess,'Popen',side_effect=AssertionError):
   for role in ('hash','sql','primary'):
    with self.assertRaises(Refused):k.CommandKernelSeal._for_material(role,material,self.b,'fixture@example.com' if role=='primary' else None)
 def test_source_for_material_makes_hash_identity_mandatory_and_sql_separate(self):
  material=object.__new__(NativeMaterial)
  for role in ('hash','sql'):
   seal=self.make(role)
   seal._material=material
   with patch.object(self.b,'inherited_group',return_value=True),patch.object(k.CommandKernelSeal,'native',return_value=seal):current=k.CommandKernelSeal._for_material(role,material,self.b)
   self.assertIs(current,seal);self.assertIs(current._hash_identity_required,role=='hash')
  other=OperationBudget(int(time.time())+8,maximum_seconds=8)
  for wrong in (self.make('sql'),self.make(budget=other)):
   with patch.object(self.b,'inherited_group',return_value=True),patch.object(k.CommandKernelSeal,'native',return_value=wrong):
    with self.assertRaises(Refused):k.CommandKernelSeal._for_material('hash',material,self.b)
 def test_hash_typed_original_phase_admission_failure_prevents_Popen(self):
  seal=self.make();seal._hash_identity_required=True
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(h.HashChildIdentity,'native',side_effect=Refused('fixture missing private identity')) as admission,patch.object(k.subprocess,'Popen',side_effect=AssertionError):
   with self.assertRaises(Refused):seal.spawn(A.HASH_PROGRAM,A.HASH_ARGS,self.end)
  self.assertEqual(admission.call_args.args,(self.b,self.end))
  fake=object.__new__(h.HashChildIdentity);fake._budget=OperationBudget(int(time.time())+8,maximum_seconds=8)
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(h.HashChildIdentity,'native',return_value=fake),patch.object(k.subprocess,'Popen',side_effect=AssertionError):
   with self.assertRaises(Refused):seal.spawn(A.HASH_PROGRAM,A.HASH_ARGS,self.end)
 def test_all_actual_drop_steps_precede_final_unveil_lock_and_pledge(self):
  helper=fixtures.IdentityTests();helper.b=self.b;helper.end=self.end;identity=helper.identity();stack,calls,state=helper.drop_fixture(identity)
  seal=self.make();seal._hash_identity_required=True
  class Fn:
   def __init__(self,name):self.name=name
   def __call__(self,*args):
    assert state=={'groups':[],'gid':(12346,)*3,'uid':(12345,)*3};calls.append((self.name,args));return 0
  class Lib:unveil=Fn('unveil');pledge=Fn('pledge')
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(h.HashChildIdentity,'native',return_value=identity):guard=seal.preexec(A.HASH_PROGRAM,A.HASH_ARGS,deadline=self.end)
  with stack,patch.object(k.sys,'platform','openbsd7'),patch.object(k.ctypes,'CDLL',return_value=Lib()):guard()
  self.assertEqual([name for name,_ in calls],['recheck','chdir','groups','gid','uid','unveil','unveil','pledge']);self.assertEqual(calls[-2],('unveil',(None,None)));self.assertEqual(calls[-1],('pledge',(seal._promises,seal._promises)));self.assertNotIn(b'id',seal._promises.split())
 def test_drop_failure_never_opens_libc_or_reaches_kernel_or_exec(self):
  helper=fixtures.IdentityTests();helper.b=self.b;helper.end=self.end;identity=helper.identity();seal=self.make();seal._hash_identity_required=True
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(h.HashChildIdentity,'native',return_value=identity):guard=seal.preexec(A.HASH_PROGRAM,A.HASH_ARGS,deadline=self.end)
  for fail in ('groups','gid','uid'):
   stack,calls,_=helper.drop_fixture(identity,fail)
   with stack,patch.object(k.sys,'platform','openbsd7'),patch.object(k.ctypes,'CDLL',side_effect=AssertionError):
    with self.assertRaises(PermissionError):guard()
 def test_sql_and_private_fixture_lane_do_not_resolve_hash_identity(self):
  for role in ('hash','sql'):
   seal=self.make(role)
   program,args=seal._command_identity[:2]
   with patch.object(self.b,'inherited_group',return_value=True),patch.object(h.HashChildIdentity,'native',side_effect=AssertionError):guard=seal.preexec(program,args)
   self.assertTrue(callable(guard));self.assertFalse(seal._hash_identity_required)
  seal=self.make('sql');seal._hash_identity_required=True
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(h.HashChildIdentity,'native',side_effect=AssertionError):
   with self.assertRaises(Refused):seal.preexec(A.SQL_PROGRAM,A.SQL_ARGS,deadline=self.end)
 def test_real_owned_child_applies_real_source_drop_flow_with_ID_ABI_and_kernel_mocked_then_reaps(self):
  code=r'''
import os,subprocess,sys,tempfile,time
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0,sys.argv[1]);sys.path.insert(0,str(Path(sys.argv[1])/'source'))
import test_hash_identity as fixture,account_command_kernel as k,account_hash_identity as h
from operation_budget import OperationBudget
from authoritative_password import AuthoritativePasswordAdapter as A
b=OperationBudget(int(time.time())+8,maximum_seconds=8);b.attach_owned_process_group();end=time.monotonic()+5
helper=fixture.IdentityTests();helper.b=b;helper.end=end
seal=k.CommandKernelSeal._fixture(A.HASH_PROGRAM,A.HASH_ARGS,None,b,(('/fixed/public-program',b'rx'),),b'stdio rpath wpath cpath prot_exec exec');seal._hash_identity_required=True
r,w=os.pipe2(os.O_CLOEXEC);c=None
try:
 with tempfile.TemporaryDirectory(prefix='osmap-hash-child-fixture-') as tmp:
  public,p,g,null,observed=helper.fixture(tmp)
  with public:guard=seal.preexec(A.HASH_PROGRAM,A.HASH_ARGS,deadline=end)
  def pre():
   assert os.getpgrp()==b._owned_group and os.getpid()!=b._owned_group
   state={'uid':(0,0,0),'gid':(0,0,0),'groups':[0,1003]};events=[]
   def change(key,args):events.append(key);state[key]=list(args) if key=='groups' else args
   class Fn:
    def __init__(self,name):self.name=name
    def __call__(self,*args):
     assert state=={'uid':(12345,)*3,'gid':(12346,)*3,'groups':[]};events.append(self.name)
     if self.name=='pledge':assert events==['groups','gid','uid','unveil','unveil','pledge'];os.write(w,b'PUBLIC_ID_KERNEL_MOCKED')
     return 0
   class Lib:unveil=Fn('unveil');pledge=Fn('pledge')
   # Fresh context preserves the same actual owned public files and same budget;
   # only IDs/platform/root custody and kernel ABI are mocked, never native.
   actual_fstat=os.fstat
   with patch.object(h,'PASSWD',p),patch.object(h,'GROUP',g),patch.object(k.sys,'platform','openbsd7'),patch.object(Path,'lstat',observed),patch.object(h.os,'fstat',lambda fd:helper.project(actual_fstat(fd))),patch.object(h.os,'getuid',lambda:state['uid'][0]),patch.object(h.os,'geteuid',lambda:state['uid'][1]),patch.object(h.os,'getgid',lambda:state['gid'][0]),patch.object(h.os,'getegid',lambda:state['gid'][1]),patch.object(h.os,'getresuid',lambda:state['uid']),patch.object(h.os,'getresgid',lambda:state['gid']),patch.object(h.os,'getgroups',lambda:state['groups']),patch.object(h.os,'setgroups',lambda groups:change('groups',groups)),patch.object(h.os,'setresgid',lambda *args:change('gid',args)),patch.object(h.os,'setresuid',lambda *args:change('uid',args)),patch.object(h.os,'chdir'),patch.object(k.ctypes,'CDLL',return_value=Lib()):guard()
   os.close(w)
  c=subprocess.Popen((sys.executable,'-I','-B','-c','import sys;assert sys.stdin.buffer.read()==b"publicfixture";print("PUBLIC_OK")'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,pass_fds=(w,),preexec_fn=pre,start_new_session=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  os.close(w);w=None;receipt=os.read(r,64);out,err=c.communicate(b'publicfixture',timeout=2)
  assert receipt==b'PUBLIC_ID_KERNEL_MOCKED' and out==b'PUBLIC_OK\n' and not err and c.returncode==0 and c.pid!=os.getpgrp()
  print('PUBLIC_OWNED_CHILD_REAPED_ID_KERNEL_MOCKED')
finally:
 if c is not None and c.returncode is None:c.kill();c.wait(timeout=2)
 if c is not None:
  for stream in (c.stdin,c.stdout,c.stderr):
   if stream is not None and not stream.closed:stream.close()
 if w is not None:os.close(w)
 os.close(r)
'''
  child=subprocess.Popen((sys.executable,'-I','-B','-c',code,str(R)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  try:
   out,err=child.communicate(timeout=10);self.assertEqual(child.returncode,0,err);self.assertEqual(out,b'PUBLIC_OWNED_CHILD_REAPED_ID_KERNEL_MOCKED\n')
   with self.assertRaises(ProcessLookupError):os.killpg(child.pid,0)
  finally:
   if child.returncode is None:child.kill();child.wait(timeout=2)
   child.stdout.close();child.stderr.close()
if __name__=='__main__':unittest.main(verbosity=2)
