"""Fixed candidate composition, graph before drop before irreversible kernel."""
import os,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R/'source'))
import account_command_kernel as k,account_hash_graph as g,account_hash_identity as h
from operation_budget import OperationBudget
from authoritative_password import Refused,AuthoritativePasswordAdapter as A
from account_native_material import NativeMaterial
import test_hash_graph as files,test_hash_identity as identities
class CompositionTests(unittest.TestCase):
 def setUp(self):self.b=OperationBudget(int(time.time())+12,maximum_seconds=12);self.end=time.monotonic()+10
 def seal(self):
  with patch.object(self.b,'inherited_group',return_value=True):return k.CommandKernelSeal._hash_candidate(self.b)
 def graph(self):v=object.__new__(g.HashInstalledGraph);v._budget=self.b;return v
 def test_production_unavailable_before_any_graph_identity_or_spawn(self):
  material=object.__new__(NativeMaterial)
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(g.HashInstalledGraph,'native',side_effect=AssertionError),patch.object(h.HashChildIdentity,'native',side_effect=AssertionError),patch.object(k.subprocess,'Popen',side_effect=AssertionError):
   with self.assertRaises(Refused):k.CommandKernelSeal._for_material('hash',material,self.b)
  self.assertEqual(k._PROFILES,())
 def test_source_candidate_fixed_command_rows_promises_both_obligations(self):
  seal=self.seal();self.assertEqual(seal._command_identity,(A.HASH_PROGRAM,A.HASH_ARGS,None,'hash'));self.assertEqual(seal._rows,g.HashInstalledGraph.rows());self.assertEqual(seal._promises,g.PROMISES);self.assertTrue(seal._hash_graph_required and seal._hash_identity_required)
  with self.assertRaises(TypeError):k.CommandKernelSeal._hash_candidate(self.b,rows=(('/unapproved',b'r'),))
  with patch.object(self.b,'inherited_group',return_value=False):
   with self.assertRaises(Refused):k.CommandKernelSeal._hash_candidate(self.b)
 def test_production_material_sets_same_hash_obligations_sql_separate(self):
  for role in ('hash','sql'):
   program,args=(A.HASH_PROGRAM,A.HASH_ARGS) if role=='hash' else (A.SQL_PROGRAM,A.SQL_ARGS)
   with patch.object(self.b,'inherited_group',return_value=True):seal=k.CommandKernelSeal._fixture(program,args,None,self.b,(('/fixed',b'rx'),),b'stdio rpath exec')
   with patch.object(self.b,'inherited_group',return_value=True),patch.object(k.CommandKernelSeal,'native',return_value=seal):k.CommandKernelSeal._for_material(role,object.__new__(NativeMaterial),self.b)
   self.assertIs(seal._hash_graph_required,role=='hash');self.assertIs(seal._hash_identity_required,role=='hash')
 def test_graph_failure_type_budget_and_profile_change_prevent_identity_Popen(self):
  for value in (Refused('graph refused'),object(),self.graph()):
   seal=self.seal()
   if type(value)is g.HashInstalledGraph:value._budget=OperationBudget(int(time.time())+8,maximum_seconds=8)
   with patch.object(self.b,'inherited_group',return_value=True),patch.object(g.HashInstalledGraph,'native',side_effect=value if isinstance(value,Exception) else None,return_value=value) as admission,patch.object(h.HashChildIdentity,'native',side_effect=AssertionError),patch.object(k.subprocess,'Popen',side_effect=AssertionError):
    with self.assertRaises(Refused):seal.spawn(A.HASH_PROGRAM,A.HASH_ARGS,self.end)
   self.assertEqual(admission.call_args.args,(self.b,self.end))
  for field,value in (('_rows',(('/usr/local/lib',b'r'),)),('_promises',g.PROMISES+b' unix'),('_hash_identity_required',False)):
   seal=self.seal();setattr(seal,field,value)
   with patch.object(self.b,'inherited_group',return_value=True),patch.object(g.HashInstalledGraph,'native',side_effect=AssertionError):
    with self.assertRaises(Refused):seal.preexec(A.HASH_PROGRAM,A.HASH_ARGS,deadline=self.end)
 def test_changed_actual_graph_prevents_ID_drop_and_kernel(self):
  helper=files.GraphTests();helper.setUp()
  try:
   helper.b=self.b;helper.end=self.end;directory,names,objects,aux=helper.fixture()
   with helper.context(objects,((aux,65536),),directory,names):
    graph=self.graph();graph._states=g.HashInstalledGraph._observe(self.b,self.end);seal=self.seal();identity=object.__new__(h.HashChildIdentity);identity._budget=self.b
    with patch.object(g.HashInstalledGraph,'native',return_value=graph),patch.object(h.HashChildIdentity,'native',return_value=identity):guard=seal.preexec(A.HASH_PROGRAM,A.HASH_ARGS,deadline=self.end)
    aux.chmod(0o644);aux.write_bytes(b'changed fixture');aux.chmod(0o444)
    with patch.object(k.sys,'platform','openbsd7'),patch.object(k.os,'getuid',return_value=0),patch.object(k.os,'geteuid',return_value=0),patch.object(h.HashChildIdentity,'drop',side_effect=AssertionError),patch.object(k.ctypes,'CDLL',side_effect=AssertionError):
     with self.assertRaises(Refused):guard()
  finally:helper.doCleanups()
 def test_owned_launcher_exec_child_real_graph_recheck_then_ID_ABI_kernel_mocked(self):
  code=r'''
import os,subprocess,sys,time
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,sys.argv[1]);sys.path.insert(0,str(Path(sys.argv[1])/'source'))
import test_hash_graph as files,test_hash_identity as identities
import account_command_kernel as k,account_hash_graph as g,account_hash_identity as h
from authoritative_password import AuthoritativePasswordAdapter as A
from operation_budget import OperationBudget
b=OperationBudget(int(time.time())+12,maximum_seconds=12);b.attach_owned_process_group();end=time.monotonic()+8
helper=files.GraphTests();helper.setUp();helper.b=b;helper.end=end
child=None;r,w=os.pipe2(os.O_CLOEXEC)
try:
 directory,names,objects,aux=helper.fixture()
 with helper.context(objects,((aux,65536),),directory,names):
  graph=object.__new__(g.HashInstalledGraph);graph._budget=b;graph._states=g.HashInstalledGraph._observe(b,end)
  seal=k.CommandKernelSeal._hash_candidate(b)
  ih=identities.IdentityTests();ih.b=b;ih.end=end;identity=ih.identity()
  with patch.object(g.HashInstalledGraph,'native',return_value=graph),patch.object(h.HashChildIdentity,'native',return_value=identity):guard=seal.preexec(A.HASH_PROGRAM,A.HASH_ARGS,deadline=end)
  def pre():
   assert os.getpgrp()==b._owned_group and os.getpid()!=b._owned_group
   stack,calls,state=ih.drop_fixture(identity);original=g.HashInstalledGraph._observe
   def observed(*args):result=original(*args);calls.append(('graph',()));return result
   class Fn:
    def __init__(self,name):self.name=name
    def __call__(self,*args):
     assert state=={'groups':[],'gid':(12346,)*3,'uid':(12345,)*3};calls.append((self.name,args))
     if self.name=='pledge':
      expected=['graph','recheck','chdir','groups','gid','uid']+['unveil']*(len(seal._rows)+1)+['pledge']
      assert [n for n,_ in calls]==expected;assert args==(g.PROMISES,g.PROMISES);os.write(w,b'PUBLIC_GRAPH_ID_KERNEL_MOCKED')
     return 0
   class Lib:unveil=Fn('unveil');pledge=Fn('pledge')
   with stack,patch.object(g.HashInstalledGraph,'_observe',side_effect=observed),patch.object(k.sys,'platform','openbsd7'),patch.object(k.ctypes,'CDLL',return_value=Lib()):guard()
   os.close(w)
  child=subprocess.Popen((sys.executable,'-I','-B','-c','import sys;assert sys.stdin.buffer.read()==b"publicfixture";print("PUBLIC_OK")'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=False,close_fds=True,pass_fds=(w,),preexec_fn=pre,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  os.close(w);w=None;receipt=os.read(r,64);out,err=child.communicate(b'publicfixture',timeout=3)
  assert receipt==b'PUBLIC_GRAPH_ID_KERNEL_MOCKED' and out==b'PUBLIC_OK\n' and not err and child.returncode==0
  print('PUBLIC_REAL_GRAPH_OWNED_CHILD_REAPED_ID_KERNEL_MOCKED')
finally:
 if child is not None:
  if child.returncode is None:child.kill();child.wait(timeout=2)
  for stream in (child.stdin,child.stdout,child.stderr):
   if stream is not None and not stream.closed:stream.close()
 if w is not None:os.close(w)
 os.close(r);helper.doCleanups()
'''
  child=subprocess.Popen((sys.executable,'-I','-B','-c',code,str(R)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  try:
   out,err=child.communicate(timeout=15);self.assertEqual(child.returncode,0,err);self.assertEqual(out,b'PUBLIC_REAL_GRAPH_OWNED_CHILD_REAPED_ID_KERNEL_MOCKED\n')
   with self.assertRaises(ProcessLookupError):os.killpg(child.pid,0)
  finally:
   if child.returncode is None:child.kill();child.wait(timeout=2)
   child.stdout.close();child.stderr.close()
if __name__=='__main__':unittest.main(verbosity=2)
