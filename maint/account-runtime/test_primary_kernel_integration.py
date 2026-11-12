"""Primary producer controls; native platform/IDs/kernel are projections only."""
import contextlib,os,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R))
import account_command_kernel as k
from account_native_material import NativeMaterial,_SqlEndpoint
from operation_budget import OperationBudget
from authoritative_password import Refused
from mutation_primary import PROGRAM,ARGS

class PrimaryKernelTests(unittest.TestCase):
 def setUp(self):
  ms=int(time.time()*1000)
  self.b=OperationBudget.from_original_deadline((ms+60000)//1000,
   received_mono=time.monotonic(),received_millis=ms,sent_millis=ms,
   deadline_millis=ms+12000,wall_millis=lambda:int(time.time()*1000))
  self.end=time.monotonic()+10
  self.material=object.__new__(NativeMaterial)
  self.material._endpoint=object.__new__(_SqlEndpoint);self.material._states=(None,)*4
  self.account='alice@example.test'
 def seal(self):
  with patch.object(k,'_PROFILES',('sql','hash','primary')),patch.object(self.b,'inherited_group',return_value=True):
   return k.CommandKernelSeal._for_material('primary',self.material,self.b,self.account)
 def test_native_primary_producer_mints_exact_account_material_and_original_budget(self):
  seal=self.seal()
  self.assertIs(seal._material,self.material);self.assertIs(seal._budget,self.b)
  self.assertEqual(seal._command_identity,(PROGRAM,ARGS+(self.account,),self.account,'primary'))
  self.assertTrue(seal._primary_identity_required and seal._primary_graph_required)
  self.assertFalse(seal._hash_identity_required or seal._hash_graph_required or seal._sql_graph_required)
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(k.subprocess,'Popen',side_effect=AssertionError):
   with self.assertRaises(Refused):seal.spawn(PROGRAM,ARGS+('bob@example.test',),self.end,'bob@example.test')
 def test_profiles_and_unobserved_private_binder_stay_closed_before_any_IO(self):
  import account_primary_identity as identity
  import account_primary_graph as graph
  self.assertEqual(k._PROFILES,());self.assertIsNone(identity.PEER_BIND_UID)
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(k.os,'open',side_effect=AssertionError),patch.object(identity.socket,'socket',side_effect=AssertionError):
   with self.assertRaises(Refused):k.CommandKernelSeal._for_material('primary',self.material,self.b,self.account)
   seal=self.seal()
   with patch.object(graph.PrimaryInstalledGraph,'native',side_effect=AssertionError),patch.object(k.subprocess,'Popen',side_effect=AssertionError):
    with self.assertRaises(Refused):seal.spawn(PROGRAM,ARGS+(self.account,),self.end,self.account)
 def test_primary_rows_bind_fixed_readonly_search_and_refuse_changed_custody(self):
  import account_primary_graph as graph
  import account_primary_identity as identity
  import account_hash_graph as common
  rows=graph.PrimaryInstalledGraph.rows();self.assertEqual(len(rows),len(common.FILES)+4)
  self.assertEqual(self.seal()._rows,rows)
  self.assertEqual([row for row in rows if row[0]==common.SEARCH_DIRECTORY],[(common.SEARCH_DIRECTORY,b'r')])
  self.assertEqual([row for row in rows if row[0]=='/dev/null'],[('/dev/null',b'rwc')])
  self.assertEqual(rows[-1],(str(identity.SOCKET),b'rw'))
  self.assertEqual(graph.PROMISES,b'stdio rpath unix prot_exec exec wpath cpath')
  self.assertEqual([name for name,access in rows if b'w'in access or b'c'in access],['/dev/null',str(identity.SOCKET)])
  self.assertEqual([name for name,access in rows if b'x'in access],[PROGRAM])
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(common,'_modules',return_value='fixed-five') as modules,patch.object(common,'_read',return_value='fixed-leaf') as reader,patch.object(common,'_search_directory',return_value='fixed-search') as search:
   states=graph.PrimaryInstalledGraph._observe(self.b,self.end)
  self.assertEqual(states,(('fixed-leaf',)*len(common.FILES),'fixed-five','fixed-search'))
  self.assertEqual(modules.call_count,2);self.assertEqual(reader.call_count,len(common.FILES))
  self.assertEqual([str(call.args[0]) for call in reader.call_args_list],[row[0] for row in common.FILES])
  self.assertEqual(search.call_args_list,[unittest.mock.call(self.b,self.end)]*2)
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(common,'_modules',return_value='fixed-five'),patch.object(common,'_read',side_effect=AssertionError),patch.object(common,'_search_directory',side_effect=Refused('search custody unavailable')):
   with self.assertRaisesRegex(Refused,'search custody unavailable'):graph.PrimaryInstalledGraph._observe(self.b,self.end)
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(common,'_modules',return_value='fixed-five'),patch.object(common,'_read',return_value='fixed-leaf'),patch.object(common,'_search_directory',side_effect=['fixed-search','changed-search']):
   with self.assertRaisesRegex(Refused,'search directory changed'):graph.PrimaryInstalledGraph._observe(self.b,self.end)
 def projected(self):
  import account_primary_identity as identity
  import account_primary_graph as graph
  selected=object.__new__(identity.PrimaryChildIdentity);selected._budget=self.b
  public=object.__new__(graph.PrimaryInstalledGraph);public._budget=self.b
  return identity,graph,selected,public
 def test_typed_identity_and_graph_are_required_and_wrong_budget_prevents_spawn(self):
  identity,graph,selected,public=self.projected();seal=self.seal()
  for wrong_identity,wrong_graph in ((object(),public),(selected,object())):
   with patch.object(self.b,'inherited_group',return_value=True),patch.object(identity.PrimaryChildIdentity,'native',return_value=wrong_identity),patch.object(graph.PrimaryInstalledGraph,'native',return_value=wrong_graph),patch.object(k.subprocess,'Popen',side_effect=AssertionError):
    with self.assertRaises(Refused):seal.spawn(PROGRAM,ARGS+(self.account,),self.end,self.account)
  selected._budget=OperationBudget(int(time.time())+8,maximum_seconds=8)
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(identity.PrimaryChildIdentity,'native',return_value=selected),patch.object(graph.PrimaryInstalledGraph,'native',side_effect=AssertionError),patch.object(k.subprocess,'Popen',side_effect=AssertionError):
   with self.assertRaises(Refused):seal.spawn(PROGRAM,ARGS+(self.account,),self.end,self.account)
 def test_graph_recheck_then_irreversible_identity_drop_precedes_locked_kernel(self):
  identity,graph,selected,public=self.projected();seal=self.seal();calls=[]
  class Fn:
   def __init__(self,name):self.name=name
   def __call__(self,*args):calls.append((self.name,args));return 0
  class Lib:unveil=Fn('unveil');pledge=Fn('pledge')
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(identity.PrimaryChildIdentity,'native',return_value=selected),patch.object(graph.PrimaryInstalledGraph,'native',return_value=public):
   guard=seal.preexec(PROGRAM,ARGS+(self.account,),self.account,deadline=self.end)
  with contextlib.ExitStack() as stack:
   stack.enter_context(patch.object(k.sys,'platform','openbsd'))
   stack.enter_context(patch.object(k.os,'getuid',return_value=0));stack.enter_context(patch.object(k.os,'geteuid',return_value=0))
   stack.enter_context(patch.object(graph.PrimaryInstalledGraph,'recheck',side_effect=lambda *args:calls.append(('graph',args))))
   stack.enter_context(patch.object(identity.PrimaryChildIdentity,'drop',side_effect=lambda *args:calls.append(('drop',args))))
   stack.enter_context(patch.object(k.ctypes,'CDLL',return_value=Lib()));guard()
  self.assertEqual([name for name,_ in calls[:2]],['graph','drop'])
  self.assertEqual(calls[:2],[('graph',(self.b,self.end)),('drop',(self.b,self.end))])
  self.assertEqual(calls[-2:], [('unveil',(None,None)),('pledge',(graph.PROMISES,)*2)])
  self.assertEqual([args for name,args in calls if name=='unveil'][:-1],[(os.fsencode(path),access) for path,access in graph.PrimaryInstalledGraph.rows()])
  with patch.object(k.sys,'platform','openbsd'),patch.object(k.os,'getuid',return_value=0),patch.object(k.os,'geteuid',return_value=0),patch.object(graph.PrimaryInstalledGraph,'recheck',side_effect=Refused('changed public leaf')),patch.object(identity.PrimaryChildIdentity,'drop',side_effect=AssertionError),patch.object(k.ctypes,'CDLL',side_effect=AssertionError):
   with self.assertRaises(Refused):guard()
  with patch.object(k.sys,'platform','openbsd'),patch.object(k.os,'getuid',return_value=0),patch.object(k.os,'geteuid',return_value=0),patch.object(graph.PrimaryInstalledGraph,'recheck'),patch.object(identity.PrimaryChildIdentity,'drop',side_effect=Refused('drop failed')),patch.object(k.ctypes,'CDLL',side_effect=AssertionError):
   with self.assertRaises(Refused):guard()

if __name__=='__main__':unittest.main(verbosity=2)
