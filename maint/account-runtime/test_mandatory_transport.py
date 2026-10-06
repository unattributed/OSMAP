"""Mandatory transport composition; fixtures never qualify installed profiles."""
import ast,os,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parent;S=Path(os.environ.get('TRANSPORT_SOURCE_DIR',str(R)))
sys.path.insert(0,str(S));sys.path.append(str(R))
from authoritative_password import AuthoritativePasswordAdapter as A,NativeExecutor,Refused
from operation_budget import OperationBudget
from account_native_material import NativeMaterial,MaterialExecutor,Unavailable
from mutation_primary import NativePrimaryVerifier,PROGRAM,ARGS
# Baseline comparison still uses the new closed kernel component only as a
# local test factory. Original transports will not call it.
sys.path.append(str(R))
import account_command_kernel as k
class TransportTests(unittest.TestCase):
 def setUp(self):
  self.b=OperationBudget(int(time.time())+8,maximum_seconds=8)
  self.material=object.__new__(NativeMaterial)
 def factory(self,role,material,budget,account=None):
  program,args=(A.SQL_PROGRAM,A.SQL_ARGS) if role=='sql' else (A.HASH_PROGRAM,A.HASH_ARGS) if role=='hash' else (PROGRAM,ARGS+(account,))
  return k.CommandKernelSeal._fixture(program,args,account,budget,((program,b'rx'),),b'stdio rpath exec')
 def test_bare_native_transport_cannot_dispatch_without_material_seal(self):
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(subprocess,'Popen',side_effect=AssertionError('UNGUARDED')):
   with self.assertRaises(Refused):NativeExecutor(self.b)(A.HASH_PROGRAM,A.HASH_ARGS,b'PUBLIC\n',A.LIMIT_SECONDS,A.OUTPUT_LIMIT)
 def test_empty_installed_graph_refuses_both_transport_constructors_before_read_or_spawn(self):
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(NativeMaterial,'recheck',side_effect=AssertionError),patch.object(k.ctypes,'CDLL',side_effect=AssertionError),patch.object(subprocess,'Popen',side_effect=AssertionError):
   with self.assertRaises(Refused):MaterialExecutor(self.b,self.material)
   with self.assertRaises(Refused):NativePrimaryVerifier('fixture@example.invalid',self.b,self.material)
 def test_no_caller_preexec_profile_or_popen_options_constructor_authority(self):
  for ctor,args in ((MaterialExecutor,(self.b,self.material)),(NativePrimaryVerifier,('fixture@example.invalid',self.b,self.material))):
   for name,value in (('preexec_fn',lambda:None),('profile',{'PASS':True}),('env',{}),('options',{})):
    with self.assertRaises(TypeError):ctor(*args,**{name:value})
 def test_foreign_or_untyped_material_and_seal_budget_refuse(self):
  with self.assertRaises(Unavailable):MaterialExecutor(self.b,object())
  with self.assertRaises(Refused):NativePrimaryVerifier('fixture@example.invalid',self.b,object())
  foreign=OperationBudget(int(time.time())+8,maximum_seconds=8)
  def other(role,material,budget,account=None):return self.factory(role,material,foreign,account)
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(foreign,'inherited_group',return_value=True),patch.object(k.CommandKernelSeal,'_for_material',side_effect=other):
   with self.assertRaises(Unavailable):MaterialExecutor(self.b,self.material)
   with self.assertRaises(Refused):NativePrimaryVerifier('fixture@example.invalid',self.b,self.material)
 def test_material_recheck_spends_original_SQL_hash_and_primary_phase(self):
  clock=[100.0]
  def delayed(*args):clock[0]+=20
  with patch.object(self.b,'inherited_group',return_value=True),patch.object(k.CommandKernelSeal,'_for_material',side_effect=self.factory),patch.object(NativeMaterial,'recheck',side_effect=delayed),patch.object(time,'monotonic',side_effect=lambda:clock[0]),patch.object(subprocess,'Popen',side_effect=AssertionError('MUST_NOT_DISPATCH')) as dispatched:
   executor=MaterialExecutor(self.b,self.material)
   for program,args in ((A.SQL_PROGRAM,A.SQL_ARGS),(A.HASH_PROGRAM,A.HASH_ARGS)):
    with self.assertRaises(Unavailable):executor(program,args,b'PUBLIC\n',A.LIMIT_SECONDS,A.OUTPUT_LIMIT)
   primary=NativePrimaryVerifier('fixture@example.invalid',self.b,self.material)
   with self.assertRaises(Refused):primary('fixture@example.invalid','PUBLIC_PASSWORD')
   dispatched.assert_not_called()
 def test_only_kernel_component_contains_native_child_Popen(self):
  for name in ('authoritative_password.py','account_native_material.py','mutation_primary.py'):
   tree=ast.parse((S/name).read_text());self.assertFalse([n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='Popen'],name)
  source=(S/'account_mutation_native.py').read_text();self.assertIn('NativePrimaryVerifier(action.account,budget,self._material)',source)
 def test_private_fixture_seam_has_no_production_importer_or_caller_path(self):
  # The test-only compatibility shim is absent from the executable dependency
  # graph. Production constructors still accept no helper/profile/path hook.
  for path in S.glob('*.py'):
   if path.name.startswith('test_') or path.name.endswith('_fixture.py') or path.name=='native_transport_test_support.py':continue
   imports=[n for n in ast.walk(ast.parse(path.read_text())) if isinstance(n,(ast.Import,ast.ImportFrom))]
   self.assertFalse([n for n in imports if isinstance(n,ast.ImportFrom) and n.module=='native_transport_test_support' or isinstance(n,ast.Import) and any(a.name=='native_transport_test_support' for a in n.names)],path.name)
  for name in ('authoritative_password.py','mutation_primary.py','account_native_material.py','account_mutation_native.py','account_command_kernel.py'):
   self.assertNotIn('_private_test_only',(S/name).read_text())
 def test_real_owned_child_transports_preserve_results_stdin_output_cleanup_and_guard_order(self):
  code=(R/'owned_transport_fixture.py').read_text()
  observer=subprocess.Popen((sys.executable,'-I','-B','-c',code,str(S),str(R)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  try:
   out,err=observer.communicate(timeout=15);self.assertEqual(observer.returncode,0,err)
   self.assertEqual(out,b'PUBLIC_7_CHILDREN_REAPED_GUARDS_SEEN_KERNEL_CUSTODY_MOCKED\n')
   with self.assertRaises(ProcessLookupError):os.killpg(observer.pid,0)
  finally:
   if observer.returncode is None:observer.kill();observer.wait(timeout=2)
   observer.stdout.close();observer.stderr.close()
if __name__=='__main__':unittest.main(verbosity=2)
