"""Actual source role-bound mint composition; local profiles never qualify host."""
import os,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parent;S=R/'source' if (R/'source/account_command_kernel.py').is_file() else R;sys.path.insert(0,str(S))
import account_command_kernel as k,account_hash_graph as g
from operation_budget import OperationBudget
from authoritative_password import AuthoritativePasswordAdapter as A,Refused
from account_native_material import NativeMaterial,_SqlEndpoint
class BoundMintTests(unittest.TestCase):
 def setUp(self):
  self.b=self.budget();self.material=object.__new__(NativeMaterial);self.material._endpoint=_SqlEndpoint(Path('/tmp/public-fixture.sock'),os.getuid());self.material._states=((),(),(),())
 def budget(self):
  millis=int(time.time()*1000);mono=time.monotonic()
  return OperationBudget.from_original_deadline((millis+60000)//1000,received_mono=mono,received_millis=millis,sent_millis=millis,deadline_millis=millis+10000,wall_millis=lambda:int(time.time()*1000))
 def context(self):return patch.object(k,'_PROFILES',('hash',))
 def test_empty_profiles_preserve_public_refusal_before_reads_or_native_helpers(self):
  self.assertEqual(k._PROFILES,())
  with patch.object(k.ctypes,'CDLL',side_effect=AssertionError),patch('os.open',side_effect=AssertionError),patch.object(g.HashInstalledGraph,'native',side_effect=AssertionError):
   for call in (lambda:k.CommandKernelSeal.native(),lambda:k.CommandKernelSeal.native('hash',self.material,self.b),lambda:k.CommandKernelSeal._for_material('hash',self.material,self.b)):
    with patch.object(self.b,'inherited_group',return_value=True),self.assertRaisesRegex(Refused,'graph unavailable'):call()
 def test_actual_producer_exact_material_role_budget_rows_and_both_obligations(self):
  with self.context(),patch.object(self.b,'inherited_group',return_value=True),patch.object(k.CommandKernelSeal,'_fixture',side_effect=AssertionError('private fixture must not mint production')),patch.object(k.CommandKernelSeal,'_hash_candidate',side_effect=AssertionError('candidate must not mint production')):
   value=k.CommandKernelSeal._for_material('hash',self.material,self.b)
  self.assertIs(value._material,self.material);self.assertIs(value._budget,self.b);self.assertEqual(value._command_identity,(A.HASH_PROGRAM,A.HASH_ARGS,None,'hash'));self.assertEqual(value._rows,g.HashInstalledGraph.rows());self.assertEqual(value._promises,g.PROMISES);self.assertTrue(value._hash_identity_required and value._hash_graph_required)
 def test_wrong_role_account_untyped_material_and_missing_custody_refuse(self):
  with self.context(),patch.object(self.b,'inherited_group',return_value=True):
   for role,material,budget,account in (('sql',self.material,self.b,None),('primary',self.material,self.b,'fixture@example.invalid'),('hash',self.material,self.b,'foreign@example.invalid'),('hash',object(),self.b,None),('hash',object.__new__(NativeMaterial),self.b,None),('hash',self.material,object(),None)):
    with self.assertRaises(Refused):k.CommandKernelSeal.native(role,material,budget,account)
 def test_generic_equal_expiry_and_changed_original_budget_receipt_refuse(self):
  generic=OperationBudget(int(self.b._expires)+1,maximum_seconds=10);generic._expires=self.b._expires;generic._deadline=self.b._deadline
  with self.context(),patch.object(self.b,'inherited_group',return_value=True),patch.object(generic,'inherited_group',return_value=True):
   with self.assertRaises(Refused):k.CommandKernelSeal._for_material('hash',self.material,generic)
   self.b._deadline+=.001
   with self.assertRaises(Refused):k.CommandKernelSeal._for_material('hash',self.material,self.b)
 def test_cross_material_foreign_budget_role_account_returned_seals_refuse(self):
  with self.context(),patch.object(self.b,'inherited_group',return_value=True):seal=k.CommandKernelSeal.native('hash',self.material,self.b)
  other=self.budget();foreign=object.__new__(NativeMaterial)
  for field,bad in (('_material',foreign),('_budget',other),('_command_identity',(A.SQL_PROGRAM,A.SQL_ARGS,None,'sql')),('_command_identity',(A.HASH_PROGRAM,A.HASH_ARGS,'foreign@example.invalid','hash'))):
   original=getattr(seal,field);setattr(seal,field,bad)
   with patch.object(self.b,'inherited_group',return_value=True),patch.object(k.CommandKernelSeal,'native',return_value=seal):
    with self.assertRaises(Refused):k.CommandKernelSeal._for_material('hash',self.material,self.b)
   setattr(seal,field,original)
 def test_sql_primary_source_profiles_and_caller_rows_promises_options_remain_closed(self):
  with patch.object(k,'_PROFILES',('sql','hash','primary')),patch.object(self.b,'inherited_group',return_value=True):
   for role in ('sql','hash','primary'):
    with self.assertRaises(Refused):k.CommandKernelSeal.native(role,self.material,self.b)
  for kwargs in ({'rows':(('/tmp',b'r'),)},{'promises':b'stdio'},{'profile':{'qualified':True}},{'preexec_fn':lambda:None}):
   with self.assertRaises(TypeError):k.CommandKernelSeal.native('hash',self.material,self.b,**kwargs)
 def test_no_deadline_receipt_reset_or_operator_read_in_mint(self):
  before=(self.b._original_receipt,self.b._deadline,self.b._expires)
  with self.context(),patch.object(self.b,'inherited_group',return_value=True),patch('os.open',side_effect=AssertionError),patch.object(k.subprocess,'Popen',side_effect=AssertionError):k.CommandKernelSeal._for_material('hash',self.material,self.b)
  self.assertEqual(before,(self.b._original_receipt,self.b._deadline,self.b._expires))
 def test_actual_MaterialExecutor_constructor_rejects_generic_and_foreign_budget(self):
  from account_native_material import MaterialExecutor,Unavailable
  original_native=k.CommandKernelSeal.native;foreign=self.budget()
  generic=OperationBudget(int(self.b._expires)+1,maximum_seconds=10);generic._expires=self.b._expires;generic._deadline=self.b._deadline
  selected=[None]
  def native(role,material,budget,account=None):
   if role=='sql':
    value=k.CommandKernelSeal._fixture(A.SQL_PROGRAM,A.SQL_ARGS,None,budget,((A.SQL_PROGRAM,b'rx'),),b'stdio rpath exec');value._material=material;return value
   return original_native(role,material,selected[0] or budget,account)
  with self.context(),patch.object(self.b,'inherited_group',return_value=True),patch.object(generic,'inherited_group',return_value=True),patch.object(foreign,'inherited_group',return_value=True),patch.object(k.CommandKernelSeal,'native',side_effect=native),patch.object(NativeMaterial,'recheck',side_effect=AssertionError('no dispatch')),patch.object(k.subprocess,'Popen',side_effect=AssertionError('no child')):
   with self.assertRaises(Refused):MaterialExecutor(generic,self.material)
   selected[0]=foreign
   with self.assertRaises(Refused):MaterialExecutor(self.b,self.material)
   with self.assertRaises(Unavailable):MaterialExecutor(self.b,object())
   with self.assertRaises(TypeError):MaterialExecutor(self.b,self.material,account='foreign@example.invalid')
 def test_actual_MaterialExecutor_owned_child_transport_and_closed_cleanup(self):
  code=(R/'owned_role_mint.py').read_text();child=subprocess.Popen((sys.executable,'-I','-B','-c',code,str(S)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  try:
   out,err=child.communicate(timeout=15);self.assertEqual(child.returncode,0,err);self.assertEqual(out,b'PUBLIC_ROLE_BOUND_MINT_MATERIAL_TRANSPORT_2_CHILDREN_REAPED_KERNEL_ID_SQL_MOCKED\n')
   with self.assertRaises(ProcessLookupError):os.killpg(child.pid,0)
  finally:
   if child.returncode is None:child.kill();child.wait(timeout=2)
   child.stdout.close();child.stderr.close()
if __name__=='__main__':unittest.main(verbosity=2)
