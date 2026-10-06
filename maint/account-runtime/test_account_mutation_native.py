"""Exact disabled native composition controls, no actual auth/SQL/provider."""
import os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from account_epoch import EpochStore
from account_mutation_worker import IntentStore,Unavailable
from account_mutation_supervisor import _Bootstrap,_Listener
from account_mutation_native import NativeDependencies,_legacy_authority_unavailable,EPOCH_ROOT,INTENT_ROOT
from account_mutation_codec import verify_request
from authoritative_password import Refused,NativeExecutor,AuthoritativePasswordAdapter
from mail_session_containment import MailSessionContainment,SmtpTerminationScope
from mutation_primary import NativePrimaryVerifier
from operation_budget import OperationBudget
import test_account_mutation_worker as f
import test_guarded_mutation_worker as g
from test_native_material import MaterialFixture
from account_native_material import MaterialExecutor
from native_transport_test_support import _construct

class NativeTests(MaterialFixture):
 def setUp(self):
  super().setUp();root=self.root
  epoch=root/'epoch';journal=root/'intent';epoch.mkdir(mode=0o700);journal.mkdir(mode=0o700)
  self.store=EpochStore(epoch,os.getuid());self.journal=IntentStore(journal,os.getuid())
  self.store.provision(f.ACCOUNT);self.journal.provision(f.ACCOUNT)
  self.bootstrap=_Bootstrap(f.KEY,g.SESSION_KEY,frozenset([f.ACCOUNT]),os.getuid())
  self.dependencies=NativeDependencies(self.bootstrap,self.journal,self.store,lambda:1000,material=self.load())
  self.action=verify_request(f.frame(),f.KEY,1000).action
 def test_native_factory_listener_and_child_refuse_before_any_file_store_or_program(self):
  with patch('account_mutation_native._Bootstrap.native',side_effect=AssertionError),\
   patch('account_mutation_native._fixed_material',side_effect=AssertionError),\
   patch('account_mutation_native.EpochStore',side_effect=AssertionError):
   with self.assertRaises(Unavailable):NativeDependencies.native()
   with self.assertRaises(Unavailable):_Listener.native()
   import account_mutation_entry
   with self.assertRaises(Unavailable):account_mutation_entry.main()
 def test_helper_owned_worker_binds_stores_keys_accounts_and_rejects_legacy_authority(self):
  w=self.dependencies.worker();self.assertIs(w._journal,self.journal)
  self.assertIs(w._epoch_store,self.store);self.assertEqual(w._key,f.KEY)
  self.assertEqual(w._session_key,g.SESSION_KEY)
  with self.assertRaises(Unavailable):w._session_authority(self.action,1000)
  self.assertEqual(EPOCH_ROOT,'/var/db/osmap-account/epoch')
  self.assertEqual(INTENT_ROOT,'/var/db/osmap-account/intents')
 def test_current_unqualified_smtp_factory_refuses_before_real_auth_or_sql(self):
  with patch.object(self.budget,'inherited_group',return_value=True),\
   patch('subprocess.Popen',side_effect=AssertionError):
   with self.assertRaises(Refused):self.dependencies._build(self.action,self.budget,lambda *a:False)
  self.assertEqual(self.store.admission(f.ACCOUNT),(0,None))
 def test_composed_writer_primary_containment_share_exact_original_budget(self):
  c=MailSessionContainment(f.ACCOUNT,lambda *a:(_ for _ in ()).throw(AssertionError),
   self.budget,SmtpTerminationScope.REQUIRED)
  authority=lambda a,t:False
  self.dependencies._material._private_test_only=True
  with patch.object(self.budget,'inherited_group',return_value=True),_construct(),\
   patch('account_mutation_native.build_native_containment',return_value=c):
   coordinator=self.dependencies._build(self.action,self.budget,authority)
  self.assertIs(coordinator.store,self.store);self.assertIs(coordinator.authorize_action,authority)
  self.assertIs(coordinator.clock,self.dependencies.clock)
  self.assertIs(type(coordinator.adapter),AuthoritativePasswordAdapter)
  self.assertIs(type(coordinator.adapter._execute),MaterialExecutor)
  self.assertIs(coordinator.adapter._execute._budget,self.budget)
  self.assertIs(type(coordinator.verify_current),NativePrimaryVerifier)
  self.assertIs(coordinator.verify_current,coordinator.verify_changed)
  self.assertIs(coordinator.verify_current._budget,self.budget)
  self.assertIs(coordinator.containment_ready.__self__,c)
  with patch('subprocess.Popen',side_effect=AssertionError):
   with self.assertRaises(Refused):coordinator.change(self.action)
  self.assertEqual(self.store.admission(f.ACCOUNT),(0,None))
 def test_missing_owned_group_or_foreign_action_refuses_before_dependency_build(self):
  with patch('account_mutation_native.MaterialExecutor',side_effect=AssertionError),\
   patch.object(self.budget,'inherited_group',return_value=False):
   with self.assertRaises(Unavailable):self.dependencies._build(self.action,self.budget,lambda *a:False)
   foreign=verify_request(f.frame(account='bob@example.test'),f.KEY,1000).action
   with self.assertRaises(Unavailable):self.dependencies._build(foreign,self.budget,lambda *a:False)
 def test_missing_material_and_caller_report_refuse_before_dependency_construction(self):
  absent=NativeDependencies(self.bootstrap,self.journal,self.store,lambda:1000)
  with patch('account_mutation_native.MaterialExecutor',side_effect=AssertionError):
   with self.assertRaises(Unavailable):absent._build(self.action,self.budget,lambda *a:False)
  with self.assertRaises(Unavailable):NativeDependencies(self.bootstrap,self.journal,self.store,material={'PASS':True})

if __name__=='__main__':unittest.main()
