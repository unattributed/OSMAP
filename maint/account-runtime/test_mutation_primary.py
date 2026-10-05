"""Public synthetic source controls; no operator authentication/SQL changes."""
from pathlib import Path
import sys,time,unittest
import json,os,signal,subprocess
from unittest.mock import patch
from mutation_primary import NativePrimaryVerifier,PROGRAM,ARGS
from operation_budget import OperationBudget
from authoritative_password import Refused
ACCOUNT='alice@example.test';PUBLIC='public synthetic password'

class PrimaryTests(unittest.TestCase):
 def verifier(self,seconds=1):
  return NativePrimaryVerifier(ACCOUNT,OperationBudget(int(time.time())+300,maximum_seconds=seconds))
 def run_fixture(self,mode,seconds=1):
  v=self.verifier(seconds);script=str(Path(__file__).with_name('mutation_primary_fixture.py'))
  # This test process is not a supervised worker group; inherited-group proof
  # is provided by separately retained actual supervised process tests.
  with patch.object(v._budget,'inherited_group',return_value=True),\
    patch.object(v,'_command',return_value=(sys.executable,'-I',script,mode)):
   return v,v(ACCOUNT,PUBLIC)
 def test_fixed_program_exact_account_and_password_stdin_only(self):
  v=self.verifier();self.assertEqual(v._command(),(PROGRAM,)+ARGS+(ACCOUNT,))
  self.assertNotIn(PUBLIC,repr(v));self.assertEqual(self.run_fixture('good')[1],True)
 def test_exact_negative_and_ambiguous_foreign_output_classification(self):
  self.assertEqual(self.run_fixture('failed')[1],False)
  for mode in ('foreign','conflict','huge'):
   with self.subTest(mode=mode),self.assertRaises(Refused):self.run_fixture(mode)
 def test_missing_group_wrong_account_unbounded_input_never_spawns(self):
  v=self.verifier()
  with patch('mutation_primary.subprocess.Popen',side_effect=AssertionError):
   for account,password in [(ACCOUNT,PUBLIC),('bob@example.test',PUBLIC),
      (ACCOUNT,'bad\npassword'),(ACCOUNT,'x'*1025),(ACCOUNT,'\ud800')]:
    with self.subTest(account=account,length=len(password)),self.assertRaises(Refused):v(account,password)
 def test_original_budget_timeout_is_not_renewed_by_primary_phase(self):
  began=time.monotonic()
  with self.assertRaises(Refused):self.run_fixture('wait',.2)
  self.assertLess(time.monotonic()-began,.45)
 def test_actual_owned_worker_inherited_primary_group_and_bounded_cleanup(self):
  script=str(Path(__file__).with_name('mutation_primary_group_fixture.py'))
  for mode in ('ownership','wait'):
   child=subprocess.Popen((sys.executable,'-I',script,mode),stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
   try:
    out,error=child.communicate(timeout=2)
   except BaseException:
    # No numeric signal after a reaped Popen child. On timeout this child remains
    # owned and unreaped; kill the group once before waiting, never by stale PID.
    if child.returncode is None:
     try:os.killpg(child.pid,signal.SIGKILL)
     except ProcessLookupError:pass
     child.wait(timeout=1)
    raise
   self.assertEqual(child.returncode,0);self.assertEqual(error,b'')
   v=json.loads(out);self.assertTrue(v['owned_group']);self.assertTrue(v['bounded'])
   self.assertFalse(v['cleanup_uncertain']);self.assertEqual(v['accepted'],mode=='ownership')
   self.assertEqual(v['refused'],mode=='wait')
 def test_original_clock_expiry_after_native_receipt_refuses_success(self):
  clock=[1000.];v=NativePrimaryVerifier(ACCOUNT,OperationBudget(1300,wall=lambda:clock[0]))
  script=str(Path(__file__).with_name('mutation_primary_fixture.py'));original=v._result
  def result(*args):
   value=original(*args);clock[0]=1300.;return value
  with patch.object(v._budget,'inherited_group',return_value=True),\
   patch.object(v,'_command',return_value=(sys.executable,'-I',script,'good')),\
   patch.object(v,'_result',side_effect=result):
   with self.assertRaises(Refused):v(ACCOUNT,PUBLIC)

if __name__=='__main__':unittest.main()
