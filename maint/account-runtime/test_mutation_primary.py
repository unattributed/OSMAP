"""Public synthetic source controls; no operator authentication/SQL changes."""
from pathlib import Path
import sys,time,unittest
import json,os,signal,subprocess,select
from unittest.mock import patch
from mutation_primary import PROGRAM,ARGS
from native_transport_test_support import PublicFixturePrimary as NativePrimaryVerifier
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
  with patch('subprocess.Popen',side_effect=AssertionError):
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

 def test_early_input_close_drains_owned_child_without_accepting_unwritten_password(self):
  for mode in ('failed','success','empty'):
   with self.subTest(mode=mode):
    v=self.verifier();real_write=os.write;real_read=os.read;observed={'broken':False,'stderr_bytes':0}
    body="import os;os.close(0);os.write(2,b'public early-close diagnostic');"
    if mode=='failed':body+="os.write(1,b'auth failed\\n');os._exit(77)"
    elif mode=='success':body+="os.write(1,b'auth succeeded\\nuser=alice@example.test\\n');os._exit(0)"
    else:body+="os._exit(1)"
    parent=os.getpid()
    def write(fd,data):
     if os.getpid()==parent and bytes(data)==(PUBLIC+'\n').encode():
      poll=select.poll();poll.register(fd,select.POLLERR)
      end=time.monotonic()+v._budget.remaining()
      while not poll.poll(5):self.assertLess(time.monotonic(),end)
      try:return real_write(fd,data)
      except BrokenPipeError:observed['broken']=True;raise
     return real_write(fd,data)
    def read(fd,size):
     raw=real_read(fd,size)
     if os.getpid()==parent and raw==b'public early-close diagnostic':observed['stderr_bytes']+=len(raw)
     return raw
    with patch.object(v._budget,'inherited_group',return_value=True),\
      patch.object(v,'_command',return_value=(sys.executable,'-I','-c',body)),\
      patch('mutation_primary.os.write',side_effect=write),patch('mutation_primary.os.read',side_effect=read):
     if mode=='failed':self.assertIs(v(ACCOUNT,PUBLIC),False)
     else:
      with self.assertRaises(Refused):v(ACCOUNT,PUBLIC)
    self.assertTrue(observed['broken']);self.assertEqual(observed['stderr_bytes'],len(b'public early-close diagnostic'))
    self.assertFalse(v._uncertain);self.assertEqual(v._retained,[])

 def test_typed_admission_seal_after_spawn_before_password_and_failure_reaps(self):
  import tempfile
  from account_epoch import EpochStore
  from test_account_admission_worker import projected_startup,AdmissionTests
  import account_command_kernel as kernel
  script=str(Path(__file__).with_name('mutation_primary_fixture.py'))
  for fail in (False,True):
   with self.subTest(native_seal_failure=fail),tempfile.TemporaryDirectory()as directory:
    root=Path(directory);root.chmod(0o700);store=EpochStore(root,os.geteuid())
    budget=AdmissionTests.original_budget();v=NativePrimaryVerifier(ACCOUNT,budget)
    children=[];writes=[];spawn=v._seal.spawn;write=os.write;parent=os.getpid()
    with projected_startup(root)as(startup,events,lib),patch.object(budget,'inherited_group',return_value=True):
     v._admission_seal=startup.bind(ACCOUNT,store,budget,v._material)
     lib.unveil.fail=fail
     def born(*args):
      child=spawn(*args);children.append(child);return child
     def controlled_write(fd,data):
      if os.getpid()==parent and bytes(data)==(PUBLIC+'\n').encode():
       self.assertEqual(events[-1],('pledge',(kernel._ADMISSION_FINAL,kernel._ADMISSION_FINAL)))
       self.assertEqual(len(children),1);writes.append(len(data))
      return write(fd,data)
     with patch.object(v,'_command',return_value=(sys.executable,'-I',script,'good')), \
          patch.object(v._seal,'spawn',side_effect=born),patch('mutation_primary.os.write',side_effect=controlled_write), \
          patch('account_command_kernel.os.getpgid',return_value=parent), \
          patch.object(v._admission_seal,'_observe_directories',wraps=v._admission_seal._observe_directories)as ancestors:
      if fail:
       with self.assertRaises(Refused):v(ACCOUNT,PUBLIC)
      else:self.assertIs(v(ACCOUNT,PUBLIC),True)
     self.assertEqual(ancestors.call_count,1)  # Preseal only; hidden path stats cannot follow lock.
     self.assertEqual(len(children),1);self.assertEqual(bool(writes),not fail)
     self.assertIsNotNone(children[0].returncode)
     self.assertTrue(all(p.closed for p in (children[0].stdin,children[0].stdout,children[0].stderr)))
     self.assertFalse(v._uncertain);self.assertEqual(v._retained,[])
     self.assertEqual(v._admission_seal._phase,'sealing'if fail else'sealed')
     if fail:
      with self.assertRaises(Refused):v._admission_seal.require_sealed(ACCOUNT,v._material,budget)
     else:v._admission_seal.require_sealed(ACCOUNT,v._material,budget)
     with self.assertRaises(Refused):v._admission_seal.check(ACCOUNT,v._material,budget)

if __name__=='__main__':unittest.main()
