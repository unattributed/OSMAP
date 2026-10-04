import json, os, pathlib, signal, subprocess, sys, tempfile, time, unittest
from unittest.mock import patch
from account_mutation_budget import LIMIT, envelope, verify_envelope, operation_budget
from account_mutation_worker import Unavailable
from authoritative_password import Refused
import test_account_mutation_worker as fixtures
frame, KEY, ACCOUNT = fixtures.frame, fixtures.KEY, fixtures.ACCOUNT

class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.h=fixtures.WorkerTests();self.h.setUp()
        # Only callback-based budget/journal semantics use synthetic metadata.
        # The separate owned-child sentinel test uses actual PID/PGID checks.
        self.scope=patch('os.getpgrp',return_value=os.getpid());self.scope.start()
    def tearDown(self): self.scope.stop();self.h.tearDown()
    def test_elapsed_budget_and_exact_v1_bytes(self):
        raw=frame();proof=verify_envelope(envelope(raw,KEY,1000000,1000500),KEY,1000200)
        self.assertEqual(proof.raw,raw);self.h.mono=10.15
        budget=operation_budget(proof,received_mono=10,received_millis=1000200,monotonic=self.h.monotonic,clock_millis=lambda:1000350)
        self.assertAlmostEqual(budget.remaining(),.15);self.h.mono=10.3
        with self.assertRaises(Refused):budget.remaining()
    def test_tamper_shape_and_expiry_zero_journal(self):
        raw=envelope(frame(),KEY,1000000,1000500)
        for field,value in [('account','bob@example.test'),('intent_reference','c'*64),('raw_sha256','d'*64),('request_signature','e'*64),('deadline_millis',1000600),('schema','other'),('request_hex','01'),('sent_millis',True)]:
            bad=json.loads(raw);bad[field]=value
            with self.assertRaises(Refused):verify_envelope(json.dumps(bad).encode(),KEY,1000100)
        for bad in [b'{"schema":"a","schema":"b"}',raw.decode().encode('utf-16'),b'x'*(LIMIT+1)]:
            with self.assertRaises(Refused):verify_envelope(bad,KEY,1000100)
        for at in [999999,1000500]:
            with self.assertRaises(Refused):verify_envelope(raw,KEY,at)
        self.assertEqual(self.h.record()['entries'],[])
    def test_budget_worker_keeps_reply_and_consumes_intent_once(self):
        raw=envelope(frame(),KEY,1000000,1000500)
        self.h.check_reply(self.h.worker().execute_budget(raw,clock_millis=lambda:1000000),'changed')
        with self.assertRaises(Unavailable):self.h.worker().execute_budget(raw,clock_millis=lambda:1000000)
        self.assertEqual(self.h.backend.writes,1)
    def test_primary_cannot_renew_original_budget(self):
        raw=envelope(frame(),KEY,1000000,1000500)
        def build(action,budget,authorize):
            result=self.h.build(action,budget,authorize)
            def primary(*args):self.h.mono+=.5;return True
            result.verify_current=primary;return result
        with self.assertRaises(Unavailable):self.h.worker(builder=build).execute_budget(raw,clock_millis=lambda:1000000)
        self.assertEqual(self.h.backend.writes,0)
    def test_postwrite_expiry_is_uncertain_and_contained(self):
        raw=envelope(frame(),KEY,1000000,1000500);original=self.h.backend.replace
        def replace(*args):result=original(*args);self.h.mono+=.5;return result
        self.h.backend.replace=replace
        with self.assertRaises(Unavailable):self.h.worker().execute_budget(raw,clock_millis=lambda:1000000)
        self.assertEqual(self.h.backend.writes,1)
        self.assertEqual(self.h.record()['entries'][0]['outcome'],{'status':'contained'})
        with self.assertRaises(Refused):self.h.store.admission(ACCOUNT)

class GroupTests(unittest.TestCase):
    def test_nested_containment_no_late_sentinel_after_outer_kill(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td);pidfile=root/'pid';sentinel=root/'late'
            script='import os,time,pathlib;pathlib.Path(%r).write_text(str(os.getpid()));time.sleep(.5);pathlib.Path(%r).write_text("owned synthetic late child");time.sleep(3)'%(str(pidfile),str(sentinel))
            outer='''import sys,time
from unittest.mock import patch
from operation_budget import OperationBudget
from mail_session_containment import MailSessionContainment,ContainmentExecutor
budget=OperationBudget(int(time.time())+300,maximum_seconds=2)
budget.attach_owned_process_group()
args=('-c',%r)
with patch.object(MailSessionContainment,'PROGRAM',sys.executable),patch.object(MailSessionContainment,'commands',return_value={'who':args}):
 ContainmentExecutor('alice@example.test',budget)(sys.executable,args,b'',2,4096)
'''%script
            process=subprocess.Popen([sys.executable,'-B','-c',outer],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,cwd=pathlib.Path(__file__).resolve().parent,env={'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C'});nested=None;handle=None;nested_group=None
            try:
                end=time.monotonic()+1
                while not pidfile.exists() and time.monotonic()<end:time.sleep(.005)
                self.assertTrue(pidfile.exists());nested=int(pidfile.read_text())
                # Capture a kernel identity before releasing/reaping the outer owner.
                # A recorded numeric PID must never authorize delayed cleanup.
                if hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'):
                    handle=os.pidfd_open(nested)
                nested_group=os.getpgid(nested)
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=1);time.sleep(.65)
                self.assertFalse(sentinel.exists(),'nested new-session child survived outer watchdog and performed late action')
                self.assertEqual(nested_group,process.pid)
            finally:
                # Popen.returncode changes only after wait; do not reap before a
                # group kill that relies on retained direct-child ownership.
                if process.returncode is None:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    process.wait(timeout=1)
                if handle is not None:
                    try:
                        # Passing inherited children were already group-killed.
                        # Only a failed escaped fixture needs identity-bound kill.
                        if nested_group != process.pid:
                            try:signal.pidfd_send_signal(handle,signal.SIGKILL)
                            except ProcessLookupError:pass
                    finally:os.close(handle)
                # Without pidfd there is no delayed numeric-PID fallback. The
                # public child fixture has a fixed 3.5-second natural lifetime.

    @unittest.skipUnless(hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'),
                         'kernel identity-bound escaped-fixture cleanup requires pidfd')
    def test_escaped_fixture_cleanup_is_identity_bound(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td);pidfile=root/'pid';sentinel=root/'late'
            child='import os,time,pathlib;pathlib.Path(%r).write_text(str(os.getpid()));time.sleep(.5);pathlib.Path(%r).write_text("late");time.sleep(3)'%(str(pidfile),str(sentinel))
            outer='import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",%r],start_new_session=True);time.sleep(2)'%child
            process=subprocess.Popen([sys.executable,'-B','-c',outer],start_new_session=True,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                env={'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C'})
            handle=None
            try:
                end=time.monotonic()+1
                while not pidfile.exists() and time.monotonic()<end:time.sleep(.005)
                self.assertTrue(pidfile.exists())
                nested=int(pidfile.read_text());handle=os.pidfd_open(nested)
                self.assertNotEqual(os.getpgid(nested),process.pid)
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=1)
                # This signal targets the captured process identity even after
                # the outer owner has been reaped; no numeric child kill exists.
                signal.pidfd_send_signal(handle,signal.SIGKILL);time.sleep(.65)
                self.assertFalse(sentinel.exists())
            finally:
                if process.returncode is None:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    process.wait(timeout=1)
                if handle is not None:
                    try:
                        try:signal.pidfd_send_signal(handle,signal.SIGKILL)
                        except ProcessLookupError:pass
                    finally:os.close(handle)
