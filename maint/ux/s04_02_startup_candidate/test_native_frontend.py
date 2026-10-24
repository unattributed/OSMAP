"""Real subprocess output through frontend, actor, frame parser and consumer.

Host fixture provisioning is a disposable local adapter; no mail/database or
native password operation runs. Guardian execution and diagnostic methods are
the source implementations, with the guardian test's explicit Linux adapters.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
def load(name,leaf):
    spec=importlib.util.spec_from_file_location(name,ROOT/leaf)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

front=load('fault_front','sources/backend/local_frontend.py')
guardian=load('fault_guardian','sources/frontend/native_http_web_guardian.py')
integration=load('fault_actor_integration','test_mutation_result.py')


def process_frontend(root,case):
    class ProcessFrontend(front.Frontend):
        def __init__(self,*args):
            with patch.object(front,'module',return_value=SimpleNamespace()):super().__init__(None)
            self.guard=guardian
            self.stage=root/'diagnostic-stage';self.stage.mkdir(mode=0o700)
        def setup(self,boot,*,confinement_probe=False):
            try:self.start()
            except BaseException as error:
                self.preserve_failure(error)
                raise
        def start(self):
            left,right=socket.socketpair()
            with patch.object(guardian,'root_peer',return_value=None),patch.object(guardian,
                    'socket_identity',side_effect=lambda s:guardian.identity(os.fstat(s.fileno()))[:6]):
                self.control=guardian.Control(left)
            # Control.current keeps real descriptor continuity; only root-peer
            # identity is inapplicable to the local uid test process.
            self.control.current=lambda:None
            env=dict(os.environ,OSMAP_TEST_HTTP_GUARDIAN_FD=str(right.fileno()))
            self.startup_operation='guardian_launch';self.control_status='OPEN'
            if case=='guardian_crash':
                argv=[sys.executable,'-c','import os,signal;os.kill(os.getpid(),signal.SIGABRT)']
            elif case=='guardian_quiet':
                argv=[sys.executable,'-c','import os;os.write(2,b"syntheticTokenSecret123");raise SystemExit(17)']
            else:argv=[sys.executable,str(ROOT/'test_native_diagnostics.py'),'--run-guardian',case,str(self.stage)]
            self.guardian=subprocess.Popen(argv,pass_fds=(right.fileno(),),start_new_session=True,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
            self.guardian_capture=guardian.Capture(self.guardian);right.close()
            self.startup_stage='GUARDIAN_BORN';self.startup_operation='custody_read'
            end=time.monotonic()+8
            self.control.write(b'{}',end)
            self.custody=front.decoded(self.control.read(2048,end))
            self.startup_stage='CUSTODY_RECEIVED';self.startup_operation='bootstrap_write'
            self.control.write(json.dumps({'version':1,'root':str(self.stage/'http/http-state')}).encode(),end)
            self.startup_stage='BOOTSTRAP_SENT';self.startup_operation='ready_read'
            self.ready=front.decoded(self.control.read(2048,end))
            raise RuntimeError('actual_native_ready')
        def group(self,allow_web=False,absolute=None):
            # Kernel-observed exact born guardian group, no arbitrary PID reuse.
            if os.getpgid(self.guardian.pid)!=self.guardian.pid:raise RuntimeError('local_group')
        def capture_generated_directories(self,*args,**kwargs):pass
        def dispose(self):
            if not self.requests_stopped:raise RuntimeError('producer_stop_required')
            # Actor's real checkpoint has already serialized and read back the
            # diagnostic before the only private source copy is removed.
            shutil.rmtree(self.stage);self.disposed=True
    return ProcessFrontend


class NativeFrontendTests(unittest.TestCase):
    def exercise(self,case,cleanup_failure=False,operation="password-change"):
        with tempfile.TemporaryDirectory()as name:
            root=Path(name)
            helper=hashlib.sha256(b'local disposable fixture').hexdigest()
            packet={'operation':operation,'source_commit':'2'*40,
                'compiler_receipt_sha256':'1'*64,'compiler_source_manifest_sha256':'1'*64,
                'helper':{'sha256':helper},'web':{'sha256':helper}}
            peer,states,phases,report,transport,packet=integration.MutationIntegration().run_actor(
                root,packet=packet,frontend_factory=process_frontend(root,case),cleanup_failure=cleanup_failure)
            self.assertEqual(peer.writes,0)
            self.assertEqual(report['mutation_requests'],0)
            self.assertEqual(report['functional_result'],'FAIL')
            result=integration.consumer.inspect(transport,1,123,packet)
            self.assertEqual(result['result'],'FAIL')
            self.assertNotIn('syntheticTokenSecret123',json.dumps(result))
            self.assertNotIn('SYNTHETIC_PASSWORD',json.dumps(result))
            self.assertNotIn('secret-token',json.dumps(result))
            diagnostic=result['native_diagnostic_evidence']['record']['native_diagnostic']
            self.assertTrue(diagnostic['guardian_reaped'])
            self.assertTrue(diagnostic['guardian_capture']['stderr_eof'])
            self.assertTrue(states['receipt'].path.exists())
            self.assertEqual((root/'diagnostic-stage').exists(),cleanup_failure)
            return result,diagnostic

    def test_confinement_probe_actual_guardian_failure_through_consumer(self):
        detail={'schema':'osmap-serve-confinement-v1','stage':'initial_pledge',
            'reason':'syscall_failed','syscall':'pledge','errno':22,'rule_ordinal':None}
        case='confinement:normal:'+json.dumps(detail,separators=(',',':'))
        result,diagnostic=self.exercise(case,operation='confinement-probe')
        self.assertEqual(result['operation'],'confinement-probe')
        self.assertEqual(result['confinement_detail'],detail)
        self.assertEqual(result['observed_http_requests'],0)
        self.assertFalse(result['start_message_sent']or result['ready_observed'])
        self.assertEqual(result['authoritative_state_certainty'],'CONFIRMED_NO_WRITE')
        self.assertTrue(result['cleanup_confirmed'])
        failed,_=self.exercise(case,cleanup_failure=True,operation='confinement-probe')
        self.assertEqual(failed['confinement_detail'],detail)
        self.assertFalse(failed['cleanup_confirmed'])

    def test_panic_survives_complete_actor_consumer_and_cleanup(self):
        result,diagnostic=self.exercise('panic')
        self.assertEqual(result['original_failure']['cause'],'native_admission_client')
        self.assertEqual(diagnostic['guardian_terminal'],1)
        self.assertEqual(diagnostic['guardian_diagnostic']['web_terminal'],101)
        self.assertTrue(diagnostic['guardian_diagnostic']['web_reaped'])
        self.assertTrue(result['cleanup_confirmed'])
        self.assertEqual(result['authoritative_state_certainty'],'CONFIRMED_NO_WRITE')

    def test_quiet_child_exit_cause_is_explicitly_unknown(self):
        result,diagnostic=self.exercise('quiet')
        self.assertEqual(result['original_failure']['cause'],'CAUSE_UNKNOWN')
        self.assertEqual(diagnostic['guardian_diagnostic']['web_terminal'],7)

    def test_guardian_abnormal_termination_retains_signal(self):
        result,diagnostic=self.exercise('guardian_crash')
        self.assertEqual(diagnostic['guardian_terminal'],-signal.SIGABRT)
        self.assertEqual(diagnostic['guardian_diagnostic_status'],'NOT_EMITTED')
        self.assertIsNotNone(result['diagnostic_deficiency'])

    def test_guardian_unstructured_secret_is_never_exported(self):
        result,diagnostic=self.exercise('guardian_quiet')
        self.assertEqual(diagnostic['guardian_terminal'],17)
        self.assertEqual(diagnostic['guardian_capture']['stderr_bytes'],23)
        self.assertEqual(result['diagnostic_completeness'],'INCOMPLETE')

    def test_cleanup_failure_keeps_original_panic_and_retains_sources(self):
        result,diagnostic=self.exercise('panic',cleanup_failure=True)
        self.assertEqual(result['original_failure']['cause'],'native_admission_client')
        self.assertFalse(result['cleanup_confirmed'])
        self.assertTrue(result['cleanup_failures'])

    def test_flood_capture_survives_actor_and_final_consumer(self):
        result,diagnostic=self.exercise('flood')
        self.assertEqual(result['original_failure']['cause'],'native_admission_client')
        self.assertTrue(diagnostic['guardian_diagnostic']['capture']['stderr_truncated'])


if __name__=='__main__':unittest.main()
