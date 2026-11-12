"""Actual isolated stdio/process fixture tests, no native SQL/provider."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import tempfile
import unittest

from account_mutation_codec import ACTION, SCHEMA, encoded
from account_mutation_continuity import signed, verify
from test_guarded_mutation_worker import guarded
from test_account_mutation_worker import KEY, frame


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='osmap-real-worker-witness-',dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.witness_root=self.tmp.name
        Path(self.witness_root).chmod(0o700)

    def exchange(self, mode):
        path=Path(__file__).with_name('runtime_real_worker_fixture.py')
        child=subprocess.Popen((sys.executable,str(path)),stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
            close_fds=True,env={'PATH':'/usr/bin','LC_ALL':'C','OSMAP_TEST_REAL_WORKER_WITNESS_ROOT':self.witness_root})
        end=time.monotonic()+5
        raw=guarded(frame(current='public-old-value',new='public-new-passphrase',confirmation='public-new-passphrase'),deadline=1005000)
        if mode in ('proof','budget'):
            value=json.loads(raw)
            value['session_proof' if mode=='proof' else 'budget']['signature']='0'*64
            raw=encoded(value)
        def read_exact(n):
            out=bytearray()
            while len(out)<n:
                remaining=end-time.monotonic()
                if remaining<=0:raise TimeoutError
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout,selectors.EVENT_READ)
                    if not selector.select(remaining):raise TimeoutError
                part=os.read(child.stdout.fileno(),n-len(out))
                if not part:raise EOFError
                out.extend(part)
            return bytes(out)
        def read_frame():
            n=int.from_bytes(read_exact(4),'big')
            self.assertLessEqual(n,4096);self.assertGreater(n,0)
            return read_exact(n)
        reply=None;challenge=None
        try:
            child.stdin.write(len(raw).to_bytes(4,'big')+raw);child.stdin.flush()
            if mode in ('proof','budget'):
                child.stdin.close();child.stdin=None
            else:
                challenge=verify(read_frame(),KEY,'challenge')
                path=Path(self.witness_root)/'runtime-real-worker-witness.json'
                observed=json.loads(path.read_bytes())
                self.assertEqual(path.stat().st_mode&0o777,0o600)
                self.assertEqual(observed['stage'],'pending-before-challenge')
                self.assertTrue(observed['proof_and_budget_verified'])
                self.assertTrue(observed['pending_before_challenge'])
                self.assertEqual((observed['writer_calls'],observed['epoch_state'],observed['journal_state']),(0,'pending','pending'))
                ack=dict(challenge,phase='ack');ack.pop('signature')
                if mode=='nonce':ack['nonce']='0'*64
                payload=signed(ack,KEY)
                if mode=='ack_mac':
                    value=json.loads(payload);value['signature']='0'*64;payload=encoded(value)
                if mode=='eof':
                    child.stdin.close();child.stdin=None
                else:
                    child.stdin.write(len(payload).to_bytes(4,'big')+payload);child.stdin.flush()
                    child.stdin.close();child.stdin=None
                reply=json.loads(read_frame())
            remaining=end-time.monotonic()
            if remaining<=0:raise TimeoutError
            extra,stderr=child.communicate(timeout=remaining)
            self.assertEqual(extra,b'');self.assertLessEqual(len(stderr),1024)
            metrics=json.loads(stderr)
            retained=json.loads((Path(self.witness_root)/'runtime-real-worker-witness.json').read_bytes())
            self.assertEqual(retained,metrics)
            self.assertTrue(metrics['cleanup_confirmed'])
            self.assertNotIn('credential',stderr.decode())
            if reply:
                body=[SCHEMA,ACTION,'response',reply['account'],reply['intent_reference'],
                      reply['request_id'],reply['request_signature'],reply['responded_at'],reply['outcome']]
                self.assertEqual(reply['signature'],hmac.new(KEY,encoded(body),hashlib.sha256).hexdigest())
            return child.returncode,challenge,reply,metrics
        finally:
            # One exact unreaped direct child/group ownership only. Never signal
            # a recorded numeric PID after wait/communicate has reaped it.
            if child.returncode is None:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait(timeout=1)
            for pipe in (child.stdin,child.stdout,child.stderr):
                if pipe is not None:pipe.close()

    def early_refusal(self):
        path=Path(__file__).with_name('runtime_real_worker_fixture.py')
        child=subprocess.Popen((sys.executable,str(path)),stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
            close_fds=True,env={'PATH':'/usr/bin','LC_ALL':'C',
                'OSMAP_TEST_REAL_WORKER_WITNESS_ROOT':self.witness_root})
        try:
            stdout,stderr=child.communicate(b'',timeout=2)
            self.assertEqual(stdout,b'');self.assertLessEqual(len(stderr),1024)
            metrics=json.loads(stderr)
            self.assertEqual(metrics['writer_calls'],0)
            self.assertTrue(metrics['cleanup_confirmed'])
            self.assertNotEqual(child.returncode,0)
        finally:
            if child.returncode is None:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait(timeout=1)
            for pipe in (child.stdin,child.stdout,child.stderr):
                if pipe is not None:pipe.close()

    def test_preexisting_witness_refuses_without_overwriting(self):
        path=Path(self.witness_root)/'runtime-real-worker-witness.json'
        path.write_bytes(b'public previous evidence');path.chmod(0o600)
        self.early_refusal()
        self.assertEqual(path.read_bytes(),b'public previous evidence')

    def test_insecure_witness_namespace_refuses_before_frame_or_writer(self):
        Path(self.witness_root).chmod(0o755)
        try:self.early_refusal()
        finally:Path(self.witness_root).chmod(0o700)
        self.assertEqual(list(Path(self.witness_root).iterdir()),[])

    def test_actual_guarded_worker_pending_nonce_ack_single_changed_result(self):
        code,challenge,reply,metrics=self.exchange('good')
        self.assertEqual(code,0);self.assertIsNotNone(challenge)
        self.assertEqual(reply['outcome'],{'status':'changed','epoch':1,'changed_at':'20261004170000'})
        self.assertEqual(metrics['writer_calls'],1)
        self.assertTrue(metrics['pending_before_challenge'])
        self.assertEqual((metrics['epoch_state'],metrics['epoch'],metrics['journal_state']),('active',1,'complete'))

    def test_forged_independent_session_proof_never_claims_or_writes(self):
        code,challenge,reply,metrics=self.exchange('proof')
        self.assertEqual(code,1);self.assertIsNone(challenge);self.assertIsNone(reply)
        self.assertEqual((metrics['writer_calls'],metrics['reader_calls']), (0,0))
        self.assertFalse(metrics['pending_before_challenge'])
        self.assertEqual((metrics['epoch_state'],metrics['epoch'],metrics['journal_state']),('active',0,'empty'))

    def test_forged_budget_mac_never_claims_or_writes(self):
        code,_,_,metrics=self.exchange('budget')
        self.assertEqual(code,1);self.assertEqual(metrics['writer_calls'],0)
        self.assertFalse(metrics['pending_before_challenge'])
        self.assertEqual(metrics['journal_state'],'empty')

    def test_valid_mac_wrong_nonce_returns_contained_zero_writer(self):
        code,_,reply,metrics=self.exchange('nonce')
        self.assertEqual(code,0);self.assertEqual(reply['outcome'],{'status':'contained'})
        self.assertTrue(metrics['pending_before_challenge']);self.assertEqual(metrics['writer_calls'],0)
        self.assertEqual((metrics['epoch_state'],metrics['epoch'],metrics['journal_state']),('contained',0,'complete'))

    def test_forged_ack_mac_returns_contained_zero_writer(self):
        code,_,reply,metrics=self.exchange('ack_mac')
        self.assertEqual(code,0);self.assertEqual(reply['outcome'],{'status':'contained'})
        self.assertTrue(metrics['pending_before_challenge']);self.assertEqual(metrics['writer_calls'],0)
        self.assertEqual(metrics['epoch_state'],'contained')

    def test_issuer_eof_after_pending_returns_contained_zero_writer(self):
        code,_,reply,metrics=self.exchange('eof')
        self.assertEqual(code,0);self.assertEqual(reply['outcome'],{'status':'contained'})
        self.assertTrue(metrics['pending_before_challenge']);self.assertEqual(metrics['writer_calls'],0)
        self.assertEqual(metrics['epoch_state'],'contained')

if __name__=='__main__':unittest.main()
