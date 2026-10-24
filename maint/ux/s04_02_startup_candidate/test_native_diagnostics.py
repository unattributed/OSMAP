"""Real disposable process regressions for native startup diagnostic custody.

--run-guardian CASE STAGE runs the actual guardian main with only fixed OpenBSD
host/privilege/copy seams replaced. Control sockets, pipes, collection, protocol,
persistence, direct-child signaling and reap execute unchanged on this host.
"""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SOURCE = HERE/'sources/frontend/native_http_web_guardian.py'
SPEC = importlib.util.spec_from_file_location('diagnostic_guardian', SOURCE)
GUARDIAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARDIAN)

CHILD = r'''
import json,os,signal,socket,sys,time
s=socket.socket(fileno=int(os.environ['CHILD_CONTROL_FD']))
def read():
    def exact(n):
        data=b''
        while len(data)<n:
            part=s.recv(n-len(data))
            if not part:sys.exit(91)
            data+=part
        return data
    return exact(int.from_bytes(exact(4),'big'))
def write(value):
    raw=json.dumps(value,separators=(',',':')).encode()
    s.sendall(len(raw).to_bytes(4,'big')+raw)
read()
case=sys.argv[1]
if case in ('panic','partial','flood'):
    raw=b"thread 'http-test' panicked at src/http/password_tests.rs:1247:10:\nHTTP fixture admission custody refused: SYNTHETIC_PASSWORD=secret-token\n"
    if case=='flood':
        for _ in range(128):
            os.write(1,b'O'*65536);os.write(2,b'E'*65536)
        os.write(2,b'\n')
    if case=='partial':
        for byte in raw:os.write(2,bytes([byte]))
    else:os.write(2,raw)
    sys.exit(101)
if case in ('quiet','cleanup_failure'):sys.exit(7)
if case=='selector':
    os.write(1,b'\nrunning 0 tests\n');sys.exit(0)
if case=='signal':os.kill(os.getpid(),signal.SIGABRT)
if case=='interrupted':
    os.write(2,b'private partial startup output')
    time.sleep(20)
if case=='unknown':
    os.write(2,b'SYNTHETIC_PASSWORD=private unknown cause\n');sys.exit(9)
write({'schema':'osmap-http-password-ready-v1','port':12345,'connections':18,'totp_counter':1})
if read()!=b'G':sys.exit(92)
write({'schema':'osmap-http-password-runtime-v1','handled_connections':18,'elapsed_millis':1,
       'alice_epoch0_refused':True,'alice_epoch1_admitted':1,'bob_epoch0_admitted':0})
'''


def run_guardian(case, stage):
    """Subprocess entry; emits only real guardian-produced safe diagnostics."""
    module = GUARDIAN
    module.STAGE = Path(stage)
    http = module.STAGE/'http'
    http.mkdir(exist_ok=True)
    code = http/'web-code'
    code.mkdir(exist_ok=True)
    binary = code/'qualified-libtest'
    binary.write_bytes(b'local disposable fixture')
    module.END = time.monotonic()+20
    module.SETUP = time.monotonic()+5
    build = {'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
             'source_manifest_sha256':'a'*64}
    def launch(_binary, control_fd, _proof, _guardian, _group):
        if case=='launch_failure':
            return subprocess.Popen([str(module.STAGE/'missing-executable')],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if case=='permission_failure':
            return subprocess.Popen([str(binary)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        env = dict(os.environ, CHILD_CONTROL_FD=str(control_fd))
        return subprocess.Popen([sys.executable,'-c',CHILD,case], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(control_fd,),env=env)
    with contextlib.ExitStack() as stack:
        for name, replacement in {
            'guardian_identity':lambda:None,
            'exact_directory':lambda path,*_:module.identity(path.lstat()),
            'namespace':lambda _:http,
            'role':lambda:None,
            'build_record':lambda:build,
            'copy_binary':lambda *_:(code,binary,module.identity(code.lstat()),module.identity(binary.lstat())),
            'drop_receipt':lambda *_:None,
            'root_peer':lambda _:None,
            'socket_identity':lambda stream:module.identity(os.fstat(stream.fileno()))[:6],
            'launch':launch,
        }.items():
            stack.enter_context(mock.patch.object(module,name,replacement))
        if case=='initialization_failure':
            stack.enter_context(mock.patch.object(module,'guardian_identity',side_effect=module.Refused('root_born_guardian')))
        if case=='identity_failure':
            stack.enter_context(mock.patch.object(module,'drop_receipt',side_effect=module.Refused('drop_proof')))
        if case=='cleanup_failure':
            original=module.DiagnosticFile.write
            calls=[0]
            def failed_final(self,report):
                calls[0]+=1
                if calls[0]>1:raise OSError('synthetic private failure')
                return original(self,report)
            stack.enter_context(mock.patch.object(module.DiagnosticFile,'write',failed_final))
        return module.main()


def exercise(case):
    """Real parent -> guardian -> child; returns safe retained evidence only."""
    with tempfile.TemporaryDirectory(prefix='osmap-pxp-stage-',dir='/tmp') as temporary:
        # Production stage shape remains enforced, rename our exclusive scratch.
        stage=Path(temporary)/('osmap-pxp-stage-'+'1'*16)
        stage.mkdir()
        left,right=socket.socketpair()
        env=dict(os.environ,OSMAP_TEST_HTTP_GUARDIAN_FD=str(right.fileno()))
        process=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--run-guardian',case,str(stage)],
            pass_fds=(right.fileno(),),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        right.close()
        def send(raw):left.sendall(len(raw).to_bytes(4,'big')+raw)
        def recv():
            def exact(n):
                raw=b''
                while len(raw)<n:
                    try:part=left.recv(n-len(raw))
                    except ConnectionResetError:return None
                    if not part:return None
                    raw+=part
                return raw
            size=exact(4)
            return None if size is None else exact(int.from_bytes(size,'big'))
        try:
            left.settimeout(6)
            send(b'{}')
            custody=recv()
            if custody is not None:
                send(json.dumps({'version':1,'root':str(stage/'http/http-state')}).encode())
            if case=='interrupted':
                time.sleep(.1)
                process.send_signal(signal.SIGTERM)
                left.shutdown(socket.SHUT_RDWR)
            ready=recv() if case!='interrupted' else None
            if ready is not None:
                send(b'G')
                recv()
                if recv()==b'WEB_DIRECT_REAPED':send(b'GROUP_ONLY_GUARDIAN')
                recv()
            stdout,stderr=process.communicate(timeout=9)
            if process.returncode==0:return {'returncode':0,'stdout_bytes':len(stdout),'stderr_bytes':len(stderr)}
            report=GUARDIAN.validate_diagnostic(json.loads(stderr))
            final=stage/'native-http-diagnostic.json'
            retained_path=final if final.exists() else stage/'native-http-diagnostic-before-stop.json'
            retained=json.loads(retained_path.read_bytes()) if retained_path.exists() else None
            return {'returncode':process.returncode,'report':report,'retained':retained}
        finally:
            left.close()
            if process.returncode is None:
                process.kill();process.wait(timeout=2)


class NativeDiagnosticTests(unittest.TestCase):
    def test_initialization_launch_and_identity_failure_boundaries(self):
        for case,stage,operation,code in (
            ('initialization_failure','initializing','initialize','root_born_guardian'),
            ('launch_failure','binary_verified','launch','exception_file_not_found'),
            ('permission_failure','binary_verified','launch','exception_permission'),
            ('identity_failure','child_born','identity','drop_proof'),
        ):
            with self.subTest(case=case):
                report=exercise(case)['report']
                self.assertEqual((report['stage'],report['operation'],report['code']),
                                 (stage,operation,code))
                if case=='identity_failure':
                    self.assertTrue(report['web_reaped'])
                    self.assertTrue(report['cleanup']['kill_sent'])
                else:self.assertIsNone(report['capture'])

    def test_every_native_code_has_source_literal_and_real_pipe_producer(self):
        rust=(HERE.parents[2]/'src/http/password_tests.rs').read_bytes()
        for message,code in GUARDIAN.NATIVE_MESSAGES.items():
            with self.subTest(code=code):
                self.assertIn(b'"'+message+b'"',rust)
                payload=b"thread 'fixture' panicked at src/http/password_tests.rs:1:1:\n"+message+b': private secret\n'
                process=subprocess.Popen([sys.executable,'-c',
                    'import os,sys;os.write(2,bytes.fromhex(sys.argv[1]));sys.exit(101)',payload.hex()],
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                capture=GUARDIAN.Capture(process)
                process.wait(timeout=2)
                result=capture.finish(time.monotonic()+1)
                self.assertEqual(result['native_code'],code)
                self.assertEqual(result['stderr_sha256'],hashlib.sha256(payload).hexdigest())
                self.assertNotIn('private secret',json.dumps(result))

    def test_pre_ready_panic_retained_after_reap(self):
        result=exercise('panic');report=result['report']
        self.assertEqual(report,result['retained'])
        self.assertEqual(report['stage'],'bootstrap_sent')
        self.assertEqual(report['operation'],'ready_read')
        self.assertEqual(report['cause'],'native_admission_client')
        self.assertEqual(report['web_terminal'],101)
        self.assertTrue(report['web_reaped'])
        self.assertEqual(report['cleanup']['status'],'PASS')
        self.assertNotIn('SYNTHETIC_PASSWORD',json.dumps(result))
        self.assertNotIn('secret-token',json.dumps(result))

    def test_missing_entrypoint_is_observed(self):
        report=exercise('selector')['report']
        self.assertEqual(report['cause'],'native_entrypoint_not_selected')
        self.assertEqual(report['web_terminal'],0)

    def test_quiet_exit_has_unknown_cause(self):
        report=exercise('quiet')['report']
        self.assertEqual(report['web_terminal'],7)
        self.assertEqual(report['cause'],'CAUSE_UNKNOWN')
        self.assertEqual(report['control_status'],'eof')
        self.assertEqual(report['capture']['stderr_bytes'],0)

    def test_unknown_output_never_exported(self):
        report=exercise('unknown')['report']
        self.assertEqual(report['cause'],'CAUSE_UNKNOWN')
        self.assertGreater(report['capture']['stderr_bytes'],0)
        self.assertNotIn('SYNTHETIC_PASSWORD',json.dumps(report))

    def test_oversized_both_pipes_do_not_block_and_late_code_survives(self):
        report=exercise('flood')['report'];capture=report['capture']
        self.assertEqual(report['cause'],'native_admission_client')
        for name in ('stdout','stderr'):
            self.assertTrue(capture[name+'_truncated'])
            self.assertEqual(capture[name+'_stored_bytes'],GUARDIAN.OUTPUT_LIMIT)
            self.assertGreaterEqual(capture[name+'_bytes'],8*1024*1024)
            self.assertTrue(capture[name+'_eof'])

    def test_partial_native_lines(self):
        self.assertEqual(exercise('partial')['report']['cause'],'native_admission_client')

    def test_signal_termination(self):
        report=exercise('signal')['report']
        self.assertEqual(report['web_terminal'],-signal.SIGABRT)
        self.assertTrue(report['web_reaped'])
        self.assertEqual(report['cause'],'CAUSE_UNKNOWN')

    def test_interruption_preserves_original_and_cleanup(self):
        report=exercise('interrupted')['report']
        self.assertIn(report['code'],('control_eof','cancelled'))
        self.assertEqual(report['cleanup']['status'],'PASS')
        self.assertTrue(report['cleanup']['kill_sent'])
        self.assertTrue(report['web_reaped'])
        self.assertGreater(report['capture']['stderr_bytes'],0)

    def test_cleanup_error_never_overwrites_original(self):
        report=exercise('cleanup_failure')['report']
        self.assertEqual(report['code'],'control_eof')
        self.assertEqual(report['cleanup']['status'],'UNKNOWN')
        self.assertEqual(report['cleanup']['code'],'exception_os')

    def test_normal_ready_report_protocol(self):
        self.assertEqual(exercise('success'),{'returncode':0,'stdout_bytes':0,'stderr_bytes':0})

    def test_malformed_schema_is_closed(self):
        report=exercise('quiet')['report']
        missing=dict(report,capture=None,cause='native_confinement')
        with self.assertRaises(GUARDIAN.Refused):GUARDIAN.validate_diagnostic(missing)
        for key in ('code','stage','operation','cause'):
            bad=dict(report);bad[key]=['secret']
            with self.assertRaises(GUARDIAN.Refused):GUARDIAN.validate_diagnostic(bad)

    def test_continuous_capture_without_final_drain(self):
        process=subprocess.Popen([sys.executable,'-c',"import os,time;os.write(2,b'before READY');time.sleep(.25)"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        capture=GUARDIAN.Capture(process)
        try:
            time.sleep(.1)
            self.assertEqual(capture.snapshot()['stderr_bytes'],12)
            process.wait(timeout=2)
            observed=capture.finish(time.monotonic()+1)
            self.assertEqual(observed['stderr_sha256'],hashlib.sha256(b'before READY').hexdigest())
        finally:
            if process.returncode is None:process.kill();process.wait(timeout=2)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--run-guardian':
        # Fixed path shape is checked by main; local nested scratch is relocated
        # only through this test seam, never exposed by a production switch.
        with mock.patch.object(GUARDIAN,'require',side_effect=lambda value,code: None if value or code=='root_stage_name' else (_ for _ in ()).throw(GUARDIAN.Refused(code))):
            raise SystemExit(run_guardian(sys.argv[2],sys.argv[3]))
    unittest.main()
