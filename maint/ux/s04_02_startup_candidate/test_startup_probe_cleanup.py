"""Focused exact-child cleanup tests for the startup-only socket probe."""
import ast,base64,hashlib,importlib.util,json,signal,subprocess,time,unittest
from pathlib import Path
from unittest import mock

PATH=Path(__file__).resolve().parent/'startup_only.py'
SPEC=importlib.util.spec_from_file_location('tested_startup_only',PATH)
MODULE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(MODULE)


class Pipe:
    def __init__(self):self.closed=False
    def close(self):self.closed=True


class Child:
    def __init__(self,error=None,wait_errors=()):
        self.pid=424242;self.returncode=None;self.stdout=Pipe();self.stderr=Pipe();self.error=error;self.waited=False
        self.wait_errors=list(wait_errors)
    def communicate(self,timeout=None):
        if self.error is not None:raise self.error
        self.returncode=0
        return json.dumps({'connected_ms':1.0,'handled_ms':2.0}).encode(),b''
    def wait(self,timeout=None):
        self.waited=True
        if self.wait_errors:raise self.wait_errors.pop(0)
        if self.returncode is None:self.returncode=-signal.SIGTERM
        return self.returncode


class ProbeTests(unittest.TestCase):
    def test_stager_first_birth_receipt_uses_callable_identity(self):
        path=PATH.parent/'stage_root.py';tree=ast.parse(path.read_text())
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main')
        # Execute the actual target-identity assignment and first receipt
        # publication expression, with host/filesystem observations mocked.
        assignment=next(n for n in function.body if isinstance(n,ast.Assign)
            and isinstance(n.value,ast.Tuple))
        producer=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='produce_stage')
        publication=next(n for n in producer.body if isinstance(n,ast.Expr)
            and isinstance(n.value,ast.Call)and getattr(n.value.func,'id',None)=='publish')
        metadata=mock.Mock();backend=mock.MagicMock();backend.lstat.return_value=metadata
        spec=importlib.util.spec_from_file_location('tested_stage',path)
        stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
        called=[];scope=dict(stage.__dict__,backend=backend,p={'not_after_utc':123},raw=b'packet',
            identity=lambda value:called.append(value)or tuple(range(9)),publish=lambda *args:None)
        exec(compile(ast.Module(body=[assignment,publication],type_ignores=[]),str(path),'exec'),scope)
        self.assertEqual(called,[metadata])

    def test_complete_packet_and_wrapper_source_closure(self):
        def load(name):
            spec=importlib.util.spec_from_file_location('closure_'+name,PATH.parent/(name+'.py'))
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
        stage=load('stage_root');wrapper=load('remote_wrapper');packet=load('bind_startup').source_packet()
        self.assertEqual(set(packet['sources']),set(stage.SOURCE_PINS))
        for name,pin in stage.SOURCE_PINS.items():
            self.assertEqual(hashlib.sha256(base64.b64decode(packet['sources'][name],validate=True)).hexdigest(),pin,name)
        self.assertEqual(hashlib.sha256((PATH.parent/'stage_root.py').read_bytes()).hexdigest(),wrapper.ROOT_SOURCE_SHA256)

    def exercise(self,error=None,group_remains=False,wait_errors=(),kill_error=None,mask_restore_error=None):
        child=Child(error,wait_errors);signals=[];disposition={}
        def killpg(_pid,number):
            signals.append(number)
            if kill_error is not None and number!=0:raise kill_error
            if number==0:
                if group_remains:return
                raise ProcessLookupError
            child.returncode=-number
        mask_calls=0
        def sigmask(*_args):
            nonlocal mask_calls
            mask_calls+=1
            if mask_restore_error is not None and mask_calls==4:raise mask_restore_error
            return set()
        with mock.patch.object(MODULE.subprocess,'Popen',return_value=child), \
             mock.patch.object(MODULE.signal,'pthread_sigmask',side_effect=sigmask), \
             mock.patch.object(MODULE.os,'killpg',side_effect=killpg):
            if error is None and not group_remains:
                value=MODULE.probe(Path('/unused'),time.monotonic()+10,disposition)
                self.assertTrue(value['cleanup_confirmed'])
            elif group_remains:
                with self.assertRaises(MODULE.ProbeCleanupUnconfirmed):
                    MODULE.probe(Path('/unused'),time.monotonic()+10,disposition)
            elif isinstance(error,subprocess.TimeoutExpired):
                with self.assertRaisesRegex(MODULE.Refused,'^authorized_probe_timeout$'):
                    MODULE.probe(Path('/unused'),time.monotonic()+10,disposition)
            else:
                with self.assertRaises(type(error)):
                    MODULE.probe(Path('/unused'),time.monotonic()+10,disposition)
        self.assertIsNotNone(child.returncode)
        self.assertIn(0,signals)
        self.assertTrue(child.stdout.closed and child.stderr.closed)
        self.assertTrue(disposition['cleanup_confirmed'])
        return child,signals

    def test_success_reaps_and_proves_group_absent(self):
        child,signals=self.exercise();self.assertEqual(child.returncode,0);self.assertEqual(signals,[0])

    def test_non_timeout_error_terminates_reaps_and_proves_absence(self):
        child,signals=self.exercise(RuntimeError('injected'))
        self.assertTrue(child.waited);self.assertEqual(signals,[signal.SIGTERM,0])

    def test_actor_interrupt_terminates_reaps_and_proves_absence(self):
        child,signals=self.exercise(MODULE.Refused('actor_interrupted'))
        self.assertTrue(child.waited);self.assertEqual(signals,[signal.SIGTERM,0])

    def test_timeout_terminates_reaps_and_proves_absence(self):
        child,signals=self.exercise(subprocess.TimeoutExpired(('probe',),1))
        self.assertTrue(child.waited);self.assertEqual(signals,[signal.SIGTERM,0])

    def test_uncertain_group_blocks_confirmed_disposition(self):
        child=Child();disposition={}
        with mock.patch.object(MODULE.subprocess,'Popen',return_value=child), \
             mock.patch.object(MODULE.signal,'pthread_sigmask',return_value=set()), \
             mock.patch.object(MODULE.os,'killpg',return_value=None):
            with self.assertRaises(MODULE.ProbeCleanupUnconfirmed):
                MODULE.probe(Path('/unused'),time.monotonic()+10,disposition)
        self.assertFalse(disposition['cleanup_confirmed'])
        owner=type('Owner',(),{'setup_complete':True,'requests_stopped':True})()
        fixture=type('Fixture',(),dict(helper_stopped=True,sql_uncertain=False,process_uncertain=False,
            identity_uncertain=False,creation_uncertain=False))()
        self.assertFalse(MODULE.can_dispose(True,False,owner,fixture))
        self.assertTrue(MODULE.can_dispose(True,True,owner,fixture))

    def test_second_wait_timeout_is_durable_uncertainty(self):
        child=Child(RuntimeError('injected'),(subprocess.TimeoutExpired('wait',2),subprocess.TimeoutExpired('wait',2)))
        disposition={}
        def killpg(_pid,number):
            if number==0:raise ProcessLookupError
        with mock.patch.object(MODULE.subprocess,'Popen',return_value=child), \
             mock.patch.object(MODULE.signal,'pthread_sigmask',return_value=set()), \
             mock.patch.object(MODULE.os,'killpg',side_effect=killpg):
            with self.assertRaises(MODULE.ProbeCleanupUnconfirmed):
                MODULE.probe(Path('/unused'),time.monotonic()+10,disposition)
        self.assertFalse(disposition['cleanup_confirmed'])

    def test_kill_error_is_durable_uncertainty(self):
        child=Child(RuntimeError('injected'));disposition={}
        def killpg(_pid,number):
            if number==signal.SIGTERM:raise PermissionError('injected')
            if number==0:raise ProcessLookupError
        with mock.patch.object(MODULE.subprocess,'Popen',return_value=child), \
             mock.patch.object(MODULE.signal,'pthread_sigmask',return_value=set()), \
             mock.patch.object(MODULE.os,'killpg',side_effect=killpg):
            with self.assertRaises(MODULE.ProbeCleanupUnconfirmed):
                MODULE.probe(Path('/unused'),time.monotonic()+10,disposition)
        self.assertFalse(disposition['cleanup_confirmed'])

    def test_pending_interrupt_cannot_erase_uncertainty(self):
        child=Child(RuntimeError('injected'),(subprocess.TimeoutExpired('wait',2),subprocess.TimeoutExpired('wait',2)))
        disposition={};calls=0
        def sigmask(*_args):
            nonlocal calls
            calls+=1
            if calls==4:raise MODULE.Refused('actor_interrupted')
            return set()
        with mock.patch.object(MODULE.subprocess,'Popen',return_value=child), \
             mock.patch.object(MODULE.signal,'pthread_sigmask',side_effect=sigmask), \
             mock.patch.object(MODULE.os,'killpg',side_effect=lambda _pid,n: (_ for _ in ()).throw(ProcessLookupError()) if n==0 else None):
            with self.assertRaises(MODULE.Refused):
                MODULE.probe(Path('/unused'),time.monotonic()+10,disposition)
        self.assertFalse(disposition['cleanup_confirmed'])

    def test_authoritative_no_write_refuses_changed_state(self):
        good={'actual_write_observed':False,'Alice_exact15_preserved':True,'Alice_epoch':0,
            'Alice_state':'active','Bob_all17_preserved':True}
        self.assertFalse(MODULE.authoritative_no_write(good)['actual_write_observed'])
        for changed in ({**good,'actual_write_observed':True},{**good,'Alice_epoch':1},
            {**good,'Alice_state':'pending'},{**good,'Bob_all17_preserved':False}):
            with self.assertRaises(MODULE.Refused):MODULE.authoritative_no_write(changed)


if __name__=='__main__':unittest.main()
