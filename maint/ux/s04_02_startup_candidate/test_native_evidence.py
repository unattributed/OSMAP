"""Protected receipt/readback and strict consumer regressions; no native mutation."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
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

actor=load('evidence_actor','sources/backend/local_journey.py')
consumer=load('evidence_consumer','consume_startup.py')
installer=load('evidence_installer','sources/backend/install_account_password.py')
frontend=load('evidence_frontend','sources/backend/local_frontend.py')


def captured_guardian_frame(guardian,report,objects=False):
    """Replay a real sanitized guardian frame through actual pipe collection."""
    process=subprocess.Popen([sys.executable,'-c',
        'import os,sys;os.write(2,sys.stdin.buffer.read());sys.exit(1)'],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    capture=guardian.Capture(process)
    try:
        process.stdin.write((json.dumps(report,separators=(',',':'))+'\n').encode())
        process.stdin.close();process.wait(timeout=3)
        value=capture.finish(time.monotonic()+2)
        if capture.guardian_diagnostic()!=report:raise RuntimeError('replayed_guardian_frame_changed')
        return (capture,process) if objects else (value,process.pid)
    finally:
        if process.returncode is None:process.kill();process.wait(timeout=2)
        process.stdout.close();process.stderr.close()


def local_owner(root):
    """Exercise real Receipt and installer I/O with local disposable ownership.

    The root target admission is deliberately not invoked. Only owner/ancestry
    policy is adapted to this unprivileged local test directory.
    """
    pin='1'*64
    p={'source_commit':'2'*40,'compiler_source_manifest_sha256':pin,
        'helper_sha256':pin,'web_sha256':pin,'not_after_utc':int(time.time()+600),
        'backend_sources':{},'frontend_sources':{}}
    f=SimpleNamespace(helper=None,helper_stopped=True,files={},dirs={},borrowed_dirs={},
        users={},groups={},rows=False,db_user=False,db_user_lease=None,db_grants_lease=None,
        baseline=None,original={},original_absent={},public_sql_before=(pin,()),master=(),
        sql_uncertain=False,process_uncertain=False,identity_uncertain=False,creation_uncertain=False,
        run=lambda *a,**k:f'{os.getpid()} 1 0 Fri Oct 23 01:02:03 2026 python'.encode())
    owner=actor.Receipt(f,installer,p)
    with patch.object(frontend,'module',return_value=SimpleNamespace()):web=frontend.Frontend(None)
    web.preserve_failure(RuntimeError('control_eof'))
    owner.web=web
    return owner,web,p


class NativeEvidence(unittest.TestCase):
    def confinement_result(self, producer, value, mode='normal'):
        actual=producer.exercise(producer.confinement_case(value,mode))['report']
        capture,process=captured_guardian_frame(producer.GUARDIAN,actual,objects=True)
        with tempfile.TemporaryDirectory()as name:
            root=Path(name)
            with self.local_policy(root),patch.object(actor,'STAGE',root), \
                    patch.object(actor,'END',time.monotonic()+10), \
                    patch.object(installer.os,'fchown',side_effect=lambda fd,u,g:None):
                owner,web,p=local_owner(root)
                p['web_sha256']=actual['source']['binary_sha256']
                web.guardian=process;web.guardian_capture=capture
                if mode=='cleanup_failure':
                    web.cleanup_status='UNCERTAIN';web.cleanup_code='FRONTEND_CLEANUP_FAILED'
                owner.checkpoint('DIAGNOSTIC_CAPTURED')
                self.assertEqual(json.loads(owner.path.read_bytes())['native_diagnostic_evidence']['record'],
                    owner.diagnostic_evidence['record'])
                packet={**p,'helper':{'sha256':p['helper_sha256']},'web':{'sha256':p['web_sha256']}}
                result=consumer.inspect_mutation_failure({'native_diagnostic_evidence':owner.diagnostic_evidence},packet)
                return result,owner.diagnostic_evidence,packet

    def construction_result(self,mode='normal'):
        producer=load('construction_evidence_producer','test_native_diagnostics.py')
        detail={'schema':'osmap-account-construction-v1','operation':'socket_validation',
            'check':'canonicalize','category':'absent'}
        adapter=SimpleNamespace(exercise=producer.exercise,GUARDIAN=producer.GUARDIAN,
            confinement_case=lambda value,selected:'construction:'+selected+':'+json.dumps(value))
        return self.confinement_result(adapter,detail,mode)

    def test_construction_survives_actual_atomic_receipt_and_rejects_rehashed_tamper(self):
        result,original,packet=self.construction_result()
        self.assertEqual(result['construction_status'],'AVAILABLE')
        self.assertEqual(result['construction_detail']['operation'],'socket_validation')
        self.assertEqual(result['original_failure']['cause'],'native_admission_client')
        self.assertEqual(result['diagnostic_preservation'],'READBACK_VERIFIED')
        for mutate in (
                lambda c:c['construction_detail'].update(path='/private/SyntheticSecret123'),
                lambda c:c['construction_detail'].update(category='SyntheticSecret123'),
                lambda c:c['construction_detail'].update(check=True),
                lambda c:c.update(construction_status='NOT_EMITTED'),
                lambda c:c.update(native_code='native_confinement')):
            evidence=copy.deepcopy(original)
            mutate(evidence['record']['native_diagnostic']['guardian_diagnostic']['capture'])
            evidence['sha256']=hashlib.sha256(json.dumps(evidence['record'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
            with self.assertRaises(Exception):
                consumer.inspect_native_diagnostic({'native_diagnostic_evidence':evidence},packet)

    @unittest.skipUnless(os.environ.get('OSMAP_TEST_CONSTRUCTION_EMITTER_BINARY'),
        'focused Rust construction emitter artifact not supplied')
    def test_actual_rust_construction_through_atomic_receipt_and_final_consumer(self):
        result,_,_=self.construction_result('rust')
        self.assertEqual(result['construction_detail'],{'schema':'osmap-account-construction-v1',
            'operation':'socket_validation','check':'canonicalize','category':'absent'})
        self.assertEqual(result['construction_status'],'AVAILABLE')
        self.assertEqual(result['original_failure']['cause'],'native_admission_client')
        self.assertEqual(result['diagnostic_preservation'],'READBACK_VERIFIED')
        self.assertEqual(result['diagnostic_completeness'],'COMPLETE')

    def test_each_confinement_variant_through_process_frontend_recovery_and_final_consumer(self):
        producer=load('confinement_evidence_producer','test_native_diagnostics.py')
        for value in producer.CONFINEMENT_VARIANTS:
            with self.subTest(stage=value['stage'],reason=value['reason']):
                result,_,_=self.confinement_result(producer,value)
                self.assertEqual(result['confinement_detail'],value)
                self.assertEqual(result['confinement_code'],'native_confinement_'+value['stage'])
                self.assertEqual(result['original_failure']['cause'],'native_confinement')
                self.assertEqual(result['confinement_status'],'AVAILABLE')
                self.assertEqual(result['diagnostic_completeness'],'COMPLETE')
                self.assertEqual(result['diagnostic_preservation'],'READBACK_VERIFIED')
                self.assertEqual(result['functional_result'],'FAIL')
                self.assertFalse(result['cleanup_confirmed'])

    @unittest.skipUnless(os.environ.get('OSMAP_TEST_CONFINEMENT_EMITTER_BINARY'),
        'focused Rust libtest emitter artifact not supplied')
    def test_actual_rust_confinement_variants_reach_final_consumer(self):
        producer=load('rust_confinement_producer','test_native_diagnostics.py')
        for value in producer.CONFINEMENT_VARIANTS:
            with self.subTest(stage=value['stage'],reason=value['reason']):
                result,_,_=self.confinement_result(producer,value,'rust')
                self.assertEqual(result['confinement_detail'],value)
                self.assertEqual(result['confinement_status'],'AVAILABLE')
                self.assertEqual(result['diagnostic_completeness'],'COMPLETE')
                self.assertEqual(result['original_failure']['cause'],'native_confinement')

    def test_confinement_uncertainty_survives_final_consumer_without_losing_original(self):
        producer=load('confinement_uncertain_producer','test_native_diagnostics.py')
        for mode,status in (('partial','INCOMPLETE'),('interrupted','INCOMPLETE'),
                ('partial_marker','INCOMPLETE'),
                ('duplicate','DUPLICATE'),('conflicting','DUPLICATE'),
                ('oversized','MALFORMED'),('earlier_failure','CONFLICTING'),
                ('cleanup_failure','AVAILABLE')):
            with self.subTest(mode=mode):
                result,_,_=self.confinement_result(producer,producer.CONFINEMENT_VARIANTS[6],mode)
                self.assertEqual(result['confinement_status'],status)
                self.assertEqual(result['functional_result'],'FAIL')
                self.assertEqual(result['disposition'],'UNCERTAIN')
                if status!='AVAILABLE':
                    self.assertIsNone(result['confinement_detail'])
                    self.assertIsNone(result['confinement_code'])
                    self.assertEqual(result['diagnostic_completeness'],'INCOMPLETE')
                    self.assertEqual(result['diagnostic_deficiency'],'CONFINEMENT_DETAIL_'+status)
                if mode=='earlier_failure':
                    self.assertEqual(result['original_failure']['cause'],'native_admission_client')
                if mode=='cleanup_failure':
                    self.assertEqual(result['original_failure']['cause'],'native_confinement')
                    diagnostic=result['native_diagnostic_evidence']['record']['native_diagnostic']
                    self.assertEqual(diagnostic['guardian_diagnostic']['cleanup']['status'],'UNKNOWN')

    def test_consumer_rejects_rehashed_confinement_secrets_and_semantic_conflicts(self):
        producer=load('confinement_tamper_producer','test_native_diagnostics.py')
        _,original,packet=self.confinement_result(producer,producer.CONFINEMENT_VARIANTS[6])
        for mutate in (
                lambda c:c['confinement_detail'].update(path='/private/SyntheticPasswordABC123'),
                lambda c:c['confinement_detail'].update(errno=True),
                lambda c:c.update(native_code='native_admission_client'),
                lambda c:c.update(confinement_status='NOT_EMITTED'),
                lambda c:c['confinement_detail'].update(syscall='pledge')):
            evidence=copy.deepcopy(original)
            mutate(evidence['record']['native_diagnostic']['guardian_diagnostic']['capture'])
            evidence['sha256']=hashlib.sha256(json.dumps(evidence['record'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
            with self.assertRaises(Exception):
                consumer.inspect_native_diagnostic({'native_diagnostic_evidence':evidence},packet)
        # Historical v1 evidence / v2 guardian records have neither optional
        # field. They remain valid without inventing a historical detail.
        evidence=copy.deepcopy(original)
        native=evidence['record']['native_diagnostic']
        for capture in (native['guardian_capture'],native['guardian_diagnostic']['capture']):
            for key in ('confinement_detail','confinement_status','construction_detail','construction_status'):
                capture.pop(key,None)
        evidence['sha256']=hashlib.sha256(json.dumps(evidence['record'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        result=consumer.inspect_mutation_failure({'native_diagnostic_evidence':evidence},packet)
        self.assertEqual(result['confinement_status'],'NOT_EMITTED')
        self.assertIsNone(result['confinement_detail'])
        self.assertEqual(result['original_failure']['cause'],'native_confinement')

    def local_policy(self,root):
        def parents(path):
            self.assertEqual(path.parent,root)
            return tuple((str(parent),installer.identity(parent.lstat())[:6])for parent in path.parents)
        return patch.object(installer,'parents',side_effect=parents)

    def test_receipt_actual_atomic_publish_readback_and_consumer_survive_resource_removal(self):
        with tempfile.TemporaryDirectory()as name:
            root=Path(name)
            with self.local_policy(root),patch.object(actor,'STAGE',root), \
                    patch.object(actor,'END',time.monotonic()+10), \
                    patch.object(installer.os,'fchown',side_effect=lambda fd,u,g:None):
                owner,web,p=local_owner(root)
                owner.checkpoint('DIAGNOSTIC_BEFORE_STOP')
                first=copy.deepcopy(owner.diagnostic_evidence)
                web.cleanup_status='UNCERTAIN';web.cleanup_code='FRONTEND_CLEANUP_FAILED'
                owner.checkpoint('DIAGNOSTIC_CAPTURED')
                stored=json.loads(owner.path.read_bytes())
                self.assertEqual(stored['native_diagnostic_evidence']['record']['native_diagnostic']['first_failure'],
                    first['record']['native_diagnostic']['first_failure'])
                self.assertEqual(owner.path.stat().st_mode&0o777,0o600)
                self.assertEqual(owner.diagnostic_evidence['recovery_sha256'],hashlib.sha256(owner.path.read_bytes()).hexdigest())
                packet={**p,'helper':{'sha256':p['helper_sha256']},'web':{'sha256':p['web_sha256']}}
                result=consumer.inspect_mutation_failure({'failure_reason':'control_eof',
                    'native_diagnostic_evidence':owner.diagnostic_evidence},packet)
                self.assertEqual(result['original_failure']['code'],'control_eof')
                self.assertEqual(result['result'],'FAIL')
                self.assertEqual(result['disposition'],'UNCERTAIN')
                self.assertEqual(result['diagnostic_completeness'],'COMPLETE')
                self.assertEqual(result['native_diagnostic_evidence']['record']['native_diagnostic']['cleanup_code'],
                    'FRONTEND_CLEANUP_FAILED')
                self.assertIsNone(result['password_mutation'])

    def test_readback_failure_never_claims_new_evidence_verified(self):
        with tempfile.TemporaryDirectory()as name:
            root=Path(name)
            with self.local_policy(root),patch.object(actor,'STAGE',root), \
                    patch.object(actor,'END',time.monotonic()+10), \
                    patch.object(installer.os,'fchown',side_effect=lambda fd,u,g:None):
                owner,_,_=local_owner(root)
                actual=installer.read_regular
                def corrupt(path,cap,end):
                    raw,meta=actual(path,cap,end)
                    if b'DIAGNOSTIC_BEFORE_STOP'in raw:return b'corrupt',meta
                    return raw,meta
                with patch.object(installer,'read_regular',side_effect=corrupt),self.assertRaises(Exception):
                    owner.checkpoint('DIAGNOSTIC_BEFORE_STOP')
                self.assertIsNone(owner.diagnostic_evidence)

    def test_consumer_rejects_rehashed_secret_unknown_field_and_source_mismatch(self):
        with tempfile.TemporaryDirectory()as name:
            root=Path(name)
            with self.local_policy(root),patch.object(actor,'STAGE',root), \
                    patch.object(actor,'END',time.monotonic()+10), \
                    patch.object(installer.os,'fchown',side_effect=lambda fd,u,g:None):
                owner,_,p=local_owner(root);owner.checkpoint('DIAGNOSTIC_CAPTURED')
                packet={**p,'helper':{'sha256':p['helper_sha256']},'web':{'sha256':p['web_sha256']}}
                for mutate in (
                        lambda r:r['native_diagnostic']['first_failure'].update(code='SyntheticPasswordABC123'),
                        lambda r:r['native_diagnostic'].update(stderr='SyntheticCookieABC123'),
                        lambda r:r['native_diagnostic'].update(guardian_created=True,guardian_pid=1,guardian_terminal=1,guardian_reaped=False),
                        lambda r:r['native_diagnostic'].update(guardian_diagnostic_status='NOT_EMITTED'),
                        lambda r:r.update(web_sha256='9'*64)):
                    evidence=copy.deepcopy(owner.diagnostic_evidence);mutate(evidence['record'])
                    evidence['sha256']=hashlib.sha256(json.dumps(evidence['record'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
                    with self.assertRaises(Exception):consumer.inspect_native_diagnostic({'native_diagnostic_evidence':evidence},packet)

    def test_existing_ready_validation_failure_survives_later_guardian_failure(self):
        producer=load('evidence_producer','test_native_diagnostics.py')
        actual=producer.exercise('panic')['report']
        capture,pid=captured_guardian_frame(producer.GUARDIAN,actual)
        with tempfile.TemporaryDirectory()as name:
            root=Path(name)
            with self.local_policy(root),patch.object(actor,'STAGE',root), \
                    patch.object(actor,'END',time.monotonic()+10), \
                    patch.object(installer.os,'fchown',side_effect=lambda fd,u,g:None):
                owner,web,p=local_owner(root)
                p['web_sha256']=actual['source']['binary_sha256']
                native=web.native_diagnostic()
                native.update(guardian_created=True,guardian_pid=pid,guardian_reaped=True,guardian_capture=capture,
                    guardian_terminal=1,guardian_diagnostic=actual,guardian_diagnostic_status='AVAILABLE')
                native['first_failure'].update(code='actual_native_ready',operation='ready_validation')
                with patch.object(web,'native_diagnostic',return_value=native):owner.checkpoint('DIAGNOSTIC_CAPTURED')
                packet={**p,'helper':{'sha256':p['helper_sha256']},'web':{'sha256':p['web_sha256']}}
                result=consumer.inspect_mutation_failure({'native_diagnostic_evidence':owner.diagnostic_evidence},packet)
                self.assertEqual(result['original_failure']['code'],'actual_native_ready')
                self.assertEqual(result['native_diagnostic_evidence']['record']['native_diagnostic']['guardian_diagnostic'],actual)
                evidence=copy.deepcopy(owner.diagnostic_evidence)
                evidence['record']['native_diagnostic']['guardian_diagnostic']=None
                evidence['record']['native_diagnostic']['guardian_diagnostic_status']='NOT_EMITTED'
                evidence['sha256']=hashlib.sha256(json.dumps(evidence['record'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
                incomplete=consumer.inspect_mutation_failure({'native_diagnostic_evidence':evidence},packet)
                self.assertEqual(incomplete['diagnostic_completeness'],'INCOMPLETE')
                self.assertEqual(incomplete['diagnostic_deficiency'],'NOT_EMITTED')
                evidence=copy.deepcopy(owner.diagnostic_evidence)
                evidence['record']['native_diagnostic']['guardian_diagnostic']['source']['binary_sha256']='9'*64
                evidence['sha256']=hashlib.sha256(json.dumps(evidence['record'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
                with self.assertRaisesRegex(RuntimeError,'native_diagnostic_binary_binding'):
                    consumer.inspect_native_diagnostic({'native_diagnostic_evidence':evidence},packet)

    def test_observed_quiet_and_unknown_output_causes_remain_explicit(self):
        producer=load('unknown_evidence_producer','test_native_diagnostics.py')
        for case,reason in (('quiet','NO_NATIVE_OUTPUT'),('unknown','NO_ALLOWLISTED_NATIVE_DIAGNOSTIC')):
            with self.subTest(case=case),tempfile.TemporaryDirectory()as name:
                actual=producer.exercise(case)['report'];root=Path(name)
                capture,pid=captured_guardian_frame(producer.GUARDIAN,actual)
                with self.local_policy(root),patch.object(actor,'STAGE',root), \
                        patch.object(actor,'END',time.monotonic()+10), \
                        patch.object(installer.os,'fchown',side_effect=lambda fd,u,g:None):
                    owner,web,p=local_owner(root);p['web_sha256']=actual['source']['binary_sha256']
                    native=web.native_diagnostic()
                    native.update(guardian_created=True,guardian_pid=pid,guardian_reaped=True,guardian_capture=capture,
                        guardian_terminal=1,guardian_diagnostic=actual,guardian_diagnostic_status='AVAILABLE')
                    with patch.object(web,'native_diagnostic',return_value=native):owner.checkpoint('DIAGNOSTIC_CAPTURED')
                    packet={**p,'helper':{'sha256':p['helper_sha256']},'web':{'sha256':p['web_sha256']}}
                    result=consumer.inspect_mutation_failure({'native_diagnostic_evidence':owner.diagnostic_evidence},packet)
                    self.assertEqual(result['unknown_cause_reason'],reason)
                    self.assertEqual(result['diagnostic_completeness'],'COMPLETE')
                    self.assertIsNone(result['diagnostic_deficiency'])
                    self.assertEqual(result['original_failure']['cause'],'CAUSE_UNKNOWN')
                    self.assertNotIn('SYNTHETIC_PASSWORD',json.dumps(result))

    def test_token_shaped_secrets_and_unknown_exception_names_are_not_codes(self):
        secret='SyntheticPasswordABC123'
        self.assertEqual(actor.failure_reason(RuntimeError(secret)),'UNEXPECTED_SANITIZED')
        self.assertEqual(actor.failure_reason(SimpleNamespace(code=secret)),'UNEXPECTED_SANITIZED')
        error=type(secret,(Exception,),{})()
        self.assertEqual(actor.failure_category(error),'Exception')
        result=consumer.inspect_mutation_failure({'failure_reason':secret},
            {'source_commit':'2'*40,'helper':{'sha256':'1'*64},'web':{'sha256':'1'*64}})
        self.assertNotIn(secret,json.dumps(result))
        self.assertEqual(result['diagnostic_deficiency'],'NO_PRESERVED_NATIVE_DIAGNOSTIC')
        self.assertFalse(result['cleanup_confirmed'])


if __name__=='__main__':unittest.main()
