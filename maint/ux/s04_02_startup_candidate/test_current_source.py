"""Current compiler receipt through real packet admission/publication/consumption.

Native artifact bytes are retrieved unchanged for local publication. Only the
host binary-location adapter and native service observations are fixtures here;
this is machinery compatibility evidence, not OpenBSD product qualification.
"""
import copy
import contextlib
import io
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
BUILD=Path(os.environ.get('OSMAP_CURRENT_BUILD_DIR',
    '/home/foo/Downloads/osmap-ux-s04/current-source-milestone1-20261023/build'))

def load(name):
    spec=importlib.util.spec_from_file_location('current_'+name,ROOT/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

binder=load('bind_startup');stage=load('stage_root');consumer=load('consume_startup')
cleanup=load('cleanup_owned_stages');startup=load('startup_only');wrapper=load('remote_wrapper')
spec=importlib.util.spec_from_file_location('current_journey',ROOT/'sources/backend/local_journey.py')
journey=importlib.util.module_from_spec(spec);spec.loader.exec_module(journey)

def actor_fixture(packet):
    probes={key:{'connected_ms':1.0,'handled_ms':2.0,'cleanup_confirmed':True}
        for key in('admission','mutation')}
    sockets={key:{'uid':0,'gid':1001,'mode':stat.S_IFSOCK|0o660}for key in(
        '/var/run/osmap-account-admission/admission.sock','/var/run/osmap-account-mutation/mutation.sock')}
    return {'schema':'osmap-single-host-startup-v1','result':'PASS','functional_result':'PASS',
        'disposition':'CONFIRMED','password_mutation':False,'credential_request_frames':0,
        'public_service_controls':False,'public_config_writes':False,'relay_operations':False,
        'credential_values_retained':False,'authoritative_no_write':{
            'actual_write_observed':False,'Alice_exact17_preserved':True,'Alice_epoch':0,
            'Alice_state':'active','Alice_changed_at':None,'Bob_all17_preserved':True,
            'Bob_epoch':0,'Bob_state':'active'},
        'native_stages':{key:'PASS'for key in('ServiceStartup','ServiceFiles','ServiceAdmission',
            'ServiceAccounts','ServiceStore','AdmissionBind','MutationBind','ParentPrepare',
            'ParentSeal','AcceptanceLoop')},
        'service_readiness':{'startup_seconds':0.5,'startup_deadline_seconds':5,
            'paired_sockets_published':True,'parent_prepare':True,'parent_seal':True,
            'acceptance_proof':'AUTHORIZED_UID_CONNECT_EOF_HANDLED_ON_BOTH_SOCKETS',
            'service_binary_sha256':packet['helper']['sha256'],'socket_metadata':sockets,'probes':probes},
        'owned_effects_report':{key:True for key in('cleanup_confirmed','public_original25_preserved',
            'public_master_preserved','owned_sql_hash_uids_absent')},'elapsed_millis':500}


class CurrentSourceIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Never replace a missing current build with the historical successful receipt.
        cls.packet=binder.packet(BUILD/'result.json',BUILD/'manifest.json')

    def setUp(self):
        self.p=copy.deepcopy(self.packet);self.p['not_after_utc']=int(time.time())+600
        stage.END=time.monotonic()+600

    def publish_binary(self,pin,destination):
        local=BUILD/('native-'+Path(pin['path']).name)
        raw=binder.private(local,256*1024*1024)
        self.assertEqual(len(raw),pin['size'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(),pin['sha256'])
        return stage.publish(destination,raw,0o500)

    def stage_fixture(self,root):
        sources=stage.admit_packet(self.p);frames=[]
        back=root/'backend';front=root/'frontend'
        with patch.object(stage,'binary_copy',side_effect=self.publish_binary):
            digest=stage.produce_stage(self.p,sources,back,front,json.dumps(self.p,sort_keys=True,separators=(',',':')).encode(),{},frames.append)
        self.assertEqual(stage.sha((back/'local-admission.json').read_bytes()),digest)
        admission=json.loads((back/'local-admission.json').read_bytes())
        self.assertEqual(admission['helper_sha256'],self.p['helper']['sha256'])
        self.assertEqual(admission['source_commit'],binder.BUILD_SOURCE_COMMIT)
        self.assertEqual(admission['web_sha256'],self.p['web']['sha256'])
        return back,front,frames

    @staticmethod
    def no_open_files(*args,**kwargs):
        return type('Result',(),{'returncode':0,'stderr':b'','stdout':b'USER CMD PID FD\n'})()

    def dispose(self,back,front,frames):
        cleanup.cleanup_owned(back,front,frames[-1]['stage_receipt_sha256'],os.geteuid(),
            self.no_open_files,expected_source=binder.BUILD_SOURCE_COMMIT)
        self.assertFalse(back.exists());self.assertFalse(front.exists())

    def test_current_artifacts_packet_producer_consumer_and_exact_cleanup(self):
        with tempfile.TemporaryDirectory()as directory:
            back,front,frames=self.stage_fixture(Path(directory))
            value={'schema':'osmap-single-host-transport-v1','result':'COMPLETE',
                'born_child_reaped':True,'born_group_gone':True,'root_exit':0,'stderr_bytes':0,
                'failure':None,'frames':frames+[actor_fixture(self.p)]}
            accepted=consumer.inspect(value,0,self.p['not_after_utc'],self.p)
            self.assertEqual(accepted['source_commit'],binder.BUILD_SOURCE_COMMIT)
            self.assertEqual(accepted['compiler_receipt_sha256'],stage.sha((BUILD/'result.json').read_bytes()))
            for key in('compiler_receipt_sha256','helper_sha256','source_commit'):
                bad=copy.deepcopy(value);bad['frames'][2][key]='0'*len(bad['frames'][2][key])
                with self.assertRaisesRegex(RuntimeError,'current_build_binding'):
                    consumer.inspect(bad,0,self.p['not_after_utc'],self.p)
            bad=copy.deepcopy(value);bad['born_group_gone']=False
            with self.assertRaisesRegex(RuntimeError,'transport_or_cleanup'):
                consumer.inspect(bad,0,self.p['not_after_utc'],self.p)
            self.dispose(back,front,frames)

    def test_failed_actor_admission_retains_exact_stages_for_cleanup(self):
        with tempfile.TemporaryDirectory()as directory:
            back,front,frames=self.stage_fixture(Path(directory))
            # Run the real actor and real journey admission; mock only native host
            # identity and directory ownership to reach the invalid hash boundary.
            fake_stage=SimpleNamespace(parent=Path('/var/run'),
                name='osmap-service-admission-root-'+'0'*16,
                lstat=lambda:SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0,st_gid=0))
            output=io.StringIO()
            with patch.object(startup,'initialize',lambda:setattr(startup,'journey',journey)), \
                    patch.object(startup.sys,'argv',['startup_only.py','invalid-pin']), \
                    patch.object(journey,'STAGE',fake_stage), \
                    patch.object(journey.os,'getuid',return_value=0), \
                    patch.object(journey.os,'geteuid',return_value=0), \
                    patch.object(journey.os,'getgid',return_value=0), \
                    patch.object(journey.os,'getegid',return_value=0), \
                    patch.object(journey.socket,'gethostname',return_value='obsd1.blackbagsecurity.com'), \
                    patch.object(journey.os,'uname',return_value=SimpleNamespace(sysname='OpenBSD',machine='amd64')), \
                    patch.object(startup.os,'chdir'),patch.object(startup.signal,'signal'), \
                    patch.object(startup.signal,'alarm'),patch.object(startup.resource,'setrlimit'), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(startup.main(),1)
            actor=json.loads(output.getvalue())
            self.assertTrue(actor['admission_or_actor_failure'])
            self.assertEqual(actor['failure_reason'],'admission_pin')
            value={'schema':'osmap-single-host-transport-v1','result':'COMPLETE',
                'born_child_reaped':True,'born_group_gone':True,'root_exit':0,'stderr_bytes':0,
                'failure':None,'frames':frames+[actor]}
            with self.assertRaisesRegex(RuntimeError,'admission_result'):
                consumer.inspect(value,0,self.p['not_after_utc'],self.p)
            self.assertTrue(back.exists());self.assertTrue(front.exists())
            self.dispose(back,front,frames)

    def test_admission_actor_output_consumes_and_rejects_missing_proofs(self):
        # Execute the actual actor producer. Native boundaries alone are doubles;
        # this establishes serialization compatibility, never functional PASS.
        accounts=('alice@osmap-password.invalid','bob@osmap-password.invalid')
        sockets=[SimpleNamespace(lstat=lambda:None) for _ in range(2)]
        class Fixture:
            def __init__(self):
                self.report={key:True for key in ('cleanup_confirmed','public_original25_preserved',
                    'public_master_preserved','owned_sql_hash_uids_absent')}
                self.report.update(actual_write_observed=False,Alice_exact15_preserved=True,
                    Alice_epoch=0,Alice_state='active',Bob_all17_preserved=True)
                self.helper=None;self.helper_stopped=False;self.provisioning_started=False
                self.sql_uncertain=self.process_uncertain=self.identity_uncertain=self.creation_uncertain=False
                self.helper_diagnostic={'helper_reaped':True,'helper_exit_code':0,'helper_signaled':False,
                    'helper_trace_stage':'stock_admission','helper_trace_error':'Authentication'}
            def preflight(self):pass
            def provision(self):self.provisioning_started=True
            def provision_service(self):pass
            def authoritative_snapshot(self,account,_end):
                return {'account':account,'epoch':0,'state':'active','changed_at':None}
            def rust_epoch(self,account):return ({'epoch':0},None)
            def start_helper(self):
                self.helper=SimpleNamespace(pid=424242)
                self.report['service_readiness']={'service_binary_sha256':self_pin,'startup_seconds':0.5}
            def stop_helper(self):self.helper_stopped=True
            def private_read(self,*_args):return b'a'*64
            def initial_password(self,_account):return 'disposable-fixture-value'
            def inspect_state(self,**_kwargs):pass
            def cleanup(self):pass
        class Receipt:
            def __init__(self,*_args):self.setup_complete=False;self.requests_stopped=False;self.path='/owned/receipt'
            def checkpoint(self,*_args):pass
        q=SimpleNamespace(Qualification=Fixture,SOCKETS=sockets)
        http=SimpleNamespace(RustAuthoritativeCustodian=type('Custodian',(),{}),
            ACCOUNTS=accounts,ALICE=accounts[0],BOB=accounts[1])
        fakejourney=SimpleNamespace(END=time.monotonic()+300,WORK=time.monotonic()+150,
            Receipt=Receipt,ident=lambda _:0,
            load=lambda name:{'stock_qualification.py':q,'rust_http_driver.py':http,
                'install_account_password.py':SimpleNamespace()}[name])
        def actual_boundary(_path,_end,disposition,boot=None):
            disposition['cleanup_confirmed']=True
            op=boot['operation'];invalid=boot['invalid_mac']
            status='closed' if invalid else ('rejected' if op.get('epoch')==1 or
                op.get('password','').endswith('-incorrect') else 'active')
            value={'result':'AWAITING_NATIVE_DIAGNOSTIC' if invalid else 'PASS',
                'status':status,'authenticated_response':not invalid,'frame_sent':True,
                'cleanup_confirmed':True,'caller_uid':1001,'server_peer_uid':0,'round_trip_ms':1.0}
            if not invalid:value.update(account=boot['account'],epoch=0 if status=='active' else None)
            return value
        self_pin=self.p['helper']['sha256']
        report={'schema':'osmap-single-host-admission-v1','admission_frames':0,'mutation_frames':0,
            **{k:False for k in ('password_mutation','public_service_controls','public_config_writes',
                'relay_operations','credential_values_retained')}}
        p={'helper_sha256':self_pin,'source_commit':self.p['source_commit'],'config_map_sha256':'a'*64,
            'public_sql_sha256':'b'*64,'backend_sources':{'custody.py':'c'*64}}
        with patch.object(startup,'journey',fakejourney),patch.object(startup,'probe',actual_boundary), \
                patch.object(startup.os,'waitid',return_value=None):
            startup.run(p,report)
        serialized=json.loads(json.dumps(report))
        self.assertEqual(consumer.inspect_admission(serialized,self.p)['result'],'PASS')
        with tempfile.TemporaryDirectory() as directory:
            back,front,frames=self.stage_fixture(Path(directory))
            wire=b''.join(json.dumps(v).encode()+b'\n' for v in frames+[serialized])
            parsed=[];wrapper.parse_actor_frames(wire,parsed)
            transport={'schema':'osmap-single-host-transport-v1','result':'COMPLETE',
                'born_child_reaped':True,'born_group_gone':True,'root_exit':0,
                'stderr_bytes':0,'failure':None,'frames':parsed}
            self.assertEqual(consumer.inspect(transport,0,self.p['not_after_utc'],self.p)['result'],'PASS')
            retained=[]
            with self.assertRaisesRegex(wrapper.Refused,'actor_frame_schema'):
                wrapper.parse_actor_frames(wire+b'{"schema":"unknown"}\n',retained)
            self.assertEqual(retained,parsed)
            retained=[]
            with self.assertRaisesRegex(wrapper.Refused,'actor_frame_termination'):
                wrapper.parse_actor_frames(wire+b'{"schema":',retained)
            self.assertEqual(retained,parsed)
            self.dispose(back,front,frames)
        for key in ('diagnostic','cleanup','preservation','signed_rejection'):
            bad=copy.deepcopy(serialized)
            if key=='diagnostic':bad['helper_diagnostic']['helper_trace_error']='Unavailable'
            elif key=='cleanup':bad['owned_effects_report']['cleanup_confirmed']=False
            elif key=='preservation':bad['after'][accounts[1]]['epoch']=1
            else:bad['requests']['alice_wrong_epoch']['authenticated_response']=False
            with self.subTest(key=key),self.assertRaises(RuntimeError):consumer.inspect_admission(bad,self.p)

    def test_invalid_source_and_profile_refuse_before_stage_effects(self):
        for kind in('source_commit','source_hash','profile'):
            p=copy.deepcopy(self.p)
            if kind=='source_commit':p['source_commit']='0'*40
            elif kind=='source_hash':p['sources']['backend/startup_only.py']='eA=='
            else:p['helper']['cargo_profile']['opt_level']='0'
            with self.subTest(kind=kind),self.assertRaises(stage.Refused):stage.admit_packet(p)

    def test_mutation_current_artifacts_actual_actor_transport_consumer_and_cleanup(self):
        mutation=load('test_mutation_result')
        self.p['operation']='password-change'
        for fault in (None,'response_lost'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory()as directory:
                root=Path(directory)
                back,front,frames=self.stage_fixture(root)
                runtime=root/'runtime';runtime.mkdir()
                peer,states,phases,report,transport,packet=mutation.MutationIntegration().run_actor(
                    runtime,fault,packet=self.p)
                wire=b''.join(json.dumps(v).encode()+b'\n'for v in frames+[report])
                parsed=[];wrapper.parse_actor_frames(wire,parsed);transport['frames']=parsed
                if fault is None:
                    accepted=consumer.inspect(transport,0,self.p['not_after_utc'],self.p)
                    self.assertTrue(accepted['password_mutation'])
                    self.assertEqual(peer.writes,1)
                    self.assertTrue(states['backend'].disposed and states['frontend'].disposed)
                else:
                    with self.assertRaises(RuntimeError):consumer.inspect(transport,0,self.p['not_after_utc'],self.p)
                    self.assertEqual(report['disposition'],'RETAINED_REQUIRES_REVIEW')
                    self.assertTrue((runtime/'http-state/sessions').exists())
                    self.assertFalse(states['backend'].disposed or states['frontend'].disposed)
                    self.assertEqual(peer.writes,1)
                # Local regression fixture only: native retained effects are never
                # passed to this inert stage-only cleanup on an uncertain write.
                self.dispose(back,front,frames)


if __name__=='__main__':unittest.main(verbosity=2)
