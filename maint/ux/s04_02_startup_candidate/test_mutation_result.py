"""Real Python caller/actor/frame/consumer regression; local peers are not native proof."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent

def load(name,leaf):
    spec=importlib.util.spec_from_file_location(name,ROOT/leaf)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

actor=load('mutation_actor','sources/backend/local_journey.py')
consumer=load('mutation_consumer','consume_startup.py')
wrapper=load('mutation_wrapper','remote_wrapper.py')
controller=load('mutation_controller','sources/backend/local_frontend.py')
fixture=load('mutation_fixture','test_password_journey.py')
front,password=fixture.front,fixture.password

class MutationIntegration(unittest.TestCase):
    def run_actor(self,root,fault=None,cleanup_failure=False,packet=None,frontend_factory=None,receipt_factory=None):
        peer=fixture.ControlledPeer(root,fault);states={};phases=[]
        pin=packet['helper']['sha256']if packet is not None else'1'*64
        p={'helper_sha256':pin,'source_commit':packet['source_commit']if packet is not None else'2'*40,'config_map_sha256':pin,
            'public_sql_sha256':pin,'backend_sources':{'custody.py':pin},
            'frontend_stage':'local','frontend_files':{},'frontend_sources':{},
            'web_sha256':packet['web']['sha256']if packet is not None else pin,
            'compiler_source_manifest_sha256':packet['compiler_source_manifest_sha256']if packet is not None else pin}
        if packet is not None and packet.get('operation')=='confinement-probe':p['operation']='confinement-probe'
        class Qualification:
            def __init__(self):
                states['backend']=self;self.recovery=None;self.helper=None;self.helper_stopped=False
                self.provisioning_started=False;self.sql_uncertain=self.process_uncertain=False
                self.identity_uncertain=self.creation_uncertain=False
                self.report={};self.helper_diagnostic={};self.disposed=False
                self.baseline=[peer.snapshot(password.ALICE),peer.snapshot(password.BOB)]
            def preflight(self):pass
            def provision(self):self.provisioning_started=True
            def provision_service(self):pass
            def prepare_rust_journey(self):self.new_password=peer.boot['new_password']
            def initial_password(self,account):return peer.boot['alice_password'if account==password.ALICE else'bob_password']
            def start_helper(self):
                self.helper=SimpleNamespace(pid=1)
                self.report['service_readiness']={'result':'PASS','service_binary_sha256':pin,'startup_seconds':.1}
            def stop_helper(self):
                self.helper_stopped=True
                self.helper_diagnostic={'helper_reaped':True,'helper_exit_code':0,'helper_signaled':False}
            def private_read(self,*args):return b'a'*64
            def authoritative_snapshot(self,account,end,*,cleanup=False):return peer.snapshot(account)
            def rust_epoch(self,account):
                v=peer.snapshot(account)
                return {**{k:v[k]for k in('epoch','state','changed_at')},'intent':None,
                    'used_intents':['opaque-local-intent']if v['epoch']else[]},None
            def inspect_state(self,**kwargs):
                password.require(peer.writes==1,'local_backend_change')
            def cleanup(self):
                if cleanup_failure:raise RuntimeError('local_cleanup_failure')
                self.disposed=True
                self.report.update({key:True for key in('cleanup_confirmed','public_original25_preserved',
                    'public_master_preserved','owned_sql_hash_uids_absent')})
        class Receipt:
            def __init__(self,f,installer,p):
                states['receipt']=self;self.setup_complete=False;self.requests_stopped=False
                self.mutation_submission_started=False;self.snapshots={};self.path=root/'receipt'
                self.web=None;self.diagnostic_evidence=None
            def checkpoint(self,phase):
                phases.append((phase,self.mutation_submission_started))
                if self.web is not None:
                    record=actor.diagnostic_record(p,self.web.native_diagnostic())
                    raw=json.dumps(record,sort_keys=True,separators=(',',':')).encode()
                    self.path.write_bytes(raw)
                    if self.path.read_bytes()!=raw:raise RuntimeError('diagnostic_readback')
                    pin=hashlib.sha256(raw).hexdigest()
                    self.diagnostic_evidence={'record':record,'sha256':pin,
                        'readback_verified':True,'recovery_sha256':pin}
        class Witness:
            def __init__(self,*args):pass
            def begin(self):pass
            def finish_after_change(self):return peer.exchange('MAIL_WITNESS',time.monotonic()+10)['result']
            def close(self):pass
        class Frontend:
            def __init__(self,*args):
                states['frontend']=self;self.requests_stopped=False;self.disposed=False
                self.cancelled=threading.Event();self.socket_lock=threading.Lock();self.http_stream=None
                self.http_root=root;self.ready={'port':1};self.sequence_end=time.monotonic()+front.JOURNEY_SECONDS
                self.custody={'selector':actor.SELECTOR};self.control=SimpleNamespace(write=lambda *args:None)
                self.journey_module=password
                with patch.object(controller,'module',return_value=SimpleNamespace()):
                    self.diagnostic_controller=controller.Frontend(None)
            def native_diagnostic(self):return self.diagnostic_controller.native_diagnostic()
            def preserve_failure(self,error):self.diagnostic_controller.preserve_failure(error)
            def setup(self,boot,*,confinement_probe=False):
                if confinement_probe:
                    self.diagnostic_controller.startup_stage='READY_VALIDATED'
                    return
                self.driver=front.FrontDriver(self,boot)
            def exchange(self,tag,end):return self.local_exchange(tag,end)
            def capture_replay_directory(self):pass
            def capture_generated_directories(self):pass
            def finish_http(self,end):
                peer.finish(end);self.requests_stopped=True
                return {'schema':'osmap-http-password-runtime-v1','handled_connections':18,'elapsed_millis':10,
                    'alice_epoch0_refused':True,'alice_epoch1_admitted':1,'bob_epoch0_admitted':0}
            def stop_requests(self):self.requests_stopped=True
            def dispose(self):self.disposed=True;shutil.rmtree(root/'http-state')
        http=SimpleNamespace(RustAuthoritativeCustodian=type('Mixin',(),{}),ALICE=password.ALICE,
            BOB=password.BOB,COLUMNS=password.COLUMNS,confirmed_change=password.confirmed_change,
            digest_fields=lambda row,fields:row['row_sha256'])
        modules={'stock_qualification.py':SimpleNamespace(Qualification=Qualification),
            'rust_http_driver.py':http,'install_account_password.py':SimpleNamespace(),
            'stock_mail_witness.py':SimpleNamespace(StockMailWitness=Witness),
            'local_frontend.py':SimpleNamespace(Frontend=frontend_factory or Frontend)}
        report={'schema':'osmap-single-host-controlled-journey-v1',**{key:False for key in
            ('installed_qualification','slice_complete','public_service_controls','public_config_writes',
             'relay_operations','credential_values_retained')}}
        with patch.object(actor,'load',side_effect=modules.__getitem__),patch.object(actor,'Receipt',receipt_factory or Receipt), \
                patch.object(actor,'END',time.monotonic()+600),patch.object(actor,'WORK',time.monotonic()+450), \
                patch.object(front,'WEB_UID',os.getuid()),patch.object(front,'WEB_GID',os.getgid()), \
                patch.object(front.socket,'create_connection',side_effect=lambda *a,**k:fixture.ControlledSocket(peer)), \
                patch.object(front,'accepted_counter',side_effect=lambda end,minimum=0:(max(peer.counter,minimum),0)):
            actor.run(p,report)
        report['elapsed_millis']=1
        packet=packet or {'operation':'password-change','source_commit':p['source_commit'],'compiler_receipt_sha256':pin,
            'compiler_source_manifest_sha256':pin,'helper':{'sha256':pin},'web':{'sha256':pin}}
        common={'backend':'local-backend','not_after_utc':packet.get('not_after_utc',123)}
        ready={**common,'frontend':'local-frontend','schema':'osmap-single-host-stage-ready-v1',
            **{key:packet[key]for key in('source_commit','compiler_receipt_sha256','compiler_source_manifest_sha256')},
            'helper_sha256':packet['helper']['sha256'],'web_sha256':packet['web']['sha256'],
            'admission_sha256':hashlib.sha256((json.dumps(p,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest(),
            'packet_sha256':hashlib.sha256(json.dumps(packet,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
        frames=[{**common,'schema':'osmap-single-host-stage-birth-v1','frontend':None},
            {**common,'schema':'osmap-single-host-stage-birth-v1','frontend':'local-frontend'},ready,report]
        parsed=[];wrapper.parse_actor_frames(b''.join(json.dumps(v).encode()+b'\n'for v in frames),parsed)
        successful=report['result']=='PASS'
        transport={'schema':'osmap-single-host-transport-v1','result':'COMPLETE'if successful else'FAIL',
            'born_child_reaped':True,'born_group_gone':True,'root_exit':0 if successful else 1,
            'stderr_bytes':0,'failure':None,'frames':parsed}
        return peer,states,phases,report,transport,packet

    def test_confinement_probe_unexpected_ready_never_starts_journey(self):
        packet={'operation':'confinement-probe','source_commit':'2'*40,
            'compiler_receipt_sha256':'1'*64,'compiler_source_manifest_sha256':'1'*64,
            'helper':{'sha256':'1'*64},'web':{'sha256':'1'*64}}
        with tempfile.TemporaryDirectory()as name:
            peer,states,phases,report,value,packet=self.run_actor(Path(name),packet=packet)
            self.assertEqual(peer.requests,[])
            self.assertEqual(peer.writes,0)
            self.assertFalse(hasattr(states['frontend'],'driver'))
            self.assertFalse(any(phase=='MUTATION_SUBMISSION_INTENT'for phase,_ in phases))
            accepted=consumer.inspect(value,1,123,packet)
            self.assertEqual(accepted['operation'],'confinement-probe')
            self.assertTrue(accepted['ready_observed'])
            self.assertFalse(accepted['ready_only_qualified'])
            self.assertEqual(accepted['authoritative_state_certainty'],'CONFIRMED_NO_WRITE')
            self.assertTrue(accepted['cleanup_confirmed'])
            for key,bad_value in(('start_message_sent',True),('observed_http_requests',1),
                    ('ready_only_qualified',True),('result','PASS')):
                bad=copy.deepcopy(value);bad['frames'][-1][key]=bad_value
                with self.assertRaisesRegex(RuntimeError,'confinement_probe_scope'):
                    consumer.inspect(bad,1,123,packet)
            wrong=copy.deepcopy(packet);wrong['operation']='password-change'
            bad=copy.deepcopy(value)
            bad['frames'][2]['packet_sha256']=hashlib.sha256(json.dumps(wrong,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            with self.assertRaisesRegex(RuntimeError,'operation_actor_binding'):
                consumer.inspect(bad,1,123,wrong)

    def test_success_runs_real_caller_actor_frame_parser_and_consumer(self):
        with tempfile.TemporaryDirectory()as name:
            peer,states,phases,report,value,packet=self.run_actor(Path(name))
            self.assertEqual(report['result'],'PASS',report)
            self.assertEqual(consumer.inspect(value,0,123,packet)['result'],'PASS')
            mismatched=copy.deepcopy(packet);mismatched['operation']='admission'
            bad=copy.deepcopy(value)
            bad['frames'][2]['packet_sha256']=hashlib.sha256(json.dumps(mismatched,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            with self.assertRaisesRegex(RuntimeError,'operation_actor_binding'):
                consumer.inspect(bad,0,123,mismatched)
            self.assertEqual(peer.writes,1)
            self.assertEqual(report['mutation_requests'],1)
            self.assertEqual(report['initial_authority_digests'],
                {password.ALICE:'a'*64,password.BOB:'a'*64})
            self.assertIn(('MUTATION_SUBMISSION_INTENT',True),phases)
            self.assertTrue(states['backend'].disposed and states['frontend'].disposed)
            self.assertFalse((Path(name)/'http-state').exists())
            for key in('terminal_response_confirmed','old_password_refused','new_password_admitted'):
                bad=copy.deepcopy(value);bad['frames'][-1]['mutation_evidence'][key]=False
                with self.assertRaises(RuntimeError):consumer.inspect(bad,0,123,packet)
            for field in('authoritative_snapshots','final_authority','durable_intents','mail_witness','frontend_cleanup'):
                bad=copy.deepcopy(value);del bad['frames'][-1][field]
                with self.assertRaises((RuntimeError,KeyError)):consumer.inspect(bad,0,123,packet)

    def test_successful_actor_evidence_cannot_omit_required_effects(self):
        with tempfile.TemporaryDirectory()as name:
            _,_,_,_,value,packet=self.run_actor(Path(name))
            mutations=(
                lambda a:a['mutation_evidence']['alice_sessions'].pop(),
                lambda a:a['mutation_evidence']['alice_sessions'][1].update(old_cookie_status=200),
                lambda a:a['mutation_evidence'].update(mutation_requests=2),
                lambda a:a['authoritative_snapshots']['SNAPSHOT_A1'].update(epoch=0),
                lambda a:a['authoritative_snapshots']['SNAPSHOT_B1'].update(password_sha256='9'*64),
                lambda a:a['durable_intents'][password.ALICE].update(used_intent_count=2),
                lambda a:a.update(known_write_time='20261023120000'),
                lambda a:a['mail_witness'].update(public_cache_zero=False),
                lambda a:a['frontend_cleanup'].update(disposed=False),
                lambda a:a['helper_diagnostic'].update(helper_reaped=False),
                lambda a:a['owned_effects_report'].update(public_original25_preserved=False),
                lambda a:a['timings'].update(totp_wait_seconds=float('nan')))
            for mutate in mutations:
                bad=copy.deepcopy(value);mutate(bad['frames'][-1])
                with self.assertRaises(RuntimeError):consumer.inspect(bad,0,123,packet)

    def test_postsubmission_failures_stop_and_retain_sessions_and_authority(self):
        for fault in('response_lost','other_not_revoked','other_cookie_admitted'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory()as name:
                peer,states,phases,report,value,packet=self.run_actor(Path(name),fault)
                self.assertEqual((report['result'],report['disposition']),('FAIL','RETAINED_REQUIRES_REVIEW'))
                self.assertEqual(peer.writes,1)
                self.assertEqual(report['mutation_requests'],1)
                self.assertTrue(report['http_failure_scalars']['http_observation_known'])
                self.assertGreater(report['http_failure_scalars']['http_request_ordinal'],0)
                self.assertTrue(states['frontend'].requests_stopped and states['backend'].helper_stopped)
                self.assertFalse(states['frontend'].disposed or states['backend'].disposed)
                self.assertTrue(list((Path(name)/'http-state/sessions').iterdir()))
                self.assertEqual(report['final_authority'][password.ALICE]['changed_at'],'20261023120001')
                self.assertNotEqual(report['milestones'].get('milestone3',{}).get('result'),'PASS')
                accepted=consumer.inspect(value,1,123,packet)
                self.assertEqual(accepted['result'],'FAIL')
                self.assertEqual(accepted['disposition'],'UNCERTAIN')
                self.assertEqual(accepted['reported_disposition'],'RETAINED_REQUIRES_REVIEW')
                self.assertIsNone(accepted['password_mutation'])
                self.assertFalse(accepted['cleanup_confirmed'])
                self.assertEqual(accepted['failure_reason'],report['native_diagnostic_evidence']['record']['native_diagnostic']['first_failure']['code'])

    def test_proven_prewrite_refusal_disposes_without_mutation(self):
        with tempfile.TemporaryDirectory()as name:
            peer,states,phases,report,value,packet=self.run_actor(Path(name),'expired')
            self.assertEqual(peer.writes,0)
            self.assertFalse(report['mutation_submission_started'])
            self.assertEqual(report['mutation_requests'],0)
            self.assertEqual(set(report['initial_authority_digests']),{password.ALICE,password.BOB})
            self.assertTrue(report['proven_before_submission_no_write'])
            self.assertEqual(report['disposition'],'CONFIRMED')
            self.assertTrue(states['frontend'].disposed and states['backend'].disposed)
            accepted=consumer.inspect(value,1,123,packet)
            self.assertEqual((accepted['result'],accepted['disposition']),('FAIL','CONFIRMED'))
            self.assertIs(accepted['password_mutation'],False)
            self.assertTrue(accepted['proven_before_submission_no_write'])
            for field in ('initial_authority_digests','final_authority','durable_intents',
                    'mutation_requests','frontend_cleanup','owned_effects_report','helper_diagnostic'):
                bad=copy.deepcopy(value);del bad['frames'][-1][field]
                unproven=consumer.inspect(bad,1,123,packet)
                self.assertEqual(unproven['disposition'],'UNCERTAIN',field)
                self.assertFalse(unproven['cleanup_confirmed'],field)
            bad=copy.deepcopy(value)
            bad['frames'][-1]['final_authority'][password.ALICE]['row_sha256']='b'*64
            unproven=consumer.inspect(bad,1,123,packet)
            self.assertIsNone(unproven['password_mutation'])
            self.assertEqual(unproven['disposition'],'UNCERTAIN')
            bad=copy.deepcopy(value);bad['frames'][-1]['public_config_writes']=True
            self.assertEqual(consumer.inspect(bad,1,123,packet)['disposition'],'UNCERTAIN')
            with self.assertRaisesRegex(RuntimeError,'transport_or_cleanup'):
                consumer.inspect(value,0,123,packet)

    def test_durable_submission_intent_survives_missing_driver(self):
        created=[]
        class InterruptedFrontend(controller.Frontend):
            def __init__(self,*args):
                with patch.object(controller,'module',return_value=SimpleNamespace()):super().__init__(None)
                created.append(self)
            def setup(self,boot):
                self.ownership_callback.__self__.mutation_submission_started=True
                self.ownership_callback('MUTATION_SUBMISSION_INTENT')
                raise RuntimeError('actor_interrupted')
        with tempfile.TemporaryDirectory()as name:
            peer,states,_,report,value,packet=self.run_actor(Path(name),frontend_factory=InterruptedFrontend)
            self.assertFalse(hasattr(created[0],'driver'))
            self.assertEqual(peer.writes,0)
            self.assertTrue(report['mutation_submission_started'])
            self.assertFalse(report['proven_before_submission_no_write'])
            self.assertEqual(report['disposition'],'RETAINED_REQUIRES_REVIEW')
            self.assertFalse(states['backend'].disposed or created[0].disposed)
            result=consumer.inspect(value,1,123,packet)
            self.assertIsNone(result['password_mutation'])
            self.assertEqual(result['authoritative_state_certainty'],'UNKNOWN')

    def test_evidence_write_failure_still_stops_producers_but_retains_resources(self):
        class FailedReceipt:
            def __init__(self,f,installer,p):
                self.setup_complete=False;self.requests_stopped=False;self.snapshots={}
                self.mutation_submission_started=False;self.path=Path('/local-test-no-receipt')
                self.diagnostic_evidence=None;self.web=None
            def checkpoint(self,phase):
                if phase=='DIAGNOSTIC_BEFORE_STOP':raise OSError('SyntheticSecretWriteFailure')
        with tempfile.TemporaryDirectory()as name:
            peer,states,_,report,value,packet=self.run_actor(Path(name),'expired',receipt_factory=FailedReceipt)
            self.assertEqual(peer.writes,0)
            self.assertEqual(report['result'],'FAIL')
            self.assertTrue(states['frontend'].requests_stopped and states['backend'].helper_stopped)
            self.assertFalse(states['frontend'].disposed or states['backend'].disposed)
            self.assertEqual(report['disposition'],'RETAINED_REQUIRES_REVIEW')
            self.assertEqual(report['cleanup_failures'][0]['phase'],'diagnostic_preservation')
            self.assertNotIn('SyntheticSecretWriteFailure',json.dumps(report))
            result=consumer.inspect(value,1,123,packet)
            self.assertEqual(result['disposition'],'UNCERTAIN')
            self.assertEqual(result['diagnostic_completeness'],'UNAVAILABLE')

    def test_cleanup_failure_cannot_emit_milestone_pass_or_dispose_sessions(self):
        with tempfile.TemporaryDirectory()as name:
            peer,states,phases,report,value,packet=self.run_actor(Path(name),cleanup_failure=True)
            self.assertEqual(report['result'],'FAIL')
            self.assertEqual(report['milestones']['milestone3']['result'],'NOT_QUALIFIED')
            self.assertFalse(states['frontend'].disposed)
            self.assertEqual(report['cleanup_failures'][0]['reason'],'UNEXPECTED_SANITIZED')
            self.assertTrue((Path(name)/'http-state/sessions').exists())
            accepted=consumer.inspect(value,1,123,packet)
            self.assertEqual((accepted['result'],accepted['disposition']),('FAIL','UNCERTAIN'))
            self.assertFalse(accepted['cleanup_confirmed'])
            self.assertIsNone(accepted['password_mutation'])

if __name__=='__main__':unittest.main()
