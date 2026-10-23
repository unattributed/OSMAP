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
cleanup=load('cleanup_owned_stages');startup=load('startup_only')
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
        self.p=copy.deepcopy(self.packet);self.p['not_after_utc']=int(time.time())+300
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
            with self.assertRaisesRegex(RuntimeError,'startup_result'):
                consumer.inspect(value,0,self.p['not_after_utc'],self.p)
            self.assertTrue(back.exists());self.assertTrue(front.exists())
            self.dispose(back,front,frames)

    def test_invalid_source_and_profile_refuse_before_stage_effects(self):
        for kind in('source_commit','source_hash','profile'):
            p=copy.deepcopy(self.p)
            if kind=='source_commit':p['source_commit']='0'*40
            elif kind=='source_hash':p['sources']['backend/startup_only.py']='eA=='
            else:p['helper']['cargo_profile']['opt_level']='0'
            with self.subTest(kind=kind),self.assertRaises(stage.Refused):stage.admit_packet(p)


if __name__=='__main__':unittest.main(verbosity=2)
