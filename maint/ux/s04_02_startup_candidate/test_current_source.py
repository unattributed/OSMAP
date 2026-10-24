"""Current compiler receipt through real packet admission/publication/consumption.

Native artifact bytes are retrieved unchanged for local publication. Only the
host binary-location adapter and native service observations are fixtures here;
this is machinery compatibility evidence, not OpenBSD product qualification.
"""
import copy
import ast
import contextlib
import io
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import signal
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parent
BUILD=Path(os.environ.get('OSMAP_CURRENT_BUILD_DIR',
    '/home/foo/Downloads/osmap-ux-s04/current-source-milestone1-20261023/build'))
HELPER_BUILD=Path(os.environ['OSMAP_HELPER_BUILD_DIR'])if os.environ.get('OSMAP_HELPER_BUILD_DIR')else None

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
        extra={}if HELPER_BUILD is None else{'helper_receipt_path':HELPER_BUILD/'result.json',
            'helper_manifest_path':HELPER_BUILD/'manifest.json'}
        cls.packet=binder.packet(BUILD/'result.json',BUILD/'manifest.json',**extra)

    def setUp(self):
        self.p=copy.deepcopy(self.packet);self.p['not_after_utc']=int(time.time())+600
        stage.END=time.monotonic()+600

    def publish_binary(self,pin,destination):
        artifact_root=HELPER_BUILD if HELPER_BUILD is not None and Path(pin['path']).name=='account-passwd'else BUILD
        local=artifact_root/('native-'+Path(pin['path']).name)
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
        self.assertEqual(admission['source_commit'],self.p['source_commit'])
        for key in stage.HELPER_BINDING:
            if key in self.p:self.assertEqual(admission[key],self.p[key])
        self.assertEqual(admission['web_sha256'],self.p['web']['sha256'])
        return back,front,frames

    @staticmethod
    def no_open_files(*args,**kwargs):
        return type('Result',(),{'returncode':0,'stderr':b'','stdout':b'USER CMD PID FD\n'})()

    def dispose(self,back,front,frames):
        cleanup.cleanup_owned(back,front,frames[-1]['stage_receipt_sha256'],os.geteuid(),
            self.no_open_files,expected_source=self.p['source_commit'])
        self.assertFalse(back.exists());self.assertFalse(front.exists())

    def test_current_artifacts_packet_producer_consumer_and_exact_cleanup(self):
        with tempfile.TemporaryDirectory()as directory:
            back,front,frames=self.stage_fixture(Path(directory))
            value={'schema':'osmap-single-host-transport-v1','result':'COMPLETE',
                'born_child_reaped':True,'born_group_gone':True,'root_exit':0,'stderr_bytes':0,
                'failure':None,'frames':frames+[actor_fixture(self.p)]}
            accepted=consumer.inspect(value,0,self.p['not_after_utc'],self.p)
            self.assertEqual(accepted['source_commit'],self.p['source_commit'])
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
            def authoritative_snapshot(self,account,_end,*,cleanup=False):
                if self.helper_stopped:
                    if not cleanup:
                        raise RuntimeError('final_authority_did_not_use_cleanup_reserve')
                    if _end != fakejourney.END:
                        raise RuntimeError('final_authority_changed_absolute_deadline')
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
                    runtime,fault,packet=self.p,admission=json.loads((back/'local-admission.json').read_bytes()))
                wire=b''.join(json.dumps(v).encode()+b'\n'for v in frames+[report])
                parsed=[];wrapper.parse_actor_frames(wire,parsed);transport['frames']=parsed
                if fault is None:
                    accepted=consumer.inspect(transport,0,self.p['not_after_utc'],self.p)
                    self.assertTrue(accepted['password_mutation'])
                    self.assertEqual(peer.writes,1)
                    self.assertTrue(states['backend'].disposed and states['frontend'].disposed)
                else:
                    accepted=consumer.inspect(transport,1,self.p['not_after_utc'],self.p)
                    self.assertEqual((accepted['result'],accepted['disposition']),('FAIL','UNCERTAIN'))
                    self.assertIsNone(accepted['password_mutation'])
                    self.assertEqual(report['disposition'],'RETAINED_REQUIRES_REVIEW')
                    self.assertTrue((runtime/'http-state/sessions').exists())
                    self.assertFalse(states['backend'].disposed or states['frontend'].disposed)
                    self.assertEqual(peer.writes,1)
                # Local regression fixture only: native retained effects are never
                # passed to this inert stage-only cleanup on an uncertain write.
                self.dispose(back,front,frames)

    def test_probe_current_artifacts_admission_actor_consumer_and_cleanup(self):
        mutation=load('test_mutation_result')
        self.p['operation']='confinement-probe'
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory)
            back,front,frames=self.stage_fixture(root)
            admission=json.loads((back/'local-admission.json').read_bytes())
            runtime=root/'runtime';runtime.mkdir()
            peer,states,phases,report,transport,packet=mutation.MutationIntegration().run_actor(
                runtime,packet=self.p,admission=admission)
            wire=b''.join(json.dumps(v).encode()+b'\n'for v in frames+[report])
            parsed=[];wrapper.parse_actor_frames(wire,parsed);transport['frames']=parsed
            accepted=consumer.inspect(transport,1,self.p['not_after_utc'],self.p)
            self.assertEqual(accepted['operation'],'confinement-probe')
            self.assertTrue(accepted['ready_observed'])
            self.assertFalse(accepted['ready_only_qualified'])
            self.assertEqual(accepted['authoritative_state_certainty'],'CONFIRMED_NO_WRITE')
            self.assertTrue(accepted['cleanup_confirmed'])
            self.assertEqual(peer.requests,[]);self.assertEqual(peer.writes,0)
            self.assertFalse(hasattr(states['frontend'],'driver'))
            self.assertFalse(any(phase=='MUTATION_SUBMISSION_INTENT'for phase,_ in phases))
            self.assertEqual(report['native_diagnostic_evidence']['record']['execution_admission_sha256'],
                stage.sha((back/'local-admission.json').read_bytes()))
            # The same published admission must bind the diagnostic; replacing
            # it with a fixture identity is refused by the real consumer.
            bad=copy.deepcopy(transport)
            bad['frames'][2]['admission_sha256']='0'*64
            with self.assertRaisesRegex(RuntimeError,'native_diagnostic_execution_binding'):
                consumer.inspect(bad,1,self.p['not_after_utc'],self.p)
            self.dispose(back,front,frames)


class BuildTransportCleanupTests(unittest.TestCase):
    def test_actual_cleanup_never_signals_reaped_transport(self):
        # Run the actual dispatch finally body without its host/build dispatch.
        build=load('build_current')
        tree=ast.parse((ROOT/'build_current.py').read_text())
        execute=next(node for node in tree.body if isinstance(node,ast.FunctionDef)
            and node.name=='execute')
        terminal=next(node for node in reversed(execute.body)if isinstance(node,ast.Try))
        code=compile(ast.Module(body=terminal.finalbody,type_ignores=[]),
            str(ROOT/'build_current.py'),'exec')
        for already_reaped,group_exists in ((True,False),(True,True),(False,False)):
            with self.subTest(already_reaped=already_reaped,group_exists=group_exists):
                child=SimpleNamespace(pid=424242,returncode=0 if already_reaped else None,
                    stdin=None,stdout=None,stderr=None,wait=Mock(return_value=0))
                signals=[]
                def observe(pid,number):
                    self.assertEqual(pid,child.pid);signals.append(number)
                    if number==0 and not group_exists:raise ProcessLookupError
                record={'native_result':'PASS'}
                context={**build.__dict__,'child':child,'record':record,
                    'root':Path('/unused-local-test'),'start':time.monotonic(),'save':Mock()}
                with patch.object(build.os,'killpg',side_effect=observe):exec(code,context)
                self.assertEqual(signals,[0]if already_reaped else[signal.SIGKILL,0])
                self.assertTrue(record['local_transport_reaped'])
                self.assertEqual(record['local_transport_group_gone'],not group_exists)
                self.assertEqual(record['native_result'],'FAIL'if group_exists else'PASS')


class LibtestBuildBindingTests(unittest.TestCase):
    """Portable compiler-selection and split-provenance checks; no native calls."""

    @staticmethod
    def receipt(commit,manifest_raw,kind='libtest-only'):
        manifest=json.loads(manifest_raw);count=len(manifest)
        phase={'code':0,'failure':None,'group_gone':True}
        profile=lambda test:{'opt_level':'0'if test else'3','debuginfo':0,
            'debug_assertions':test,'overflow_checks':test,'test':test}
        def artifact(test):
            return {'path':'/home/foo/.osmap-s04-02-artifacts-local/'+('osmap-libtest'if test else'account-passwd'),
                'sha256':'e'*64 if test else binder.REUSED_HELPER_SHA256,
                'size':1024,'dev':1,'ino':2 if test else 3,'uid':1000,'gid':1000,
                'mode':0o700,'nlink':1,'source_count':count,'profile_test':test,
                'tests_executed':False,'application_executed':False,
                'cargo_target_kind':['lib']if test else['bin'],'cargo_profile':profile(test)}
        digest=hashlib.sha256(manifest_raw).hexdigest()
        build={'schema':'osmap-controlled-native-build-current-v1','signed_base_commit':commit,
            'build_kind':kind,'source_manifest_sha256':digest,'archive_sha256':'c'*64,
            'tests_executed':False,'application_executed':False,'activation':False,
            'account_operations':False,'public_service_operations':False,'ordinary_Runtime_qualification':False,
            'identity':{'hostname':'obsd1.blackbagsecurity.com','system':'OpenBSD','machine':'amd64',
                **{key:1000 for key in('uid','euid','gid','egid')}},'scratch_gone':True,
            'cleanup_uncertain':False,'result':'PASS','rust':dict(phase),'source_count':count,
            'source_before':True,'source_after':True,'helper_built':kind!='libtest-only',
            'parent_limits_unchanged':True,'compiler_data_soft_bytes':4294967296,
            'compiler_build_jobs':1,'full_action_seconds':100,
            'build_programs':{name:{'resolved':name,'uid':0,'mode':0o755,'sha256':'d'*64}
                for name in('/usr/local/bin/cargo','/usr/local/bin/rustc')},
            'compiler_versions':{name:{**phase,'stderr':'','stdout':'version'}
                for name in('/usr/local/bin/cargo','/usr/local/bin/rustc')},
            'artifact_stage':{'path':'/home/foo/.osmap-s04-02-artifacts-local','uid':1000,'mode':0o700},
            'native_test_binary':artifact(True)}
        if kind!='libtest-only':build.update(helper=dict(phase),native_helper_binary=artifact(False))
        if kind=='helper-only':
            del build['rust'];del build['native_test_binary']
        return {'native_result':'PASS','remote_disposition':'CONFIRMED','signed_base_commit':commit,
            'source_manifest_sha256':digest,'ssh_code':0,'local_transport_reaped':True,
            'local_transport_group_gone':True,'result':build}

    def test_remote_selected_phases_feed_real_receipt_consumer(self):
        # Execute the actual remote selection/capture statements. Compiler calls
        # and binary custody are doubles; receipt validation is the real consumer.
        compiler=load('build_current')
        tree=ast.parse((ROOT/'build_remote.py').read_text())
        main=next(node for node in tree.body if isinstance(node,ast.Try))
        selection=[node for node in main.body if isinstance(node,ast.If)
            and isinstance(node.test,ast.Compare)and isinstance(node.test.left,ast.Name)
            and node.test.left.id=='BUILD_KIND']
        capture_block=next(node for node in main.body if isinstance(node,ast.If)
            and any(isinstance(child,ast.FunctionDef)and child.name=='capture'for child in node.body))
        final=[node for node in capture_block.body if isinstance(node,ast.If)]
        for kind in('pair','libtest-only','helper-only'):
            with self.subTest(kind=kind):
                receipt=self.receipt('a'*40,b'{"Cargo.toml":"a"}',kind)
                observed=receipt['result']
                artifacts={name:observed.pop(name)for name in('native_helper_binary','native_test_binary')if name in observed}
                for phase in('helper','rust'):observed.pop(phase,None)
                observed['helper_built']=False
                command=Mock(return_value={'code':0,'failure':None,'group_gone':True})
                capture=Mock(side_effect=lambda name,test:artifacts['native_test_binary'if test else'native_helper_binary'])
                context={'BUILD_KIND':kind,'report':observed,'command':command,
                    'capture':capture,'retain_phase':Mock(),'uncertain':False,'require':binder.require}
                exec(compile(ast.Module(body=[*selection,*final],type_ignores=[]),
                    '<actual-native-build-selection>','exec'),context)
                expected=[]
                if kind!='libtest-only':expected.append(['/usr/local/bin/cargo','build','--release','--offline','--locked','--bin','account-passwd','--message-format=json'])
                if kind!='helper-only':expected.append(['/usr/local/bin/cargo','test','--offline','--locked','--lib','--no-run','--message-format=json'])
                self.assertEqual([call.args[0]for call in command.call_args_list],expected)
                binding={'signed_base_commit':'a'*40,'build_kind':kind,'source_count':1,
                    'hashes':{'manifest.json':receipt['source_manifest_sha256'],'source.tar.gz':'c'*64}}
                self.assertEqual(compiler.inspect_receipt(json.loads(json.dumps(observed)),0,binding),('PASS','CONFIRMED'))
                bad=copy.deepcopy(observed);bad['cleanup_uncertain']=True
                with self.assertRaisesRegex(RuntimeError,'compiler_completion'):
                    compiler.inspect_receipt(bad,0,binding)
                bad['result']='FAIL'
                self.assertEqual(compiler.inspect_receipt(bad,1,binding),('FAIL','UNCERTAIN'))

    def test_prepare_freezes_explicit_signed_source_and_selection(self):
        compiler=load('build_current');commit='b'*40
        for kind in('pair','libtest-only','helper-only'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory()as name,patch.object(compiler,'signed_source')as signed,\
                    patch.object(compiler,'source_closure',return_value=({'Cargo.toml':b'local input'},[]))as closure:
                root=Path(name)/'prepared'
                binding=compiler.prepare(root,commit,libtest_only=kind=='libtest-only',
                    helper_only=kind=='helper-only',attempt_id='S04-02-helper-build-test',recipe_id='helper-build-test')
                signed.assert_called_once_with(commit);closure.assert_called_once_with(commit)
                self.assertEqual(binding['signed_base_commit'],commit)
                self.assertEqual(binding['build_kind'],kind)
                tree=ast.parse((root/'remote.py').read_text())
                constants={node.targets[0].id:node.value.value for node in tree.body
                    if isinstance(node,ast.Assign)and isinstance(node.targets[0],ast.Name)
                    and isinstance(node.value,ast.Constant)}
                self.assertEqual(constants['BASE'],commit)
                self.assertEqual(constants['BUILD_KIND'],kind)
                self.assertFalse(binding['native_dispatched'])
                self.assertFalse((root/'attempt-started.json').exists())
                self.assertEqual(json.loads((root/'packet.json').read_text())['signed_base_commit'],commit)
        with self.assertRaisesRegex(RuntimeError,'helper_build_action_required'):
            compiler.build_action({'build_kind':'helper-only'})
        with self.assertRaisesRegex(RuntimeError,'build_selection'):
            compiler.prepare(Path('/unused'),commit,libtest_only=True,helper_only=True)

    def test_fresh_compile_action_is_frozen_and_historical_defaults_are_preserved(self):
        compiler=load('build_current')
        with tempfile.TemporaryDirectory()as name,patch.object(compiler,'signed_source'),\
                patch.object(compiler,'source_closure',return_value=({'Cargo.toml':b'local input'},[])):
            root=Path(name)/'prepared'
            binding=compiler.prepare(root,'b'*40,libtest_only=True,
                attempt_id='S04-02-confinement-libtest-build161',recipe_id='confinement-libtest-build161')
            persisted=json.loads((root/'BINDING.json').read_bytes())
            self.assertEqual(binding,persisted)
            self.assertEqual(compiler.build_action(persisted),
                ('S04-02-confinement-libtest-build161','confinement-libtest-build161'))
            self.assertEqual(compiler.build_action({'build_kind':'libtest-only'}),
                ('S04-02-timing-libtest-build157','timing-libtest-build157'))
            self.assertEqual(compiler.build_action({}),(compiler.ATTEMPT,compiler.RECIPE))
        for bad in ({'attempt_id':'S04-02-new'}, {'recipe_id':'new'},
                    {'attempt_id':'S04-02-new\n','recipe_id':'new'},
                    {'attempt_id':'S04-02-new','recipe_id':'../new'},
                    {'attempt_id':True,'recipe_id':'new'}):
            with self.subTest(bad=bad),self.assertRaises(RuntimeError):compiler.build_action(bad)

    def test_libtest_receipt_rejects_helper_effect_or_wrong_mode(self):
        compiler=load('build_current');raw=b'{"Cargo.toml":"a"}\n'
        receipt=self.receipt('a'*40,raw);observed=receipt['result']
        binding={'signed_base_commit':'a'*40,'build_kind':'libtest-only','source_count':1,
            'hashes':{'manifest.json':receipt['source_manifest_sha256'],'source.tar.gz':'c'*64}}
        self.assertEqual(compiler.inspect_receipt(observed,0,binding),('PASS','CONFIRMED'))
        for key,value in(('helper_built',True),('helper',observed['rust']),
                ('native_helper_binary',observed['native_test_binary']),('build_kind','pair')):
            bad=copy.deepcopy(observed);bad[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):compiler.inspect_receipt(bad,0,binding)

    def test_helper_receipt_rejects_test_effect_or_wrong_mode(self):
        compiler=load('build_current');raw=b'{"Cargo.toml":"a"}\n'
        receipt=self.receipt('a'*40,raw,'helper-only');observed=receipt['result']
        binding={'signed_base_commit':'a'*40,'build_kind':'helper-only','source_count':1,
            'hashes':{'manifest.json':receipt['source_manifest_sha256'],'source.tar.gz':'c'*64}}
        self.assertEqual(compiler.inspect_receipt(observed,0,binding),('PASS','CONFIRMED'))
        for key,value in(('helper_built',False),('rust',observed['helper']),
                ('native_test_binary',observed['native_helper_binary']),('build_kind','pair')):
            bad=copy.deepcopy(observed);bad[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):compiler.inspect_receipt(bad,0,binding)

    def test_independent_signed_helper_accepts_exact_inputs_across_checkpoints(self):
        files={'Cargo.toml':b'[package]\n','Cargo.lock':b'lock\n',
            'src/openbsd.rs':b'current production confinement\n',
            'src/http/password_tests.rs':b'current tests\n'}
        for helper_commit,drift in (('a'*40,None),('b'*40,None),
                ('b'*40,'src/openbsd.rs'),('b'*40,'src/http/password_tests.rs')):
            with self.subTest(helper_commit=helper_commit,drift=drift),tempfile.TemporaryDirectory()as name:
                root=Path(name);helper_files=dict(files)
                if drift:helper_files[drift]+=b'other compiled input\n'
                trees={'a'*40:files,helper_commit:helper_files}
                def git(argv,**kwargs):
                    if argv[1]=='ls-tree':return ('\n'.join(trees[argv[4]])+'\n').encode()
                    if argv[1]=='show':
                        commit,path=argv[2].split(':',1);return trees[commit][path]
                    raise AssertionError(argv)
                paths=[]
                for prefix,commit,inputs,kind in(('web','a'*40,files,'libtest-only'),
                        ('helper',helper_commit,helper_files,'helper-only')):
                    raw=(json.dumps({key:hashlib.sha256(value).hexdigest()for key,value in inputs.items()},sort_keys=True)+'\n').encode()
                    manifest=root/(prefix+'-manifest.json');manifest.write_bytes(raw);manifest.chmod(0o600)
                    receipt=self.receipt(commit,raw,kind)
                    if kind=='helper-only':receipt['result']['native_helper_binary']['sha256']='f'*64
                    path=root/(prefix+'-receipt.json');path.write_text(json.dumps(receipt));path.chmod(0o600)
                    paths.append((path,manifest))
                for path,raw in files.items():
                    destination=root/path;destination.parent.mkdir(parents=True,exist_ok=True)
                    destination.write_bytes(raw);destination.chmod(0o600)
                verified=SimpleNamespace(returncode=0,stderr=('[GNUPG:] VALIDSIG '+binder.SIGNER+' ').encode())
                with patch.object(binder,'REPO',root),patch.object(binder.subprocess,'run',return_value=verified),\
                        patch.object(binder.subprocess,'check_output',side_effect=git),\
                        patch.object(binder,'source_packet',return_value={}):
                    call=lambda:binder.packet(*paths[0],helper_receipt_path=paths[1][0],helper_manifest_path=paths[1][1])
                    if drift:
                        with self.assertRaisesRegex(RuntimeError,'qualified_helper_selection'):call()
                    else:
                        result=call()
                        self.assertEqual(result['helper_source_commit'],helper_commit)
                        self.assertEqual(result['source_commit'],'a'*40)
                        self.assertEqual(result['helper']['sha256'],'f'*64)
                        self.assertEqual(result['compiler_source_manifest_sha256'],result['helper_compiler_source_manifest_sha256'])
                        self.assertNotEqual(result['compiler_receipt_sha256'],result['helper_compiler_receipt_sha256'])
                        with self.assertRaisesRegex(RuntimeError,'web_compiler_selection'):
                            binder.packet(*paths[1])

    def test_separate_signed_service_binding_accepts_only_test_file_difference(self):
        old_commit=binder.BUILD_SOURCE_COMMIT;new_commit='a'*40
        http=b'#[cfg(test)]\nmod tests {\nmod password_tests { include!("http/password_tests.rs"); }\n}\n'
        old={'Cargo.toml':b'[package]\n','Cargo.lock':b'lock\n','src/http.rs':http,
            'src/http/password_tests.rs':b'old timing\n','src/bin/account_passwd.rs':b'service\n'}
        new={**old,'src/http/password_tests.rs':b'new timing\n'}
        for drift in(None,'src/bin/account_passwd.rs','Cargo.lock','cfg_scope'):
            with self.subTest(drift=drift),tempfile.TemporaryDirectory()as name:
                root=Path(name);sources=dict(new)
                if drift=='cfg_scope':sources['src/http.rs']=http.replace(b'#[cfg(test)]\n',b'')
                elif drift is not None:sources[drift]+=b'changed\n'
                trees={old_commit:old,new_commit:sources}
                def git(argv,**kwargs):
                    if argv[1]=='ls-tree':return ('\n'.join(trees[argv[4]])+'\n').encode()
                    if argv[1]=='show':
                        commit,path=argv[2].split(':',1);return trees[commit][path]
                    raise AssertionError(argv)
                paths=[]
                for prefix,commit,files,kind in(('old',old_commit,old,'pair'),('new',new_commit,sources,'libtest-only')):
                    raw=(json.dumps({key:hashlib.sha256(value).hexdigest()for key,value in files.items()},sort_keys=True)+'\n').encode()
                    manifest=root/(prefix+'-manifest.json');manifest.write_bytes(raw);manifest.chmod(0o600)
                    receipt=root/(prefix+'-receipt.json');receipt.write_text(json.dumps(self.receipt(commit,raw,kind)));receipt.chmod(0o600)
                    paths.append((receipt,manifest))
                for path,raw in sources.items():
                    destination=root/path;destination.parent.mkdir(parents=True,exist_ok=True)
                    destination.write_bytes(raw);destination.chmod(0o600)
                verified=SimpleNamespace(returncode=0,stderr=('[GNUPG:] VALIDSIG '+binder.SIGNER+' ').encode())
                with patch.object(binder,'REPO',root),patch.object(binder.subprocess,'run',return_value=verified),\
                        patch.object(binder.subprocess,'check_output',side_effect=git),\
                        patch.object(binder,'source_packet',return_value={}):
                    call=lambda:binder.packet(*paths[1],helper_receipt_path=paths[0][0],helper_manifest_path=paths[0][1])
                    if drift:
                        with self.assertRaisesRegex(RuntimeError,'helper_non_test_source_changed'):call()
                    else:
                        result=call()
                        self.assertEqual(result['source_commit'],new_commit)
                        self.assertEqual(result['helper_source_commit'],old_commit)
                        self.assertEqual(result['helper']['sha256'],binder.REUSED_HELPER_SHA256)
                        self.assertNotEqual(result['compiler_source_manifest_sha256'],result['helper_compiler_source_manifest_sha256'])
                        self.assertNotEqual(result['compiler_receipt_sha256'],result['helper_compiler_receipt_sha256'])
                        with self.assertRaisesRegex(RuntimeError,'helper_receipt_selection'):
                            binder.packet(*paths[1])


if __name__=='__main__':unittest.main(verbosity=2)
