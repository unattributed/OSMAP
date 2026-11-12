"""One fresh root-owned single-host journey; no relay/public service controls.

Root admits this exact carrier and scalar compiler/stage receipts before launch.
Only disposable passwords generated in this process enter the owned runtime.
The durable receipt contains metadata/digests, never key/password/SQL bodies.
Incomplete setup or custody yields a retained no-op disposition, never adoption.
"""
import hashlib,importlib.util,json,math,os,re,resource,signal,socket,stat,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
STAGE=Path(__file__).resolve().parent
START=time.monotonic();END=None;WORK=None
STOPS={signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGALRM}
EVENTS=('SNAPSHOT_B0','SNAPSHOT_A0','SNAPSHOT_A1','SNAPSHOT_B1','MAIL_WITNESS')
SELECTOR='http::tests::password_tests::genuine_http_pilot::native_single_host_rust_http_password_runtime_entrypoint'
BACKEND_SOURCE_NAMES={'custody.py','stock_qualification.py','stock_schema.py',
    'rust_http_driver.py','stock_mail_witness.py','install_account_password.py',
    'local_frontend.py','local_journey.py'}
FRONTEND_SOURCE_NAMES={'native_http_front_driver.py','native_http_password_driver.py',
    'native_http_web_guardian.py'}
HELPER_BINDING={'helper_source_commit','helper_compiler_source_manifest_sha256','helper_compiler_receipt_sha256'}
SAFE_FAILURE_CODES=frozenset(('UNEXPECTED_SANITIZED', 'confinement_probe_ready_observed', 'admission_operation', 'actor_birth', 'actor_interrupted', 'actual_http_stopped', 'admission_fields', 'admission_pin', 'authority_changed_before_disposal', 'backend_stage', 'backend_stage_custody', 'complete_event_set', 'control_eof', 'controlled_journey_failed', 'diagnostic_bound', 'diagnostic_evidence_unavailable', 'diagnostic_not_preserved', 'diagnostic_readback', 'duplicate_field', 'fresh_original_expiry', 'frontend_disposal', 'frontend_files', 'frontend_original_lease', 'frontend_stage', 'frontend_stage_custody', 'helper_binding_fields', 'helper_binding_scalars', 'input_continuity', 'input_custody', 'input_deadline', 'input_hash', 'input_mode', 'input_open', 'mail_witness', 'native_local_selector', 'native_startup_failed', 'nonfinite', 'one_admission_hash', 'ordered_local_event', 'original_http_deadline', 'original_local_deadline', 'owned_cleanup', 'producer_stop_required', 'purpose_key_shape', 'receipt_bound', 'receipt_scalar', 'recovery_changed', 'recovery_collision', 'recovery_readback', 'root_target', 'single_durable_mutation_intent', 'source_commit', 'source_sets', 'stock_bob_nonce_home', 'web_build_binding', 'web_source_map'))
class Refused(Exception):pass
def require(ok,reason):
    if not ok:raise Refused(reason)
def failure_reason(error):
    reason=getattr(error,'code',None) or str(error)
    return reason if type(reason)is str and reason in SAFE_FAILURE_CODES else'UNEXPECTED_SANITIZED'
def failure_category(error):
    name=type(error).__name__
    return name if name in {'Refused','RuntimeError','OSError','ValueError','TimeoutError',
        'InterruptedError','KeyboardInterrupt','SystemExit','FileNotFoundError','PermissionError'}else'Exception'
def unique(pairs):
    out={}
    for key,value in pairs:require(key not in out,'duplicate_field');out[key]=value
    return out
def decode(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(Refused('nonfinite')))
def sha(raw):return hashlib.sha256(raw).hexdigest()
def ident(m):return(m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
def read(path,cap,expected=None,mode=None):
    m=path.lstat();before=ident(m)
    require(stat.S_ISREG(m.st_mode)and m.st_uid==m.st_gid==0 and m.st_nlink==1 and not m.st_mode&0o022 and 0<m.st_size<=cap,'input_custody')
    require(mode is None or stat.S_IMODE(m.st_mode)==mode,'input_mode')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        require(ident(os.fstat(fd))==before,'input_open');out=bytearray()
        while len(out)<=cap:
            require(time.monotonic()<END,'input_deadline');part=os.read(fd,min(262144,cap+1-len(out)))
            if not part:break
            out.extend(part)
        require(len(out)==m.st_size and ident(os.fstat(fd))==before and ident(path.lstat())==before,'input_continuity')
        require(expected is None or sha(out)==expected,'input_hash');return bytes(out)
    finally:os.close(fd)
def load(name):
    spec=importlib.util.spec_from_file_location('local_'+name.removesuffix('.py'),STAGE/name)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module

def admission(expected):
    global END,WORK
    require(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0
        and socket.gethostname()=='obsd1.blackbagsecurity.com'
        and (os.uname().sysname,os.uname().machine)==('OpenBSD','amd64'),'root_target')
    require(STAGE.parent==Path('/var/run')and re.fullmatch('osmap-service-admission-root-[a-f0-9]{16}',STAGE.name),'backend_stage')
    m=STAGE.lstat();require(stat.S_ISDIR(m.st_mode)and(m.st_uid,m.st_gid,stat.S_IMODE(m.st_mode))==(0,0,0o700),'backend_stage_custody')
    require(re.fullmatch('[a-f0-9]{64}',expected),'admission_pin')
    END=START+600;WORK=END-150
    p=decode(read(STAGE/'local-admission.json',65536,expected,0o400))
    require(set(p)-HELPER_BINDING-{'operation'}=={'version','not_after_utc','source_commit','compiler_source_manifest_sha256','helper_sha256','web_sha256','web_bytes','backend_sources','frontend_sources','frontend_stage','frontend_stage_lease','frontend_files','config_map_sha256','public_sql_sha256','prerequisite_sha256'},'admission_fields')
    require(p.get('operation','password-change')in('password-change','confinement-probe'),'admission_operation')
    require(not(HELPER_BINDING&set(p))or HELPER_BINDING<=set(p),'helper_binding_fields')
    if HELPER_BINDING<=set(p):
        require(re.fullmatch('[a-f0-9]{40}',p['helper_source_commit'])and all(re.fullmatch('[a-f0-9]{64}',p[k])for k in HELPER_BINDING-{'helper_source_commit'}),'helper_binding_scalars')
    require(p['version']==1 and type(p['not_after_utc'])is int and 0<p['not_after_utc']-time.time()<=600,'fresh_original_expiry')
    END=min(END,time.monotonic()+p['not_after_utc']-time.time());WORK=END-150
    require(re.fullmatch('[a-f0-9]{40}',p['source_commit']),'source_commit')
    for key in('compiler_source_manifest_sha256','helper_sha256','web_sha256','config_map_sha256','public_sql_sha256','prerequisite_sha256'):require(type(p[key])is str and re.fullmatch('[a-f0-9]{64}',p[key]),'receipt_scalar')
    backend=BACKEND_SOURCE_NAMES;frontend=FRONTEND_SOURCE_NAMES
    require(set(p['backend_sources'])==backend and set(p['frontend_sources'])==frontend,'source_sets')
    for name,pin in p['backend_sources'].items():read(STAGE/name,262144,pin,0o400)
    root=Path(p['frontend_stage']);require(root.parent==Path('/tmp')and re.fullmatch('osmap-pxp-stage-[a-f0-9]{16}',root.name),'frontend_stage')
    m=root.lstat();require(ident(m)[:6]==tuple(p['frontend_stage_lease'])and(m.st_uid,m.st_gid,stat.S_IMODE(m.st_mode))==(0,0,0o700),'frontend_stage_custody')
    require(set(p['frontend_files'])==frontend|{'source-input-manifest.json','http-build.json','qualified-openbsd-libtest'},'frontend_files')
    for name,pin in p['frontend_sources'].items():read(root/name,262144,pin,0o400)
    for name,lease in p['frontend_files'].items():require(ident((root/name).lstat())==tuple(lease),'frontend_original_lease')
    build=decode(read(root/'http-build.json',4096,mode=0o400))
    require(build=={'version':1,'binary_sha256':p['web_sha256'],'binary_bytes':p['web_bytes'],'source_manifest_sha256':sha(read(root/'source-input-manifest.json',65536,mode=0o400))},'web_build_binding')
    require(decode(read(root/'source-input-manifest.json',65536))==p['frontend_sources'],'web_source_map')
    return p

def diagnostic_record(p,diagnostic):
    return {'schema':'osmap-native-diagnostic-evidence-v1',
        'execution_admission_sha256':sha((json.dumps(p,sort_keys=True,separators=(',',':'))+'\n').encode()),
        'source_commit':p['source_commit'],
        'compiler_source_manifest_sha256':p['compiler_source_manifest_sha256'],
        'helper_sha256':p['helper_sha256'],'web_sha256':p['web_sha256'],
        'native_diagnostic':diagnostic}

class Receipt:
    def __init__(self,f,installer,p):
        self.f,self.installer,self.p=f,installer,p;self.path=STAGE/'local-owned-recovery.json';self.previous=None
        self.diagnostic_evidence=None
        self.setup_complete=False;self.requests_stopped=False;self.restoration_attempted=False;self.mutation_submission_started=False;self.sequence=0;self.snapshots={};self.web=None
        self.actor=f.run(('/bin/ps','-p',str(os.getpid()),'-o','pid=,ppid=,uid=,lstart=,comm='),'local_actor_birth',cap=2048).decode('ascii')
        row=self.actor.split();require(len(row)==9 and row[0]==str(os.getpid())and row[2]=='0','actor_birth')
        self.checkpoint('INITIAL')
    def checkpoint(self,phase):
        f=self.f;self.sequence+=1
        state={'schema':'osmap-single-host-owned-recovery-v1','sequence':self.sequence,'phase':phase,'source_commit':self.p['source_commit'],'compiler_source_manifest_sha256':self.p['compiler_source_manifest_sha256'],'sources':self.p['backend_sources'],'frontend_sources':self.p['frontend_sources'],'original_expiry_utc':self.p['not_after_utc'],'actor_birth':self.actor,'setup_complete':self.setup_complete,'requests_stopped':self.requests_stopped,'restoration_attempted':self.restoration_attempted,'helper_stopped':f.helper is None or f.helper_stopped,'files':{str(k):list(v)for k,v in f.files.items()},'dirs':{str(k):list(v)for k,v in f.dirs.items()},'borrowed_dirs':{str(k):[list(x)for x in v]for k,v in f.borrowed_dirs.items()},'users':{k:list(v)for k,v in f.users.items()},'groups':{k:[v[0],list(v[1])]for k,v in f.groups.items()},'rows_created':f.rows,'database_user_created':f.db_user,'database_create_sha256':None if f.db_user_lease is None else sha(f.db_user_lease),'database_grants_sha256':None if f.db_grants_lease is None else sha(f.db_grants_lease),'observed_snapshots':self.snapshots,'helper_pid':None if f.helper is None else f.helper.pid,'initial_rows':[]if f.baseline is None else[{'account':r['username'],'full17_sha256':f.http.digest_fields(r,f.http.COLUMNS),'immutable15_sha256':f.http.digest_fields(r,f.http.NONCREDENTIAL_COLUMNS)}for r in f.baseline],'public_original':{str(k):{'sha256':v[0],'metadata':list(v[1])}for k,v in f.original.items()},'public_original_absent':{str(k):[{'path':str(parent),'metadata':list(prior)}for parent,prior in ancestry]for k,ancestry in f.original_absent.items()},'public_sql':{'sha256':f.public_sql_before[0],'metadata':list(f.public_sql_before[1])},'master':list(f.master),'uncertainty':{k:getattr(f,k)for k in('sql_uncertain','process_uncertain','identity_uncertain','creation_uncertain')}}
        web=self.web
        state['frontend']=None if web is None else {'root':None if web.http_root is None else str(web.http_root),'files':{str(k):list(v)for k,v in web.files.items()},'dirs':{str(k):list(v)for k,v in web.dirs.items()},'generated_dirs':{str(k):list(v)for k,v in web.generated_dirs.items()},'guardian_pid':None if web.guardian is None else web.guardian.pid,'custody':getattr(web,'custody',None),'requests_stopped':web.requests_stopped,'disposed':web.disposed}
        state['helper_sha256']=self.p['helper_sha256'];state['web_sha256']=self.p['web_sha256']
        state.update({k:self.p[k]for k in HELPER_BINDING if k in self.p})
        state['mutation_submission_started']=self.mutation_submission_started
        if web is not None:
            diagnostic=web.native_diagnostic()
            record=diagnostic_record(self.p,diagnostic)
            raw_record=json.dumps(record,sort_keys=True,separators=(',',':')).encode()
            require(len(raw_record)<=32768,'diagnostic_bound')
            state['native_diagnostic_evidence']={'record':record,'sha256':sha(raw_record)}
        raw=json.dumps(state,sort_keys=True,separators=(',',':')).encode();require(len(raw)<=131072,'receipt_bound')
        if self.previous is None:require(not os.path.lexists(self.path),'recovery_collision')
        else:
            old,m=self.installer.read_regular(self.path,131072,END);require((sha(old),m)==self.previous,'recovery_changed')
        self.installer.publish(self.path,raw,0o600,0,0,END,{},readback_cap=131072)
        stored,m=self.installer.read_regular(self.path,131072,END);require(stored==raw,'recovery_readback');self.previous=(sha(raw),m)
        if 'native_diagnostic_evidence'in state:
            self.diagnostic_evidence={**state['native_diagnostic_evidence'],
                'readback_verified':True,'recovery_sha256':sha(raw)}


def run(p,report):
    probe=p.get('operation')=='confinement-probe'
    if probe:
        report.update(schema='osmap-single-host-confinement-probe-v1',
            observed_http_requests=0,start_message_sent=False,ready_observed=False,ready_only_qualified=False)
    q=load('stock_qualification.py');http=load('rust_http_driver.py');installer=load('install_account_password.py');w=load('stock_mail_witness.py');front=load('local_frontend.py')
    q.HELPER_SHA256=p['helper_sha256'];q.SIGNED_SOURCE_COMMIT=p.get('helper_source_commit',p['source_commit']);q.CONFIG_MAP_SHA256=p['config_map_sha256'];q.PUBLIC_SQL_SHA256=p['public_sql_sha256'];q.CUSTODY_SHA256=p['backend_sources']['custody.py']
    class LocalQualification(http.RustAuthoritativeCustodian,q.Qualification):
        def __init__(self):
            super().__init__();self.end=END;self.work_end=WORK;self.installer=installer;self.http=http
        def remaining(self,cleanup=False):
            left=(END if cleanup else WORK)-time.monotonic();require(left>0,'original_local_deadline');return left
        def directory(self,path,mode):
            try:return super().directory(path,mode)
            finally:
                if self.recovery is not None:self.recovery.checkpoint('DIRECTORY_BIRTH')
    f=LocalQualification();owner=None;web=None;witness=None;complete=False;events=[];snapshots={};failure=False;preservation_failure=None
    milestones={};journey_started=None;admission_finished=None;mutation_finished=None
    report['milestones']=milestones;report['authoritative_snapshots']=snapshots
    try:
        f.preflight();owner=f.recovery=Receipt(f,installer,p)
        f.provision();f.provision_service();f.prepare_rust_journey();owner.setup_complete=True;owner.checkpoint('FIXTURE_PROVISIONED')
        report['initial_authority_digests']={account:http.digest_fields(f.baseline[index],http.COLUMNS)
            for index,account in enumerate((http.ALICE,http.BOB))}
        f.start_helper();owner.checkpoint('HELPER_READY')
        milestones['milestone1']={'result':'PASS',**f.report['service_readiness']}
        # This observer spans setup, all HTTP/TOTP work and final readback. Use
        # the original work horizon, never a shorter independent lifetime.
        witness=w.StockMailWitness(f,WORK);witness.begin()
        boot={'version':1,'alice_password':f.initial_password(http.ALICE),'bob_password':f.initial_password(http.BOB),'new_password':f.new_password}
        for key,path in(('admission_key','/etc/osmap/account-admission.key'),('mutation_key','/etc/osmap/account-runtime/mutation.key'),('session_proof_key','/etc/osmap/account-runtime/session-proof.key')):
            raw=f.private_read(Path(path),64);require(re.fullmatch(rb'[a-f0-9]{64}',raw),'purpose_key_shape');boot[key]=raw.decode('ascii')
        front.STAGE=p['frontend_stage'];front.STAGE_FILES=p['frontend_files'];front.SOURCE_PINS=p['frontend_sources'];front.END=END;front.WORK=WORK
        web=front.Frontend(None);owner.web=web;web.ownership_callback=owner.checkpoint
        def exchange(tag,end):
            nonlocal admission_finished,mutation_finished
            require(len(events)<5 and tag==EVENTS[len(events)]and time.monotonic()<end,'ordered_local_event');events.append(tag)
            if tag!='MAIL_WITNESS':
                account=http.BOB if tag in('SNAPSHOT_B0','SNAPSHOT_B1')else http.ALICE
                value=f.authoritative_snapshot(account,end);snapshots[tag]=value;owner.snapshots[tag]=value;owner.checkpoint('SNAPSHOT_OBSERVED')
                if tag=='SNAPSHOT_A0':
                    admission_finished=time.monotonic()
                    readiness=milestones['milestone1'];readiness.update(parent_prepare=True,parent_seal=True,
                        acceptance_proof='ACTUAL_ALICE_AND_BOB_TRUSTED_PEER_ADMISSION')
                    milestones['milestone2']={'result':'PASS','elapsed_seconds':round(admission_finished-journey_started,6),
                        'alice_admitted':True,'bob_admitted':True,'initial_epoch':0,
                        'stored_sessions_observed':True,'mutation_totp_consumed':False}
                elif tag=='SNAPSHOT_A1':
                    mutation_finished=time.monotonic()
                    milestones['milestone3']={'result':'PENDING_VERIFICATION','elapsed_seconds':round(mutation_finished-admission_finished,6),
                        'authoritative_conditional_write_observed':True,'alice_epoch':value['epoch'],
                        'alice_state':value['state'],'changed_at':value['changed_at']}
                return {'phase':tag,'snapshot':value}
            http.confirmed_change(snapshots['SNAPSHOT_A0'],snapshots['SNAPSHOT_A1'],snapshots['SNAPSHOT_B0'],snapshots['SNAPSHOT_B1'])
            value=witness.finish_after_change();require(time.monotonic()<end,'original_http_deadline')
            require(value['result']=='PASS','mail_witness');report['mail_witness']=value
            milestones['milestone4']={'result':'PENDING_DISPOSITION','elapsed_seconds':round(time.monotonic()-mutation_finished,6),
                'bob_mail_projection_preserved':value['bob_mail_projection_preserved'],
                'bob_home_absent':value['bob_home_absent'],'bob_mail_absent':value['bob_mail_absent'],
                'public_cache_zero':value['public_cache_zero']}
            return {'phase':tag,'result':value}
        web.local_exchange=exchange
        if probe:
            # The only diagnostic route exits through existing preservation and
            # no-write cleanup, even when confinement unexpectedly reaches READY.
            web.setup(boot,confinement_probe=True)
            require(web.custody['selector']==SELECTOR,'native_local_selector')
            report['ready_observed']=True
            raise Refused('confinement_probe_ready_observed')
        web.setup(boot)
        def mutation_submission_checkpoint():
            owner.mutation_submission_started=True;owner.checkpoint('MUTATION_SUBMISSION_INTENT')
        web.driver.mutation_submission_checkpoint=mutation_submission_checkpoint
        require(web.custody['selector']==SELECTOR,'native_local_selector')
        web.control.write(b'G',min(WORK,time.monotonic()+5))
        journey_started=time.monotonic()
        outcome=web.journey_module.journey(web.driver);require(events==list(EVENTS),'complete_event_set')
        require(web.requests_stopped,'actual_http_stopped');f.inspect_state(after_test=True)
        report.update(functional_result='PASS',observed_http_requests=outcome['observed_http_requests'],known_write_time=outcome['known_write_time'],actual_http_report=web.driver.actual_http_report,mutation_evidence=outcome['mutation_evidence'],timings=outcome['timings'])
        complete=True
    except BaseException as error:
        failure=True;report['functional_result']='FAIL'
        report['failure_category']=failure_category(error)
        report['failure_reason']=failure_reason(error)
        if web is not None and hasattr(web,'preserve_failure'):
            try:web.preserve_failure(error)
            except BaseException as secondary:preservation_failure=secondary
    finally:
        cleanup_started=time.monotonic();cleanup_ok=True
        def cleanup_error(phase,error):
            report.setdefault('cleanup_failures',[]).append({'phase':phase,
                'category':failure_category(error),'reason':failure_reason(error)})
        if preservation_failure is not None:
            cleanup_ok=False;cleanup_error('diagnostic_preservation',preservation_failure)
        # A durable intent is authoritative even if driver construction/dispatch
        # is interrupted; never reset it from a missing driver attribute.
        submitted=bool((owner is not None and owner.mutation_submission_started)or
            (web is not None and getattr(getattr(web,'driver',None),'mutation_submission_started',False)))
        report['mutation_submission_started']=submitted
        report['mutation_requests']=getattr(getattr(web,'driver',None),'mutation_requests',0)
        if owner is not None:owner.mutation_submission_started=submitted
        if web is not None and getattr(web,'driver',None) is not None:
            report['timings']=dict(getattr(web.driver,'milestone_timings',report.get('timings',{})))
            if web.driver.actual_http_report is not None:
                report['actual_http_report']=web.driver.actual_http_report
            if failure:report['http_failure_scalars']=web.driver.failure_scalars()
        try:
            if owner is not None and web is not None:
                owner.checkpoint('DIAGNOSTIC_BEFORE_STOP')
        except BaseException as error:
            cleanup_ok=False;cleanup_error('diagnostic_preservation',error)
        try:
            if web is not None:
                if not web.requests_stopped:web.stop_requests()
                require(web.requests_stopped,'producer_stop_required')
            if owner is not None:owner.requests_stopped=True;owner.checkpoint('REQUESTS_STOPPED')
        except BaseException as error:
            cleanup_ok=False;cleanup_error('frontend_stop',error)
        try:
            if witness is not None:witness.close()
        except BaseException as error:
            cleanup_ok=False;cleanup_error('witness_close',error)
        try:
            if f.helper is not None and not f.helper_stopped:f.stop_helper()
            if owner is not None:owner.checkpoint('HELPER_STOPPED')
        except BaseException as error:
            cleanup_ok=False;cleanup_error('helper_stop',error)
        # Freeze the final capture in the existing protected recovery receipt
        # before owned directories, session state or native evidence are removed.
        diagnostic_preserved=web is None
        try:
            if owner is not None and web is not None:
                owner.checkpoint('DIAGNOSTIC_CAPTURED')
                evidence=getattr(owner,'diagnostic_evidence',None)
                if evidence is not None:
                    report['native_diagnostic_evidence']=evidence
                    diagnostic_preserved=evidence['readback_verified']is True
                else:raise Refused('diagnostic_not_preserved')
        except BaseException as error:
            cleanup_ok=False;cleanup_error('diagnostic_preservation',error)
        report['diagnostic_preservation']='READBACK_VERIFIED'if report.get('native_diagnostic_evidence')else'UNAVAILABLE'
        no_write=False
        try:
            if cleanup_ok and owner is not None and owner.setup_complete:
                # Fresh authority reads after stopping both producers. No rollback.
                observed={account:f.authoritative_snapshot(account,END,cleanup=True)for account in(http.ALICE,http.BOB)}
                report['final_authority']=observed
                owner.snapshots.update(FINAL_ALICE=observed[http.ALICE],FINAL_BOB=observed[http.BOB])
                owner.checkpoint('FINAL_AUTHORITY_OBSERVED')
                epochs={account:f.rust_epoch(account)[0]for account in(http.ALICE,http.BOB)}
                report['durable_intents']={account:{'epoch':v['epoch'],'state':v['state'],
                    'changed_at':v['changed_at'],'pending_intent':v['intent']is not None,
                    'used_intent_count':len(v['used_intents'])}for account,v in epochs.items()}
                if complete:
                    require(observed=={http.ALICE:snapshots['SNAPSHOT_A1'],http.BOB:snapshots['SNAPSHOT_B1']},
                        'authority_changed_before_disposal')
                    require(epochs[http.ALICE]['intent']is None and len(epochs[http.ALICE]['used_intents'])==1
                        and epochs[http.BOB]['intent']is None and epochs[http.BOB]['used_intents']==[],
                        'single_durable_mutation_intent')
                no_write=not submitted and all(value['row_sha256']==http.digest_fields(f.baseline[index],http.COLUMNS)
                    and value['epoch']==0 and value['state']=='active'and value['changed_at']is None
                    and epochs[account]['intent']is None and epochs[account]['used_intents']==[]
                    for index,(account,value)in enumerate(observed.items()))
        except BaseException as error:
            cleanup_ok=False;cleanup_error('final_authority',error)
            if complete:report['functional_result']='FAIL';complete=False
        report['proven_before_submission_no_write']=no_write
        report['authoritative_state_certainty']='CONFIRMED_NO_WRITE'if no_write else('CONFIRMED_CHANGE'if complete and cleanup_ok else'UNKNOWN')
        try:
            if cleanup_ok and diagnostic_preserved and (complete or no_write) and owner is not None and owner.setup_complete and owner.requests_stopped and (f.helper is None or f.helper_stopped) and all(not getattr(f,k)for k in('sql_uncertain','process_uncertain','identity_uncertain','creation_uncertain')):
                owner.checkpoint('DISPOSITION_INTENT')
                # Full verified success or independently proven pre-submission no-write only.
                # Keep session files until backend disposal has succeeded.
                f.cleanup();require(f.report.get('cleanup_confirmed')is True,'owned_cleanup')
                if web is not None:web.dispose();require(web.disposed,'frontend_disposal')
                owner.checkpoint('DISPOSED');report['disposition']='CONFIRMED'
            elif owner is None and not f.provisioning_started:report['disposition']='NO_EFFECTS'
            else:report['disposition']='RETAINED_REQUIRES_REVIEW'
        except BaseException as error:
            report['disposition']='RETAINED_REQUIRES_REVIEW';cleanup_error('owned_disposal',error)
        report.setdefault('timings',{})['cleanup_seconds']=round(time.monotonic()-cleanup_started,6)
        report['frontend_cleanup']={'requests_stopped':web is None or web.requests_stopped,'disposed':web is None or web.disposed}
        report['helper_diagnostic']=f.helper_diagnostic
        report['owned_effects_report']=f.report
        report['result']='PASS'if complete and not failure and report['disposition']=='CONFIRMED'else'FAIL'
        if report['result']=='PASS':
            milestones['milestone3']['result']='PASS';milestones['milestone4']['result']='PASS'
        else:
            for key in('milestone3','milestone4'):
                if key in milestones:milestones[key]['result']='NOT_QUALIFIED'
        report['recovery_receipt']=None if owner is None else str(owner.path)
        if owner is not None and getattr(owner,'diagnostic_evidence',None)is not None:
            report['native_diagnostic_evidence']=owner.diagnostic_evidence


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077);os.chdir('/')
    report={'schema':'osmap-single-host-controlled-journey-v1','result':'FAIL','functional_result':'NOT_RUN','disposition':'NOT_RUN','installed_qualification':False,'slice_complete':False,'public_service_controls':False,'public_config_writes':False,'relay_operations':False,'credential_values_retained':False}
    def stop(_number,_frame):raise Refused('actor_interrupted')
    for number in STOPS:signal.signal(number,stop)
    try:
        require(len(sys.argv)==2,'one_admission_hash');p=admission(sys.argv[1]);signal.alarm(max(1,math.ceil(END-time.monotonic())));run(p,report)
    except BaseException as error:
        report['result']='FAIL';report['admission_or_actor_failure']=True
        report.setdefault('failure_category',failure_category(error));report.setdefault('failure_reason',failure_reason(error))
    finally:signal.alarm(0)
    report['elapsed_millis']=int((time.monotonic()-START)*1000);print(json.dumps(report,sort_keys=True));return 0 if report['result']=='PASS'else 1
if __name__=='__main__':raise SystemExit(main())
