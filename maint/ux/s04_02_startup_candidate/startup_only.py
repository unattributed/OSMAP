"""Finite native admission qualification using the existing owned fixture."""
import importlib.util,json,math,os,resource,signal,socket,stat,subprocess,sys,time
import re
from pathlib import Path

sys.dont_write_bytecode=True
STAGE=Path(__file__).resolve().parent
START=time.monotonic();STOP_SIGNALS=(signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGALRM)

# A real wire caller, executed as the configured trusted UID. Secrets enter
# only its inherited stdin pipe; no mutation socket or operation is reachable.
ADMISSION_CALLER=r'''
import ctypes,hashlib,hmac,json,os,resource,secrets,socket,struct,sys,time
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
class Refused(Exception):pass
def require(ok,code):
    if not ok:raise Refused(code)
def encode(value):return json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
def unique(pairs):
    result={}
    for k,v in pairs:require(k not in result,'duplicate_response');result[k]=v
    return result
def receive(sock,count,end):
    value=b''
    while len(value)<count:
        left=end-time.monotonic();require(left>0,'native_deadline');sock.settimeout(left)
        part=sock.recv(count-len(value));require(bool(part),'native_response_eof');value+=part
    return value
result={'result':'FAIL','frame_sent':False};started=None
try:
    boot=json.loads(sys.stdin.buffer.read(4097));require(set(boot)=={'account','operation','key','invalid_mac'},'boot_shape')
    require(os.getuid()==os.geteuid()==1001,'caller_uid')
    account=boot['account'];operation=boot['operation'];key=boot['key'].encode('ascii')
    require(account in ('alice@osmap-password.invalid','bob@osmap-password.invalid') and len(key)==64,'caller_scope')
    require(operation.get('operation') in ('authenticate','admit'),'admission_only')
    require(set(operation)==({'operation','password'} if operation['operation']=='authenticate' else {'operation','epoch'}),'operation_shape')
    schema='osmap-account-admission-v1';issued=int(time.time());nonce=secrets.token_hex(16)
    payload=[schema,'request',account,operation,issued,issued+35,nonce]
    signature=hmac.new(key,encode(payload),hashlib.sha256).hexdigest()
    if boot['invalid_mac']:signature=('0' if signature[0]!='0' else '1')+signature[1:]
    request={'schema':schema,'account':account,'operation':operation,'issued':issued,'expires':issued+35,'nonce':nonce,'signature':signature}
    wire=encode(request);require(0<len(wire)<=4096,'request_bound')
    started=time.monotonic();end=started+30
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(max(.001,end-time.monotonic()));sock.connect('/var/run/osmap-account-admission/admission.sock')
        libc=ctypes.CDLL(None,use_errno=True);uid=ctypes.c_uint();gid=ctypes.c_uint()
        libc.getpeereid.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint),ctypes.POINTER(ctypes.c_uint)];libc.getpeereid.restype=ctypes.c_int
        require(libc.getpeereid(sock.fileno(),ctypes.byref(uid),ctypes.byref(gid))==0 and uid.value==0,'server_peer_uid')
        sock.settimeout(max(.001,end-time.monotonic()));sock.sendall(struct.pack('!I',len(wire))+wire);result['frame_sent']=True
        if boot['invalid_mac']:
            sock.settimeout(max(.001,end-time.monotonic()));require(sock.recv(1)==b'','invalid_mac_returned_admission')
            result.update(result='AWAITING_NATIVE_DIAGNOSTIC',status='closed',authenticated_response=False)
        else:
            length=struct.unpack('!I',receive(sock,4,end))[0];require(0<length<=4096,'response_bound')
            response=json.loads(receive(sock,length,end),object_pairs_hook=unique)
            require(set(response) in ({'schema','account','nonce','status','epoch','signature'}, {'schema','account','nonce','status','epoch','signature','changed_at'}),'response_shape')
            require(response['schema']==schema and response['account']==account and response['nonce']==nonce,'response_binding')
            require(issued<=int(time.time())<issued+35 and time.monotonic()<end,'response_expired')
            response_payload=[schema,'response',account,nonce,response['status'],response['epoch']]
            if response.get('changed_at') is not None:response_payload.append(response['changed_at'])
            require(hmac.compare_digest(hmac.new(key,encode(response_payload),hashlib.sha256).hexdigest(),response['signature']),'response_mac')
            require(response.get('changed_at') is None,'unexpected_changed_at')
            require((response['status']=='active' and type(response['epoch']) is int and 0<=response['epoch']<2**64-1) or (response['status']=='rejected' and response['epoch'] is None),'response_status')
            if operation['operation']=='admit' and response['status']=='active':require(response['epoch']==operation['epoch'],'response_epoch')
            result.update(result='PASS',status=response['status'],epoch=response['epoch'],account=account,authenticated_response=True)
    result.update(server_peer_uid=0,caller_uid=1001)
except BaseException as error:
    result['failure']=str(error) if type(error) is Refused else 'caller_'+type(error).__name__
finally:
    if started is not None:result['round_trip_ms']=round((time.monotonic()-started)*1000,3)
print(json.dumps(result,sort_keys=True))
'''


def load_path(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


journey=None
class Refused(Exception):pass
class ProbeCleanupUnconfirmed(Refused):pass
def require(value,code):
    if not value:raise Refused(code)
def failure_reason(error):
    """Preserve a structured refusal code without exporting arbitrary text."""
    code=getattr(error,'code',None)
    if isinstance(code,str)and re.fullmatch(r'[A-Za-z0-9_.:-]{1,96}',code):return code
    reason=str(error)
    if type(error)in(Refused,ProbeCleanupUnconfirmed,getattr(journey,'Refused',None))and re.fullmatch(r'[A-Za-z0-9_.:-]{1,96}',reason):return reason
    return 'UNEXPECTED_SANITIZED'
def initialize():
    global journey
    journey=load_path('milestone1_retained_journey',STAGE/'local_journey.py')


def drop_probe_identity():
    os.setgroups([1001,1003]);os.setgid(1001);os.setuid(1001)


def probe(path,absolute_end,disposition,boot=None):
    """One UID-authorized connect/EOF exchange; writes no protocol frame."""
    disposition.clear();disposition['cleanup_confirmed']=False
    code=("import json,socket,sys,time\n"
          "p=sys.argv[1];s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(8)\n"
          "t=time.monotonic();s.connect(p);connected=time.monotonic();s.shutdown(socket.SHUT_WR)\n"
          "data=s.recv(1);closed=time.monotonic();s.close()\n"
          "if data:raise SystemExit(7)\n"
          "print(json.dumps({'connected_ms':round((connected-t)*1000,3),'handled_ms':round((closed-t)*1000,3)}))\n")
    if boot is not None:code=ADMISSION_CALLER
    child=None;result=None
    try:
        require(time.monotonic()<absolute_end,'probe_deadline')
        previous=signal.pthread_sigmask(signal.SIG_BLOCK,STOP_SIGNALS)
        try:
            def child_setup():
                signal.pthread_sigmask(signal.SIG_SETMASK,previous);drop_probe_identity()
            child=subprocess.Popen(('/usr/local/bin/python3','-I','-c',code,str(path)),cwd='/',
                stdin=subprocess.DEVNULL if boot is None else subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                close_fds=True,start_new_session=True,preexec_fn=child_setup,
                env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/var/empty','LC_ALL':'C'})
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
        timeout=max(.001,min(12 if boot is None else 32,absolute_end-time.monotonic()))
        if boot is None:out,err=child.communicate(timeout=timeout)
        else:out,err=child.communicate(json.dumps(boot,separators=(',',':')).encode(),timeout=timeout)
        require(child.returncode==0 and not err and 0<len(out)<=1024,'authorized_probe_failed')
        value=json.loads(out)
        require(type(value)is dict,'probe_result')
        if boot is None:require(set(value)=={'connected_ms','handled_ms'}
            and all(type(value[k])in(int,float)and 0<=value[k]<12000 for k in value),'probe_result')
        result=value
    except subprocess.TimeoutExpired:
        raise Refused('authorized_probe_timeout')from None
    finally:
        if child is not None:
            cleanup_error=False;reaped=False;group_absent=False
            mask=signal.pthread_sigmask(signal.SIG_BLOCK,STOP_SIGNALS)
            try:
                if child.returncode is None:
                    try:os.killpg(child.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    except BaseException:cleanup_error=True
                    try:child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        try:os.killpg(child.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        except BaseException:cleanup_error=True
                        try:child.wait(timeout=2)
                        except BaseException:cleanup_error=True
                    except BaseException:cleanup_error=True
                reaped=child.returncode is not None
                for pipe in(child.stdout,child.stderr,getattr(child,'stdin',None)):
                    if pipe is not None and not pipe.closed:
                        try:pipe.close()
                        except BaseException:cleanup_error=True
                try:os.killpg(child.pid,0)
                except ProcessLookupError:group_absent=True
                except PermissionError:pass
                except BaseException:cleanup_error=True
                if reaped and group_absent and not cleanup_error:
                    disposition['cleanup_confirmed']=True
            finally:signal.pthread_sigmask(signal.SIG_SETMASK,mask)
            if disposition['cleanup_confirmed']is not True:
                raise ProbeCleanupUnconfirmed('probe_cleanup_unconfirmed')
    require(result is not None,'probe_result_missing');result['cleanup_confirmed']=True;return result


def authoritative_no_write(effects):
    """Convert the actual SQL/epoch inspection into a closed no-write receipt."""
    require(effects.get('actual_write_observed')is False,'startup_password_write_observed')
    require(effects.get('Alice_exact15_preserved')is True and effects.get('Alice_epoch')==0
        and effects.get('Alice_state')=='active','startup_Alice_not_baseline')
    require(effects.get('Bob_all17_preserved')is True,'startup_Bob_not_baseline')
    return {'actual_write_observed':False,'Alice_exact17_preserved':True,
        'Alice_epoch':0,'Alice_state':'active','Alice_changed_at':None,
        'Bob_all17_preserved':True,'Bob_epoch':0,'Bob_state':'active'}


def can_dispose(cleanup_ok,probe_cleanup_ok,owner,fixture):
    return (cleanup_ok and probe_cleanup_ok and owner is not None and owner.setup_complete
        and owner.requests_stopped and fixture.helper_stopped
        and all(not getattr(fixture,key)for key in('sql_uncertain','process_uncertain','identity_uncertain','creation_uncertain')))


def run(p,report):
    q=journey.load('stock_qualification.py');http=journey.load('rust_http_driver.py');installer=journey.load('install_account_password.py')
    q.HELPER_SHA256=p['helper_sha256'];q.SIGNED_SOURCE_COMMIT=p['source_commit'];q.CONFIG_MAP_SHA256=p['config_map_sha256'];q.PUBLIC_SQL_SHA256=p['public_sql_sha256'];q.CUSTODY_SHA256=p['backend_sources']['custody.py']
    class LocalQualification(http.RustAuthoritativeCustodian,q.Qualification):
        def __init__(self):
            super().__init__();self.end=journey.END;self.work_end=journey.WORK;self.installer=installer;self.http=http
        def remaining(self,cleanup=False):
            left=(journey.END if cleanup else journey.WORK)-time.monotonic();require(left>0,'original_local_deadline');return left
        def directory(self,path,mode):
            try:return super().directory(path,mode)
            finally:
                if self.recovery is not None:self.recovery.checkpoint('DIRECTORY_BIRTH')
    f=LocalQualification();owner=None;complete=False;probe_dispositions=[]
    try:
        overhead=time.monotonic()
        f.preflight();owner=f.recovery=journey.Receipt(f,installer,p)
        f.provision();f.provision_service();owner.setup_complete=True;owner.checkpoint('FIXTURE_PROVISIONED')
        baseline={account:f.authoritative_snapshot(account,journey.WORK) for account in http.ACCOUNTS}
        epoch_baseline={account:f.rust_epoch(account)[0] for account in http.ACCOUNTS}
        report['baseline']=baseline
        report['fixture_overhead_seconds']=round(time.monotonic()-overhead,6)
        startup_started=time.monotonic()
        try:f.start_helper()
        finally:report['startup_observation_seconds']=round(time.monotonic()-startup_started,6)
        owner.checkpoint('HELPER_READY')
        readiness=f.report['service_readiness'];before={str(path):journey.ident(path.lstat()) for path in q.SOCKETS}
        key=f.private_read(Path('/etc/osmap/account-admission.key'),64).decode('ascii')
        requests=report['requests']={}
        def request(label,account,operation,status,invalid=False):
            report['current_operation']=label
            disposition={};probe_dispositions.append(disposition)
            value=probe(q.SOCKETS[0],min(journey.WORK,time.monotonic()+32),disposition,
                {'account':account,'operation':operation,'key':key,'invalid_mac':invalid})
            requests[label]=value
            if value.get('frame_sent') is True:report['admission_frames']+=1
            require(value.get('result')==('AWAITING_NATIVE_DIAGNOSTIC' if invalid else 'PASS'),
                label+'_'+value.get('failure','caller_result'))
            require(value['status']==status,label+'_unexpected_status')
            if status=='active':require(value['account']==account and value['epoch']==baseline[account]['epoch'],label+'_authority')
            require(os.waitid(os.P_PID,f.helper.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is None,'helper_exited_after_request')
            require(all(journey.ident(path.lstat())==before[str(path)] for path in q.SOCKETS),'socket_changed_after_request')
            return value
        alice=request('alice_authenticate',http.ALICE,{'operation':'authenticate','password':f.initial_password(http.ALICE)},'active')
        request('alice_admit',http.ALICE,{'operation':'admit','epoch':alice['epoch']},'active')
        # Fixed disposable incorrect credential; never reuse another request's nonce.
        wrong=f.initial_password(http.ALICE)+'-incorrect'
        request('alice_wrong_password',http.ALICE,{'operation':'authenticate','password':wrong},'rejected')
        request('alice_wrong_epoch',http.ALICE,{'operation':'admit','epoch':alice['epoch']+1},'rejected')
        request('invalid_mac',http.ALICE,{'operation':'admit','epoch':alice['epoch']},'closed',True)
        request('bob_authenticate',http.BOB,{'operation':'authenticate','password':f.initial_password(http.BOB)},'active')
        report['current_operation']='authoritative_preservation'
        after={account:f.authoritative_snapshot(account,journey.WORK) for account in http.ACCOUNTS}
        require(after==baseline,'authoritative_snapshot_changed')
        require(all(f.rust_epoch(account)[0]==epoch_baseline[account] for account in http.ACCOUNTS),'durable_epoch_changed')
        report['after']=after
        f.inspect_state(after_test=False)
        no_write=authoritative_no_write(f.report)
        readiness.update(parent_prepare=True,parent_seal=True,
            acceptance_proof='SIGNED_NATIVE_ALICE_BOB_AUTHENTICATION_AND_EPOCH_ADMISSION')
        report.update(functional_result='PENDING_INTEGRITY_DIAGNOSTIC',service_readiness=readiness,
            authoritative_no_write=no_write,authoritative_preservation=True,
            stored_sessions={'issuance':'NOT_RUN','existing_controlled_session':'ABSENT_IN_THIS_FIXTURE',
                'reason':'No guarded session runtime started; epoch admission is not session issuance.'})
        complete=True
    except BaseException as error:
        report['functional_result']='FAIL';report['failure_category']=type(error).__name__
        report['failure_reason']=failure_reason(error)
    finally:
        probe_cleanup_ok=all(item.get('cleanup_confirmed')is True for item in probe_dispositions)
        cleanup_ok=True
        try:
            if owner is not None:owner.requests_stopped=True;owner.checkpoint('REQUESTS_STOPPED')
            if f.helper is not None and not f.helper_stopped:f.stop_helper()
            if owner is not None:owner.checkpoint('HELPER_STOPPED')
            if owner is not None and owner.setup_complete and 'baseline' in report:
                observed={account:f.authoritative_snapshot(account,journey.END) for account in http.ACCOUNTS}
                report['after']=observed
                report['authoritative_preservation']=observed==report['baseline']
                require(report['authoritative_preservation'],'authoritative_snapshot_changed')
        except BaseException as error:
            cleanup_ok=False;report['cleanup_failure_reason']=failure_reason(error)
        try:
            if can_dispose(cleanup_ok,probe_cleanup_ok,owner,f):
                owner.restoration_attempted=True;owner.checkpoint('DISPOSITION_INTENT');f.cleanup();require(f.report.get('cleanup_confirmed')is True,'owned_cleanup')
                owner.checkpoint('DISPOSED');report['disposition']='CONFIRMED'
            elif owner is None and not f.provisioning_started:report['disposition']='NO_EFFECTS'
            else:report['disposition']='RETAINED_REQUIRES_REVIEW'
        except BaseException as error:
            report['disposition']='RETAINED_REQUIRES_REVIEW'
            report['cleanup_failure_reason']=failure_reason(error)
        if complete:
            diagnostic=f.helper_diagnostic
            if diagnostic.get('helper_trace_stage')=='stock_admission' and diagnostic.get('helper_trace_error')=='Authentication':
                report['requests']['invalid_mac'].update(result='PASS',native_refusal='Authentication')
                report['functional_result']='PASS'
            else:
                complete=False;report['functional_result']='FAIL';report['failure_reason']='integrity_diagnostic_missing'
        report['helper_diagnostic']=f.helper_diagnostic;report['owned_effects_report']=f.report
        report['result']='PASS'if complete and report['disposition']=='CONFIRMED'else'FAIL'
        report['recovery_receipt']=None if owner is None else str(owner.path)


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077);os.chdir('/')
    report={'schema':'osmap-single-host-admission-v1','result':'FAIL','functional_result':'NOT_RUN','disposition':'NOT_RUN','password_mutation':False,'admission_frames':0,'mutation_frames':0,'public_service_controls':False,'public_config_writes':False,'relay_operations':False,'credential_values_retained':False}
    def stop(_number,_frame):raise journey.Refused('actor_interrupted')
    for number in STOP_SIGNALS:signal.signal(number,stop)
    try:
        initialize();require(len(sys.argv)==2,'one_admission_hash');p=journey.admission(sys.argv[1]);signal.alarm(max(1,math.ceil(journey.END-time.monotonic())));run(p,report)
    except BaseException as error:
        report['result']='FAIL';report['admission_or_actor_failure']=True;report['failure_category']=type(error).__name__
        report['failure_reason']=failure_reason(error)
    finally:signal.alarm(0)
    report['elapsed_millis']=int((time.monotonic()-START)*1000);print(json.dumps(report,sort_keys=True));return 0 if report['result']=='PASS'else 1


if __name__=='__main__':raise SystemExit(main())
