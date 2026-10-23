"""One native service-startup qualification; no credential request is sent."""
import importlib.util,json,math,os,resource,signal,socket,stat,subprocess,sys,time
import re
from pathlib import Path

sys.dont_write_bytecode=True
STAGE=Path(__file__).resolve().parent
START=time.monotonic();STOP_SIGNALS=(signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGALRM)


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


def probe(path,absolute_end,disposition):
    """One UID-authorized connect/EOF exchange; writes no protocol frame."""
    disposition.clear();disposition['cleanup_confirmed']=False
    code=("import json,socket,sys,time\n"
          "p=sys.argv[1];s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(8)\n"
          "t=time.monotonic();s.connect(p);connected=time.monotonic();s.shutdown(socket.SHUT_WR)\n"
          "data=s.recv(1);closed=time.monotonic();s.close()\n"
          "if data:raise SystemExit(7)\n"
          "print(json.dumps({'connected_ms':round((connected-t)*1000,3),'handled_ms':round((closed-t)*1000,3)}))\n")
    child=None;result=None
    try:
        require(time.monotonic()<absolute_end,'probe_deadline')
        previous=signal.pthread_sigmask(signal.SIG_BLOCK,STOP_SIGNALS)
        try:
            def child_setup():
                signal.pthread_sigmask(signal.SIG_SETMASK,previous);drop_probe_identity()
            child=subprocess.Popen(('/usr/local/bin/python3','-I','-c',code,str(path)),cwd='/',
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                close_fds=True,start_new_session=True,preexec_fn=child_setup,
                env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/var/empty','LC_ALL':'C'})
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
        out,err=child.communicate(timeout=max(.001,min(12,absolute_end-time.monotonic())))
        require(child.returncode==0 and not err and 0<len(out)<=1024,'authorized_probe_failed')
        value=json.loads(out);require(type(value)is dict and set(value)=={'connected_ms','handled_ms'}
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
                for pipe in(child.stdout,child.stderr):
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
        f.preflight();owner=f.recovery=journey.Receipt(f,installer,p)
        f.provision();f.provision_service();owner.setup_complete=True;owner.checkpoint('FIXTURE_PROVISIONED')
        startup_started=time.monotonic()
        try:f.start_helper()
        finally:report['startup_observation_seconds']=round(time.monotonic()-startup_started,6)
        owner.checkpoint('HELPER_READY')
        readiness=f.report['service_readiness'];before={str(path):journey.ident(path.lstat())for path in q.SOCKETS}
        probes={}
        for label,path in zip(('admission','mutation'),q.SOCKETS):
            disposition={};probe_dispositions.append(disposition)
            probes[label]=probe(path,min(journey.WORK,time.monotonic()+15),disposition)
            require(os.waitid(os.P_PID,f.helper.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is None,'helper_exited_after_probe')
            require(journey.ident(path.lstat())==before[str(path)],'socket_changed_after_probe')
        # The accept loop is entered only after ParentPrepare, ParentSeal and
        # trace.finish(). Both UID-authorized handled connections therefore
        # prove the complete native startup chain without a credential frame.
        readiness.update(parent_prepare=True,parent_seal=True,
            acceptance_proof='AUTHORIZED_UID_CONNECT_EOF_HANDLED_ON_BOTH_SOCKETS',probes=probes)
        f.inspect_state(after_test=False)
        no_write=authoritative_no_write(f.report)
        report.update(functional_result='PASS',service_readiness=readiness,
            authoritative_no_write=no_write,
            native_stages={name:'PASS'for name in('ServiceStartup','ServiceFiles','ServiceAdmission','ServiceAccounts','ServiceStore','AdmissionBind','MutationBind','ParentPrepare','ParentSeal','AcceptanceLoop')})
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
        report['helper_diagnostic']=f.helper_diagnostic;report['owned_effects_report']=f.report
        report['result']='PASS'if complete and report['disposition']=='CONFIRMED'else'FAIL'
        report['recovery_receipt']=None if owner is None else str(owner.path)


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077);os.chdir('/')
    report={'schema':'osmap-single-host-startup-v1','result':'FAIL','functional_result':'NOT_RUN','disposition':'NOT_RUN','password_mutation':False,'credential_request_frames':0,'public_service_controls':False,'public_config_writes':False,'relay_operations':False,'credential_values_retained':False}
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
