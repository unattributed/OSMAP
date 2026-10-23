"""One checked Milestone 1 startup-only dispatch; no retry or credential frame."""
import base64,datetime,hashlib,importlib.util,json,os,shlex,signal,subprocess,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parent;REPO=Path('/home/foo/Workspace/OSMAP')
ATTEMPT='S04-02-native-milestone1-startup145';RECIPE='single-host-milestone1-startup145'
BASE='b4bc371bd645ea009e4d257b269c73bd7294c8e9'
VALIDATOR_SHA256='a11d5cae00e64eb8e604ddfef45a9074a55e3f320fc0437ee29f036f5ca1659d'


def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(value,code):
    if not value:raise RuntimeError(code)
def save(name,raw):
    fd=os.open(ROOT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
def module(name):
    spec=importlib.util.spec_from_file_location('startup_'+name,ROOT/(name+'.py'));value=importlib.util.module_from_spec(spec);sys.modules[spec.name]=value;spec.loader.exec_module(value);return value
def dispose(child,record):
    record['local_transport_disposition']='UNCERTAIN'
    if child.returncode is None:
        try:os.killpg(child.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        try:child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            if child.returncode is None:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
            child.wait(timeout=2)
    if child.returncode is not None:
        record['local_transport_reaped']=True
        try:os.killpg(child.pid,0)
        except ProcessLookupError:record['local_transport_disposition']='CONFIRMED'
        except PermissionError:pass


def main():
    os.umask(0o077);started=time.monotonic();child=None
    record={'schema':'osmap-milestone1-startup-dispatch-v1','attempt_id':ATTEMPT,'dispatched':False,
        'native_result':'NOT_RUN','remote_disposition':'NOT_DISPATCHED','password_mutation':False,'public_service_operations':False}
    try:
        for name in('startup-attempt-started.json','startup-result.json','startup-pre-action-stdout.log','startup-pre-action-stderr.log'):
            require(not os.path.lexists(ROOT/name),'one_shot_collision')
        save('startup-attempt-started.json',json.dumps(record,sort_keys=True).encode())
        pins=json.loads((ROOT/'RUN_SOURCE_SHA256.json').read_bytes());review=json.loads((ROOT/'startup-independent-review.json').read_bytes())
        require(review['decision']=='CLEAR'and review['reviewer']=='/root/delivery_controller'and review['sources']==pins,'independent_review')
        for name,pin in pins.items():
            path=ROOT/name;info=path.lstat();require(info.st_uid==os.geteuid()and info.st_nlink==1
                and stat_mode(info)==0o600 and not path.is_symlink()and path.is_file()and sha(path.read_bytes())==pin,'source_custody')
        require(subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,timeout=5).decode().strip()==BASE,'signed_source')
        ledger=(REPO/'docs/UX_EXECUTION_LEDGER.md').read_text();block=ledger.split('<!-- OSMAP_ACTIVE_WORK_ORDER -->')[1].split('<!-- /OSMAP_ACTIVE_WORK_ORDER -->')[0].strip();order=json.loads(block[8:-4])
        action=order['execution_contract']['planned_action'];require(action['attempt_id']==ATTEMPT and action['source_revision']==pins['remote_wrapper.py'],'planned_action')
        require(sha((REPO/'maint/ux/validate_acceptance.py').read_bytes())==VALIDATOR_SHA256,'validator_source_changed')
        gate=subprocess.run(['/usr/bin/python3','-B','maint/ux/validate_acceptance.py','--work-order-only','--pre-action','--attempt-id',ATTEMPT],cwd=REPO,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        save('startup-pre-action-stdout.log',gate.stdout);save('startup-pre-action-stderr.log',gate.stderr)
        require(gate.returncode==0 and type(json.loads(gate.stdout))is dict,'pre_action_refused')
        packet=module('bind_startup').packet();packet['not_after_utc']=int(time.time())+300
        root_source=(ROOT/'stage_root.py').read_bytes();remote=(ROOT/'remote_wrapper.py').read_bytes()
        wire=json.dumps({'root_source':base64.b64encode(root_source).decode(),'packet':packet},sort_keys=True,separators=(',',':')).encode();require(len(wire)<=4*1024*1024,'packet_bound')
        save('startup-bound-packet.json',wire);record.update(packet_sha256=sha(wire),source_revision=pins['remote_wrapper.py'],not_after_utc=packet['not_after_utc'])
        command='exec /usr/local/bin/python3 -I -c '+shlex.quote(remote.decode())
        argv=['/usr/bin/ssh','-S','none','-i','/home/foo/.ssh/id_ed25519','-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ConnectTimeout=8','-o','ConnectionAttempts=1','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2','foo@192.168.1.44',command]
        record.update(dispatched=True,native_result='UNKNOWN',remote_disposition='UNCERTAIN');save('startup-dispatch-started.json',json.dumps(record,sort_keys=True).encode())
        child=subprocess.Popen(argv,cwd=REPO,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,close_fds=True)
        try:out,err=child.communicate(wire,timeout=330)
        finally:dispose(child,record)
        require(record['local_transport_disposition']=='CONFIRMED'and len(out)<=524288 and len(err)<=8192,'transport_cleanup_or_bound')
        record.update(ssh_exit=child.returncode,stdout_sha256=sha(out),stderr_sha256=sha(err),stderr_bytes=len(err));require(not err,'ssh_stderr')
        value=json.loads(out);record['transport']=value;accepted=module('consume_startup').inspect(value,child.returncode,packet['not_after_utc'])
        record.update(native_result='PASS',remote_disposition='CONFIRMED',accepted=accepted)
    except BaseException as error:
        record['failure']=str(error)if type(error)is RuntimeError else type(error).__name__
        if not record['dispatched']:record.update(native_result='REFUSED',remote_disposition='NOT_DISPATCHED')
    finally:
        record['elapsed_seconds']=round(time.monotonic()-started,3);record['ended_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        save('startup-result.json',(json.dumps(record,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps({key:value for key,value in record.items()if key!='transport'},sort_keys=True));return 0 if record['native_result']=='PASS'and record['remote_disposition']=='CONFIRMED'else 1


def stat_mode(info):return info.st_mode&0o7777
if __name__=='__main__':raise SystemExit(main())
