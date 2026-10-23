"""One checked native operation; mutation requires specific operator authority."""
import argparse,base64,datetime,hashlib,importlib.util,json,os,shlex,signal,subprocess,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parent;REPO=Path('/home/foo/Workspace/OSMAP')
RUN=ROOT
SOURCE_FILES={
    'bind_startup.py','stage_root.py','dispatch_startup.py','consume_startup.py',
    'remote_wrapper.py','startup_only.py',
    'sources/backend/custody.py','sources/backend/install_account_password.py',
    'sources/backend/local_frontend.py','sources/backend/local_journey.py',
    'sources/backend/rust_http_driver.py','sources/backend/stock_mail_witness.py',
    'sources/backend/stock_qualification.py','sources/backend/stock_schema.py',
    'sources/frontend/native_http_front_driver.py','sources/frontend/native_http_password_driver.py',
    'sources/frontend/native_http_web_guardian.py'}
VALIDATOR_SHA256='1a08edebf49a265e389f3f71a51d1dfcedc039ce9189210f96101c5bd07ecc76'


def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(value,code):
    if not value:raise RuntimeError(code)
def save(name,raw):
    fd=os.open(RUN/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
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


def check_action(order,args,pins):
    contract=order['execution_contract'];action=contract['planned_action']
    require(action['attempt_id']==args.attempt_id and action['source_revision']==pins['remote_wrapper.py']
        and action['recipe_id']==args.recipe,'planned_action')
    recipes=[item for item in contract['recipes']if item['id']==args.recipe]
    require(len(recipes)==1,'planned_recipe');recipe=recipes[0]
    arguments=[str(ROOT/'dispatch_startup.py'),'--build-receipt',args.build_receipt,
        '--source-manifest',args.source_manifest,'--run-dir',str(RUN),
        '--attempt-id',args.attempt_id,'--recipe',args.recipe]
    if getattr(args,'operation','admission')=='password-change':
        arguments+=['--operation','password-change']
    require(recipe['kind']=='NATIVE'and recipe['environment_ids']==['obsd1']
        and recipe['operations']==[{'target_id':'local','program':'/usr/bin/python3',
            'arguments':arguments,'privilege':'user'}],'planned_operation')
    targets=[item for item in contract['environment']if item['id']=='obsd1']
    require(len(targets)==1 and targets[0]['host']=='obsd1.blackbagsecurity.com'
        and targets[0]['address']=='192.168.1.44'and targets[0]['status']=='PASS','planned_target')
    require(action['max_seconds']>=360,'planned_operation_bound')


def main():
    global RUN
    parser=argparse.ArgumentParser()
    for name in('build-receipt','source-manifest','run-dir','attempt-id','recipe'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--operation',choices=('admission','password-change'),default='admission')
    args=parser.parse_args();RUN=Path(args.run_dir).resolve()
    info=RUN.lstat();require(RUN.is_dir()and info.st_uid==os.geteuid()and stat_mode(info)==0o700,'run_directory_custody')
    ATTEMPT=args.attempt_id;RECIPE=args.recipe
    os.umask(0o077);started=time.monotonic();child=None
    record={'schema':'osmap-milestone1-startup-dispatch-v1','attempt_id':ATTEMPT,'dispatched':False,
        'native_result':'NOT_RUN','remote_disposition':'NOT_DISPATCHED','operation':args.operation,
        'password_mutation':False,'public_service_operations':False}
    try:
        for name in('startup-attempt-started.json','startup-result.json','startup-pre-action-stdout.log','startup-pre-action-stderr.log'):
            require(not os.path.lexists(RUN/name),'one_shot_collision')
        save('startup-attempt-started.json',json.dumps(record,sort_keys=True).encode())
        pins=json.loads((RUN/'RUN_SOURCE_SHA256.json').read_bytes());review=json.loads((RUN/'startup-independent-review.json').read_bytes())
        require(set(pins)==SOURCE_FILES,'review_source_set')
        reviewer='/root/delivery_controller' if args.operation=='password-change' else '/root/admission_review'
        require(review['decision']=='CLEAR'and review['reviewer']==reviewer and review['sources']==pins,'independent_review')
        if args.operation=='password-change':
            authority=json.loads((RUN/'operator-authorization.json').read_bytes())
            require(authority.get('confirmed') is True and authority.get('target')=='obsd1.blackbagsecurity.com'
                and authority.get('account')=='alice@osmap-password.invalid'
                and type(authority.get('password_changes')) is int and authority['password_changes']==1
                and type(authority.get('operator_confirmation')) is str and bool(authority['operator_confirmation'].strip())
                and authority.get('exact_owned_cleanup') is True
                and authority.get('retain_uncertain_state') is True,'specific_mutation_authority')
        for name,pin in pins.items():
            path=ROOT/name;info=path.lstat();require(info.st_uid==os.geteuid()and info.st_nlink==1
                and stat_mode(info)==0o600 and not path.is_symlink()and path.is_file()and sha(path.read_bytes())==pin,'source_custody')
        packet=module('bind_startup').packet(args.build_receipt,args.source_manifest)
        if args.operation=='password-change':packet['operation']='password-change'
        ledger=(REPO/'docs/UX_EXECUTION_LEDGER.md').read_text();block=ledger.split('<!-- OSMAP_ACTIVE_WORK_ORDER -->')[1].split('<!-- /OSMAP_ACTIVE_WORK_ORDER -->')[0].strip();order=json.loads(block[8:-4])
        check_action(order,args,pins)
        require(sha((REPO/'maint/ux/validate_acceptance.py').read_bytes())==VALIDATOR_SHA256,'validator_source_changed')
        gate=subprocess.run(['/usr/bin/python3','-B','maint/ux/validate_acceptance.py','--work-order-only','--pre-action','--attempt-id',ATTEMPT],cwd=REPO,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        save('startup-pre-action-stdout.log',gate.stdout);save('startup-pre-action-stderr.log',gate.stderr)
        require(gate.returncode==0 and type(json.loads(gate.stdout))is dict,'pre_action_refused')
        packet['not_after_utc']=int(time.time())+300
        root_source=(ROOT/'stage_root.py').read_bytes();remote=(ROOT/'remote_wrapper.py').read_bytes()
        wire=json.dumps({'root_source':base64.b64encode(root_source).decode(),'packet':packet},sort_keys=True,separators=(',',':')).encode();require(len(wire)<=4*1024*1024,'packet_bound')
        save('startup-bound-packet.json',wire);record.update(packet_sha256=sha(wire),source_revision=pins['remote_wrapper.py'],not_after_utc=packet['not_after_utc'])
        command='exec /usr/local/bin/python3 -I -c '+shlex.quote(remote.decode())
        argv=['/usr/bin/ssh','-S','none','-i','/home/foo/.ssh/id_ed25519','-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ConnectTimeout=8','-o','ConnectionAttempts=1','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2','foo@192.168.1.44',command]
        record.update(dispatched=True,native_result='UNKNOWN',remote_disposition='UNCERTAIN',
            password_mutation=None if args.operation=='password-change' else False);save('startup-dispatch-started.json',json.dumps(record,sort_keys=True).encode())
        child=subprocess.Popen(argv,cwd=REPO,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,close_fds=True)
        try:out,err=child.communicate(wire,timeout=330)
        except subprocess.TimeoutExpired as error:
            out=error.output or b'';err=error.stderr or b''
            record.update(partial_stdout_sha256=sha(out),partial_stderr_sha256=sha(err),
                partial_stdout_bytes=len(out),partial_stderr_bytes=len(err))
            if len(out)<=524288:
                save('startup-partial-stdout.log',out)
                try:record['partial_transport']=json.loads(out)
                except (ValueError,UnicodeError):pass
            if len(err)<=8192:save('startup-partial-stderr.log',err)
            raise RuntimeError('ssh_transport_timeout')from None
        finally:dispose(child,record)
        require(record['local_transport_disposition']=='CONFIRMED'and len(out)<=524288 and len(err)<=8192,'transport_cleanup_or_bound')
        record.update(ssh_exit=child.returncode,stdout_sha256=sha(out),stderr_sha256=sha(err),stderr_bytes=len(err));require(not err,'ssh_stderr')
        value=json.loads(out);record['transport']=value;accepted=module('consume_startup').inspect(value,child.returncode,packet['not_after_utc'],packet)
        record.update(native_result='PASS',remote_disposition='CONFIRMED',accepted=accepted,
            password_mutation=args.operation=='password-change')
    except BaseException as error:
        record['failure']=str(error)if type(error)is RuntimeError else type(error).__name__
        if not record['dispatched']:record.update(native_result='REFUSED',remote_disposition='NOT_DISPATCHED')
    finally:
        record['elapsed_seconds']=round(time.monotonic()-started,3);record['ended_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        save('startup-result.json',(json.dumps(record,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps({key:value for key,value in record.items()if key!='transport'},sort_keys=True));return 0 if record['native_result']=='PASS'and record['remote_disposition']=='CONFIRMED'else 1


def stat_mode(info):return info.st_mode&0o7777
if __name__=='__main__':raise SystemExit(main())
