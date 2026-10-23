"""Fixed root stage producer; reviewed source and receipt scalars on stdin only.

Stages and their sanitized ownership receipt are deliberately retained. The
unchanged local actor owns and disposes only its freshly provisioned effects.
No recovery signals a PID from a receipt or reuses an expired fixture.
"""
import base64,hashlib,json,math,os,re,resource,secrets,signal,socket,stat,sys,time
from pathlib import Path

START=time.monotonic();END=START+600
BASE='77f63794d3f60e4003db157eada39f4bd4222b6a'
PYTHON=Path('/usr/local/bin/python3')
PYTHON_TARGET=re.compile(r'python3\.[0-9]{1,2}\Z')
SOURCE_PINS = {'backend/custody.py': '390e9c1ebf82dccab00323b080c8bd7fa8cb0724271bae84318c68efb56ef30e', 'backend/install_account_password.py': '536a6bcad0f666b06dbc35e0f99cd736c84d34db9774b2acc98a48f5a8ed7358', 'backend/local_frontend.py': '5b51834ba64e20aa575969bf2d1ae05b2cc2aae9c02b0be131fed6339c135a39', 'backend/local_journey.py': 'f305b1758d975e643e9fd4b65781bdb56a76a40eadf547217d70a9e40ce0542b', 'backend/rust_http_driver.py': '3f942b47f4d1068a508ffe376f8fb036c852a23841a3e5706ee392aa61a4b750', 'backend/startup_only.py': '0f286ffef32a8f85c060c9055f218d750d7cef76d4a0123427de614c94b6828f', 'backend/stock_mail_witness.py': 'ee00c432821a2caa401879af3fd4bf03b5afadefeba2950618cf2d8868290874', 'backend/stock_qualification.py': '8f851a3c3b5240699b6bdcbc687e0df098fdc23f582b4252e09b8e634e6f2e86', 'backend/stock_schema.py': '51861add9908ac12efd4d648857d31f2fed852f1fcfb1bb46019995cc5a9cb90', 'frontend/native_http_front_driver.py': '94ed7df857ba1421afa1d724372abafe0fcc055679b3a07e33d4e97d6b0645fd', 'frontend/native_http_password_driver.py': '3f942b47f4d1068a508ffe376f8fb036c852a23841a3e5706ee392aa61a4b750', 'frontend/native_http_web_guardian.py': 'a7026319931027cd286dca0e86e7d1f844cc73bb38367808f66a1f81458d2dc7'}
CONFIG_PATHS=('/etc/dovecot/dovecot.conf', '/etc/dovecot/conf.d/10-auth.conf', '/etc/dovecot/conf.d/10-director.conf', '/etc/dovecot/conf.d/10-logging.conf', '/etc/dovecot/conf.d/10-mail.conf', '/etc/dovecot/conf.d/10-master.conf', '/etc/dovecot/conf.d/10-metrics.conf', '/etc/dovecot/conf.d/10-ssl.conf', '/etc/dovecot/conf.d/15-lda.conf', '/etc/dovecot/conf.d/15-mailboxes.conf', '/etc/dovecot/conf.d/20-imap.conf', '/etc/dovecot/conf.d/20-lmtp.conf', '/etc/dovecot/conf.d/20-managesieve.conf', '/etc/dovecot/conf.d/20-pop3.conf', '/etc/dovecot/conf.d/20-submission.conf', '/etc/dovecot/conf.d/90-acl.conf', '/etc/dovecot/conf.d/90-plugin.conf', '/etc/dovecot/conf.d/90-quota.conf', '/etc/dovecot/conf.d/90-sieve-extprograms.conf', '/etc/dovecot/conf.d/90-sieve.conf', '/etc/dovecot/conf.d/99-bbs-imaps-only.conf', '/etc/dovecot/conf.d/99-bbs-managesieve-policy.conf', '/etc/dovecot/conf.d/99-rspamd-warning-labels.conf', '/etc/dovecot/local.conf', '/etc/dovecot/conf.d/auth-sql.conf.ext')
OPTIONAL=('/etc/dovecot/conf.d/99-bbs-imaps-only.conf','/etc/dovecot/conf.d/99-bbs-managesieve-policy.conf')
class Refused(Exception):pass
def require(ok,code):
    if not ok:raise Refused(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def identity(m):return(m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
def unique(pairs):
    out={}
    for k,v in pairs:require(k not in out,'duplicate_field');out[k]=v
    return out
def decode(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(Refused('nonfinite')))
def encode(value):return(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def stage_birth_receipt(backend,backend_identity,packet_sha256,not_after_utc):
    return {'schema':'osmap-single-host-stage-birth-v1','backend':str(backend),
        'backend_identity':backend_identity,'source_commit':BASE,'packet_sha256':packet_sha256,
        'not_after_utc':not_after_utc,'disposition':'PARTIAL_STAGE_RETAINED_NO_ADOPTION'}
def stage_birth_frame(backend,frontend,not_after_utc):
    return {'schema':'osmap-single-host-stage-birth-v1','backend':str(backend),
        'frontend':None if frontend is None else str(frontend),'not_after_utc':not_after_utc}
def stage_ownership_receipt(backend,frontend,backend_identity,frontend_identity,
        compiler_receipt_sha256,packet_sha256,not_after_utc,files):
    return {'schema':'osmap-single-host-stage-v1','source_commit':BASE,
        'compiler_receipt_sha256':compiler_receipt_sha256,'packet_sha256':packet_sha256,
        'not_after_utc':not_after_utc,'backend':str(backend),'frontend':str(frontend),
        'backend_identity':backend_identity,'frontend_identity':frontend_identity,
        'disposition':'STAGES_RETAINED','files':files,'historical_pid_signals':False}
def deadline():require(time.monotonic()<END-150,'stage_work_deadline')
def directory(path,owner,mode=None):
    m=path.lstat();require(stat.S_ISDIR(m.st_mode)and m.st_uid==owner and not m.st_mode&0o022,'directory_custody')
    require(mode is None or stat.S_IMODE(m.st_mode)==mode,'directory_mode')
    return identity(m)
def protected(path):
    for parent in reversed(path.parents):directory(parent,0)
def publish(path,raw,mode):
    deadline();fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        view=memoryview(raw)
        while view:deadline();n=os.write(fd,view);require(n>0,'publish_write');view=view[n:]
        os.fchmod(fd,mode);os.fsync(fd);before=identity(os.fstat(fd))
    finally:os.close(fd)
    require(identity(path.lstat())==before,'publish_continuity');return before
def read_root(path,cap):
    protected(path);m=path.lstat();before=identity(m)
    require(stat.S_ISREG(m.st_mode)and m.st_uid==0 and m.st_nlink==1 and not m.st_mode&0o022 and 0<m.st_size<=cap,'public_input_custody')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        require(identity(os.fstat(fd))==before,'public_open');raw=bytearray()
        while len(raw)<=cap:
            deadline();part=os.read(fd,min(16384,cap+1-len(raw)))
            if not part:break
            raw.extend(part)
        require(len(raw)==m.st_size and identity(os.fstat(fd))==before and identity(path.lstat())==before,'public_continuity');return raw
    finally:os.close(fd)
def select_python(alias=PYTHON,running=None,owner=0,ancestor_owners=(0,),version=None):
    """Admit one relative package alias and its regular sibling target."""
    try:
        require(isinstance(alias,Path)and alias.is_absolute(),'python_alias_path')
        for parent in alias.parents:
            m=parent.lstat();require(stat.S_ISDIR(m.st_mode)and m.st_uid in ancestor_owners and not m.st_mode&0o022,'python_parent_custody')
        before=alias.lstat();target_name=os.readlink(alias)if stat.S_ISLNK(before.st_mode)else''
        require(stat.S_ISLNK(before.st_mode)and before.st_uid==owner and before.st_nlink==1
            and PYTHON_TARGET.fullmatch(target_name)is not None,'python_alias_custody')
        target=alias.parent/target_name
        require(target.resolve(strict=True)==target,'python_target_chain')
        for parent in target.parents:
            m=parent.lstat();require(stat.S_ISDIR(m.st_mode)and m.st_uid in ancestor_owners and not m.st_mode&0o022,'python_target_parent_custody')
        prior=target.lstat()
        require(stat.S_ISREG(prior.st_mode)and prior.st_uid==owner and prior.st_nlink==1
            and not prior.st_mode&0o022 and not prior.st_mode&0o6000 and prior.st_mode&0o111
            and 0<prior.st_size<=64*1024*1024,'python_target_custody')
        fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:require(identity(os.fstat(fd))==identity(prior),'python_target_open')
        finally:os.close(fd)
        selected=Path(sys.executable if running is None else running).resolve(strict=True)
        require(selected==target,'python_running_identity')
        actual=sys.version_info[:3]if version is None else tuple(version)
        require(len(actual)==3 and all(type(x)is int for x in actual)
            and (3,9)<=actual[:2]<(4,0),'python_incompatible')
        require(callable(getattr(signal,'pthread_sigmask',None))and callable(getattr(os,'waitid',None))
            and all(hasattr(os,name)for name in('WNOWAIT','WNOHANG','WEXITED'))
            and hasattr(str,'removesuffix'),'python_features')
        require(identity(alias.lstat())==identity(before)and os.readlink(alias)==target_name
            and identity(target.lstat())==identity(prior),'python_selection_changed')
        return {'entrypoint':str(alias),'resolved_path':str(target),'version':list(actual),
            'identity':{'dev':prior.st_dev,'ino':prior.st_ino,'uid':prior.st_uid,'gid':prior.st_gid,
                'mode':stat.S_IMODE(prior.st_mode),'nlink':prior.st_nlink,'size':prior.st_size},
            'features':['pthread_sigmask','waitid','WNOWAIT','removesuffix']}
    except Refused:raise
    except BaseException as error:
        raise Refused('python_selection_'+type(error).__name__)from None
def binary_copy(pin,destination):
    require(type(pin)is dict and set(pin)=={'path','sha256','size','dev','ino','uid','gid','mode','nlink','cargo_profile','cargo_target_kind','profile_test','source_count','tests_executed','application_executed'},'binary_pin_fields')
    source=Path(pin['path']);require(source.parent.parent==Path('/home/foo')and re.fullmatch(r'\.osmap-s04-02-artifacts-[A-Za-z0-9_-]+',source.parent.name),'binary_stage_selection')
    require(source.name in('account-passwd','osmap-libtest'),'binary_leaf_selection')
    for p in(Path('/'),Path('/home')):directory(p,0)
    directory(Path('/home/foo'),1000);parent=directory(source.parent,1000,0o700)
    m=source.lstat();before=identity(m)
    require(stat.S_ISREG(m.st_mode)and(m.st_uid,m.st_gid,stat.S_IMODE(m.st_mode),m.st_nlink)==(1000,1000,0o700,1),'binary_custody')
    require(all(type(pin[k])is int for k in('dev','ino','uid','gid','mode','nlink','size'))and all(getattr(m,'st_'+k)==pin[k]for k in('dev','ino','uid','gid','nlink','size'))and pin['mode']==0o700,'binary_receipt_identity')
    require(0<m.st_size<=256*1024*1024 and re.fullmatch('[a-f0-9]{64}',pin['sha256']),'binary_bound')
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);out=None
    try:
        require(identity(os.fstat(fd))==before,'binary_open');out=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);digest=hashlib.sha256();size=0
        while True:
            deadline();part=os.read(fd,262144)
            if not part:break
            size+=len(part);require(size<=pin['size'],'binary_grew');digest.update(part);view=memoryview(part)
            while view:n=os.write(out,view);require(n>0,'binary_copy_write');view=view[n:]
        require(size==pin['size']and digest.hexdigest()==pin['sha256']and identity(os.fstat(fd))==before and identity(source.lstat())==before and identity(source.parent.lstat())==parent,'binary_continuity')
        os.fchmod(out,0o500);os.fsync(out);owned=identity(os.fstat(out))
    finally:
        if out is not None:os.close(out)
        os.close(fd)
    require(identity(destination.lstat())==owned,'binary_publication');return owned
def admit_packet(p):
    require(set(p)=={'version','source_commit','compiler_source_manifest_sha256','compiler_receipt_sha256','prerequisite_sha256','config_map','public_sql_sha256','sources','helper','web','not_after_utc'},'packet_fields')
    require(p['version']==1 and p['source_commit']==BASE and type(p['not_after_utc'])is int and 150<p['not_after_utc']-time.time()<=600,'original_lease')
    for k in('compiler_source_manifest_sha256','compiler_receipt_sha256','prerequisite_sha256','public_sql_sha256'):require(type(p[k])is str and re.fullmatch('[a-f0-9]{64}',p[k]),'receipt_scalar')
    require(set(p['sources'])==set(SOURCE_PINS),'source_set');sources={}
    for name,pin in SOURCE_PINS.items():
        value=base64.b64decode(p['sources'][name],validate=True);require(0<len(value)<=262144 and sha(value)==pin,'source_pin');sources[name]=value
    for label,test in(('helper',False),('web',True)):
        pin=p[label];profile=pin['cargo_profile'];require(pin['profile_test']is test and profile['test']is test and type(pin['source_count'])is int and pin['source_count']>0 and pin['tests_executed']is False and pin['application_executed']is False,'artifact_kind')
        require(profile['opt_level']==('0'if test else'3')and profile['debuginfo']==0 and profile['debug_assertions']is test and profile['overflow_checks']is test,'artifact_profile')
        require(pin['cargo_target_kind']==(['lib']if test else['bin'])and Path(pin['path']).name==('osmap-libtest'if test else'account-passwd'),'artifact_target')
    require(p['helper']['source_count']==p['web']['source_count'],'artifact_source_count')
    return sources

def produce_stage(p,sources,backend,frontend,raw,interpreter,emit):
    # No adoption or collision retries; any partial publication is retained.
    backend.mkdir(mode=0o700)
    emit(stage_birth_frame(backend,None,p['not_after_utc']))
    publish(backend/'stage-birth.json',encode(stage_birth_receipt(backend,
        identity(backend.lstat()),sha(raw),p['not_after_utc'])),0o600)
    frontend.mkdir(mode=0o700);files={}
    stage=stage_ownership_receipt(backend,frontend,identity(backend.lstat()),
        identity(frontend.lstat()),p['compiler_receipt_sha256'],sha(raw),p['not_after_utc'],files)
    stage_path=backend/'stage-ownership.json'
    # Emit owned directory births before subsequent fallible publication. A
    # failure reports partial stages; it never dispatches or recursively removes.
    emit(stage_birth_frame(backend,frontend,p['not_after_utc']))
    for name,value in sources.items():
        target=(backend if name.startswith('backend/')else frontend)/Path(name).name;files[str(target)]=publish(target,value,0o400)
    files[str(backend/'account-passwd')]=binary_copy(p['helper'],backend/'account-passwd')
    files[str(frontend/'qualified-openbsd-libtest')]=binary_copy(p['web'],frontend/'qualified-openbsd-libtest')
    config=encode(p['config_map']);files[str(backend/'original-config-sha256.json')]=publish(backend/'original-config-sha256.json',config,0o400)
    back={Path(k).name:v for k,v in SOURCE_PINS.items()if k.startswith('backend/')and k!='backend/startup_only.py'};front={Path(k).name:v for k,v in SOURCE_PINS.items()if k.startswith('frontend/')}
    source_manifest=encode(front);files[str(frontend/'source-input-manifest.json')]=publish(frontend/'source-input-manifest.json',source_manifest,0o400)
    build=encode({'version':1,'binary_sha256':p['web']['sha256'],'binary_bytes':p['web']['size'],'source_manifest_sha256':sha(source_manifest)})
    files[str(frontend/'http-build.json')]=publish(frontend/'http-build.json',build,0o400)
    admission={'version':1,'not_after_utc':p['not_after_utc'],'source_commit':BASE,'compiler_source_manifest_sha256':p['compiler_source_manifest_sha256'],'helper_sha256':p['helper']['sha256'],'web_sha256':p['web']['sha256'],'web_bytes':p['web']['size'],'backend_sources':back,'frontend_sources':front,'frontend_stage':str(frontend),'frontend_stage_lease':identity(frontend.lstat())[:6],'frontend_files':{name:identity((frontend/name).lstat())for name in(*front,'source-input-manifest.json','http-build.json','qualified-openbsd-libtest')},'config_map_sha256':sha(config),'public_sql_sha256':p['public_sql_sha256'],'prerequisite_sha256':p['prerequisite_sha256']}
    admission_raw=encode(admission);files[str(backend/'local-admission.json')]=publish(backend/'local-admission.json',admission_raw,0o400)
    stage['admission_sha256']=sha(admission_raw);publish(stage_path,encode(stage),0o600)
    emit({'schema':'osmap-single-host-stage-ready-v1','backend':str(backend),'frontend':str(frontend),'stage_receipt':str(stage_path),'stage_receipt_sha256':sha(encode(stage)),'admission_sha256':sha(admission_raw),'not_after_utc':p['not_after_utc'],'interpreter':interpreter,'source_commit':p['source_commit'],'compiler_receipt_sha256':p['compiler_receipt_sha256'],'compiler_source_manifest_sha256':p['compiler_source_manifest_sha256'],'helper_sha256':p['helper']['sha256'],'web_sha256':p['web']['sha256'],'packet_sha256':sha(raw)})
    return sha(admission_raw)

def main():
    global END
    os.umask(0o077)
    def interrupted(_number,_frame):raise Refused('stage_interrupted')
    for number in(signal.SIGALRM,signal.SIGHUP,signal.SIGINT,signal.SIGTERM):signal.signal(number,interrupted)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.chdir('/')
    host_identity=(os.getuid(),os.geteuid(),os.getgid(),os.getegid(),socket.gethostname(),os.uname().sysname,os.uname().machine)
    require(host_identity==(0,0,0,0,'obsd1.blackbagsecurity.com','OpenBSD','amd64'),'root_target')
    require(len(sys.argv)==1,'no_arguments')
    interpreter=select_python()
    raw=sys.stdin.buffer.read(4*1024*1024+1);require(0<len(raw)<=4*1024*1024,'packet_bound');p=decode(raw)
    sources=admit_packet(p)
    END=min(END,time.monotonic()+p['not_after_utc']-time.time());signal.alarm(max(1,math.ceil(END-time.monotonic())))
    # The selected closed set is independently checked again by the unchanged
    # Qualification before provisioning; stage creation does not authorize it.
    require(type(p['config_map'])is dict and set(p['config_map'])==set(CONFIG_PATHS),'config_map_shape')
    for name,pin in p['config_map'].items():
        path=Path(name)
        require(path.parent==Path('/etc/dovecot')or path.parent==Path('/etc/dovecot/conf.d'),'public_fixed_parent')
        if pin is None:
            require(name in OPTIONAL,'absence_scope');protected(path)
            require(not os.path.lexists(path),'absence_changed')
        else:require(type(pin)is str and re.fullmatch('[a-f0-9]{64}',pin)and sha(read_root(path,131072))==pin,'public_changed')
    require(sha(read_root(Path('/etc/dovecot/dovecot-sql.conf.ext'),131072))==p['public_sql_sha256'],'public_sql_changed')
    protected(Path('/var/run/owned'));tmp=Path('/tmp').lstat();require(stat.S_ISDIR(tmp.st_mode)and tmp.st_uid==0,'tmp_custody')
    require(stat.S_IMODE(Path('/tmp').lstat().st_mode)==0o1777,'tmp_sticky')
    backend=Path('/var/run')/('osmap-service-admission-root-'+secrets.token_hex(8));frontend=Path('/tmp')/('osmap-pxp-stage-'+secrets.token_hex(8))
    admission_sha=produce_stage(p,sources,backend,frontend,raw,interpreter,lambda frame:print(json.dumps(frame),flush=True))
    deadline();require(select_python()==interpreter,'python_selection_changed')
    os.execve('/usr/local/bin/python3',['/usr/local/bin/python3','-I','-B',str(backend/'startup_only.py'),admission_sha],{'PATH':'/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/root','LC_ALL':'C'})
if __name__=='__main__':
    try:main()
    except BaseException as error:
        print(json.dumps({'schema':'osmap-single-host-stage-refusal-v1','result':'REFUSED','reason':str(error)if type(error)is Refused else type(error).__name__,'disposition':'PARTIAL_STAGES_RETAINED_NO_ADOPTION','public_service_operations':False}),flush=True);raise SystemExit(1)
