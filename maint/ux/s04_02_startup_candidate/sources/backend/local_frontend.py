"""Fixed obsd1 root keeper for the real existing Rust HTTP journey.

Stage/pins are bound from actual publication receipts by the root executor.
Only fixed framing crosses SSH; private credentials remain in RAM and existing
protected purpose-key files. No old Python account/factory is instantiated.
"""
import importlib.util,json,hashlib,os,pwd,queue,re,resource,secrets,selectors
import signal,socket,stat,subprocess,sys,threading,time
from pathlib import Path
from datetime import datetime, timezone

sys.dont_write_bytecode=True

STAGE = None
SOURCE_PINS = {}
STAGE_FILES = {}
START = time.monotonic()
END = START + 600
WORK = END - 150
STOPS = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGALRM}
ALICE, BOB = 'alice@osmap-password.invalid', 'bob@osmap-password.invalid'
UID, GID = 1001, 1001
EVENTS = ('SNAPSHOT_B0','SNAPSHOT_A0','SNAPSHOT_A1','SNAPSHOT_B1','MAIL_WITNESS')
DIAGNOSTIC_STAGES = ('INITIAL','RUNTIME_PREPARED','GUARDIAN_BORN','CUSTODY_RECEIVED',
    'BOOTSTRAP_SENT','READY_RECEIVED','READY_VALIDATED','DRIVER_CONSTRUCTED')
DIAGNOSTIC_OPERATIONS = ('setup','guardian_launch','custody_read','custody_validation',
    'bootstrap_write','ready_read','ready_validation','driver_construction','journey','stop_requests')
DIAGNOSTIC_CODES = frozenset(('control_eof','cancelled','original_deadline','frame_bound',
    'actual_guardian_custody','actual_native_ready','insufficient_original_journey_budget',
    'original_frontend_setup_deadline','fixed_front_bootstrap','control_changed','root_control_peer',
    'unnamed_control','node_frame_cap','node_frame_object','duplicate_node_field',
    'nonfinite_node_number','STARTUP_INTERRUPTED','PROCESS_LAUNCH_FAILED','CONTROL_IO_FAILED',
    'UNEXPECTED_SANITIZED','FRONTEND_CLEANUP_FAILED'))


def diagnostic_code(error):
    # Shape-based redaction cannot distinguish a token-shaped secret from a code.
    if type(error) is RuntimeError and error.args and type(error.args[0])is str and error.args[0] in DIAGNOSTIC_CODES:
        return error.args[0]
    if isinstance(error,(KeyboardInterrupt,SystemExit)):return 'STARTUP_INTERRUPTED'
    if isinstance(error,subprocess.SubprocessError):return 'PROCESS_LAUNCH_FAILED'
    if isinstance(error,OSError):return 'CONTROL_IO_FAILED'
    # The pinned guardian Refused type carries fixed codes; no arbitrary text.
    if type(error).__name__=='Refused' and error.args and type(error.args[0])is str and error.args[0] in DIAGNOSTIC_CODES:
        return error.args[0]
    return 'UNEXPECTED_SANITIZED'


def validate_native_diagnostic(value,guardian_validator,capture_validator):
    require(type(value)is dict and set(value)=={'schema','first_failure','guardian_created',
        'guardian_pid','guardian_terminal','guardian_reaped','guardian_capture',
        'guardian_diagnostic','guardian_diagnostic_status','control_status','cleanup_status',
        'cleanup_code'},'native_diagnostic_schema')
    require(value['schema']=='osmap-native-startup-diagnostic-v1','native_diagnostic_schema')
    failure=value['first_failure']
    require(failure is None or(type(failure)is dict and set(failure)=={'component','stage','operation','code'}
        and failure['component']=='frontend_controller'and failure['stage']in DIAGNOSTIC_STAGES
        and failure['operation']in DIAGNOSTIC_OPERATIONS and failure['code']in DIAGNOSTIC_CODES),
        'native_diagnostic_failure')
    require(type(value['guardian_created'])is bool and type(value['guardian_reaped'])is bool
        and(value['guardian_terminal']is None or(type(value['guardian_terminal'])is int
            and -128<=value['guardian_terminal']<=255)),'native_diagnostic_process')
    require((type(value['guardian_pid'])is int and value['guardian_pid']>0)
        if value['guardian_created']else value['guardian_pid']is None,'native_diagnostic_pid')
    require(value['guardian_reaped']==(value['guardian_terminal']is not None)
        and(not value['guardian_reaped']or value['guardian_created']),
        'native_diagnostic_reap')
    require(value['guardian_diagnostic_status']in('AVAILABLE','NOT_EMITTED','MALFORMED',
        'CAPTURE_INCOMPLETE','NOT_CREATED')and value['control_status']in('OPEN','EOF','CLOSED','UNKNOWN')
        and value['cleanup_status']in('NOT_RUN','CONFIRMED','UNCERTAIN')
        and value['cleanup_code']in(None,'FRONTEND_CLEANUP_FAILED'),'native_diagnostic_disposition')
    native=value['guardian_diagnostic']
    require((native is not None)==(value['guardian_diagnostic_status']=='AVAILABLE'),'native_diagnostic_availability')
    require(native is None or(value['guardian_created']and value['guardian_capture']is not None),
        'native_diagnostic_producer')
    require(value['guardian_created']or(value['guardian_capture']is None
        and value['guardian_diagnostic_status']=='NOT_CREATED'),'native_diagnostic_birth')
    if native is not None:guardian_validator(native)
    # The guardian validator owns the stream schema; use its source-owned
    # validator for the same capture shape without accepting arbitrary keys.
    capture=value['guardian_capture']
    if capture is not None:
        capture_validator(capture)
    return value


def require(value,code='fixed_frontend_node_refused'):
    if not value:raise RuntimeError(code)


def identity(m):
    return(m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)


def unique(pairs):
    result={}
    for k,v in pairs:
        require(k not in result,'duplicate_node_field');result[k]=v
    return result


def nonfinite(_value):raise RuntimeError('nonfinite_node_number')


def decoded(raw):
    require(type(raw)is bytes and 0<len(raw)<=32768,'node_frame_cap')
    result=json.loads(raw,object_pairs_hook=unique,parse_constant=nonfinite)
    require(type(result)is dict,'node_frame_object');return result


def pinned(name):
    require(type(name)is str and name in SOURCE_PINS and '/'not in name,'fixed_node_source_name')
    path=Path(STAGE)/name;m=path.lstat()
    require(path.resolve()==path and stat.S_ISREG(m.st_mode)and m.st_uid==m.st_gid==0
        and stat.S_IMODE(m.st_mode)==0o400 and m.st_nlink==1 and 0<m.st_size<=262144,'fixed_node_source_metadata')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        require(identity(os.fstat(fd))==identity(m),'node_source_open_changed')
        raw=os.read(fd,262145)
        require(len(raw)==m.st_size and hashlib.sha256(raw).hexdigest()==SOURCE_PINS[name]
            and identity(os.fstat(fd))==identity(m)and identity(path.lstat())==identity(m),'node_source_hash_changed')
        return raw
    finally:os.close(fd)


def module(name,filename):
    pinned(filename)
    spec=importlib.util.spec_from_file_location(name,Path(STAGE)/filename)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
    return value


class Frontend:
    def __init__(self,wire):
        self.wire=wire;self.end=END
        self.ownership_callback=None;self.local_exchange=None;self.cancelled=threading.Event();self.socket_lock=threading.Lock();self.program_lock=threading.Lock();self.relay_lock=threading.Lock()
        self.http_stream=None;self.guardian=None;self.control=None;self.guard=None
        self.worker=None;self.worker_error=None
        self.events=queue.Queue();self.replies=queue.Queue();self.worker_done=threading.Event()
        self.children=[];self.process_uncertain=False;self.created=[];self.files={};self.dirs={}
        self.report={'groups':[]};self.ready=None;self.requests_stopped=False;self.disposed=False
        self.generated_dirs={};self.stage_id=0;self.failure=None
        self.http_root=None
        self.guardian_capture=None;self.guardian_observation=None
        self.startup_stage='INITIAL';self.startup_operation='setup'
        self.control_status='UNKNOWN';self.cleanup_status='NOT_RUN';self.cleanup_code=None
        self.http_module=module('fixed_front_http','native_http_front_driver.py')
        self.journey_module=module('fixed_front_journey','native_http_password_driver.py')
    def remaining(self,cleanup=False):
        left=(END if cleanup else WORK)-time.monotonic()
        require(left>0,'original_frontend_horizon');return left
    def run(self,argv,label,data=b'',cap=16384,seconds=5,cleanup=False,absolute=None):
        # The two concrete consumers use only fixed keygen and root group ps.
        require(argv==('/bin/ps','-ax','-o','pid=,ppid=,pgid=,uid=,comm='),'fixed_front_program')
        require(data==b''and type(cap)is int and cap<=65536 and 0<seconds<=5,'fixed_front_program_bounds')
        with self.program_lock:
            deadline=min(time.monotonic()+seconds,END if cleanup else WORK,absolute or END)
            require(time.monotonic()<deadline-1,'front_program_original_deadline')
            child=None;out=[bytearray(),bytearray()];error=None;gone=reaped=False
            previous=signal.pthread_sigmask(signal.SIG_BLOCK,STOPS)
            try:
                child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,start_new_session=True,close_fds=True,
                    env={'PATH':'/usr/bin:/bin:/usr/local/bin','LC_ALL':'C','HOME':'/root'},
                    preexec_fn=lambda:signal.pthread_sigmask(signal.SIG_SETMASK,previous))
                self.children.append(child)
            finally:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
            try:
                with selectors.DefaultSelector()as selected:
                    for i,pipe in enumerate((child.stdout,child.stderr)):
                        os.set_blocking(pipe.fileno(),False);selected.register(pipe,selectors.EVENT_READ,i)
                    while selected.get_map():
                        require(time.monotonic()<deadline-1,'front_program_io_deadline')
                        for key,_ in selected.select(.02):
                            part=os.read(key.fd,4096)
                            if not part:selected.unregister(key.fileobj)
                            out[key.data].extend(part);require(len(out[key.data])<=cap,'front_program_output_cap')
                    while os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is None:
                        require(time.monotonic()<deadline-1,'front_program_exit_deadline');time.sleep(.01)
            except BaseException as exc:error=exc
            finally:
                try:
                    try:os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    child.wait(timeout=max(.001,deadline-time.monotonic()));reaped=True
                    try:os.killpg(child.pid,0)
                    except ProcessLookupError:gone=True
                finally:
                    child.stdout.close();child.stderr.close()
                    self.report['groups'].append({'operation':label,'reaped':reaped,'group_gone':gone,'code':child.returncode})
                    self.process_uncertain|=not(reaped and gone)
            if error is not None:raise error
            require(reaped and gone and child.returncode==0 and not out[1],'actual_front_program_failed')
            return bytes(out[0])
    def directory(self,path,uid,gid,mode):
        try:
            require(not os.path.lexists(path),'fresh_front_directory')
            path.mkdir(mode=0o700);self.dirs[path]=identity(path.lstat())
            os.chown(path,uid,gid);os.chmod(path,mode);self.dirs[path]=identity(path.lstat())
        finally:
            if self.ownership_callback is not None:self.ownership_callback('WEB_OWNERSHIP')
    def file(self,path,raw,uid,gid,mode):
        try:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                self.files[path]=identity(os.fstat(fd));view=memoryview(raw)
                while view:
                    self.remaining();n=os.write(fd,view);require(n>0);view=view[n:]
                os.fchown(fd,uid,gid);os.fchmod(fd,mode);os.fsync(fd)
                self.files[path]=identity(os.fstat(fd));require(identity(path.lstat())==self.files[path])
            finally:
                self.files[path]=identity(os.fstat(fd))
                os.close(fd)
        finally:
            if self.ownership_callback is not None:self.ownership_callback('WEB_OWNERSHIP')
    def capture_generated_directories(self,require_replay=False):
        try:
            if self.http_root is None:return
            for relative in('http-state/cache/totp-replay','http-state/cache/login-throttle','http-state/settings/password-stepup-rate'):
                path=self.http_root/relative
                if not os.path.lexists(path):
                    require(not(require_replay and relative.endswith('/totp-replay')),'actual_replay_directory_missing')
                    continue
                require(path.parent in self.dirs and identity(path.parent.lstat())[:5]==self.dirs[path.parent][:5]
                    and path.resolve()==path,'fixed_generated_parent')
                m=path.lstat()
                require(stat.S_ISDIR(m.st_mode)and(m.st_uid,m.st_gid,stat.S_IMODE(m.st_mode),m.st_nlink)==(UID,GID,0o700,2),
                    'fixed_generated_directory')
                current=identity(m)[:6]
                if path not in self.generated_dirs:self.generated_dirs[path]=current
                require(self.generated_dirs[path]==current,'generated_directory_birth_changed')
        finally:
            if self.ownership_callback is not None:self.ownership_callback('WEB_OWNERSHIP')
    def capture_guardian_code(self):
        # The pinned guardian owns this one copied public executable. Record its
        # exact leaves after its custody receipt, so an interrupted run can
        # dispose of them without broadening generated-file cleanup.
        try:
            code=self.http_root/'web-code';binary=code/'qualified-libtest'
            require(identity(self.http_root.lstat())[:5]==self.dirs[self.http_root][:5]
                and code.parent==self.http_root and binary.parent==code,'guardian_code_parent')
            stage=Path(STAGE)/'http-build.json';expected=tuple(STAGE_FILES['http-build.json'])
            require(identity(stage.lstat())==expected and 0<expected[6]<=4096,'guardian_build_lease')
            fd=os.open(stage,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            try:
                require(identity(os.fstat(fd))==expected,'guardian_build_open')
                raw=os.read(fd,4097)
                require(len(raw)==expected[6] and identity(os.fstat(fd))==expected
                    and identity(stage.lstat())==expected,'guardian_build_changed')
            finally:os.close(fd)
            build=decoded(raw)
            source=Path(STAGE)/'qualified-openbsd-libtest'
            require(identity(source.lstat())==tuple(STAGE_FILES['qualified-openbsd-libtest']),
                'guardian_binary_source_lease')
            require(type(build.get('binary_bytes'))is int
                and build['binary_bytes']==STAGE_FILES['qualified-openbsd-libtest'][6]
                and type(build.get('binary_sha256'))is str
                and re.fullmatch('[a-f0-9]{64}',build['binary_sha256'])
                and self.custody['binary_sha256']==build['binary_sha256'],'guardian_binary_source')
            directory=identity(code.lstat());leaf=identity(binary.lstat())
            require(stat.S_ISDIR(directory[4]) and directory[2:6]==(0,GID,stat.S_IFDIR|0o750,2)
                and sorted(p.name for p in code.iterdir())==['qualified-libtest'],
                'guardian_code_directory')
            require(stat.S_ISREG(leaf[4]) and leaf[2:6]==(0,GID,stat.S_IFREG|0o550,1)
                and leaf[6]==build['binary_bytes'] and identity(code.lstat())==directory
                and identity(binary.lstat())==leaf,'guardian_code_binary')
            self.dirs[code]=directory;self.files[binary]=leaf
        finally:
            if self.ownership_callback is not None:self.ownership_callback('WEB_OWNERSHIP')
    def capture_replay_directory(self):
        self.capture_generated_directories(require_replay=True)
    def preserve_failure(self,error):
        if self.failure is None:
            self.failure={'component':'frontend_controller','stage':self.startup_stage,
                'operation':self.startup_operation,'code':diagnostic_code(error)}
            if self.failure['code']=='control_eof':self.control_status='EOF'
        return self.native_diagnostic()
    def native_diagnostic(self):
        capture=self.guardian_capture
        native=None;status='NOT_CREATED'if self.guardian is None else'NOT_EMITTED'
        if capture is not None:
            self.guardian_observation=capture.snapshot()
            try:
                native=capture.guardian_diagnostic()
                if native is not None:status='AVAILABLE'
                elif self.guardian_observation['capture_error'] is not None or not all(
                    self.guardian_observation[name+'_eof'] for name in ('stdout','stderr')):
                    status='CAPTURE_INCOMPLETE'
            except Exception:status='MALFORMED'
        value={'schema':'osmap-native-startup-diagnostic-v1','first_failure':self.failure,
            'guardian_created':self.guardian is not None,
            'guardian_pid':None if self.guardian is None else self.guardian.pid,
            'guardian_terminal':None if self.guardian is None else self.guardian.returncode,
            'guardian_reaped':self.guardian is not None and self.guardian.returncode is not None,
            'guardian_capture':self.guardian_observation,'guardian_diagnostic':native,
            'guardian_diagnostic_status':status,'control_status':self.control_status,
            'cleanup_status':self.cleanup_status,'cleanup_code':self.cleanup_code}
        return value
    def checkpoint_diagnostic(self):
        self.native_diagnostic()
        if self.ownership_callback is not None:self.ownership_callback('WEB_DIAGNOSTIC_PRESERVED')
    def setup(self,boot):
        try:return self._setup(boot)
        except BaseException as error:
            self.preserve_failure(error)
            raise
    def _setup(self,boot):
        # Refuse before frontend birth if setup and the full journey cannot fit
        # before the actor's protected cleanup reserve. Never shorten it silently.
        require(WORK-time.monotonic() >= 30+self.http_module.JOURNEY_SECONDS,
            'insufficient_original_journey_budget')
        setup=min(WORK,time.monotonic()+20)
        require(set(boot)=={'version','alice_password','bob_password','new_password','admission_key','mutation_key','session_proof_key'}
            and boot['version']==1 and all(type(v)is str and re.fullmatch('[a-f0-9]{64}',v)for k,v in boot.items()if k!='version'),'fixed_front_bootstrap')
        self.boot=boot
        # The imported Control/drain helpers run under this actor's original
        # bound. The guardian subprocess owns its separate 330s process clock;
        # importing its helpers must not start a second, earlier guardian clock.
        self.guard=module('fixed_front_guardian','native_http_web_guardian.py')
        self.guard.END=END
        self.http_root=Path('/var/run')/('osmap-pxp-'+secrets.token_hex(8))
        root=self.http_root/'http-state'
        for path in(self.http_root,root,root/'keys',root/'secrets'):self.directory(path,0,GID,0o750)
        for name in('run','sessions','settings','drafts','audit','cache','secrets/totp'):
            self.directory(root/name,UID,GID,0o700)
        for key,name in(('admission_key','admission.key'),('mutation_key','mutation.key'),('session_proof_key','session-proof.key')):
            self.file(root/'keys'/name,boot[key].encode('ascii'),UID,GID,0o600)
        parent,child=socket.socketpair();self.control=self.guard.Control(parent)
        self.control_status='OPEN';self.startup_stage='RUNTIME_PREPARED';self.startup_operation='guardian_launch'
        require(time.monotonic()<setup,'original_frontend_setup_deadline')
        previous=signal.pthread_sigmask(signal.SIG_BLOCK,STOPS)
        try:
            self.guardian=subprocess.Popen(('/usr/local/bin/python3','-I','-B',str(Path(STAGE)/'native_http_web_guardian.py')),
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
                close_fds=True,pass_fds=(child.fileno(),),env={'PATH':'/usr/bin:/bin:/usr/local/bin','LC_ALL':'C','TZ':'UTC',
                    'OSMAP_TEST_HTTP_GUARDIAN_FD':str(child.fileno())},
                preexec_fn=lambda:signal.pthread_sigmask(signal.SIG_SETMASK,previous))
            self.guardian_capture=self.guard.Capture(self.guardian)
            self.startup_stage='GUARDIAN_BORN'
            if self.ownership_callback is not None:self.ownership_callback('GUARDIAN_BIRTH')
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,previous);child.close()
        self.control.write(json.dumps({'version':1,'http_root':str(self.http_root)}).encode(),setup)
        self.startup_operation='custody_read'
        self.custody=decoded(self.control.read(2048,setup))
        self.startup_operation='custody_validation'
        require(set(self.custody)=={'schema','web_uid','web_gid','binary_sha256','selector','web_pid','guardian_pid','guardian_group'}
            and self.custody['schema']=='osmap-http-web-custody-v1'and self.custody['web_uid']==UID
            and self.custody['web_gid']==GID and self.custody['guardian_pid']==self.guardian.pid
            and self.custody['guardian_group']==self.guardian.pid,'actual_guardian_custody')
        self.startup_stage='CUSTODY_RECEIVED'
        self.capture_guardian_code()
        self.group(allow_web=True)
        self.startup_operation='bootstrap_write'
        self.control.write(json.dumps({'version':1,'root':str(root)}).encode(),setup)
        self.startup_stage='BOOTSTRAP_SENT';self.startup_operation='ready_read'
        self.ready=decoded(self.control.read(2048,setup))
        self.startup_stage='READY_RECEIVED';self.startup_operation='ready_validation'
        require(set(self.ready)=={'schema','port','connections','totp_counter'}
            and self.ready['schema']=='osmap-http-password-ready-v1'and self.ready['connections']==18
            and type(self.ready['port'])is int and 0<self.ready['port']<=65535
            and abs(self.ready['totp_counter']-int(time.time())//30)<=1,'actual_native_ready')
        self.startup_stage='READY_VALIDATED'
        require(WORK-time.monotonic() >= 10+self.http_module.JOURNEY_SECONDS,
            'insufficient_original_journey_budget')
        self.sequence_end=time.monotonic()+self.http_module.JOURNEY_SECONDS
        self.startup_operation='driver_construction'
        self.driver=self.http_module.FrontDriver(self,boot)
        self.startup_stage='DRIVER_CONSTRUCTED';self.startup_operation='journey'
    def group(self,allow_web=False,absolute=None):
        raw=self.run(('/bin/ps','-ax','-o','pid=,ppid=,pgid=,uid=,comm='),'actual_front_guardian_group',cap=65536,cleanup=True,absolute=min(END-3,absolute or END))
        rows=[]
        for line in raw.decode('ascii').splitlines():
            f=line.split(maxsplit=4);require(len(f)==5 and all(re.fullmatch('[0-9]{1,10}',v)for v in f[:4]),'exact_front_group_row')
            row=tuple(map(int,f[:4]))+(f[4],)
            if row[2]==self.guardian.pid:rows.append(row)
        require(any(row[:4]==(self.guardian.pid,os.getpid(),self.guardian.pid,0)for row in rows),'owned_guardian_group_identity')
        if allow_web:
            require(1<=len(rows)<=2 and all(row[0]==self.guardian.pid or
                row[:4]==(self.custody['web_pid'],self.guardian.pid,self.guardian.pid,UID)for row in rows),'fixed_web_group_members')
        else:require(len(rows)==1,'web_process_not_absent')
    def finish_http(self,end):
        result=decoded(self.control.read(2048,end));self.guard.rust_report(json.dumps(result).encode())
        require(self.control.read(64,end)==b'WEB_DIRECT_REAPED','actual_web_direct_reap')
        self.group(absolute=end);self.control.write(b'GROUP_ONLY_GUARDIAN',end)
        require(self.control.read(64,end)==b'WEB_REAPED_GROUP_GONE','actual_web_code_disposition')
        self.guardian.wait(timeout=max(.001,end-time.monotonic()))
        capture=self.guardian_capture.finish(end)
        require(self.guardian.returncode==0 and capture['stderr_bytes']==0,'actual_guardian_terminal')
        try:os.killpg(self.guardian.pid,0)
        except ProcessLookupError:pass
        else:raise RuntimeError('actual_guardian_group_not_gone')
        require(time.monotonic()<end,'original_http_deadline')
        self.requests_stopped=True;return result
    def exchange(self,tag,end):
        require(not self.cancelled.is_set() and self.local_exchange is not None,'local_backend_event_unavailable')
        return self.local_exchange(tag,end)
    def stop_requests(self):
        error=None
        try:
            self.checkpoint_diagnostic()
        except BaseException as failure:
            # A failed evidence write forbids resource disposal, but cannot
            # leave an active request producer running without bounded stop.
            error=failure
        try:
            self._stop_requests()
        except BaseException as failure:
            if error is None:error=failure
        self.cleanup_status='CONFIRMED'if error is None else'UNCERTAIN'
        self.cleanup_code=None if error is None else'FRONTEND_CLEANUP_FAILED'
        try:
            if self.guardian_capture is not None:
                self.guardian_observation=self.guardian_capture.snapshot()
            self.checkpoint_diagnostic()
        except BaseException as failure:
            self.cleanup_status='UNCERTAIN';self.cleanup_code='FRONTEND_CLEANUP_FAILED'
            if error is None:error=failure
        if error is not None:raise error
    def _stop_requests(self):
        self.cancelled.set()
        with self.socket_lock:
            if self.http_stream is not None:
                try:self.http_stream.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                self.http_stream.close();self.http_stream=None
        if self.guardian is not None and not self.requests_stopped:
            if self.control is not None:
                self.control.stream.close()
                if self.control_status!='EOF':self.control_status='CLOSED'
            if self.guardian.returncode is None and self.control_status=='EOF':
                # EOF may precede normal interpreter exit by a few scheduling
                # turns. Observe the direct child's original status before
                # signalling, within the existing cleanup budget.
                try:self.guardian.wait(timeout=max(.001,min(.1,END-10-time.monotonic())))
                except subprocess.TimeoutExpired:pass
            if self.guardian.returncode is None:
                custody=getattr(self,'custody',None)
                # Before custody arrives only the still-unreaped direct handle
                # grants signalling authority. The trusted guardian owns its
                # child; an unknown group is never adopted for cleanup.
                if custody is not None:self.group(allow_web=True)
                try:
                    if custody is not None:os.killpg(self.guardian.pid,signal.SIGTERM)
                    else:os.kill(self.guardian.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                stop_end=min(END-10,time.monotonic()+5)
                while time.monotonic()<stop_end:
                    status=os.waitid(os.P_PID,self.guardian.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                    if status is not None:break
                    time.sleep(.02)
                else:
                    if custody is not None:os.killpg(self.guardian.pid,signal.SIGKILL)
                    else:os.kill(self.guardian.pid,signal.SIGKILL)
                self.guardian.wait(timeout=max(.001,END-10-time.monotonic()))
            if self.guardian_capture is not None:
                self.guardian_observation=self.guardian_capture.finish(END-10)
            # finish_http may have reaped the direct child before a terminal
            # validation/drain failure. Its historical PID no longer grants
            # signalling authority or requires a live guardian inventory.
            # A surviving group is uncertain and must be retained, not killed.
            try:os.killpg(self.guardian.pid,0)
            except ProcessLookupError:pass
            else:raise RuntimeError('unconfirmed_front_request_group')
        if self.worker is not None:
            self.worker.join(max(0,END-10-time.monotonic()))
            require(not self.worker.is_alive(),'unconfirmed_http_request_thread')
        require(not self.process_uncertain,'unconfirmed_front_program_group')
        self.capture_generated_directories()
        self.requests_stopped=True
    def dispose(self):
        require(self.requests_stopped,'producer_stop_before_dispose')
        # Remove only owned generated namespace leaves; never follow symlinks,
        # operator paths, source stage or an unrecorded extra directory.
        if self.http_root is not None:
            self.cleanup_http()
        self.disposed=True
    def cleanup_http(self):
        require(self.requests_stopped and self.http_root.resolve()==self.http_root,'owned_http_cleanup')
        # Fixed Rust state roots may contain generated sessions/replay/seeds;
        # only regular singly-linked files owned by the exact web/root roles.
        allowed={self.http_root,self.http_root/'http-state'}
        allowed.update(self.dirs);allowed.update(self.generated_dirs)
        for path in sorted(self.http_root.rglob('*'),key=lambda p:len(p.parts),reverse=True):
            self.remaining(cleanup=True)
            m=path.lstat();require(path.is_relative_to(self.http_root)and not stat.S_ISLNK(m.st_mode),'HTTP_cleanup_scope')
            if stat.S_ISDIR(m.st_mode):
                require(path in allowed,'HTTP_directory_scope')
                expected=self.dirs[path][:6]if path in self.dirs else self.generated_dirs[path]
                require(identity(m)[:6]==expected and not tuple(path.iterdir()),'HTTP_directory_custody');path.rmdir()
            else:
                require(stat.S_ISREG(m.st_mode)and m.st_nlink==1 and m.st_uid in(0,UID)
                    and not m.st_mode&0o022,'HTTP_generated_file_custody')
                if path in self.files:require(identity(m)==self.files[path],'HTTP_provisioned_file_changed')
                else:require(m.st_uid==UID and stat.S_IMODE(m.st_mode)==0o600,'HTTP_generated_web_file')
                path.unlink()
        require(identity(self.http_root.lstat())[:6]==self.dirs[self.http_root][:6]and not tuple(self.http_root.iterdir()),'HTTP_root_custody');self.http_root.rmdir()
