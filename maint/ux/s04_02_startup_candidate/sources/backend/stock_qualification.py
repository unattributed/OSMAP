"""Account-only stock service qualification over existing bounded custody.

No public mail config, listener, service lifecycle, plugin, PF or Generation
operation exists in this producer. Existing locked SQL/hash roles and two fixed
synthetic rows are owned only for this fresh action; ordinary auth stays live.
"""
import hashlib,importlib.util,json,os,pwd,grp,re,secrets,signal,socket,stat,subprocess,sys,time
from pathlib import Path

STAGE=Path(__file__).resolve().parent
HELPER=Path('/usr/local/libexec/osmap/account-passwd')
HELPER_SHA256=None
SIGNED_SOURCE_COMMIT=None
CONFIG_MAP_SHA256=None
PUBLIC_SQL_SHA256=None
CUSTODY_SHA256=None
ROLES=('_osmapsql','_osmaphash')
SOCKETS=(Path('/var/run/osmap-account-admission/admission.sock'),Path('/var/run/osmap-account-mutation/mutation.sock'))
RUNTIME=Path('/etc/osmap/account-runtime')
CONNECTOR_PARENT=Path('/usr/local/libexec/osmap/account-runtime')
CONNECTOR_FILES=tuple(CONNECTOR_PARENT/('osmap_account_'+purpose+'_connector')for purpose in('admission','mutation'))
SERVICE_FILES=(Path('/etc/osmap/account-admission.json'),Path('/etc/osmap/account-admission.key'),RUNTIME/'config.json',RUNTIME/'mutation.key',RUNTIME/'session-proof.key')
MAIN='/etc/dovecot/dovecot.conf'
KNOWN_ABSENT=('/etc/dovecot/conf.d/99-bbs-imaps-only.conf', '/etc/dovecot/conf.d/99-bbs-managesieve-policy.conf')
PRESERVED_CONFIG_PATHS=('/etc/dovecot/dovecot.conf', '/etc/dovecot/conf.d/10-auth.conf', '/etc/dovecot/conf.d/10-director.conf', '/etc/dovecot/conf.d/10-logging.conf', '/etc/dovecot/conf.d/10-mail.conf', '/etc/dovecot/conf.d/10-master.conf', '/etc/dovecot/conf.d/10-metrics.conf', '/etc/dovecot/conf.d/10-ssl.conf', '/etc/dovecot/conf.d/15-lda.conf', '/etc/dovecot/conf.d/15-mailboxes.conf', '/etc/dovecot/conf.d/20-imap.conf', '/etc/dovecot/conf.d/20-lmtp.conf', '/etc/dovecot/conf.d/20-managesieve.conf', '/etc/dovecot/conf.d/20-pop3.conf', '/etc/dovecot/conf.d/20-submission.conf', '/etc/dovecot/conf.d/90-acl.conf', '/etc/dovecot/conf.d/90-plugin.conf', '/etc/dovecot/conf.d/90-quota.conf', '/etc/dovecot/conf.d/90-sieve-extprograms.conf', '/etc/dovecot/conf.d/90-sieve.conf', '/etc/dovecot/conf.d/99-bbs-imaps-only.conf', '/etc/dovecot/conf.d/99-bbs-managesieve-policy.conf', '/etc/dovecot/conf.d/99-rspamd-warning-labels.conf', '/etc/dovecot/local.conf', '/etc/dovecot/conf.d/auth-sql.conf.ext')
sys.dont_write_bytecode=True
def fixed_read(path, cap, digest=None):
    for parent in path.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise RuntimeError('fixed_input_parent')
    before = path.lstat()
    if not (stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and not before.st_mode & 0o022 and before.st_size <= cap):
        raise RuntimeError('fixed_input_metadata')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        identity=lambda m:(m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
        if identity(os.fstat(fd)) != identity(before): raise RuntimeError('fixed_input_open')
        raw = bytearray()
        while len(raw)<=cap:
            part=os.read(fd,min(262144,cap+1-len(raw)))
            if not part:break
            raw.extend(part)
        if len(raw)!=before.st_size or identity(os.fstat(fd))!=identity(before) or identity(path.lstat())!=identity(before):raise RuntimeError('fixed_input_continuity')
        if digest is not None and hashlib.sha256(raw).hexdigest()!=digest:raise RuntimeError('fixed_input_digest')
        return bytes(raw)
    finally:os.close(fd)


raw=fixed_read(STAGE/'custody.py',65536,CUSTODY_SHA256)
spec=importlib.util.spec_from_file_location('osmap_stock_custody',STAGE/'custody.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
require=base.require
schema_raw=fixed_read(STAGE/'stock_schema.py',16384)
schema_spec=importlib.util.spec_from_file_location('osmap_stock_schema',STAGE/'stock_schema.py')
stock_schema=importlib.util.module_from_spec(schema_spec);schema_spec.loader.exec_module(stock_schema)


def stock_fresh_reserved_schema(raw):
    try:return stock_schema.stock_fresh_reserved_schema(raw)
    except stock_schema.StockSchemaRefused as error:
        raise base.Refused(error.code)from None

# Source-owned numeric projection of the existing Rust StartupTrace matrix.
# No native text, account, path or process argument is exported.
HELPER_TRACE_PREFIXES = ('primary_fstat_service_native', 'primary_fstat_service_dumps', 'primary_fstat_service_cwd', 'primary_fstat_service_files', 'primary_fstat_service_admission', 'primary_fstat_service_accounts', 'primary_fstat_service_startup', 'primary_fstat_service_store', 'primary_fstat_service_fence', 'primary_fstat_before_recheck', 'primary_fstat_graph_fstat', 'primary_fstat_graph_kvm', 'primary_fstat_graph_libc', 'primary_fstat_graph_loader', 'primary_fstat_graph_hints', 'primary_fstat_pair', 'primary_fstat_command', 'primary_fstat_budget', 'primary_fstat_spawn', 'primary_fstat_hello', 'primary_fstat_hello_eof', 'primary_fstat_hello_frame', 'primary_fstat_after_recheck', 'primary_fstat_worker_peer', 'primary_fstat_custody_capture', 'primary_fstat_seal', 'primary_fstat_activate', 'primary_fstat_worker_hello', 'primary_fstat_admission_bind', 'primary_fstat_mutation_bind', 'primary_fstat_publication_bind', 'primary_fstat_publication_group', 'primary_fstat_policy_bind', 'primary_fstat_policy_nonblocking', 'primary_fstat_registration_refresh', 'primary_fstat_parent_prepare', 'primary_fstat_parent_seal', 'primary_fstat_parent_activate', 'primary_fstat_setup_deadline', 'primary_fstat_service_signals', 'primary_fstat_stock_master_pid', 'primary_fstat_stock_master_row', 'primary_fstat_stock_helper_row', 'primary_fstat_stock_roles', 'primary_fstat_stock_program_pins', 'primary_fstat_stock_config_files', 'primary_fstat_stock_config_includes', 'primary_fstat_stock_passdb', 'primary_fstat_stock_sql', 'primary_fstat_stock_runtime_files', 'primary_fstat_stock_passwd', 'primary_fstat_stock_auth_pin', 'primary_fstat_stock_main_selection', 'primary_fstat_stock_socket_metadata', 'primary_fstat_stock_socket_connect', 'primary_fstat_stock_socket_peer', 'primary_fstat_stock_worker_rows', 'primary_fstat_stock_worker_argv', 'primary_fstat_stock_worker_birth', 'primary_fstat_stock_socket_continuity', 'primary_fstat_stock_cache_pin', 'primary_fstat_stock_cache_query', 'primary_fstat_stock_recheck_files', 'primary_fstat_stock_recheck_snapshot')
HELPER_WORKER_TRACE_PREFIXES = ('primary_fstat_bootstrap_service_native', 'primary_fstat_bootstrap_service_dumps', 'primary_fstat_bootstrap_service_cwd', 'primary_fstat_bootstrap_service_files', 'primary_fstat_bootstrap_service_admission', 'primary_fstat_bootstrap_service_accounts', 'primary_fstat_bootstrap_service_startup', 'primary_fstat_bootstrap_service_store', 'primary_fstat_bootstrap_service_fence', 'primary_fstat_bootstrap_before_recheck', 'primary_fstat_bootstrap_graph_fstat', 'primary_fstat_bootstrap_graph_kvm', 'primary_fstat_bootstrap_graph_libc', 'primary_fstat_bootstrap_graph_loader', 'primary_fstat_bootstrap_graph_hints', 'primary_fstat_bootstrap_pair', 'primary_fstat_bootstrap_command', 'primary_fstat_bootstrap_budget', 'primary_fstat_bootstrap_spawn', 'primary_fstat_bootstrap_hello', 'primary_fstat_bootstrap_hello_eof', 'primary_fstat_bootstrap_hello_frame', 'primary_fstat_bootstrap_after_recheck', 'primary_fstat_bootstrap_worker_peer', 'primary_fstat_bootstrap_custody_capture', 'primary_fstat_bootstrap_seal', 'primary_fstat_bootstrap_activate', 'primary_fstat_bootstrap_worker_hello', 'primary_fstat_bootstrap_admission_bind', 'primary_fstat_bootstrap_mutation_bind', 'primary_fstat_bootstrap_publication_bind', 'primary_fstat_bootstrap_publication_group', 'primary_fstat_bootstrap_policy_bind', 'primary_fstat_bootstrap_policy_nonblocking', 'primary_fstat_bootstrap_registration_refresh', 'primary_fstat_bootstrap_parent_prepare', 'primary_fstat_bootstrap_parent_seal', 'primary_fstat_bootstrap_parent_activate', 'primary_fstat_bootstrap_setup_deadline', 'primary_fstat_bootstrap_service_signals', 'primary_fstat_bootstrap_stock_master_pid', 'primary_fstat_bootstrap_stock_master_row', 'primary_fstat_bootstrap_stock_helper_row', 'primary_fstat_bootstrap_stock_roles', 'primary_fstat_bootstrap_stock_program_pins', 'primary_fstat_bootstrap_stock_config_files', 'primary_fstat_bootstrap_stock_config_includes', 'primary_fstat_bootstrap_stock_passdb', 'primary_fstat_bootstrap_stock_sql', 'primary_fstat_bootstrap_stock_runtime_files', 'primary_fstat_bootstrap_stock_passwd', 'primary_fstat_bootstrap_stock_auth_pin', 'primary_fstat_bootstrap_stock_main_selection', 'primary_fstat_bootstrap_stock_socket_metadata', 'primary_fstat_bootstrap_stock_socket_connect', 'primary_fstat_bootstrap_stock_socket_peer', 'primary_fstat_bootstrap_stock_worker_rows', 'primary_fstat_bootstrap_stock_worker_argv', 'primary_fstat_bootstrap_stock_worker_birth', 'primary_fstat_bootstrap_stock_socket_continuity', 'primary_fstat_bootstrap_stock_cache_pin', 'primary_fstat_bootstrap_stock_cache_query', 'primary_fstat_bootstrap_stock_recheck_files', 'primary_fstat_bootstrap_stock_recheck_snapshot')
HELPER_TRACE_CATEGORIES = ('unknown', 'denied', 'invalid', 'absent', 'busy', 'capacity', 'deadline', 'eof', 'exit', 'signal', 'protocol', 'output')
HELPER_TRACE_ERRORS = ('Invalid', 'Refused', 'Unavailable', 'Authentication', 'Replay', 'Expired', 'Capacity', 'CleanupUnconfirmed')

def helper_trace_scalars(stdout,stderr):
    result={'helper_trace_known':False,'helper_trace_worker':False,
        'helper_trace_operation_id':0,'helper_trace_category_id':0,'helper_trace_error_id':0}
    if stdout or len(stderr)>4096 or not stderr.isascii():return result
    for stage,operation in (('stock_operation',65),('stock_admission',66)):
        for error,name in enumerate(HELPER_TRACE_ERRORS):
            if stderr==('account_password_service stage='+stage+' error='+name+'\n').encode('ascii'):
                result.update(helper_trace_known=True,helper_trace_operation_id=operation,
                    helper_trace_error_id=error+1,helper_trace_stage=stage,helper_trace_error=name)
                return result
    lines=stderr.splitlines(keepends=True)
    if len(lines)!=2 or not all(x.endswith(b'\n')for x in lines) or lines[1]!=b'Account password service unavailable.\n':return result
    for worker,prefixes in((False,HELPER_TRACE_PREFIXES),(True,HELPER_WORKER_TRACE_PREFIXES)):
        for operation,prefix in enumerate(prefixes):
            for category,suffix in enumerate(HELPER_TRACE_CATEGORIES):
                for error,name in enumerate(HELPER_TRACE_ERRORS):
                    expected=('account_password_service stage='+prefix+'_'+suffix+' error='+name+'\n').encode('ascii')
                    if lines[0]==expected:
                        result.update(helper_trace_known=True,helper_trace_worker=worker,
                            helper_trace_operation_id=operation+1,helper_trace_category_id=category+1,
                            helper_trace_error_id=error+1)
                        return result
    return result

class Qualification(base.Fixture):
    def __init__(self):
        super().__init__()
        self.helper=None;self.helper_stopped=False;self.borrowed_dirs={};self.original={};self.original_absent={};self.master=None
        self.passwords=[];self.provisioning_started=False;self.local_client=False;self.client_binary=None
        self.recovery=None
        self.helper_substep_id=0
        self.helper_diagnostic={'helper_child_created':False,'helper_reaped':False,
            'helper_exit_known':False,'helper_exit_code':0,'helper_signaled':False,'helper_signal':0,
            'helper_stdout_bytes':0,'helper_stderr_bytes':0,'helper_output_known':False,
            'helper_trace_known':False,'helper_trace_worker':False,'helper_trace_operation_id':0,
            'helper_trace_category_id':0,'helper_trace_error_id':0}
        self.report.update(component='actual_stock_Rust_password_service',public_service_controls=False,
            public_config_writes=False,external_sessions_terminated=False)
    def pinned_file(self,path,expected,cap=131072):
        self.remaining(True)
        raw=fixed_read(path,cap,expected)
        self.remaining(True)
        return raw

    def check_binary(self,path,digest):
        before=path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and not before.st_mode&0o022 and 0<before.st_size<=512*1024**2,'current_binary_metadata')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        try:
            require(base.file_identity(os.fstat(fd))==base.file_identity(before),'current_binary_open')
            h=hashlib.sha256();total=0
            while True:
                self.remaining()
                chunk=os.read(fd,262144)
                if not chunk:break
                h.update(chunk);total+=len(chunk);require(total<=before.st_size,'current_binary_bound')
            require(total==before.st_size and h.hexdigest()==digest and base.file_identity(os.fstat(fd))==base.file_identity(before) and base.file_identity(path.lstat())==base.file_identity(before),'current_binary_digest_continuity')
        finally:os.close(fd)

    def copy_binary(self,source,target,digest,mode,gid=0):
        # Source-stage carrier handles may legitimately remain held by the
        # root keeper. Only the independently born installed copy is later
        # required to have no process/text references after its owned child ends.
        before=source.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and 0<before.st_size<=512*1024**2 and not before.st_mode&0o022,'binary_input_metadata')
        src=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
        dst=None
        self.creation_uncertain=True
        try:
            require(base.file_identity(os.fstat(src))==base.file_identity(before),'binary_input_open')
            dst=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
            self.files[target]=base.file_identity(os.fstat(dst));self.creation_uncertain=False
            os.fchown(dst,0,gid);os.fchmod(dst,mode)
            self.files[target]=base.file_identity(os.fstat(dst))
            h=hashlib.sha256();count=0
            while True:
                self.remaining()
                block=os.read(src,262144)
                if not block:break
                count+=len(block);require(count<=before.st_size,'binary_copy_bound');h.update(block)
                view=memoryview(block)
                while view:self.remaining();view=view[os.write(dst,view):]
            os.fsync(dst)
            self.files[target]=base.file_identity(os.fstat(dst))
            require(count==before.st_size and h.hexdigest()==digest and base.file_identity(os.fstat(src))==base.file_identity(before) and base.file_identity(source.lstat())==base.file_identity(before),'binary_copy_digest_continuity')
        finally:
            if dst is not None:os.close(dst)
            os.close(src)
        self.check_binary(target,digest)

    def master_row(self):
        raw=fixed_read(Path('/var/dovecot/master.pid'),64)
        require(re.fullmatch(b'[1-9][0-9]{0,8}\n',raw) is not None,'master_pid_shape')
        pid=int(raw)
        row=self.run(('/bin/ps','-p',str(pid),'-o','pid=,ppid=,pgid=,uid=,gid=,lstart=,comm='),'current_master',cleanup=True).decode('ascii').split()
        require(len(row)==11 and row[0]==str(pid) and row[1]=='1' and row[2]==str(pid) and row[3:5]==['0','0'] and row[10]=='dovecot','current_main_master_role')
        return tuple(row)

    def capture_original_map(self,mapping):
        require(type(mapping)is dict and set(mapping)==set(PRESERVED_CONFIG_PATHS),'stock_original25_shape')
        for name,digest in mapping.items():
            path=Path(name)
            if digest is None:
                require(name in KNOWN_ABSENT and not os.path.lexists(path),'stock_absent_config_scope')
                ancestry=[]
                for parent in path.parents:
                    info=parent.lstat()
                    require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,'stock_absent_config_ancestry')
                    ancestry.append((parent,base.file_identity(info)[:6]))
                require(not os.path.lexists(path),'stock_absent_config_created')
                self.original_absent[path]=tuple(ancestry)
            else:
                require(type(digest)is str and re.fullmatch('[a-f0-9]{64}',digest),'stock_present_config_digest')
                self.original[path]=(digest,base.file_identity(path.lstat()));self.pinned_file(path,digest)
        self.original_config_current()
    def original_config_current(self):
        for path,(digest,identity) in self.original.items():
            self.pinned_file(path,digest)
            require(base.file_identity(path.lstat())==identity,'original_config_changed')
        for path,ancestry in self.original_absent.items():
            require(str(path)in KNOWN_ABSENT and not os.path.lexists(path),'original_absent_config_created')
            for parent,prior in ancestry:
                info=parent.lstat()
                require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,'original_absent_ancestry_custody')
                require(base.file_identity(info)[:6]==prior,'original_absent_ancestry_changed')

    def shared_dir(self,path,gid):
        try:m=path.lstat()
        except FileNotFoundError:
            self.directory(path,0o700);m=path.lstat()
        else:
            require(stat.S_ISDIR(m.st_mode) and m.st_uid==m.st_gid==0 and not m.st_mode&0o077 and not tuple(path.iterdir()),'borrowed_empty_directory_required')
            self.borrowed_dirs[path]=(base.identity(m),base.file_identity(m))
        os.chown(path,0,gid);os.chmod(path,0o750)
        if path in self.dirs:self.dirs[path]=base.identity(path.lstat())
        else:self.borrowed_dirs[path]+=(base.identity(path.lstat()),)

    def start_helper(self):
        self.helper_substep_id=1
        require(self.remaining()>=45,'service_client_and_cleanup_budget')
        self.phase='actual production helper startup'
        startup_started=time.monotonic()
        blocked=signal.pthread_sigmask(signal.SIG_BLOCK,base.STOPS)
        self.process_uncertain=True
        try:
            self.helper_substep_id=2
            self.helper=subprocess.Popen((str(HELPER),),cwd='/',stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,close_fds=True,preexec_fn=lambda:signal.pthread_sigmask(signal.SIG_SETMASK,blocked),env={'PATH':'/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/root','LC_ALL':'C'})
            self.helper_substep_id=3;self.helper_diagnostic['helper_child_created']=True
            self.children.append(self.helper)
            self.process_uncertain=False
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
        self.helper_substep_id=4
        end=min(self.end-35,time.monotonic()+6)
        while time.monotonic()<end:
            done=os.waitid(os.P_PID,self.helper.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            require(done is None,'production_helper_exited_before_admission')
            if all(p.exists() for p in SOCKETS):
                elapsed=time.monotonic()-startup_started
                require(elapsed<5,'production_helper_five_second_startup_deadline')
                socket_metadata={}
                for path in SOCKETS:
                    metadata=path.lstat()
                    require(stat.S_ISSOCK(metadata.st_mode)and metadata.st_uid==0,
                        'production_helper_socket_metadata')
                    socket_metadata[str(path)]={'uid':metadata.st_uid,'gid':metadata.st_gid,
                        'mode':stat.S_IMODE(metadata.st_mode)}
                self.report['service_readiness']={'startup_seconds':round(elapsed,6),
                    'startup_deadline_seconds':5,'paired_sockets_published':True,
                    'socket_metadata':socket_metadata,'service_binary_sha256':HELPER_SHA256,
                    'configured_trusted_web_uid':1001,'configured_trusted_relay_uid':1001,
                    'parent_prepare':False,'parent_seal':False,
                    'acceptance_proof':'PENDING_ACTUAL_TRUSTED_PEER_ADMISSION'}
                self.helper_substep_id=5;return
            time.sleep(.02)
        raise base.Refused('production_helper_startup_deadline')

    def capture_helper_exit(self):
        # Only called after wait() of this exact born child. Read before any
        # success predicate so a nonzero startup is diagnosable but still fails.
        code=self.helper.returncode
        require(type(code)is int,'helper_exit_not_reaped')
        self.helper_diagnostic.update(helper_reaped=True,helper_exit_known=True,
            helper_exit_code=code if 0<=code<=1000000 else 0,
            helper_signaled=code<0,helper_signal=-code if -128<=code<0 else 0)
        captured={}
        for name,pipe in(('stdout',self.helper.stdout),('stderr',self.helper.stderr)):
            os.set_blocking(pipe.fileno(),False)
            data=bytearray()
            while len(data)<=4096:
                try:part=os.read(pipe.fileno(),4097-len(data))
                except BlockingIOError:raise base.Refused('helper_stdio_cleanup_unknown')
                if not part:break
                data.extend(part)
            self.helper_diagnostic['helper_'+name+'_bytes']=len(data)
            require(len(data)<=4096,'helper_output_bound')
            captured[name]=bytes(data);pipe.close()
        self.helper_diagnostic.update(helper_output_known=True,
            **helper_trace_scalars(captured['stdout'],captured['stderr']))

    def stop_helper(self):
        if self.helper is None:return
        # It is the exact born, unreaped child; its PID cannot be recycled.
        self.process_uncertain=True
        self.helper.send_signal(signal.SIGTERM)
        try:self.helper.wait(timeout=min(5,self.remaining(True)))
        except subprocess.TimeoutExpired:
            # Still our born unreaped child/group; stop that group only. A
            # forced stop remains uncertain about independently grouped roles.
            os.killpg(self.helper.pid,signal.SIGKILL)
            self.helper.wait(timeout=min(2,self.remaining(True)))
            self.capture_helper_exit()
            self.report['groups'].append({'operation':'forced_production_helper_stop','pid':self.helper.pid,'reaped':True,'group_gone':False,'component_absence_confirmed':False,'session_reconstruction_claimed':False,'failure':'forced_helper_stop','code':self.helper.returncode,'stdout_bytes':None,'stderr_bytes':None,'sql_error_code':None,'separate_primary_absence':'UNKNOWN'})
            raise base.Refused('forced_helper_stop_retains_namespace')
        self.capture_helper_exit()
        require(self.helper.returncode==0 and all(not p.exists() for p in SOCKETS),'helper_clean_stop_or_endpoint_removal_unknown')
        try:os.killpg(self.helper.pid,0)
        except ProcessLookupError:pass
        else:raise base.Refused('helper_owned_group_still_present')
        self.helper_stopped=True
        helper_record={'operation':'actual_production_helper','pid':self.helper.pid,'reaped':True,'group_gone':True,'component_absence_confirmed':False,'session_reconstruction_claimed':False,'failure':None,'code':0,'stdout_bytes':None,'stderr_bytes':None,'sql_error_code':None}
        self.report['groups'].append(helper_record)
        helper_record.update(stdout_bytes=self.helper_diagnostic['helper_stdout_bytes'],stderr_bytes=self.helper_diagnostic['helper_stderr_bytes'])
        # Utility groups are separate from helper's group. Fresh dedicated UID
        # absence, not parent-group disappearance, is the required extra proof.
        for name in ROLES:
            uid=self.users[name][0]
            out=self.run(('/bin/ps','-ax','-o','uid=,pid=,comm='),'fresh_role_process_absence',cleanup=True)
            require(not any(row.split() and row.split()[0]==str(uid).encode('ascii') for row in out.splitlines()),'dedicated_role_process_still_present')
        for target in ((HELPER,self.client_binary) if self.local_client else (HELPER,)):
            lines=self.run(('/usr/bin/fstat','-n',str(target)),'owned_installed_copy_reference_absence',cleanup=True).splitlines()
            require(len(lines)==1 and lines[0].split()[:4]==[b'USER',b'CMD',b'PID',b'FD'],'owned_installed_copy_reference_remaining')
        helper_record['component_absence_confirmed']=True
        self.process_uncertain=False
        self.report['owned_sql_hash_uids_absent']=True

    def run(self,argv,label,data=b'',cap=16384,seconds=5,cleanup=False,test=False,absolute=None,client=False):
        require(not test and not client,'no_legacy_test_or_client_mode')
        readonly=(len(argv)==5 and argv[:4]==('/usr/local/bin/doveconf','-c',MAIN,'-h')
            and argv[4]in('auth_verbose_passwords','auth_debug_passwords','verbose_proctitle','auth_cache_size','mail_location'))
        readonly|=(len(argv)==5 and argv[:3]==('/usr/local/bin/doveadm','user','-f')
            and argv[3]in('home','mail','uid','gid')and argv[4]=='bob@osmap-password.invalid')
        meta=(argv[:3]==('/bin/ps','-ax','-o')and argv[3:]in(
            ('uid=,pid=,comm=',),('pid=,ppid=,pgid=,uid=,gid=,lstart=,comm=',)))
        meta|=(len(argv)==5 and argv[:2]==('/bin/ps','-p')and argv[2].isdigit()
            and argv[3]=='-o'and argv[4]in('pid=,ppid=,pgid=,uid=,gid=,lstart=,comm=','pid=,ppid=,uid=,lstart=,comm='))
        refs=(len(argv)==3 and argv[:2]==('/usr/bin/fstat','-n')and argv[2]==str(HELPER))
        roles=(len(argv)==2 and argv[0]in('/usr/sbin/groupadd','/usr/sbin/userdel','/usr/sbin/groupdel')and argv[1]in ROLES)
        roles|=(len(argv)==8 and argv[:2]==('/usr/sbin/useradd','-g')and argv[2]in ROLES
            and argv[3:7]==('-d','/var/empty','-s','/sbin/nologin')and argv[7]==argv[2])
        require(tuple(argv)==base.SQL or tuple(argv)==base.HASH or readonly or meta or refs or roles,'stock_fixed_command_only')
        return super().run(argv,label,data=data,cap=cap,seconds=seconds,cleanup=cleanup,
            test=False,absolute=min(self.end,absolute or self.end))

    def publish(self,path,raw,mode=0o600,gid=0):
        try:return super().publish(path,raw,mode=mode,gid=gid)
        finally:
            if self.recovery is not None:self.recovery.checkpoint('FIXTURE_PUBLICATION')

    def own_principal(self,name):
        try:return super().own_principal(name)
        finally:
            if self.recovery is not None:self.recovery.checkpoint('ROLE_CREATED_OR_UNCERTAIN')

    def sql(self,text,mutation=False,cleanup=False):
        prior=self.sql_uncertain
        if mutation and self.recovery is not None:
            self.sql_uncertain=True;self.recovery.checkpoint('SQL_MUTATION_INTENT')
        value=super().sql(text,mutation=mutation,cleanup=cleanup)
        if mutation:
            self.sql_uncertain=prior
            if self.recovery is not None:self.recovery.checkpoint('SQL_MUTATION_OBSERVED')
        return value

    def preflight(self):
        require(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0 and socket.gethostname()=='obsd1.blackbagsecurity.com'
            and (os.uname().sysname,os.uname().machine)==('OpenBSD','amd64'), 'fixed_stock_authority')
        self.report['observed_release']=os.uname().release
        require(self.stage.parent==Path('/var/run') and re.fullmatch('osmap-service-admission-root-[a-f0-9]{16}',self.stage.name),'fixed_stock_stage')
        require(all(type(v)is str and re.fullmatch('[a-f0-9]{64}',v)for v in(HELPER_SHA256,CONFIG_MAP_SHA256,CUSTODY_SHA256)),'stock_build_bindings')
        self.check_binary(self.stage/'account-passwd',HELPER_SHA256)
        mapping=json.loads(self.pinned_file(self.stage/'original-config-sha256.json',CONFIG_MAP_SHA256))
        self.capture_original_map(mapping)
        # Public SQL is a separate protected input; never expand frozen original25.
        sql=Path('/etc/dovecot/dovecot-sql.conf.ext')
        self.public_sql_before=(hashlib.sha256(fixed_read(sql,16384)).hexdigest(),base.file_identity(sql.lstat()))
        require(self.public_sql_before[0]==PUBLIC_SQL_SHA256,'stock_public_SQL_profile_pin')
        for path in(HELPER,*SOCKETS,*SERVICE_FILES,*CONNECTOR_FILES,base.CONFIG,base.PLAN,base.CONTEXT):
            require(not os.path.lexists(path),'stock_namespace_collision')
        for name in ROLES:
            require(not any(p.pw_name==name for p in pwd.getpwall())and not any(g.gr_name==name for g in grp.getgrall()),'stock_role_collision')
        connector=pwd.getpwnam('_osmap')
        require((connector.pw_uid,connector.pw_gid)==(1001,1001),'current_connector_identity')
        for parent in(Path('/etc/osmap'),Path('/var/db/osmap-account'),Path('/usr/local/libexec/osmap')):
            try:m=parent.lstat()
            except FileNotFoundError:
                require(parent==Path('/var/db/osmap-account'),'stock_missing_parent_scope')
                m=parent.parent.lstat();require(stat.S_ISDIR(m.st_mode)and m.st_uid==m.st_gid==0 and not m.st_mode&0o022 and parent.parent.resolve()==parent.parent,'stock_owned_parent_ancestry')
                continue
            require(stat.S_ISDIR(m.st_mode)and m.st_uid==m.st_gid==0
                and not m.st_mode&0o022 and parent.resolve()==parent,'stock_preexisting_fixed_parent')
        if os.path.lexists(CONNECTOR_PARENT):
            m=CONNECTOR_PARENT.lstat()
            require(stat.S_ISDIR(m.st_mode)and m.st_uid==m.st_gid==0 and stat.S_IMODE(m.st_mode)==0o755
                and CONNECTOR_PARENT.resolve()==CONNECTOR_PARENT,'stock_connector_parent_metadata')
        self.master=self.master_row()
        raw=self.sql("SELECT CURRENT_USER(),VERSION(); SELECT COUNT(*) FROM mysql.user WHERE User='osmap_account_mutation'; SELECT COUNT(*) FROM postfixadmin.mailbox WHERE username IN ('alice@osmap-password.invalid','bob@osmap-password.invalid'); SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA='postfixadmin' AND TABLE_NAME='mailbox'; SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE EVENT_OBJECT_SCHEMA='postfixadmin' AND EVENT_OBJECT_TABLE='mailbox'; SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA='postfixadmin' AND TABLE_NAME='mailbox' AND REFERENCED_TABLE_NAME IS NOT NULL;\n")
        schema = stock_fresh_reserved_schema(raw)
        self.report['stock_schema'] = schema
        self.report['fresh_before_counts']={'database_user':schema['reserved_database_users'],
            'controlled_rows':schema['controlled_rows']}
        for option in('auth_verbose_passwords','auth_debug_passwords','verbose_proctitle'):
            require(self.run(('/usr/local/bin/doveconf','-c',MAIN,'-h',option),'stock_secret_log_precondition').strip()==b'no','stock_log_precondition')
        require(self.run(('/usr/local/bin/doveconf','-c',MAIN,'-h','auth_cache_size'),'stock_cache_zero_precondition')==b'0\n','stock_cache_not_zero')
        self.original_config_current()

    def prepare_connector_directory(self):
        # The sole additional fixed dependency. Record exclusive0700 birth
        # under the existing umask before making executable root0755 access.
        path=CONNECTOR_PARENT;fd=None
        try:
            if os.path.lexists(path):
                m=path.lstat()
                require(stat.S_ISDIR(m.st_mode)and m.st_uid==m.st_gid==0
                    and stat.S_IMODE(m.st_mode)==0o755 and path.resolve()==path,
                    'stock_connector_parent_metadata')
                return
            self.directory(path,0o700)
            require(path in self.dirs,'stock_connector_directory_birth_not_owned')
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            require(base.identity(os.fstat(fd))==self.dirs[path]==base.identity(path.lstat()),
                'stock_connector_directory_open_changed')
            self.creation_uncertain=True
            os.fchmod(fd,0o755)
            current=base.identity(os.fstat(fd));self.dirs[path]=current
            require(current==base.identity(path.lstat())and current[2:5]==(0,0,stat.S_IFDIR|0o755),
                'stock_connector_directory_changed')
            os.fsync(fd)
            parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                require(base.identity(os.fstat(parent))==base.identity(path.parent.lstat()),
                    'stock_connector_parent_changed')
                os.fsync(parent)
            finally:os.close(parent)
            self.creation_uncertain=False
        finally:
            if fd is not None:
                self.dirs[path]=base.identity(os.fstat(fd));os.close(fd)
            if self.recovery is not None:self.recovery.checkpoint('CONNECTOR_DIRECTORY_OBSERVED')

    def provision(self):
        return self._provision_accounts()
    def _provision_accounts(self):
        self.phase = 'stock account-only provisioning'
        self.provisioning_started=True
        for name in NAMES:
            self.own_principal(name)
        require(self.users[NAMES[0]][0] != self.users[NAMES[1]][0]
                and self.users[NAMES[0]][1] != self.users[NAMES[1]][1], 'distinct_purpose_identities')
        directories=(('/etc/osmap',0o755),('/etc/osmap/account-runtime',0o700),
            ('/var/db/osmap-account',0o700),(str(EPOCH),0o700),('/usr/local/libexec/osmap',0o755))
        for name, mode in directories:
            self.directory(Path(name), mode)
        for account in ACCOUNTS:
            stem = hashlib.sha256(b'osmap-account-epoch-v1\0' + account.encode('ascii')).hexdigest()
            for suffix in ('.json', '.lock', '.uncertain'):
                p = EPOCH / (stem + suffix)
                require(not p.exists() and not p.is_symlink(), 'reserved_epoch_collision')
            self.publish(EPOCH / (stem + '.lock'), b'')
            self.publish(EPOCH / (stem + '.json'), b'{"epoch":0,"state":"active","changed_at":null,"intent":null,"used_intents":[]}\n')
        role_password = secrets.token_hex(32)
        self.sql('CREATE USER ' + PRINCIPAL + " IDENTIFIED BY '" + role_password + "';\n", mutation=True)
        self.db_user = True
        self.sql('GRANT SELECT(username,password,modified,active,smtp_active),UPDATE(password,modified) ON postfixadmin.mailbox TO ' + PRINCIPAL + ';\n', mutation=True)
        grantee = hexsql(PRINCIPAL)
        grants = self.sql('SELECT COLUMN_NAME,PRIVILEGE_TYPE FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE=' + grantee + " AND TABLE_SCHEMA='postfixadmin' AND TABLE_NAME='mailbox';\n")
        require(set(tuple(r.split('\t')) for r in grants.decode('ascii').splitlines()) == GRANTS, 'exact_seven_column_grants')
        broad = self.sql('SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=' + grantee + " AND PRIVILEGE_TYPE<>'USAGE'; SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=" + grantee + '; SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE=' + grantee + ';\n')
        require(broad == b'0\n0\n0\n', 'no_broad_database_grants')
        self.db_user_lease = self.sql('SHOW CREATE USER ' + PRINCIPAL + ';\n')
        require(0 < len(self.db_user_lease) <= 4096, 'created_database_user_lease')
        self.db_grants_lease = self.sql('SHOW GRANTS FOR ' + PRINCIPAL + ';\n')
        require(0 < len(self.db_grants_lease) <= 4096, 'created_database_grants_lease')
        self.report['restricted_column_grants'] = 7
        self.publish(CONFIG, ('[client]\nuser=osmap_account_mutation\npassword=' + role_password
            + '\nprotocol=SOCKET\nsocket=/var/run/mysql/mysql.sock\n').encode('ascii'), 0o440, self.users['_osmapsql'][1])
        self.publish(PLAN, json.dumps({'version': 1, 'authority': 'mail.blackbagsecurity.com',
            'purpose': 'osmap-account-mutation', 'server': '_mysql', 'socket': '/var/run/mysql/mysql.sock',
            'database_user': 'osmap_account_mutation'}, sort_keys=True).encode('ascii'))
        hashes = []
        self.passwords=[]
        for _ in ACCOUNTS:
            password = secrets.token_hex(32)
            self.passwords.append(password)
            hashed = self.run(HASH, 'initial_private_hash', (password + '\n' + password + '\n').encode('ascii'), seconds=10).decode('ascii').removesuffix('\n')
            require(ARGON.fullmatch(hashed), 'initial_actual_ARGON2ID')
            hashes.append(hashed)
        values = []
        for account, hashed in zip(ACCOUNTS, hashes):
            local = account.split('@')[0]
            values.append('(' + ','.join((hexsql(account), hexsql(hashed), hexsql('osmap fixture ' + self.lease),
                hexsql('osmap-password.invalid/' + local + '-' + self.lease + '/'), '0', hexsql(local),
                hexsql('osmap-password.invalid'), 'UTC_TIMESTAMP()', "'2000-01-01 00:00:00'", '1',
                "''", "''", "''", "'2000-01-01 00:00:00'", "'2099-01-01 00:00:00'", 'NULL', '1')) + ')')
        self.sql('START TRANSACTION; INSERT INTO postfixadmin.mailbox (' + ','.join(COLUMNS)
                 + ') VALUES ' + ','.join(values) + '; COMMIT;\n', mutation=True)
        self.rows = True
        self.baseline = self.row_read()
        require(all(r['password'] == h and r['name'] == 'osmap fixture ' + self.lease
                    and r['active'] == r['smtp_active'] == 1 for r, h in zip(self.baseline, hashes)), 'inserted_exact_owned_rows')
    def provision_service(self):
        require(self.provisioning_started and self.baseline is not None,'owned_rows_before_service')
        for path in(Path('/var/run/osmap-account-admission'),Path('/var/run/osmap-account-mutation')):
            self.shared_dir(path,1003)
        self.copy_binary(self.stage/'account-passwd',HELPER,HELPER_SHA256,0o500)
        keys=[secrets.token_hex(32).encode('ascii')for _ in range(3)]
        require(len(set(keys))==3,'stock_distinct_keys')
        self.publish(SERVICE_FILES[0],json.dumps({'version':1,'socket':str(SOCKETS[0]),'trusted_web_uid':1001,'accounts':ACCOUNTS}).encode('ascii'))
        self.publish(SERVICE_FILES[1],keys[0])
        self.publish(RUNTIME/'config.json',json.dumps({'version':1,'authority':'mail.blackbagsecurity.com','purpose':'osmap-account-mutation','accounts':ACCOUNTS,'trusted_relay_uid':1001}).encode('ascii'))
        self.publish(RUNTIME/'mutation.key',keys[1]);self.publish(RUNTIME/'session-proof.key',keys[2])
        self.original_config_current();require(self.master_row()==self.master,'public_master_changed')

    def cleanup(self):
        if not self.provisioning_started:
            self.report['cleanup_confirmed']=True;return
        if self.helper is not None and not self.helper_stopped:self.stop_helper()
        require(not self.process_uncertain,'owned_helper_cleanup_unknown')
        self.original_config_current();require(self.master_row()==self.master,'public_master_cleanup_changed')
        sql,identity=self.public_sql_before
        require(hashlib.sha256(fixed_read(Path('/etc/dovecot/dovecot-sql.conf.ext'),16384)).hexdigest()==sql
            and base.file_identity(Path('/etc/dovecot/dovecot-sql.conf.ext').lstat())==identity,'public_SQL_changed')
        super().cleanup()
        for path,(before,full,ours)in self.borrowed_dirs.items():
            require(base.identity(path.lstat())==ours and not tuple(path.iterdir()),'borrowed_stock_dir_cleanup')
            os.chown(path,before[2],before[3]);os.chmod(path,stat.S_IMODE(before[4]))
            require(base.identity(path.lstat())==before,'borrowed_stock_dir_restored')
        self.original_config_current();require(self.master_row()==self.master,'public_master_final_changed')
        self.report.update(cleanup_confirmed=True,public_original25_preserved=True,public_master_preserved=True)

EPOCH,CONFIG,PLAN,CONTEXT=base.EPOCH,base.CONFIG,base.PLAN,base.CONTEXT
ACCOUNTS,NAMES,PRINCIPAL,GRANTS,HASH,ARGON,COLUMNS=base.ACCOUNTS,base.NAMES,base.PRINCIPAL,base.GRANTS,base.HASH,base.ARGON,base.COLUMNS
hexsql=base.hexsql
