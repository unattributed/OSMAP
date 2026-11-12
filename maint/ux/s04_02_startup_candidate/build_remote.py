"""Current signed-source native compiler; finite compile-only operation."""
import base64, hashlib, io, json, os, resource, selectors, shutil, signal, socket, stat, subprocess, sys, tarfile, tempfile, time, traceback
def require(value, code):
    if not value:
        raise RuntimeError(code)

START = time.monotonic()
END = START + 650
os.umask(63)
from pathlib import Path
BASE = '__SIGNED_BASE__'
BUILD_KIND = '__BUILD_KIND__'
MANIFEST_SHA = '__MANIFEST_SHA__'
ARCHIVE_SHA = '__ARCHIVE_SHA__'
REQUIRED_DATA = 4294967296

def interrupted(signum, frame):
    raise TimeoutError('native_build_interrupted')
STOPS = {signal.SIGALRM, signal.SIGHUP, signal.SIGTERM, signal.SIGINT}
for number in STOPS:
    signal.signal(number, interrupted)
signal.alarm(650)
report = {'result': 'FAIL', 'activation': False, 'account_operations': False, 'scratch_gone': False, 'plugin_built': False, 'tests_executed': False, 'application_executed': False}
root = None
lease = None
uncertain = False
artifact_stage = None
initial_limits = {str(n): list(resource.getrlimit(getattr(resource, n))) for n in ('RLIMIT_CORE', 'RLIMIT_CPU', 'RLIMIT_DATA', 'RLIMIT_FSIZE', 'RLIMIT_NOFILE', 'RLIMIT_NPROC', 'RLIMIT_RSS', 'RLIMIT_STACK')}
report.update({'schema': 'osmap-controlled-native-build-current-v1', 'signed_base_commit': BASE, 'build_kind': BUILD_KIND, 'source_manifest_sha256': MANIFEST_SHA, 'archive_sha256': ARCHIVE_SHA, 'ordinary_Runtime_qualification': False, 'public_service_operations': False, 'compiler_data_soft_bytes': REQUIRED_DATA, 'compiler_build_jobs': 1, 'initial_parent_limits': initial_limits})

def command(argv, phase, client_profile=False):
    global uncertain
    began = time.monotonic()
    deadline = min(END, time.monotonic() + phase)
    io_end = deadline - 2
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/home/foo', 'LC_ALL': 'C', 'TMPDIR': str(root / 'tmp'), 'CARGO_HOME': '/home/foo/.cargo', 'CARGO_TARGET_DIR': str(root / 'target'), 'CARGO_BUILD_JOBS': '1'}
    require(type(client_profile) is bool, 'build_contract_line_25')
    if client_profile:
        env.update({'CARGO_PROFILE_TEST_OPT_LEVEL': '0', 'CARGO_PROFILE_TEST_DEBUG': '0'})
    require((Path(argv[0]).resolve() == Path('/usr/local/bin/cargo')
             or argv == ['/usr/local/bin/rustc', '--version']) and Path.cwd() == root, 'compiler_program')
    require(root.is_dir() and str(root).startswith('/tmp/osmap-s04-02-rust-'), 'build_contract_line_28')
    child = None
    buffers = [bytearray(), bytearray()]
    failure = None
    code = None

    def child_setup():
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        soft, hard = resource.getrlimit(resource.RLIMIT_DATA)
        if hard != resource.RLIM_INFINITY and hard < REQUIRED_DATA:
            raise RuntimeError('DATA_HARD_BELOW_4GIB')
        resource.setrlimit(resource.RLIMIT_DATA, (REQUIRED_DATA, hard))
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, STOPS)
    try:
        try:
            if time.monotonic() >= io_end:
                raise TimeoutError('prespawn_original_deadline')
            child = subprocess.Popen(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=True, preexec_fn=child_setup)
            report['last_owned_group'] = child.pid
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        with selectors.DefaultSelector() as sel:
            for index, pipe in enumerate([child.stdout, child.stderr]):
                os.set_blocking(pipe.fileno(), False)
                sel.register(pipe, selectors.EVENT_READ, index)
            while time.monotonic() < io_end:
                for key, _ in sel.select(min(0.02, max(0, io_end - time.monotonic()))):
                    data = os.read(key.fileobj.fileno(), 4096)
                    if not data:
                        sel.unregister(key.fileobj)
                    else:
                        buffers[key.data].extend(data)
                        if len(buffers[key.data]) > 1048576:
                            raise ValueError('output_cap')
                if not sel.get_map():
                    state = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if state is not None and state.si_pid == child.pid:
                        break
            else:
                raise TimeoutError('phase_deadline')
    except Exception as error:
        failure = type(error).__name__
    finally:
        if child is not None:
            cleanup_mask = signal.pthread_sigmask(signal.SIG_BLOCK, STOPS)
            uncertain = True
            signal_ok = False
            reaped = False
            gone = False
            try:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                    signal_ok = True
                except ProcessLookupError:
                    signal_ok = True
                try:
                    code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
                    reaped = True
                except Exception:
                    pass
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    gone = True
                except Exception:
                    pass
                uncertain = not (signal_ok and reaped and gone)
                child.stdout.close()
                child.stderr.close()
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, cleanup_mask)
    return {'code': code, 'failure': failure, 'group_gone': not uncertain, 'elapsed_seconds': round(time.monotonic() - began, 3), 'phase_cap_seconds': phase, 'stdout': bytes(buffers[0]).decode('utf8', 'replace'), 'stderr': bytes(buffers[1]).decode('utf8', 'replace')}
try:
    require(BUILD_KIND in ('pair', 'libtest-only', 'helper-only'), 'build_selection')
    report['stage'] = 'identity'
    require(socket.gethostname() == 'obsd1.blackbagsecurity.com' and os.getuid() == os.geteuid() == 1000 and (os.getgid() == os.getegid() == 1000), 'build_contract_line_77')
    uname = os.uname()
    require(uname.sysname == 'OpenBSD' and uname.machine == 'amd64', 'build_contract_line_79')
    report['identity'] = {'hostname': socket.gethostname(), 'system': uname.sysname, 'release': uname.release, 'machine': uname.machine, 'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(), 'egid': os.getegid()}
    report['build_programs'] = {}
    for name in ['/usr/local/bin/cargo', '/usr/local/bin/rustc']:
        q = Path(name)
        m = q.lstat()
        require(q.resolve() == q and stat.S_ISREG(m.st_mode) and (m.st_uid == 0) and (m.st_nlink == 1) and (stat.S_IMODE(m.st_mode) == 493), 'build_contract_line_84')
        for parent in q.parents:
            pm = parent.lstat()
            require(stat.S_ISDIR(pm.st_mode) and pm.st_uid == 0 and (not pm.st_mode & 18), 'build_contract_line_86')
        report['build_programs'][name] = {'resolved': str(q.resolve()), 'uid': m.st_uid, 'mode': stat.S_IMODE(m.st_mode), 'nlink': m.st_nlink}
        def program_identity(item):
            return (item.st_dev, item.st_ino, item.st_uid, item.st_gid, item.st_mode,
                    item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(0 < m.st_size < 512 * 1024 * 1024, 'compiler_file_size')
        fd = os.open(q, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        digest = hashlib.sha256()
        try:
            require(program_identity(os.fstat(fd)) == program_identity(m), 'compiler_file_open_changed')
            while True:
                require(time.monotonic() < END, 'compiler_hash_deadline')
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            require(program_identity(os.fstat(fd)) == program_identity(m)
                    and program_identity(q.lstat()) == program_identity(m), 'compiler_file_changed')
        finally:
            os.close(fd)
        report['build_programs'][name].update(sha256=digest.hexdigest(), metadata=list(program_identity(m)))
    for q in [Path('/home/foo/.cargo')]:
        m = q.lstat()
        require(stat.S_ISDIR(m.st_mode) and m.st_uid == 1000 and (not m.st_mode & 18), 'build_contract_line_89')
    require(all((hasattr(os, name) for name in ['waitid', 'WNOWAIT', 'WEXITED', 'P_PID'])) and hasattr(signal, 'pthread_sigmask'), 'build_contract_line_90')
    soft, hard = resource.getrlimit(resource.RLIMIT_DATA)
    require(hard == resource.RLIM_INFINITY or hard >= REQUIRED_DATA, 'build_contract_line_92')
    report['stage'] = 'packet'
    packet_raw = sys.stdin.buffer.read(5 * 1024 * 1024 + 1)
    require(len(packet_raw) <= 5 * 1024 * 1024, 'build_contract_line_94')
    packet = json.loads(packet_raw)
    require(set(packet) == {'signed_base_commit', 'source_manifest_sha256', 'manifest', 'archive_sha256', 'archive'}, 'build_contract_line_95')
    require(packet['signed_base_commit'] == BASE and packet['source_manifest_sha256'] == MANIFEST_SHA and (packet['archive_sha256'] == ARCHIVE_SHA), 'build_contract_line_96')
    raw = base64.b64decode(packet['archive'], validate=True)
    require(len(raw) <= 4 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == packet['archive_sha256'], 'build_contract_line_98')
    pins = packet['manifest']
    require(len(pins) == __SOURCE_COUNT__, 'build_contract_line_99')
    require(hashlib.sha256((json.dumps(pins, sort_keys=True, indent=2) + '\n').encode()).hexdigest() == MANIFEST_SHA, 'build_contract_line_100')
    source = tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz')
    members = source.getmembers()
    require(len(members) == len(pins) and sum((m.size for m in members)) <= 16 * 1024 * 1024, 'build_contract_line_102')
    require(all((m.isfile() and m.name in pins and (not m.name.startswith('/')) and ('..' not in m.name.split('/')) and (m.size <= 4 * 1024 * 1024) for m in members)), 'build_contract_line_103')
    require(len(set((m.name for m in members))) == len(members), 'build_contract_line_104')
    report['stage'] = 'source_extract'
    root = __import__('pathlib').Path(tempfile.mkdtemp(prefix='osmap-s04-02-rust-'))
    root.chmod(448)
    s = root.lstat()
    lease = (s.st_dev, s.st_ino, s.st_uid, stat.S_IMODE(s.st_mode))
    report['scratch'] = str(root)
    for member in members:
        data = source.extractfile(member).read()
        require(hashlib.sha256(data).hexdigest() == pins[member.name], 'build_contract_line_109')
        target = root / member.name
        target.parent.mkdir(parents=True, exist_ok=True, mode=448)
        with target.open('xb') as f:
            f.write(data)
        target.chmod(384)
    (root / 'tmp').mkdir(mode=448)
    os.chdir(root)

    def parity():
        for name, digest in pins.items():
            path = root / name
            s = path.lstat()
            if not stat.S_ISREG(s.st_mode) or s.st_uid != 1000 or s.st_nlink != 1 or (stat.S_IMODE(s.st_mode) != 384) or (hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                return False
        return True
    require(parity(), 'build_contract_line_120')
    report['source_count'] = len(pins)
    report['source_before'] = True
    report['compiler_versions'] = {}
    for program in ('/usr/local/bin/cargo', '/usr/local/bin/rustc'):
        version = command([program, '--version'], 10)
        require(version['code'] == 0 and version['failure'] is None and version['group_gone'] is True
                and not version['stderr'] and 0 < len(version['stdout']) <= 4096, 'compiler_version_observation')
        report['compiler_versions'][program] = version
    report['helper_built'] = False
    report['artifact_observations'] = []
    artifact_stage = Path(tempfile.mkdtemp(prefix='.osmap-s04-02-artifacts-', dir='/home/foo'))
    artifact_stage.chmod(448)
    sm = artifact_stage.lstat()
    report['artifact_stage'] = {'path': str(artifact_stage), 'dev': sm.st_dev, 'ino': sm.st_ino, 'uid': sm.st_uid, 'gid': sm.st_gid, 'mode': stat.S_IMODE(sm.st_mode)}

    def retain_phase(name, phase):
        for kind in ('stdout', 'stderr'):
            raw = phase[kind].encode()
            require(len(raw) <= 2 * 1024 * 1024, 'build_contract_line_127')
            q = artifact_stage / (name + '.' + kind + '.log')
            fd = os.open(q, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
            with os.fdopen(fd, 'wb') as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
        report.setdefault('retained_compiler_logs', {})[name] = {'stdout_sha256': hashlib.sha256(phase['stdout'].encode()).hexdigest(), 'stderr_sha256': hashlib.sha256(phase['stderr'].encode()).hexdigest()}
    if BUILD_KIND != 'libtest-only':
        report['stage'] = 'compile_helper'
        report['helper'] = command(['/usr/local/bin/cargo', 'build', '--release', '--offline', '--locked', '--bin', 'account-passwd', '--message-format=json'], 300)
        retain_phase('helper', report['helper'])
        require(report['helper']['code'] == 0 and report['helper']['failure'] is None and report['helper']['group_gone'] and (not uncertain), 'build_contract_line_135')
        report['helper_built'] = True
    if BUILD_KIND != 'helper-only':
        report['stage'] = 'compile_frontend'
        report['rust'] = command(['/usr/local/bin/cargo', 'test', '--offline', '--locked', '--lib', '--no-run', '--message-format=json'], 300, client_profile=True)
        retain_phase('rust', report['rust'])
        report['client_profile_scope'] = 'CURRENT_CONTROLLED_HTTP_CALLER_ONLY_NOT_ORDINARY_RUNTIME_TIMING'
        require(report['rust']['code'] == 0 and report['rust']['failure'] is None and report['rust']['group_gone'] and (not uncertain), 'build_contract_line_141')
    report['stage'] = 'source_after'
    report['source_after'] = parity()
    if report['source_after'] and not uncertain:
        records = [json.loads(line) for name in ('helper', 'rust') if name in report for line in report[name]['stdout'].splitlines() if line.startswith('{')]

        def capture(target, test):
            artifacts = [x for x in records if x.get('reason') == 'compiler-artifact' and x.get('target', {}).get('name') == target and (x.get('target', {}).get('kind') == (['lib'] if test else ['bin'])) and (x.get('profile', {}).get('test') is test) and x.get('executable')]
            require(len(artifacts) == 1 and type(artifacts[0]['fresh']) is bool, 'build_contract_line_148')
            profile = artifacts[0]['profile']
            require(profile['opt_level'] == ('0' if test else '3') and profile['debuginfo'] == 0 and (profile['test'] is test) and (profile['debug_assertions'] is test) and (profile['overflow_checks'] is test), 'build_contract_line_149')
            executable = __import__('pathlib').Path(artifacts[0]['executable'])
            if test:
                require(executable.parent == root / 'target/debug/deps' and executable.name.startswith('osmap-') and (len(executable.name) <= 80), 'build_contract_line_151')
            else:
                require(executable == root / 'target/release/account-passwd' and artifacts[0]['target']['kind'] == ['bin'], 'build_contract_line_152')

            def binary_identity(m):
                return (m.st_dev, m.st_ino, m.st_uid, m.st_gid, m.st_mode, m.st_nlink, m.st_size, m.st_mtime_ns, m.st_ctime_ns)
            before = executable.lstat()
            report['artifact_observations'].append({'path': str(executable), 'cargo_profile': profile, 'cargo_target_kind': artifacts[0]['target']['kind'], 'fresh': artifacts[0]['fresh'], 'metadata': list(binary_identity(before))})
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 1000 and (before.st_nlink in ((1,) if test else (1, 2))) and (stat.S_IMODE(before.st_mode) in (448, 493)) and (0 < before.st_size < 512 * 1024 * 1024), 'build_contract_line_157')
            fd = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            digest = hashlib.sha256()
            try:
                require(binary_identity(os.fstat(fd)) == binary_identity(before), 'build_contract_line_160')
                while True:
                    require(time.monotonic() < END, 'build_contract_line_162')
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                require(binary_identity(os.fstat(fd)) == binary_identity(before) and binary_identity(executable.lstat()) == binary_identity(before), 'build_contract_line_166')
            finally:
                os.close(fd)
            require(artifact_stage is not None, 'build_contract_line_168')
            copied = artifact_stage / ('osmap-libtest' if test else 'account-passwd')
            srcfd = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            dstfd = os.open(copied, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 448)
            copied_digest = hashlib.sha256()
            try:
                require(binary_identity(os.fstat(srcfd)) == binary_identity(before), 'build_contract_line_174')
                while True:
                    require(time.monotonic() < END, 'build_contract_line_176')
                    chunk = os.read(srcfd, 1024 * 1024)
                    if not chunk:
                        break
                    copied_digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(dstfd, view)
                        require(written > 0, 'build_contract_line_182')
                        view = view[written:]
                os.fsync(dstfd)
                require(binary_identity(os.fstat(srcfd)) == binary_identity(before) and binary_identity(executable.lstat()) == binary_identity(before), 'build_contract_line_183')
            finally:
                os.close(srcfd)
                os.close(dstfd)
            require(copied_digest.hexdigest() == digest.hexdigest(), 'build_contract_line_185')
            cm = copied.lstat()
            require(cm.st_uid == 1000 and cm.st_nlink == 1 and (stat.S_IMODE(cm.st_mode) == 448) and (cm.st_size == before.st_size), 'build_contract_line_186')
            return {'path': str(copied), 'compiler_path': str(executable), 'compiler_metadata': list(binary_identity(before)), 'gid': cm.st_gid, 'sha256': digest.hexdigest(), 'size': before.st_size, 'dev': cm.st_dev, 'ino': cm.st_ino, 'uid': cm.st_uid, 'mode': stat.S_IMODE(cm.st_mode), 'nlink': cm.st_nlink, 'source_count': len(pins), 'fresh': artifacts[0]['fresh'], 'profile_test': test, 'cargo_profile': profile, 'cargo_target_kind': artifacts[0]['target']['kind'], 'tests_executed': False, 'application_executed': False}
        report['stage'] = 'capture_artifact'
        if BUILD_KIND != 'libtest-only':
            report['native_helper_binary'] = capture('account-passwd', False)
        if BUILD_KIND != 'helper-only':
            report['native_test_binary'] = capture('osmap', True)
        report['result'] = 'PASS'
except Exception as error:
    report['failure_class'] = type(error).__name__
    report['failure_reason'] = str(error) if type(error) is RuntimeError else type(error).__name__
    report['failure_line'] = traceback.extract_tb(error.__traceback__)[-1].lineno
finally:
    report['cleanup_uncertain'] = uncertain
    report['parent_limits_unchanged'] = initial_limits == {str(n): list(resource.getrlimit(getattr(resource, n))) for n in initial_limits}
    if not report['parent_limits_unchanged']:
        report['result'] = 'FAIL'
    for key in ('helper', 'rust'):
        if key in report:
            phase = report[key]
            out = phase.pop('stdout')
            err = phase.pop('stderr')
            phase['stdout_bytes'] = len(out.encode())
            phase['stderr_bytes'] = len(err.encode())
            phase['stderr_sha256'] = hashlib.sha256(err.encode()).hexdigest()
            phase['out_of_memory'] = 'out of memory' in err.lower() or 'out_of_memory' in err.lower()
            phase['progress_tail'] = [line[:240] for line in err.splitlines() if line.startswith(('   Compiling ', '    Finished ', 'error: could not compile '))][-6:]
            errors = 0
            malformed = 0
            for line in out.splitlines():
                if not line.startswith('{'):
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    malformed += 1
                    continue
                errors += int(row.get('reason') == 'compiler-message' and row.get('message', {}).get('level') == 'error')
            phase['diagnostic_error_count'] = errors
            phase['malformed_json_lines'] = malformed
    if root is not None:
        try:
            s = root.lstat()
            require((s.st_dev, s.st_ino, s.st_uid, stat.S_IMODE(s.st_mode)) == lease, 'build_contract_line_214')
            if not uncertain:
                shutil.rmtree(root)
                report['scratch_gone'] = not root.exists()
        except Exception:
            report['cleanup_uncertain'] = True
    signal.alarm(0)
    report['full_action_seconds'] = round(time.monotonic() - START, 3)
    print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if report['result'] == 'PASS' and report['scratch_gone'] else 1)
