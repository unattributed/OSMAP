"""Prepare or execute one current-source native build using the existing recipe."""
import argparse
import ast
import base64
import datetime
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import signal
import stat
import subprocess
import tarfile
import time

REPO = Path(__file__).resolve().parents[3]
BASE = '77f63794d3f60e4003db157eada39f4bd4222b6a'
DEFAULT_ROOT = Path('/home/foo/Downloads/osmap-ux-s04/current-source-milestone1-20261023/build')
ATTEMPT = 'S04-02-current-source-build146'
RECIPE = 'current-source-native-build146'


def require(value, code):
    if not value:
        raise RuntimeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def save(root, name, raw):
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def private(path):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
            and metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == 0o600, 'private_file')
    return path.read_bytes()


def signed_source(source_commit=BASE):
    require(type(source_commit) is str and re.fullmatch('[0-9a-f]{40}', source_commit),
            'approved_source_commit')
    # The carrier may be committed after the exact signed compiler source.
    # source_closure still checks every working compiler input against this tree.
    subprocess.run(['git', 'verify-commit', source_commit], cwd=REPO, capture_output=True, check=True, timeout=15)


def source_closure(source_commit=BASE):
    """Read the signed tree, all src files, and their literal include dependencies."""
    archive = subprocess.check_output(['git', 'archive', '--format=tar', source_commit], cwd=REPO, timeout=30)
    with tarfile.open(fileobj=io.BytesIO(archive)) as reader:
        tree = {member.name: reader.extractfile(member).read() for member in reader.getmembers() if member.isfile()}
    names = {'Cargo.toml', 'Cargo.lock'} | {name for name in tree if name.startswith('src/')}
    closure = []
    for name in sorted(names):
        if not name.endswith('.rs'):
            continue
        for match in re.finditer(r'include(?:_str|_bytes)?!\s*\(\s*"([^"\n]+)"\s*\)', tree[name].decode()):
            literal = match.group(1)
            target = posixpath.normpath(str(PurePosixPath(name).parent / literal))
            require(target in tree and not target.startswith('../'), 'include_outside_signed_tree')
            names.add(target)
            closure.append({'source': name, 'literal': literal, 'target': target})
    data = {name: tree[name] for name in sorted(names)}
    for name, raw in data.items():
        path = REPO / name
        require(path.resolve() == path and path.is_file() and path.read_bytes() == raw, 'working_source_differs:' + name)
    return data, closure


def build_action(binding):
    """Use frozen action identifiers; never recycle a consumed compiler action."""
    explicit = ('attempt_id' in binding, 'recipe_id' in binding)
    require(explicit[0] == explicit[1], 'build_action_pair')
    if explicit[0]:
        attempt, recipe = binding['attempt_id'], binding['recipe_id']
        require(type(attempt) is str and type(recipe) is str
                and re.fullmatch(r'S04-02-[a-z0-9-]{1,96}', attempt)
                and re.fullmatch(r'[a-z0-9-]{1,96}', recipe), 'build_action_identity')
        return attempt, recipe
    return (('S04-02-timing-libtest-build157', 'timing-libtest-build157')
            if binding.get('build_kind', 'pair') == 'libtest-only' else (ATTEMPT, RECIPE))


def prepare(root, source_commit=BASE, libtest_only=False, *, attempt_id=None, recipe_id=None):
    require(type(libtest_only) is bool, 'build_selection')
    require((attempt_id is None) == (recipe_id is None), 'build_action_pair')
    action = {} if attempt_id is None else {'attempt_id': attempt_id, 'recipe_id': recipe_id}
    build_action(action)
    signed_source(source_commit)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not tuple(root.iterdir()), 'build_directory_not_empty')
    data, closure = source_closure(source_commit)
    manifest = {name: sha(raw) for name, raw in data.items()}
    manifest_raw = encoded(manifest)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as writer:
        for name, raw in data.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o600
            member.size = len(raw)
            writer.addfile(member, io.BytesIO(raw))
    archive = gzip.compress(buffer.getvalue(), mtime=0)
    remote = (Path(__file__).with_name('build_remote.py')).read_text()
    build_kind = 'libtest-only' if libtest_only else 'pair'
    for old, new in [('__SIGNED_BASE__', source_commit), ('__BUILD_KIND__', build_kind), ('__MANIFEST_SHA__', sha(manifest_raw)),
                     ('__ARCHIVE_SHA__', sha(archive)), ('__SOURCE_COUNT__', str(len(manifest)))]:
        remote = remote.replace(old, new)
    ast.parse(remote)
    require(not any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(remote))), 'assert_execution_gate')
    packet = {'signed_base_commit': source_commit, 'source_manifest_sha256': sha(manifest_raw),
              'manifest': manifest, 'archive_sha256': sha(archive), 'archive': base64.b64encode(archive).decode()}
    outputs = {'manifest.json': manifest_raw, 'include-closure.json': encoded(closure),
               'source.tar.gz': archive, 'remote.py': remote.encode(), 'packet.json': encoded(packet)}
    binding = {'schema': 'osmap-current-native-build-binding-v1', 'signed_base_commit': source_commit,
               'build_kind': build_kind,
               'source_count': len(manifest), 'literal_include_count': len(closure),
               'committed_and_working_inputs_match': True, 'native_dispatched': False,
               'dispatcher_sha256': sha(Path(__file__).read_bytes()),
               'hashes': {name: sha(raw) for name, raw in outputs.items()},
               'created_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    binding.update(action)
    for name, raw in outputs.items():
        save(root, name, raw)
    save(root, 'BINDING.json', encoded(binding))
    return binding


def inspect_receipt(observed, code, binding):
    pins = binding['hashes']
    build_kind = binding.get('build_kind', 'pair')
    require(build_kind in ('pair', 'libtest-only') and observed.get('build_kind', 'pair') == build_kind,
            'compiler_build_selection')
    require(observed['schema'] == 'osmap-controlled-native-build-current-v1'
            and observed['signed_base_commit'] == binding['signed_base_commit']
            and observed['source_manifest_sha256'] == pins['manifest.json']
            and observed['archive_sha256'] == pins['source.tar.gz'], 'compiler_source_binding')
    for key in ('tests_executed', 'application_executed', 'activation', 'account_operations',
                'public_service_operations', 'ordinary_Runtime_qualification'):
        require(observed[key] is False, 'unexpected_build_effect:' + key)
    identity = observed['identity']
    require(identity['hostname'] == 'obsd1.blackbagsecurity.com' and identity['system'] == 'OpenBSD'
            and identity['machine'] == 'amd64'
            and all(identity[key] == 1000 for key in ('uid', 'euid', 'gid', 'egid')), 'compiler_target')
    phases = [key for key in ('helper', 'rust') if key in observed]
    disposition = 'CONFIRMED' if (observed['scratch_gone'] is True and observed['cleanup_uncertain'] is False
                                and all(observed[key]['group_gone'] is True for key in phases)) else 'UNCERTAIN'
    if observed['result'] != 'PASS':
        return 'FAIL', disposition
    expected_phases = ['rust'] if build_kind == 'libtest-only' else ['helper', 'rust']
    require(code == 0 and disposition == 'CONFIRMED' and phases == expected_phases, 'compiler_completion')
    require(observed['source_count'] == binding['source_count'] and observed['source_before'] is True
            and observed['source_after'] is True and observed['helper_built'] is (build_kind == 'pair'), 'compiler_source_parity')
    if build_kind == 'libtest-only':
        require('native_helper_binary' not in observed, 'unexpected_helper_artifact')
    require(observed['parent_limits_unchanged'] is True and observed['compiler_data_soft_bytes'] == 4294967296
            and observed['compiler_build_jobs'] == 1 and 0 < observed['full_action_seconds'] <= 650, 'compiler_recipe')
    for program in ('/usr/local/bin/cargo', '/usr/local/bin/rustc'):
        binary = observed['build_programs'][program]
        version = observed['compiler_versions'][program]
        require(binary['resolved'] == program and binary['uid'] == 0 and binary['mode'] == 0o755
                and re.fullmatch('[0-9a-f]{64}', binary['sha256']) is not None, 'compiler_binary_evidence')
        require(version['code'] == 0 and version['failure'] is None and version['group_gone'] is True
                and not version['stderr'] and 0 < len(version['stdout']) <= 4096, 'compiler_version_evidence')
    stage = observed['artifact_stage']
    stagepath = Path(stage['path'])
    require(stagepath.parent == Path('/home/foo') and stagepath.name.startswith('.osmap-s04-02-artifacts-')
            and stage['uid'] == 1000 and stage['mode'] == 0o700, 'artifact_stage')
    artifacts = [('native_test_binary', True, 'osmap-libtest')]
    if build_kind == 'pair':
        artifacts.insert(0, ('native_helper_binary', False, 'account-passwd'))
    for key, test, name in artifacts:
        artifact = observed[key]
        profile = artifact['cargo_profile']
        phase = observed['rust' if test else 'helper']
        require(phase['code'] == 0 and phase['failure'] is None and phase['group_gone'] is True, 'compiler_phase')
        require(artifact['path'] == str(stagepath / name) and artifact['uid'] == 1000
                and artifact['mode'] == 0o700 and artifact['nlink'] == 1 and 0 < artifact['size'] < 512 * 1024 * 1024,
                'artifact_custody')
        require(artifact['source_count'] == binding['source_count'] and artifact['profile_test'] is test
                and artifact['tests_executed'] is False and artifact['application_executed'] is False,
                'artifact_provenance')
        require(artifact['cargo_target_kind'] == (['lib'] if test else ['bin'])
                and profile['opt_level'] == ('0' if test else '3') and profile['debuginfo'] == 0
                and profile['debug_assertions'] is test and profile['overflow_checks'] is test
                and profile['test'] is test, 'artifact_profile')
        require(re.fullmatch('[0-9a-f]{64}', artifact['sha256']) is not None, 'artifact_hash')
    return 'PASS', disposition


def execute(root):
    start = time.monotonic()
    metadata = root.lstat()
    require(root.resolve() == root and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o700, 'build_directory_custody')
    require(not any(os.path.lexists(root / name) for name in ('attempt-started.json', 'result.json')), 'one_shot_consumed')
    binding = json.loads(private(root / 'BINDING.json'))
    require(binding['dispatcher_sha256'] == sha(Path(__file__).read_bytes()), 'dispatcher_changed')
    frozen = {name: private(root / name) for name in binding['hashes']}
    require(all(sha(raw) == binding['hashes'][name] for name, raw in frozen.items()), 'build_input_hash')
    source_commit = binding['signed_base_commit']
    libtest_only = binding.get('build_kind', 'pair') == 'libtest-only'
    attempt, recipe_id = build_action(binding)
    signed_source(source_commit)
    data, _ = source_closure(source_commit)
    require({name: sha(raw) for name, raw in data.items()} == json.loads(frozen['manifest.json']), 'build_source_changed')
    gate = subprocess.run(['/usr/bin/python3', str(REPO / 'maint/ux/validate_acceptance.py'), '--repo', str(REPO),
                           '--work-order-only', '--pre-action', '--attempt-id', attempt],
                          cwd=REPO, capture_output=True, timeout=30)
    save(root, 'pre-action-stdout.log', gate.stdout[:65536])
    save(root, 'pre-action-stderr.log', gate.stderr[:65536])
    require(gate.returncode == 0 and len(gate.stdout) <= 65536 and len(gate.stderr) <= 65536, 'pre_action_gate')
    spec = importlib.util.spec_from_file_location('current_build_work_order', REPO / 'maint/ux/validate_acceptance.py')
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    order = validator.active_work_order((REPO / 'docs/UX_EXECUTION_LEDGER.md').read_text())
    planned = order['accountability']['next_attempt']
    action = order['execution_contract']['planned_action']
    require(order['slice'] == 'S04-02' and order['state'] == 'IN_PROGRESS'
            and planned['id'] == attempt and planned['source_revision'] == binding['hashes']['manifest.json'],
            'planned_build_source')
    require(action['attempt_id'] == attempt and action['recipe_id'] == recipe_id
            and action['source_revision'] == binding['hashes']['manifest.json']
            and action['max_seconds'] == 720, 'planned_build_action')
    recipe = next(row for row in order['execution_contract']['recipes'] if row['id'] == recipe_id)
    arguments = [str(Path(__file__).resolve()), 'execute']
    if root != DEFAULT_ROOT:
        arguments += ['--root', str(root)]
    require(recipe['kind'] == 'NATIVE' and recipe['operations'] == [{'target_id': 'local',
            'program': '/usr/bin/python3', 'arguments': arguments,
            'privilege': 'user'}], 'planned_build_recipe')
    require(binding['dispatcher_sha256'] in json.dumps(planned, sort_keys=True)
            and binding['hashes']['remote.py'] in json.dumps(planned, sort_keys=True), 'planned_build_carrier_hashes')
    review_raw = private(root / 'independent-review.json')
    review = json.loads(review_raw)
    require(review['decision'] == 'CLEAR' and review['dispatcher_sha256'] == binding['dispatcher_sha256']
            and review['remote_sha256'] == binding['hashes']['remote.py'], 'independent_build_review')
    require(sha(review_raw) in json.dumps(planned, sort_keys=True), 'planned_independent_build_review')
    environments = {row['id']: row for row in order['execution_contract']['environment']}
    require(len(recipe['environment_ids']) == 1, 'build_environment_count')
    environment = environments[recipe['environment_ids'][0]]
    require((environment['host'], environment['address'], environment['status']) ==
            ('obsd1.blackbagsecurity.com', '192.168.1.44', 'PASS'), 'build_environment')
    record = {'schema': 'osmap-current-native-build-dispatch-v1', 'attempt_id': attempt,
              'signed_base_commit': source_commit, 'source_manifest_sha256': binding['hashes']['manifest.json'],
              'build_kind': binding.get('build_kind', 'pair'),
              'native_result': 'UNKNOWN', 'remote_disposition': 'UNCERTAIN', 'pre_action_gate': 'PASS',
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_build_only': True, 'ordinary_Runtime_qualification': False}
    save(root, 'attempt-started.json', encoded(record))
    argv = ['/usr/bin/ssh', '-S', 'none', '-i', '/home/foo/.ssh/id_ed25519', '-o', 'IdentitiesOnly=yes',
            '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=8',
            '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
            'foo@192.168.1.44', '/usr/local/bin/python3 -I -c ' + shlex.quote(frozen['remote.py'].decode())]
    child = None
    try:
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True)
        out, err = child.communicate(input=frozen['packet.json'], timeout=690)
        save(root, 'stdout.log', out[:131072])
        save(root, 'stderr.log', err[:16384])
        record['ssh_code'] = child.returncode
        require(len(out) <= 131072 and not err, 'compiler_transport_output')
        record['result'] = json.loads(out)
        record['native_result'], record['remote_disposition'] = inspect_receipt(record['result'], child.returncode, binding)
    except Exception as error:
        record['failure_class'] = type(error).__name__
        record['failure_reason'] = str(error) if type(error) is RuntimeError else type(error).__name__
        if isinstance(error, subprocess.TimeoutExpired):
            save(root, 'stdout.log', (error.stdout or b'')[:131072])
            save(root, 'stderr.log', (error.stderr or b'')[:16384])
    finally:
        record['local_transport_reaped'] = False
        record['local_transport_group_gone'] = False
        if child is not None:
            try:
                # communicate() reaps on ordinary completion. Its historical
                # PID must never authorize a later destructive group signal.
                if child.returncode is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                child.wait(timeout=5)
                record['local_transport_reaped'] = True
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    record['local_transport_group_gone'] = True
            except Exception as error:
                record['local_cleanup_failure'] = type(error).__name__
            for pipe in (child.stdin, child.stdout, child.stderr):
                if pipe is not None:
                    pipe.close()
        if not (record['local_transport_reaped'] and record['local_transport_group_gone']):
            record['native_result'] = 'FAIL'
        record['full_action_seconds'] = round(time.monotonic() - start, 3)
        save(root, 'result.json', encoded(record))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'execute'))
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    parser.add_argument('--source-commit', default=BASE,
                        help='Exact signed compiler source commit (prepare only)')
    parser.add_argument('--libtest-only', action='store_true',
                        help='Build only the affected libtest artifact (prepare only)')
    parser.add_argument('--attempt-id', help='Fresh exact compiler action ID (prepare only)')
    parser.add_argument('--recipe-id', help='Fresh exact compiler recipe ID (prepare only)')
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == 'execute':
        require(not args.libtest_only and args.source_commit == BASE
                and args.attempt_id is None and args.recipe_id is None, 'execute_uses_frozen_binding')
    result = prepare(args.root, args.source_commit, args.libtest_only,
                     attempt_id=args.attempt_id, recipe_id=args.recipe_id) if args.action == 'prepare' else execute(args.root)
    print(json.dumps({key: value for key, value in result.items() if key != 'result'}, sort_keys=True))
    return 0 if args.action == 'prepare' or (result['native_result'] == 'PASS' and result['remote_disposition'] == 'CONFIRMED') else 1


if __name__ == '__main__':
    raise SystemExit(main())
