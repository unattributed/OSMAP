"""Focused table test for the S04-02 current-observer capture boundary."""
import ast
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("s04_02_observe_current.py")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def load_module():
    spec = importlib.util.spec_from_file_location("s04_02_observe_current", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def program(value=None, exit_status=0, raw=None, exception=None):
    if exception is not None:
        source = "raise " + exception + "\n"
    elif raw is not None:
        source = "print(" + repr(raw) + ")\nraise SystemExit(" + str(exit_status) + ")\n"
    elif value is None:
        source = "raise SystemExit(" + str(exit_status) + ")\n"
    else:
        source = (
            "import json\nprint(json.dumps(" + repr(value) + ",sort_keys=True))\n"
            "raise SystemExit(" + str(exit_status) + ")\n"
        )
    raw_source = source.encode("utf-8")
    return raw_source, hashlib.sha256(raw_source).hexdigest()


def backend(result="GAPS_PRESENT", cleanup=True, failure=None):
    return {
        "schema": "osmap-single-host-backend-prerequisite-v1",
        "result": result,
        "failure": failure,
        "cleanup_confirmed": cleanup,
        "host_file_writes": False,
        "database_writes": False,
        "public_service_operations": False,
        "authentication_requests": False,
        "raw_query_or_config_output_retained": False,
        "commands": [],
    }


def configuration():
    return {
        "schema": "osmap-single-host-current-config-map-v1",
        "result": "CAPTURE_PASS",
        "host_file_writes": False,
        "public_service_operations": False,
        "database_operations": False,
        "credential_operations": False,
        "contents_retained": False,
        "historical_hash_values_reused": False,
    }


def expect_refusal(module, observer, source, pin, category, checks=None):
    advanced = False
    try:
        module.capture(observer, source, pin)
        advanced = True
    except module.ObserverRefused as error:
        receipt = error.receipt
        require(receipt["observer"] == observer, category + ": observer identity lost")
        require(receipt["category"] == category, category + ": wrong refusal category")
        if checks is not None:
            checks(receipt)
    require(not advanced, category + ": failed admission advanced downstream")


def embedded_definitions(source):
    # Load the actual embedded functions without executing their main entry,
    # installing signal handlers, or making any host observation.
    tree = ast.parse(source)
    tree.body = [node for node in tree.body if isinstance(node,
        (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef, ast.ClassDef))]
    namespace = {'__name__': 'local_embedded_observer_test'}
    exec(compile(tree, '<actual-embedded-observer>', 'exec'), namespace)
    return namespace


def exercise_embedded_observers(module):
    # Metadata from unrelated siblings may change; identity and protection may not.
    config = embedded_definitions(module.config_source)
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        parent = root / 'protected'
        parent.mkdir(mode=0o700)
        prior = config['identity'](parent.lstat())
        (parent / 'unrelated-sibling').mkdir()
        require(config['identity'](parent.lstat()) != prior,
            'directory mutation did not exercise full metadata change')
        config['current_ancestors']([(parent, prior)])
        for fault in ('mode', 'replacement'):
            if fault == 'mode':
                parent.chmod(0o750)
            else:
                parent.chmod(0o700)
                parent.rename(root / 'original')
                parent.mkdir(mode=0o700)
            try:
                config['current_ancestors']([(parent, prior)])
            except config['Refused'] as error:
                require(str(error) == 'ANCESTOR_CHANGED', 'ancestor refusal lost')
            else:
                raise RuntimeError('changed ancestor authority admitted: ' + fault)

    # The real observe() parser receives bounded utility output, not a fabricated
    # success dict. Only OS/native commands are replaced in this local test.
    for version, password_limit, expected in (
            (b'11.4.9-MariaDB', 255, 'PREREQUISITES_MATCH'),
            (b'MariaDB stable package build', 255, 'PREREQUISITES_MATCH'),
            (b'MariaDB stable package build', 64, 'GAPS_PRESENT')):
        backend = embedded_definitions(module.backend_source)
        rows = []
        for column in backend['COLUMNS']:
            kind, limit = ('datetime', 0) if column == 'modified' else \
                ('tinyint', 0) if column in ('active', 'smtp_active') else \
                ('varchar', password_limit if column == 'password' else 255)
            rows.append(f'{column}\t{kind}\t{limit}\tNO\t0'.encode())
        reply = b'\n'.join([version, b'1\t1', *rows, b'1', b'0', b'0', b'0', b'0']) + b'\n'
        backend['run'] = lambda label, argv, data=b'': reply if data else \
            b'0\n' if argv[-1] == 'auth_cache_size' else b'no\n'
        backend['trusted_program'] = lambda path: 'READY'
        user = SimpleNamespace(pw_uid=1001, pw_gid=1001)
        groups = [SimpleNamespace(gr_gid=n, gr_name='local-role', gr_mem=['_osmap'])
            for n in (1001, 1002, 1003)]
        with ExitStack() as patches:
            for owner, key, value in (
                    (backend['resource'], 'setrlimit', None),
                    (backend['os'], 'chdir', None),
                    (backend['os'], 'uname', SimpleNamespace(sysname='OpenBSD',
                        machine='amd64', release='local-observation-only')),
                    (backend['socket'], 'gethostname', 'obsd1.blackbagsecurity.com'),
                    (backend['pwd'], 'getpwnam', user),
                    (backend['pwd'], 'getpwall', [user]),
                    (backend['grp'], 'getgrall', groups),
                    (backend['os'], 'getgrouplist', [1001, 1002, 1003]),
                    *((backend['os'], key, 0) for key in
                        ('getuid', 'geteuid', 'getgid', 'getegid'))):
                patches.enter_context(patch.object(owner, key, return_value=value))
            backend['observe']()
        require(backend['result']['result'] == expected,
            'schema capability was replaced by a version-format gate')
        require(backend['result']['sql']['version'] == version.decode('ascii'),
            'observed version text was not retained')


def exercise():
    module = load_module()
    # Check the literal pins actually consumed by main(), not separately
    # computed expectations passed only by these synthetic capture cases.
    captures = [node for node in ast.walk(ast.parse(MODULE_PATH.read_text()))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == 'capture']
    require(len(captures) == 2, 'actual embedded capture set changed')
    for call in captures:
        observer = call.args[0].value
        require(call.args[1].id == observer + '_source', 'actual embedded source binding changed')
        require(hashlib.sha256(getattr(module, call.args[1].id)).hexdigest() == call.args[2].value,
            'actual embedded source-to-capture pin mismatch: ' + observer)
    success, success_pin = program(backend())
    value, receipt = module.capture("backend", success, success_pin)
    require(value["result"] == "GAPS_PRESENT", "success result not parsed")
    require(receipt == {
        "observer": "backend",
        "exit_status": 0,
        "stdout_bytes": receipt["stdout_bytes"],
        "result": "GAPS_PRESENT",
        "reported_failure": None,
        "cleanup_status": True,
    }, "success receipt fields changed")

    config, config_pin = program(configuration())
    config_value, config_receipt = module.capture("config", config, config_pin)
    require(config_value["result"] == "CAPTURE_PASS", "config success not parsed")
    require(config_receipt["cleanup_status"] is None, "unreported cleanup was invented")

    failed = backend(result="REFUSED", cleanup=False, failure="READ_ONLY_COMMAND_REFUSED")
    nonzero, nonzero_pin = program(failed, exit_status=7)
    expect_refusal(
        module, "backend", nonzero, nonzero_pin, "NONZERO_EXIT",
        lambda receipt: require(
            receipt["exit_status"] == 7
            and receipt["result"] == "REFUSED"
            and receipt["reported_failure"] == "READ_ONLY_COMMAND_REFUSED"
            and receipt["cleanup_status"] is False
            and receipt["observer_result"] == failed
            and len(json.dumps(receipt, sort_keys=True).encode("utf-8")) < 49152,
            "nonzero structured failure evidence was not preserved",
        ),
    )

    malformed, malformed_pin = program(raw="{")
    missing, missing_pin = program()
    unexpected, unexpected_pin = program(exception="RuntimeError('must-not-be-retained')")
    uncertain, uncertain_pin = program(backend(cleanup=False))
    excessive, excessive_pin = program(raw="x" * (module.OUTPUT_CAP + 1))
    unsafe_value = backend()
    unsafe_value["database_writes"] = True
    unsafe, unsafe_pin = program(unsafe_value)
    cases = [
        (malformed, malformed_pin, "MALFORMED_STRUCTURED_OUTPUT"),
        (missing, missing_pin, "MISSING_STRUCTURED_OUTPUT"),
        (unexpected, unexpected_pin, "UNEXPECTED_EXCEPTION"),
        (uncertain, uncertain_pin, "CLEANUP_UNCONFIRMED"),
        (excessive, excessive_pin, "OUTPUT_BOUND_EXCEEDED"),
        (unsafe, unsafe_pin, "UNSAFE_RESULT_CLAIM"),
    ]
    for source, pin, category in cases:
        expect_refusal(module, "backend", source, pin, category)
    exercise_embedded_observers(module)

    print(json.dumps({
        "schema": "osmap-s04-02-current-observer-focused-test-v1",
        "result": "PASS",
        "cases": 8,
        "embedded_schema_and_ancestor_cases": 6,
        "actual_embedded_capture_pins_verified": 2,
        "optimized": not __debug__,
        "failed_admission_advanced": False,
    }, sort_keys=True))


def main():
    if "--child" in sys.argv:
        exercise()
        return 0
    commands = [
        [sys.executable, "-B", str(Path(__file__).resolve()), "--child"],
        [sys.executable, "-B", "-O", str(Path(__file__).resolve()), "--child"],
    ]
    results = []
    for command in commands:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        require(completed.returncode == 0, "focused child failed: " + completed.stderr[:512])
        result = json.loads(completed.stdout)
        require(result["result"] == "PASS", "focused child did not pass")
        results.append(result)
    require([result["optimized"] for result in results] == [False, True], "optimized-mode coverage missing")
    print(json.dumps({
        "schema": "osmap-s04-02-current-observer-focused-matrix-v1",
        "result": "PASS",
        "runs": results,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
