"""Focused table-driven validation of the corrected fixed interpreter carrier."""
import ast
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
MODULE_PATHS = (HERE / 'remote_wrapper.py', HERE / 'stage_root.py')


class TestFailure(Exception):
    pass


def require(value, message):
    if not value:
        raise TestFailure(message)


def load(path):
    spec = importlib.util.spec_from_file_location('tested_' + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(root, leaf='python3.13'):
    target = root / leaf
    target.write_bytes(b'#!/bin/sh\nexit 0\n')
    target.chmod(0o500)
    alias = root / 'python3'
    alias.symlink_to(leaf)
    return alias, target


def refusal(module, alias, target, version=(3, 13, 0)):
    try:
        module.select_python(
            alias=alias,
            running=target,
            owner=os.geteuid(),
            ancestor_owners=(0, os.geteuid()),
            version=version,
        )
    except module.Refused as error:
        return str(error)
    raise TestFailure('expected_refusal')


def exercise(module, path):
    cases = []
    # The selector correctly rejects the group-writable repository ancestry.
    # Exercise it below the operator's private home, matching the host custody
    # contract instead of weakening the production check for a test fixture.
    with tempfile.TemporaryDirectory(prefix='selector-', dir=Path.home()) as temporary:
        root = Path(temporary)

        alias, target = fixture(root)
        record = module.select_python(alias, target, os.geteuid(), (0, os.geteuid()), (3, 13, 7))
        require(record['entrypoint'] == str(alias), 'trusted_entrypoint')
        require(record['resolved_path'] == str(target), 'trusted_target')
        require(record['version'] == [3, 13, 7], 'trusted_version')
        cases.append('trusted_success')

        alias.unlink()
        target.unlink()
        alias, target = fixture(root, 'python3.14')
        record = module.select_python(alias, target, os.geteuid(), (0, os.geteuid()), (3, 14, 0))
        require(record['resolved_path'].endswith('/python3.14'), 'upgraded_alias_target')
        cases.append('stable_upgrade_success')

        target.chmod(0o522)
        require(refusal(module, alias, target) == 'python_target_custody', 'untrusted_target')
        target.chmod(0o500)
        cases.append('untrusted_target_refused')

        alias.unlink()
        target.unlink()
        real = root / 'python-real'
        real.write_bytes(b'x')
        real.chmod(0o500)
        target = root / 'python3.13'
        target.symlink_to(real.name)
        alias.symlink_to(target.name)
        require(refusal(module, alias, target) == 'python_target_chain', 'unsafe_chain')
        cases.append('unsafe_chain_refused')

        alias.unlink()
        target.unlink()
        real.unlink()
        alias, target = fixture(root)
        require(refusal(module, alias, target, (3, 8, 18)) == 'python_incompatible', 'incompatible')
        cases.append('incompatible_refused')

        other = root / 'other'
        other.write_bytes(b'x')
        other.chmod(0o500)
        require(refusal(module, alias, other) == 'python_running_identity', 'running_identity')
        other.unlink()
        cases.append('invalid_identity_refused')

        alias.unlink()
        alias.write_bytes(b'x')
        alias.chmod(0o500)
        require(refusal(module, alias, alias) == 'python_alias_custody', 'alias_identity')
        alias.unlink()
        alias.symlink_to(target.name)
        cases.append('invalid_alias_refused')

        with mock.patch.object(module.os, 'readlink', side_effect=OSError('SECRET_MARKER')):
            code = refusal(module, alias, target)
        require(code == 'python_selection_OSError', 'exception_category')
        require('SECRET_MARKER' not in code, 'exception_disclosure')
        cases.append('exception_sanitized')

    tree = ast.parse(path.read_text())
    require(not any(isinstance(node, ast.Assert) for node in ast.walk(tree)), 'assert_present_' + path.name)
    cases.append('no_optimized_bypass')
    return cases


def worker():
    results = {}
    modules = {}
    for path in MODULE_PATHS:
        module = load(path)
        modules[path.name] = module
        results[path.name] = exercise(module, path)

    wrapper = modules['remote_wrapper.py']
    advanced = False
    with mock.patch.object(wrapper, 'select_python', side_effect=wrapper.Refused('python_alias_custody')):
        with mock.patch.object(wrapper.subprocess, 'Popen') as popen:
            try:
                wrapper.spawn_actor(b'{}', b'pass', set())
            except wrapper.Refused as error:
                require(str(error) == 'python_alias_custody', 'spawn_refusal_category')
            else:
                raise TestFailure('spawn_not_refused')
            advanced = popen.called
    require(not advanced, 'failed_selector_spawned_actor')

    stage_tree = ast.parse(MODULE_PATHS[1].read_text())
    main = next(node for node in stage_tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    selections = [node.lineno for node in ast.walk(main) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'select_python']
    mutations = [node.lineno for node in ast.walk(main) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ('mkdir', 'execve')]
    require(selections and mutations and min(selections) < min(mutations), 'root_selection_order')

    return {
        'schema': 'osmap-python-carrier-test-v1',
        'mode': 'optimized' if not __debug__ else 'normal',
        'result': 'PASS',
        'modules': results,
        'failed_selector_advanced_transport': advanced,
        'root_selection_before_stage_mutation': True,
    }


def controller():
    runs = []
    for optimized in (False, True):
        command = [sys.executable]
        if optimized:
            command.append('-O')
        command.extend([str(Path(__file__).resolve()), '--worker'])
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        require(completed.returncode == 0, 'worker_exit_' + ('optimized' if optimized else 'normal') + ':' + completed.stderr[:160])
        runs.append(json.loads(completed.stdout))
    require([run['mode'] for run in runs] == ['normal', 'optimized'], 'mode_coverage')
    require(all(run['result'] == 'PASS' for run in runs), 'run_result')
    return {'schema': 'osmap-python-carrier-validation-v1', 'result': 'PASS', 'runs': runs}


if __name__ == '__main__':
    try:
        outcome = worker() if sys.argv[1:] == ['--worker'] else controller()
        print(json.dumps(outcome, sort_keys=True))
    except BaseException as error:
        print(json.dumps({'schema': 'osmap-python-carrier-validation-v1', 'result': 'FAIL',
                          'failure': (type(error).__name__ + ':' + str(error))[:240]},
                         sort_keys=True))
        raise SystemExit(1)
