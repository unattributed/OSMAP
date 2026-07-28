#!/usr/bin/env python3
"""Fail-closed OSMAP direct-dependency admission gate."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import argparse, hashlib, json, tomllib

SCHEMA = 'osmap-v15-risk-based-dependency-admission-v1'
REQUIRED_TEXT_FIELDS = (
    'purpose', 'trust_boundary_justification', 'replacement_analysis',
    'removal_analysis', 'locally_maintained_code_removed',
    'trusted_computing_base_effect',
)
REQUIRED_OBJECT_FIELDS = (
    'maintainer_provenance', 'licence_compatibility', 'maintenance_status',
    'openbsd_compatibility', 'unsafe_code_assessment',
    'transitive_dependency_inventory', 'vulnerability_review',
    'feature_minimisation', 'default_feature_review', 'sbom_effect',
)
ALLOWED_DECISIONS = {
    'accepted_existing_baseline', 'accepted_new_dependency',
    'accepted_dependency_change',
}

def fail(message: str) -> None:
    raise SystemExit(f'FAIL: {message}')

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f'{label} must be non-empty text')
    return value.strip()

def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        fail(f'{label} must be a non-empty object')
    require_text(value.get('status'), f'{label}.status')
    require_text(value.get('rationale'), f'{label}.rationale')
    return value

def normalise_spec(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        spec = {'version': value}
    elif isinstance(value, dict):
        spec = dict(value)
    else:
        fail(f'unsupported Cargo dependency specification: {value!r}')
    version, path, git = spec.get('version'), spec.get('path'), spec.get('git')
    if sum(item is not None for item in (version, path, git)) != 1:
        fail('each direct dependency must declare exactly one of version, path, or git')
    if version is not None:
        source, requirement = 'crates.io', require_text(version, 'dependency version')
    elif path is not None:
        requirement = f"path:{require_text(path, 'dependency path')}"
        source = requirement
    else:
        requirement = f"git:{require_text(git, 'dependency git URL')}"
        source = requirement
    features = spec.get('features', [])
    if not isinstance(features, list) or not all(isinstance(item, str) and item for item in features):
        fail('dependency features must be a list of non-empty strings')
    return {
        'requirement': requirement, 'source': source,
        'default_features': bool(spec.get('default-features', True)),
        'features': sorted(set(features)), 'optional': bool(spec.get('optional', False)),
    }

def cargo_dependencies(cargo: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    found: dict[tuple[str, str], dict[str, Any]] = {}
    def add(scope: str, table: Any) -> None:
        if table is None:
            return
        if not isinstance(table, dict):
            fail(f'Cargo section {scope} must be a table')
        for name, specification in table.items():
            key = (scope, name)
            if key in found:
                fail(f'duplicate Cargo dependency key: {scope}/{name}')
            found[key] = normalise_spec(specification)
    for section in ('dependencies', 'dev-dependencies', 'build-dependencies'):
        add(section, cargo.get(section))
    target = cargo.get('target', {})
    if target is not None:
        if not isinstance(target, dict):
            fail('Cargo target section must be a table')
        for target_name, target_data in target.items():
            if not isinstance(target_data, dict):
                fail(f'Cargo target {target_name} must be a table')
            for section in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                add(f'target.{target_name}.{section}', target_data.get(section))
    return found

def check(repo: Path, record_path: Path) -> None:
    cargo_path, lock_path = repo / 'Cargo.toml', repo / 'Cargo.lock'
    if not cargo_path.is_file() or not lock_path.is_file() or not record_path.is_file():
        fail('Cargo manifest, lockfile, or dependency admission record is missing')
    cargo = tomllib.loads(cargo_path.read_text(encoding='utf-8'))
    lock = tomllib.loads(lock_path.read_text(encoding='utf-8'))
    record = json.loads(record_path.read_text(encoding='utf-8'))
    if record.get('schema') != SCHEMA:
        fail(f"unsupported admission schema: {record.get('schema')!r}")
    policy = record.get('policy')
    if not isinstance(policy, dict):
        fail('policy must be an object')
    if policy.get('admission_model') != 'risk_based':
        fail('policy.admission_model must be risk_based')
    if policy.get('numeric_dependency_ceiling') is not None:
        fail('arbitrary numeric dependency ceilings are prohibited')
    if policy.get('fail_closed') is not True:
        fail('policy.fail_closed must be true')
    if policy.get('scope') != 'all_direct_cargo_dependencies':
        fail('policy.scope must cover all direct Cargo dependencies')
    baseline = record.get('cargo_baseline')
    if not isinstance(baseline, dict):
        fail('cargo_baseline must be an object')
    actual_toml_sha, actual_lock_sha = sha256(cargo_path), sha256(lock_path)
    packages = lock.get('package')
    if not isinstance(packages, list):
        fail('Cargo.lock package inventory is missing')
    actual_lock_count = len(packages)
    if baseline.get('cargo_toml_sha256') != actual_toml_sha:
        fail('Cargo.toml changed without refreshing the dependency admission record')
    if baseline.get('cargo_lock_sha256') != actual_lock_sha:
        fail('Cargo.lock changed without refreshing the dependency admission record')
    if baseline.get('locked_package_count') != actual_lock_count:
        fail('locked package count differs from the admission baseline')
    actual_dependencies = cargo_dependencies(cargo)
    records = record.get('dependencies')
    if not isinstance(records, list):
        fail('dependencies must be an array')
    admitted: dict[tuple[str, str], dict[str, Any]] = {}
    for index, item in enumerate(records):
        label = f'dependencies[{index}]'
        if not isinstance(item, dict):
            fail(f'{label} must be an object')
        name, scope = require_text(item.get('name'), f'{label}.name'), require_text(item.get('scope'), f'{label}.scope')
        key = (scope, name)
        if key in admitted:
            fail(f'duplicate admission record: {scope}/{name}')
        if item.get('decision') not in ALLOWED_DECISIONS:
            fail(f"{label}.decision is unsupported: {item.get('decision')!r}")
        admitted[key] = item
        for field in REQUIRED_TEXT_FIELDS:
            require_text(item.get(field), f'{label}.{field}')
        for field in REQUIRED_OBJECT_FIELDS:
            require_object(item.get(field), f'{label}.{field}')
        require_text(item.get('requirement'), f'{label}.requirement')
        require_text(item.get('source'), f'{label}.source')
        if not isinstance(item.get('default_features'), bool):
            fail(f'{label}.default_features must be boolean')
        features = item.get('features')
        if not isinstance(features, list) or not all(isinstance(feature, str) and feature for feature in features):
            fail(f'{label}.features must be non-empty strings')
        if features != sorted(set(features)):
            fail(f'{label}.features must be sorted and unique')
        if not isinstance(item.get('optional'), bool):
            fail(f'{label}.optional must be boolean')
        transitive = item['transitive_dependency_inventory']
        if transitive.get('cargo_lock_sha256') != actual_lock_sha:
            fail(f'{label} transitive inventory lock digest differs')
        if transitive.get('locked_package_count') != actual_lock_count:
            fail(f'{label} transitive inventory count differs')
    actual_keys, admitted_keys = set(actual_dependencies), set(admitted)
    if actual_keys != admitted_keys:
        fail(f'direct dependency admission coverage differs: missing={sorted(actual_keys-admitted_keys)} stale={sorted(admitted_keys-actual_keys)}')
    for key, actual in actual_dependencies.items():
        item = admitted[key]
        for field in ('requirement', 'source', 'default_features', 'features', 'optional'):
            if item.get(field) != actual[field]:
                fail(f'admission record drift for {key[0]}/{key[1]} field={field}: expected={actual[field]!r} recorded={item.get(field)!r}')
    if len(records) != len(actual_dependencies):
        fail('admission record count differs from direct dependency count')
    print(f'schema={SCHEMA}')
    print(f'direct_dependency_count={len(actual_dependencies)}')
    print(f'locked_package_count={actual_lock_count}')
    print(f'cargo_toml_sha256={actual_toml_sha}')
    print(f'cargo_lock_sha256={actual_lock_sha}')
    print('numeric_dependency_ceiling=none')
    print('PASS: risk-based dependency admission gate passed')

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, default=Path('.'))
    parser.add_argument('--record', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    record = args.record if args.record.is_absolute() else repo / args.record
    try:
        check(repo, record.resolve())
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        fail(str(exc))
if __name__ == '__main__':
    main()
