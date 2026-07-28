#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import copy, json, subprocess, sys, tempfile
repo = Path(sys.argv[1]).resolve()
gate = repo / 'maint/security/osmap-v15-dependency-admission-gate.py'
record = repo / 'maint/security/v15-dependency-admission.json'
cargo, lock = repo / 'Cargo.toml', repo / 'Cargo.lock'
def run(test_repo: Path, test_record: Path, success: bool, marker: str) -> None:
    completed = subprocess.run([sys.executable, '-B', str(gate), '--repo', str(test_repo), '--record', str(test_record)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if success != (completed.returncode == 0):
        raise SystemExit(f'FAIL: unexpected status for {marker}\n{completed.stdout}')
    if marker not in completed.stdout:
        raise SystemExit(f'FAIL: expected marker {marker!r}\n{completed.stdout}')
def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')
baseline = json.loads(record.read_text(encoding='utf-8'))
run(repo, record, True, 'PASS: risk-based dependency admission gate passed')
with tempfile.TemporaryDirectory(prefix='osmap-dependency-admission-test.') as temp:
    test_repo = Path(temp)
    (test_repo/'Cargo.toml').write_bytes(cargo.read_bytes())
    (test_repo/'Cargo.lock').write_bytes(lock.read_bytes())
    cases = []
    value = copy.deepcopy(baseline); value['dependencies'] = value['dependencies'][1:]; cases.append(('missing.json', value, 'direct dependency admission coverage differs'))
    value = copy.deepcopy(baseline); value['dependencies'][0].pop('licence_compatibility'); cases.append(('field.json', value, 'licence_compatibility must be a non-empty object'))
    value = copy.deepcopy(baseline); value['policy']['numeric_dependency_ceiling'] = 8; cases.append(('ceiling.json', value, 'arbitrary numeric dependency ceilings are prohibited'))
    value = copy.deepcopy(baseline); value['cargo_baseline']['cargo_lock_sha256'] = '0'*64; cases.append(('lock.json', value, 'Cargo.lock changed without refreshing'))
    value = copy.deepcopy(baseline); value['dependencies'].append(copy.deepcopy(value['dependencies'][0])); cases.append(('duplicate.json', value, 'duplicate admission record'))
    value = copy.deepcopy(baseline); value['dependencies'][0]['default_features'] = False; cases.append(('feature.json', value, 'admission record drift'))
    for filename, value, marker in cases:
        path = test_repo/filename; write(path, value); run(test_repo, path, False, marker)
    cargo_text = cargo.read_text(encoding='utf-8').replace('[dependencies]\n', '[dependencies]\nregex = "1.12.2"\n', 1)
    (test_repo/'Cargo.toml').write_text(cargo_text, encoding='utf-8')
    path = test_repo/'new.json'; write(path, baseline); run(test_repo, path, False, 'Cargo.toml changed without refreshing')
print('PASS: dependency-admission gate regression tests passed')
