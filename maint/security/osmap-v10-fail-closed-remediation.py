#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXCLUDE_DIRS = {'.git', 'target', '.cargo', 'vendor', 'node_modules', 'dist', 'build', 'coverage'}
PATTERNS = (
    ('unwrap_call', '.unwrap('),
    ('expect_call', '.expect('),
    ('panic_macro', 'panic!'),
    ('todo_macro', 'todo!'),
    ('unimplemented_macro', 'unimplemented!'),
    ('unreachable_macro', 'unreachable!'),
)
TEST_MARKERS = ('#[cfg(test)]', 'mod tests', '#[test]')

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

def rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()

def is_test_path(path: str) -> bool:
    lower = path.lower()
    return lower.startswith('tests/') or '/tests/' in lower or lower.startswith('benches/') or lower.startswith('examples/') or 'test' in Path(lower).name or 'fixture' in lower

def marker_index(line: str) -> int | None:
    indexes = [line.find(marker) for marker in TEST_MARKERS if line.find(marker) >= 0]
    return min(indexes) if indexes else None

def classify(path: str, kind: str, test_scope: bool, line: str) -> dict[str, str]:
    lower_path = path.lower()
    lower_line = line.lower()
    if test_scope or is_test_path(path):
        return {'classification': 'test_or_fixture_assumption', 'fail_closed_relevance': 'low', 'disposition': 'accepted_test_or_fixture_assumption_after_scope_refinement'}
    if kind in {'todo_macro', 'unimplemented_macro'}:
        return {'classification': 'implementation_gap_signal', 'fail_closed_relevance': 'high', 'disposition': 'remediation_required_before_expanding_release_claims'}
    if kind == 'panic_macro':
        return {'classification': 'panic_path_assumption', 'fail_closed_relevance': 'high' if lower_path.startswith('src/') else 'medium', 'disposition': 'requires_runtime_path_review_or_explicit_fail_closed_conversion'}
    if kind in {'unwrap_call', 'expect_call'}:
        if any(marker in lower_line for marker in ('std::env', 'env::', 'oncecell', 'oncelock', 'lazy_static')):
            return {'classification': 'startup_or_global_invariant', 'fail_closed_relevance': 'medium', 'disposition': 'document_or_convert_to_explicit_startup_error'}
        if lower_path.startswith('src/'):
            return {'classification': 'production_adjacent_assumption', 'fail_closed_relevance': 'high', 'disposition': 'candidate_for_explicit_error_or_fail_closed_response'}
        return {'classification': 'tooling_or_helper_assumption', 'fail_closed_relevance': 'medium', 'disposition': 'review_before_using_as_release_evidence'}
    if kind == 'unreachable_macro':
        return {'classification': 'control_flow_invariant', 'fail_closed_relevance': 'medium', 'disposition': 'review_for_explicit_error_path_if_user_reachable'}
    return {'classification': 'unclassified_assumption', 'fail_closed_relevance': 'medium', 'disposition': 'manual_review_required'}

def iter_rust_files(root: Path):
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        current_path = Path(current)
        for name in sorted(files):
            if name.endswith('.rs'):
                yield current_path / name

def scan(root: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for path in sorted(iter_rust_files(root), key=lambda p: p.as_posix()):
        rp = rel(path, root)
        path_test = is_test_path(rp)
        test_scope_started = path_test
        try:
            lines = path.read_text(encoding='utf-8').splitlines()
        except UnicodeDecodeError:
            lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
        for lineno, line in enumerate(lines, 1):
            first_marker = marker_index(line)
            has_marker = first_marker is not None
            for kind, needle in PATTERNS:
                pos = line.find(needle)
                if pos < 0:
                    continue
                test_scope = test_scope_started or path_test or (has_marker and pos >= first_marker)
                item = {'file': rp, 'line': lineno, 'kind': kind}
                item.update(classify(rp, kind, test_scope, line))
                entries.append(item)
            if has_marker:
                test_scope_started = True
    by_kind = Counter(e['kind'] for e in entries)
    by_class = Counter(e['classification'] for e in entries)
    by_rel = Counter(e['fail_closed_relevance'] for e in entries)
    normalized = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return {
        'entries': entries,
        'summary': {
            'total_count': len(entries),
            'inventory_sha256': hashlib.sha256(normalized).hexdigest(),
            'by_kind': dict(sorted(by_kind.items())),
            'by_classification': dict(sorted(by_class.items())),
            'by_fail_closed_relevance': dict(sorted(by_rel.items())),
        },
    }

def build(repo: Path) -> dict[str, Any]:
    baseline = json.loads((repo / 'maint/security/v10-rust-assumption-audit.json').read_text(encoding='utf-8'))
    refined = scan(repo)
    bs = baseline.get('summary', {})
    rs = refined['summary']
    src_test_count = sum(1 for e in refined['entries'] if e['file'].startswith('src/') and e['classification'] == 'test_or_fixture_assumption')
    high_by_file = Counter(e['file'] for e in refined['entries'] if e.get('fail_closed_relevance') == 'high')
    return {
        'schema_version': 1,
        'slice': 'V10 Slice 5',
        'purpose': 'Targeted fail-closed remediation register for Rust assumption handling after the Slice 4 audit.',
        'generated_at_utc': utc_now(),
        'baseline': {
            'source': 'maint/security/v10-rust-assumption-audit.json',
            'slice': baseline.get('slice'),
            'schema_version': baseline.get('schema_version'),
            'total_count': bs.get('total_count'),
            'inventory_sha256': bs.get('inventory_sha256'),
            'by_classification': bs.get('by_classification', {}),
            'by_fail_closed_relevance': bs.get('by_fail_closed_relevance', {}),
        },
        'refined_current': {
            'total_count': rs.get('total_count'),
            'inventory_sha256': rs.get('inventory_sha256'),
            'by_classification': rs.get('by_classification', {}),
            'by_fail_closed_relevance': rs.get('by_fail_closed_relevance', {}),
            'high_relevance_top_files': dict(high_by_file.most_common(10)),
        },
        'selected_remediation': {
            'target': 'src_test_module_assumption_reclassification',
            'reason': 'Separate assumptions inside Rust test modules from production-adjacent runtime assumptions before runtime code rewrites.',
            'classification_change_count': src_test_count,
            'remediation_type': 'audit_precision_and_gate_remediation',
            'product_behavior_changed': False,
            'production_state_changed': False,
            'live_host_state_changed': False,
        },
        'summary': {
            'classification_complete': True,
            'baseline_total_count': bs.get('total_count'),
            'refined_total_count': rs.get('total_count'),
            'source_test_module_assumption_count': src_test_count,
            'high_relevance_before': bs.get('by_fail_closed_relevance', {}).get('high', 0),
            'high_relevance_after': rs.get('by_fail_closed_relevance', {}).get('high', 0),
            'test_or_fixture_before': bs.get('by_classification', {}).get('test_or_fixture_assumption', 0),
            'test_or_fixture_after': rs.get('by_classification', {}).get('test_or_fixture_assumption', 0),
            'product_behavior_changed': False,
            'production_state_changed': False,
            'live_host_state_changed': False,
        },
        'explicit_non_claims': [
            'This slice does not claim production Rust paths are panic-free.',
            'This slice does not claim all high relevance assumptions have been remediated.',
            'This slice does not claim broad public release readiness.',
            'This slice does not change production deployment state.',
        ],
        'required_followups': [
            'Use the refined high-relevance list to select the first concrete runtime code remediation.',
            'Convert selected user-reachable assumptions into explicit errors or fail-closed HTTP responses.',
            'Add regression tests for each runtime remediation.',
        ],
    }

def write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')

def check(repo: Path, expected_path: Path) -> int:
    expected = json.loads(expected_path.read_text(encoding='utf-8'))
    current = build(repo)
    errors: list[str] = []
    if expected.get('schema_version') != 1:
        errors.append('schema_version must be 1')
    if expected.get('slice') != 'V10 Slice 5':
        errors.append('slice must be V10 Slice 5')
    es = expected.get('summary', {})
    cs = current.get('summary', {})
    for key in ('classification_complete', 'product_behavior_changed', 'production_state_changed', 'live_host_state_changed'):
        if es.get(key) != current.get('summary', {}).get(key):
            errors.append(f'summary.{key} drift')
    for key in ('baseline_total_count', 'refined_total_count', 'source_test_module_assumption_count', 'high_relevance_before', 'high_relevance_after', 'test_or_fixture_before', 'test_or_fixture_after'):
        if es.get(key) != cs.get(key):
            errors.append(f'summary.{key} drift: expected {es.get(key)!r}, current {cs.get(key)!r}')
    if expected.get('refined_current', {}).get('inventory_sha256') != current.get('refined_current', {}).get('inventory_sha256'):
        errors.append('refined_current.inventory_sha256 drift')
    if expected.get('selected_remediation', {}).get('target') != 'src_test_module_assumption_reclassification':
        errors.append('selected_remediation.target must be src_test_module_assumption_reclassification')
    if es.get('source_test_module_assumption_count', 0) <= 0:
        errors.append('source_test_module_assumption_count must be greater than zero')
    if errors:
        for error in errors:
            print(f'V10 fail-closed remediation check failed: {error}')
        return 1
    print('V10 fail-closed remediation check passed')
    return 0

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', default='.')
    parser.add_argument('--write')
    parser.add_argument('--check')
    args = parser.parse_args()
    repo = Path(args.repo).resolve()
    if args.write:
        write(Path(args.write), build(repo))
        return 0
    if args.check:
        return check(repo, Path(args.check))
    print(json.dumps(build(repo), indent=2, sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
