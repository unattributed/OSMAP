#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXCLUDE_DIRS = {
    '.git',
    'target',
    '.cargo',
    'vendor',
    'node_modules',
    'dist',
    'build',
    'coverage',
}

PATTERNS = (
    ('unwrap_call', '.unwrap('),
    ('expect_call', '.expect('),
    ('panic_macro', 'panic!'),
    ('todo_macro', 'todo!'),
    ('unimplemented_macro', 'unimplemented!'),
    ('unreachable_macro', 'unreachable!'),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def iter_rust_files(root: Path):
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        current_path = Path(current)
        for name in sorted(files):
            if name.endswith('.rs'):
                yield current_path / name


def rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def classify(path: str, line: str, kind: str) -> dict[str, str]:
    lower_path = path.lower()
    lower_line = line.lower()
    is_test_path = (
        lower_path.startswith('tests/')
        or '/tests/' in lower_path
        or lower_path.startswith('benches/')
        or lower_path.startswith('examples/')
        or 'test' in Path(lower_path).name
        or 'fixture' in lower_path
    )

    if is_test_path or '#[test]' in lower_line or 'cfg(test)' in lower_line:
        return {
            'classification': 'test_or_fixture_assumption',
            'fail_closed_relevance': 'low',
            'disposition': 'accepted_test_or_fixture_assumption',
        }

    if kind in {'todo_macro', 'unimplemented_macro'}:
        return {
            'classification': 'implementation_gap_signal',
            'fail_closed_relevance': 'high',
            'disposition': 'remediation_required_before_expanding_release_claims',
        }

    if kind == 'panic_macro':
        relevance = 'high' if lower_path.startswith('src/') else 'medium'
        return {
            'classification': 'panic_path_assumption',
            'fail_closed_relevance': relevance,
            'disposition': 'requires_path_review_before_broader_release_claims',
        }

    if kind in {'unwrap_call', 'expect_call'}:
        if any(marker in lower_line for marker in ('std::env', 'env::', 'oncecell', 'oncelock', 'lazy_static')):
            return {
                'classification': 'startup_or_global_invariant',
                'fail_closed_relevance': 'medium',
                'disposition': 'document_or_convert_to_explicit_startup_error',
            }
        if lower_path.startswith('src/'):
            return {
                'classification': 'production_adjacent_assumption',
                'fail_closed_relevance': 'high',
                'disposition': 'convert_to_explicit_error_or_fail_closed_response_in_later_slice',
            }
        return {
            'classification': 'tooling_or_helper_assumption',
            'fail_closed_relevance': 'medium',
            'disposition': 'review_before_using_as_release_evidence',
        }

    if kind == 'unreachable_macro':
        return {
            'classification': 'control_flow_invariant',
            'fail_closed_relevance': 'medium',
            'disposition': 'review_for_explicit_error_path_if_user_reachable',
        }

    return {
        'classification': 'unclassified_assumption',
        'fail_closed_relevance': 'medium',
        'disposition': 'manual_review_required',
    }


def scan(root: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for path in sorted(iter_rust_files(root), key=lambda p: p.as_posix()):
        rp = rel(path, root)
        try:
            lines = path.read_text(encoding='utf-8').splitlines()
        except UnicodeDecodeError:
            lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
        for lineno, line in enumerate(lines, 1):
            for kind, needle in PATTERNS:
                if needle in line:
                    item = {
                        'file': rp,
                        'line': lineno,
                        'kind': kind,
                    }
                    item.update(classify(rp, line, kind))
                    entries.append(item)

    by_kind: dict[str, int] = {}
    by_classification: dict[str, int] = {}
    by_relevance: dict[str, int] = {}
    for entry in entries:
        by_kind[entry['kind']] = by_kind.get(entry['kind'], 0) + 1
        by_classification[entry['classification']] = by_classification.get(entry['classification'], 0) + 1
        by_relevance[entry['fail_closed_relevance']] = by_relevance.get(entry['fail_closed_relevance'], 0) + 1

    normalized = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode('utf-8')
    inventory_sha256 = hashlib.sha256(normalized).hexdigest()
    return {
        'schema_version': 1,
        'slice': 'V10 Slice 4',
        'purpose': 'Rust assumption and fail-closed audit register for V10 governance.',
        'generated_at_utc': utc_now(),
        'scanner': {
            'patterns': [kind for kind, _ in PATTERNS],
            'excluded_directories': sorted(EXCLUDE_DIRS),
            'line_excerpt_recorded': False,
        },
        'summary': {
            'total_count': len(entries),
            'slice0_carried_forward_rust_assumption_count': 712,
            'inventory_sha256': inventory_sha256,
            'by_kind': by_kind,
            'by_classification': by_classification,
            'by_fail_closed_relevance': by_relevance,
            'classification_complete': True,
            'product_behavior_changed': False,
            'production_state_changed': False,
            'live_host_state_changed': False,
        },
        'non_claims': [
            'This audit does not claim that all Rust assumptions are safe.',
            'This audit does not claim that production request paths are panic-free.',
            'This audit does not claim that any runtime behavior changed.',
            'This audit does not claim broad public release readiness.',
        ],
        'required_followups': [
            'Review high relevance production-adjacent assumptions first.',
            'Convert confirmed user-reachable unwrap, expect, panic, todo, unimplemented, or unreachable assumptions into explicit errors or fail-closed responses in later slices.',
            'Add targeted regression tests for any remediated production-adjacent assumption.',
        ],
        'assumptions': entries,
    }


def write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def check(root: Path, expected_path: Path) -> int:
    expected = json.loads(expected_path.read_text(encoding='utf-8'))
    current = scan(root)
    exp_summary = expected.get('summary', {})
    cur_summary = current.get('summary', {})
    errors: list[str] = []
    if expected.get('schema_version') != 1:
        errors.append('schema_version must be 1')
    if expected.get('slice') != 'V10 Slice 4':
        errors.append('slice must be V10 Slice 4')
    if exp_summary.get('classification_complete') is not True:
        errors.append('classification_complete must be true')
    if exp_summary.get('product_behavior_changed') is not False:
        errors.append('product_behavior_changed must be false')
    if exp_summary.get('production_state_changed') is not False:
        errors.append('production_state_changed must be false')
    if exp_summary.get('live_host_state_changed') is not False:
        errors.append('live_host_state_changed must be false')
    if exp_summary.get('slice0_carried_forward_rust_assumption_count') != 712:
        errors.append('slice0_carried_forward_rust_assumption_count must be 712')
    if exp_summary.get('total_count') != cur_summary.get('total_count'):
        errors.append(f"total_count drift: expected {exp_summary.get('total_count')}, current {cur_summary.get('total_count')}")
    if exp_summary.get('inventory_sha256') != cur_summary.get('inventory_sha256'):
        errors.append('inventory_sha256 drift')
    if errors:
        for error in errors:
            print(f'Rust assumption audit failed: {error}')
        return 1
    print('Rust assumption audit passed')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', default='.')
    parser.add_argument('--write')
    parser.add_argument('--check')
    args = parser.parse_args()
    root = Path(args.repo).resolve()
    if args.write:
        write(Path(args.write), scan(root))
        return 0
    if args.check:
        return check(root, Path(args.check))
    data = scan(root)
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
