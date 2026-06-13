#!/usr/bin/env python3
"""Repository guard for CWE Top 25-aligned weak coding patterns.

This is intentionally a high-signal regression guard, not a full static
analyzer. It blocks classes of code that OSMAP has already decided must stay
out of the production Rust boundary unless they are reviewed and allowlisted.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


TOP25_VERSION = "MITRE CWE Top 25 2025"


@dataclass(frozen=True)
class Finding:
    cwe: str
    category: str
    path: Path
    line_number: int
    line_text: str


@dataclass(frozen=True)
class PatternRule:
    cwe: str
    category: str
    pattern: re.Pattern[str]
    allow_paths: tuple[str, ...] = ()


PRODUCTION_RULES = (
    PatternRule(
        "CWE-787/CWE-416/CWE-125/CWE-120/CWE-121/CWE-122",
        "memory-unsafe Rust outside reviewed OpenBSD FFI boundary",
        re.compile(r"\bunsafe\s*(?:fn|impl|trait|\{)"),
        ("src/openbsd.rs",),
    ),
    PatternRule(
        "CWE-78/CWE-77",
        "shell-based command execution",
        re.compile(r"(/bin/sh\b|\bsh\s+-c\b|\bcmd\s+/c\b|\bpowershell\b)"),
    ),
    PatternRule(
        "CWE-78/CWE-77",
        "unreviewed direct process execution",
        re.compile(r"\bCommand::new\s*\("),
        ("src/auth.rs",),
    ),
    PatternRule(
        "CWE-94/CWE-79",
        "browser/client code execution sink",
        re.compile(
            r"(\beval\s*\(|\bFunction\s*\(|innerHTML|outerHTML|document\.write|"
            r"\bsrcdoc\b|serviceWorker|new\s+WebSocket|BroadcastChannel|"
            r"RTCPeerConnection|\bfetch\s*\()"
        ),
    ),
    PatternRule(
        "CWE-502",
        "generic untrusted deserialization surface",
        re.compile(
            r"(bincode::deserialize|serde_yaml::from_str|rmp_serde::from_|"
            r"serde_pickle::from_|postcard::from_bytes)"
        ),
    ),
    PatternRule(
        "CWE-89",
        "raw SQL construction in production Rust",
        re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE\s+TABLE|DROP\s+TABLE)\b"),
    ),
)


DEPENDENCY_RULES = (
    PatternRule(
        "CWE-89",
        "SQL database dependency introduced into application crate",
        re.compile(r"^\s*(rusqlite|sqlx|diesel|postgres|tokio-postgres|mysql|mysql_async)\s*(=|\{)"),
    ),
    PatternRule(
        "CWE-918",
        "outbound HTTP client dependency introduced into application crate",
        re.compile(r"^\s*(reqwest|ureq|isahc|surf|hyper|curl)\s*(=|\{)"),
    ),
    PatternRule(
        "CWE-502",
        "generic binary/object deserialization dependency introduced into application crate",
        re.compile(r"^\s*(bincode|rmp-serde|serde_pickle|postcard|serde_yaml)\s*(=|\{)"),
    ),
)


def repo_relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def brace_delta(line: str) -> int:
    return line.count("{") - line.count("}")


def production_rust_lines(path: Path) -> list[tuple[int, str]]:
    """Return Rust source lines with common cfg(test) modules removed.

    The project keeps many hostile payload strings inside unit tests. Scanning
    them as production code would create noisy false positives, so this strips
    conventional `#[cfg(test)] mod tests { ... }` blocks before applying the
    high-risk production rules.
    """

    result: list[tuple[int, str]] = []
    pending_cfg_test = False
    skipping_test_module = False
    skip_depth = 0

    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        stripped = line.strip()

        if skipping_test_module:
            skip_depth += brace_delta(line)
            if skip_depth <= 0:
                skipping_test_module = False
                skip_depth = 0
            continue

        if stripped.startswith("#[cfg(test)]"):
            pending_cfg_test = True
            continue

        if pending_cfg_test:
            if re.match(r"(?:pub(?:\([^)]*\))?\s+)?mod\s+tests\b", stripped):
                skipping_test_module = True
                skip_depth = max(brace_delta(line), 1)
                continue
            pending_cfg_test = False

        result.append((line_number, line))

    return result


def scan_rust(root: Path) -> list[Finding]:
    src_dir = root / "src"
    if not src_dir.exists():
        return []

    findings: list[Finding] = []
    for path in sorted(src_dir.rglob("*.rs")):
        rel = repo_relative(path, root)
        for line_number, line in production_rust_lines(path):
            for rule in PRODUCTION_RULES:
                if rel in rule.allow_paths:
                    continue
                if rule.pattern.search(line):
                    findings.append(
                        Finding(
                            rule.cwe,
                            rule.category,
                            Path(rel),
                            line_number,
                            line.strip(),
                        )
                    )
    return findings


def scan_dependencies(root: Path) -> list[Finding]:
    cargo_toml = root / "Cargo.toml"
    if not cargo_toml.exists():
        return []

    findings: list[Finding] = []
    for line_number, line in enumerate(cargo_toml.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        for rule in DEPENDENCY_RULES:
            if rule.pattern.search(line):
                findings.append(
                    Finding(
                        rule.cwe,
                        rule.category,
                        Path("Cargo.toml"),
                        line_number,
                        line.strip(),
                    )
                )
    return findings


def render_findings(findings: list[Finding]) -> str:
    lines = [
        f"error: CWE Top 25 guard found {len(findings)} high-risk pattern(s)",
        f"benchmark={TOP25_VERSION}",
    ]
    for finding in findings:
        lines.append(
            f"{finding.path}:{finding.line_number}: {finding.cwe}: "
            f"{finding.category}: {finding.line_text}"
        )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="OSMAP CWE Top 25 regression guard")
    parser.add_argument(
        "--repo-root",
        default=".",
        help="repository root to scan, defaults to current directory",
    )
    args = parser.parse_args(argv)

    root = Path(args.repo_root).resolve()
    findings = scan_dependencies(root) + scan_rust(root)
    if findings:
        print(render_findings(findings), file=sys.stderr)
        return 1

    print(f"CWE Top 25 guard passed ({TOP25_VERSION})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
