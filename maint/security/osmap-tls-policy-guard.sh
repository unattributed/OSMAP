#!/bin/sh
#
# Static guard for OSMAP TLS policy drift in repository code and tooling.

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

python3 - "$repo_root" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

repo = Path(sys.argv[1])
tracked = subprocess.check_output(["git", "ls-files"], cwd=repo, text=True).splitlines()

allow_pattern_files = {
    "maint/security/osmap-tls-policy-guard.sh": "the guard owns the prohibited-pattern list",
    "maint/security/osmap-live-tls-standard-validate.py": "the live validator must intentionally probe rejected legacy TLS versions and ciphers",
}

skip_prefixes = (
    "docs/",
    "maint/live/",
)

skip_exact = {
    "README.md",
}

prohibited = [
    ("ssl.PROTOCOL_TLSv1", re.compile(r"\bssl\.PROTOCOL_TLSv1\b")),
    ("ssl.PROTOCOL_TLSv1_1", re.compile(r"\bssl\.PROTOCOL_TLSv1_1\b")),
    ("ssl.PROTOCOL_SSLv2", re.compile(r"\bssl\.PROTOCOL_SSLv2\b")),
    ("ssl.PROTOCOL_SSLv3", re.compile(r"\bssl\.PROTOCOL_SSLv3\b")),
    ("ssl.wrap_socket", re.compile(r"\bssl\.wrap_socket\b")),
    ("_create_unverified_context", re.compile(r"\b_create_unverified_context\b")),
    ("check_hostname = False", re.compile(r"\bcheck_hostname\s*=\s*False\b")),
    ("CERT_NONE", re.compile(r"\bCERT_NONE\b")),
    ("TLSv1", re.compile(r"\bTLSv1(?!\.2|\.3)\b")),
    ("TLSv1.0", re.compile(r"\bTLSv1\.0\b")),
    ("TLSv1.1", re.compile(r"\bTLSv1\.1\b")),
    ("RC4", re.compile(r"\bRC4\b", re.IGNORECASE)),
    ("3DES", re.compile(r"\b3DES\b", re.IGNORECASE)),
    ("DES-CBC", re.compile(r"\bDES-CBC\b", re.IGNORECASE)),
    ("AES256-SHA", re.compile(r"\bAES256-SHA\b", re.IGNORECASE)),
    ("AES128-SHA", re.compile(r"\bAES128-SHA\b", re.IGNORECASE)),
    ("MD5", re.compile(r"\bMD5\b", re.IGNORECASE)),
    ("NULL cipher", re.compile(r"\bNULL\b")),
    ("anonymous cipher", re.compile(r"\banonymous\b", re.IGNORECASE)),
]

failures: list[str] = []


def skip_for_prohibited_patterns(path: str) -> bool:
    return path in skip_exact or path in allow_pattern_files or any(path.startswith(prefix) for prefix in skip_prefixes)


for rel in tracked:
    path = repo / rel
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue

    if not skip_for_prohibited_patterns(rel):
        for label, pattern in prohibited:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                failures.append(f"{rel}:{line}: prohibited TLS pattern: {label}")

    if rel.endswith(".py") and rel not in allow_pattern_files:
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if "ssl.create_default_context(" not in line:
                continue
            window = lines[index + 1 : index + 5]
            if not any("minimum_version" in candidate and "ssl.TLSVersion.TLSv1_2" in candidate for candidate in window):
                failures.append(
                    f"{rel}:{index + 1}: ssl.create_default_context() must immediately set minimum_version to ssl.TLSVersion.TLSv1_2"
                )

standard = repo / "docs" / "TLS_STANDARD.md"
if not standard.is_file():
    failures.append("docs/TLS_STANDARD.md missing")
else:
    standard_text = standard.read_text(encoding="utf-8")
    for phrase in [
        "TLS 1.2 is the minimum allowed protocol version.",
        "TLS 1.3 is preferred where supported.",
        "TLS 1.0 and TLS 1.1 are prohibited.",
        "SSLv2 and SSLv3 are prohibited.",
        "TLS 1.2 must use only strong forward-secret AEAD suites.",
        "Certificate validation and hostname verification must remain enabled",
        "The test harness must fail closed when weak TLS is detected.",
    ]:
        if phrase not in standard_text:
            failures.append(f"docs/TLS_STANDARD.md missing required phrase: {phrase}")

if failures:
    for failure in failures:
        print(failure, file=sys.stderr)
    raise SystemExit(1)

print("TLS policy guard passed")
PY
