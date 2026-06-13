#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

generated_at=${OSMAP_EVIDENCE_METADATA_GENERATED_AT:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}
git_commit=${OSMAP_EVIDENCE_METADATA_GIT_COMMIT:-$(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown')}

python3 - "$repo_root" "$generated_at" "$git_commit" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
generated_at = sys.argv[2]
git_commit = sys.argv[3]


def run(command):
    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {
            "status": "unavailable",
            "version": None,
            "detail": type(exc).__name__,
        }
    output = completed.stdout.strip().splitlines()
    version = output[0].strip() if output else None
    if completed.returncode != 0:
        return {
            "status": "unavailable",
            "version": version,
            "detail": f"exit_status={completed.returncode}",
        }
    return {
        "status": "available",
        "version": version,
    }


def git_output(args):
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


hostname = run(["hostname"]).get("version") or "unknown"
uname = run(["uname", "-a"]).get("version") or "unknown"
tags = [
    line.strip()
    for line in git_output(["tag", "--points-at", git_commit]).splitlines()
    if line.strip()
]

metadata = {
    "schema": "osmap-evidence-metadata-v1",
    "generated_at_utc": generated_at,
    "git": {
        "commit": git_commit,
        "tags": tags,
    },
    "host": {
        "hostname": hostname,
        "os": uname,
    },
    "tools": {
        "rustc": run(["rustc", "--version"]),
        "cargo": run(["cargo", "--version"]),
        "cargo_fmt": run(["cargo", "fmt", "--version"]),
        "cargo_clippy": run(["cargo", "clippy", "--version"]),
        "cargo_audit": run(["cargo", "audit", "--version"]),
        "cargo_deny": run(["cargo", "deny", "--version"]),
        "make": run(["make", "--version"]),
    },
}

print(json.dumps(metadata, indent=2, sort_keys=True))
PY
