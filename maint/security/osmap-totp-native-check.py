#!/usr/bin/env python3
"""Run synthetic lifecycle checks on OpenBSD; never touch live factor stores."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def main():
    if platform.system() != "OpenBSD":
        raise SystemExit("native lifecycle qualification requires OpenBSD")
    for command in ("bash", "python3", "gpg", "gpgconf", "stat", "sha256"):
        if not shutil.which(command):
            raise SystemExit(f"missing native qualification dependency: {command}")
    print("qualification=synthetic_openbsd", flush=True)
    print("live_factor_mutation=false", flush=True)
    print("real_authenticator_acceptance=false", flush=True)
    print("ssh_and_doas_boundaries=synthetic_adapters", flush=True)
    print("remote_stat_and_sha256=native", flush=True)
    with tempfile.TemporaryDirectory(prefix="osmap-native-check-") as directory:
        # The coordinator normally runs on the Linux workstation. Supply only
        # its one-file sha256sum interface for these on-host synthetic tests.
        # The actual remote bodies still use OpenBSD stat and sha256 unchanged.
        checksum = Path(directory, "sha256sum")
        checksum.write_text('''#!/bin/sh
set -eu
[ "$#" -eq 1 ] || exit 2
digest=$(/bin/sha256 -q "$1")
printf '%s  %s\\n' "$digest" "$1"
''')
        checksum.chmod(0o700)
        environment = dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"])
        # Legacy --self-test commands use Linux workstation stat syntax and
        # are qualified separately on that workstation, not adapted here.
        for operation in ("rotation", "recovery"):
            script = ROOT / f"maint/security/test-osmap-totp-{operation}.py"
            subprocess.run(["python3", str(script)], env=environment, check=True)
    print("NATIVE_SYNTHETIC_LIFECYCLE=PASS", flush=True)


if __name__ == "__main__":
    main()
