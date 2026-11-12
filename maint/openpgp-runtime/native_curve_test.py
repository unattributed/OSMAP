#!/usr/bin/env python3
"""Public curve metadata proof using only disposable obsd1 key homes."""
import json
import os
import pathlib
import socket
import subprocess
import tempfile


def main():
    assert socket.gethostname() == "obsd1.blackbagsecurity.com"
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="osmap-public-curve-") as scratch:
        root = pathlib.Path(scratch)
        secret = root / "generate"
        public = root / "public"
        for home in [secret, public]:
            home.mkdir(mode=0o700)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C"}

        def run(args, data=b"", timeout=30):
            r = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=timeout)
            assert r.returncode == 0, "disposable curve operation refused"
            return r.stdout

        def gpg(home, args, data=b""):
            return run(["/usr/local/bin/gpg", "--no-options", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""] + args, data)

        try:
            gpg(secret, ["--quick-generate-key", "Synthetic Curve <curve@fixture.test>", "ed25519", "cert,sign", "0"])
            fingerprint = next(line.split(":")[9] for line in gpg(secret, ["--with-colons", "--list-keys"]).decode().splitlines() if line.startswith("fpr:"))
            gpg(secret, ["--quick-add-key", fingerprint, "cv25519", "encrypt", "0"])
            gpg(public, ["--import"], gpg(secret, ["--export", fingerprint]))
            gpg(public, ["--list-keys"])
            worker = root / "inventory"
            run(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include", str(pathlib.Path(__file__).with_name("inventory.c")), "-L/usr/local/lib", "-lgpgme", "-lgpg-error", "-o", str(worker)])
            result = json.loads(run([str(worker), str(public)]))
            assert result["ok"] and len(result["keys"]) == 1
            key = result["keys"][0]
            assert key["primary"]["curve"] == "ed25519"
            assert len(key["subkeys"]) == 1 and key["subkeys"][0]["curve"] == "cv25519"
            print(json.dumps({"ed25519_curve_exact": True, "cv25519_curve_exact": True, "public_home_only": True}))
        finally:
            for home in [secret, public]:
                subprocess.run(["/usr/local/bin/gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, timeout=10, check=True)
    print("disposable_agents_stopped=PASS scratch_cleanup=PASS")


if __name__ == "__main__":
    main()
