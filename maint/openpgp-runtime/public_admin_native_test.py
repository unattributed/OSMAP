#!/usr/bin/env python3
"""Disposable obsd1 public-only staging operations; no actual account commits."""
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import tempfile


def main():
    assert socket.gethostname() == "obsd1.blackbagsecurity.com"
    os.umask(0o077)
    source = pathlib.Path(__file__).parent
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C"}
    checks = {}
    with tempfile.TemporaryDirectory(prefix="osmap-public-admin-") as directory:
        root = pathlib.Path(directory)
        homes = []

        def run(args, data=b"", timeout=30, cwd=None, pass_fds=()):
            return subprocess.run(args, input=data, capture_output=True, timeout=timeout, env=env,
                                  cwd=cwd, pass_fds=pass_fds)

        def gpg(home, args, data=b""):
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b"\n")
            os.close(write_fd)
            try:
                result = run(["/usr/local/bin/gpg", "--no-options", "--homedir", str(home), "--batch",
                              "--pinentry-mode", "loopback", "--passphrase-fd", str(read_fd)] + args,
                             data, 90, home, (read_fd,))
            finally:
                os.close(read_fd)
            assert result.returncode == 0, "disposable GPG operation refused"
            return result.stdout

        def home(name):
            value = root / name
            value.mkdir(mode=0o700)
            homes.append(value)
            return value

        def manifest(home):
            return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in home.iterdir() if p.is_file()}

        worker = root / "inventory-worker"
        compiled = run(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include",
                        str(source / "inventory.c"), "-L/usr/local/lib", "-lgpgme", "-lgpg-error", "-o", str(worker)])
        if compiled.returncode:
            print(compiled.stderr.decode(), flush=True)
        assert compiled.returncode == 0
        engine = root / "crypto-engine"
        compiled = run(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", str(source / "crypto_engine.c"), "-o", str(engine)])
        assert compiled.returncode == 0
        try:
            alice, bob = home("alice"), home("bob")
            fps = []
            for key_home in (alice, bob):
                gpg(key_home, ["--quick-generate-key", "Synthetic admin <admin@fixture.test>", "ed25519", "cert,sign", "0"])
                listed = gpg(key_home, ["--with-colons", "--list-keys"]).decode()
                fp = next(line.split(":")[9] for line in listed.splitlines() if line.startswith("fpr:"))
                fps.append(fp)
                gpg(key_home, ["--quick-add-key", fp, "cv25519", "encrypt", "0"])
            afp, bfp = fps
            public = gpg(alice, ["--armor", "--export", afp])
            public_binary = gpg(alice, ["--export", afp])
            secret = gpg(alice, ["--armor", "--export-secret-keys", afp])
            secret_binary = gpg(alice, ["--export-secret-keys", afp])
            sub_secret = gpg(alice, ["--export-secret-subkeys", afp])
            bob_public = gpg(bob, ["--export", bfp])
            gpg(alice, ["--import"], bob_public)
            before = manifest(alice)
            for fp, expected in [(afp, False), (bfp, True)]:
                checked = run([str(worker), str(alice), "guard-removal", fp, str(engine)], cwd=alice)
                assert (checked.returncode == 0) == expected and json.loads(checked.stdout)["ok"] == expected
                assert before == manifest(alice), "readonly secret-capability guard changed actual home"
            checks["actual_home_secret_primary_refused_public_correspondent_accepted"] = True
            public_guard = home("public-guard")
            gpg(public_guard, ["--import"], public)
            gpg(public_guard, ["--list-secret-keys"])
            accepted = run([str(worker), str(public_guard), "guard-removal", afp, str(engine)], cwd=public_guard)
            assert accepted.returncode == 0 and json.loads(accepted.stdout)["ok"]
            before_guard = manifest(public_guard)
            stopped = run(["/usr/local/bin/gpgconf", "--homedir", str(public_guard), "--kill", "gpg-agent"])
            assert stopped.returncode == 0
            absent = run([str(worker), str(public_guard), "guard-removal", afp, str(engine)], cwd=public_guard)
            assert absent.returncode != 0 and not json.loads(absent.stdout)["ok"]
            assert before_guard == manifest(public_guard) and not (public_guard / "S.gpg-agent").exists()
            checks["existing_public_key_guard_refuses_absent_agent_without_autostart"] = True
            stage = home("stage")
            # Initialize only provisioned public files, then remove auto-created
            # empty directories. Never copy private files into the staging home.
            gpg(stage, ["--list-keys"])
            for directory in stage.iterdir():
                if directory.is_dir():
                    directory.rmdir()

            def operation(mode, fp, data=b"", expected=True):
                before = manifest(stage)
                before_private = {p.name for p in stage.iterdir() if p.name.startswith("S.gpg-agent") or p.name == "private-keys-v1.d"}
                result = run([str(worker), str(stage), mode, fp, str(engine)], data, 15, stage)
                payload = json.loads(result.stdout)
                assert (result.returncode == 0) == expected and payload["ok"] == expected, (mode, result.returncode, payload)
                assert len(result.stdout) <= 65536
                assert before_private == {p.name for p in stage.iterdir() if p.name.startswith("S.gpg-agent") or p.name == "private-keys-v1.d"}, "private capability appeared in staging"
                if not expected:
                    assert before == manifest(stage), "refused input changed staged public files"
                # GnuPG may leave its public-only backup; it is not a permitted
                # initial resource for the next isolated staging invocation.
                backup = stage / "pubring.kbx~"
                if backup.exists():
                    backup.unlink()
                return payload

            for name, packet in [("secret_armor", secret), ("secret_binary", secret_binary),
                                 ("secret_subkey_stub_primary", sub_secret),
                                 ("secret_packets_disguised_public_armor", secret.replace(b"PRIVATE KEY", b"PUBLIC KEY"))]:
                operation("import-public", afp, packet, False)
                checks[name + "_refused_before_public_write"] = True
            operation("import-public", afp, public)
            checks["actual_public_certificate_import"] = True
            operation("import-public", afp, public)
            checks["public_reimport"] = True
            operation("import-public", afp, public_binary)
            checks["public_binary_import"] = True
            for name, fp, packet in [("wrong_primary", bfp, public), ("multiple_certificates", afp, public + bob_public),
                                     ("malformed", afp, b"not a certificate"), ("empty", afp, b""),
                                     ("oversize", afp, b"x" * 65537), ("v6_unqualified", "A" * 64, public)]:
                operation("import-public", fp, packet, False)
                checks[name + "_refused_without_write"] = True
            operation("import-public", afp, public_binary + bob_public, False)
            operation("import-public", afp, public_binary + secret_binary, False)
            checks["multiple_binary_certificates_and_public_plus_secret_packets_refused"] = True
            listed = gpg(alice, ["--with-colons", "--list-keys"]).decode()
            subfp = [line.split(":")[9] for line in listed.splitlines() if line.startswith("fpr:")][1]
            operation("remove-public", subfp, expected=False)
            operation("remove-public", afp, b"unexpected", False)
            operation("remove-public", bfp, expected=False)
            checks["subkey_unknown_and_nonempty_remove_refused"] = True
            operation("remove-public", afp)
            checks["actual_public_certificate_remove"] = True
            foreign = stage / "private-keys-v1.d"
            foreign.mkdir(mode=0o700)
            operation("import-public", afp, public, False)
            foreign.rmdir()
            checks["private_directory_staging_refused"] = True
            public_result = run([str(worker), str(alice)], cwd=alice)
            assert public_result.returncode == 0 and json.loads(public_result.stdout)["ok"]
            checks["existing_readonly_home_with_private_keys_still_supported"] = True
            print(json.dumps({"checks": checks, "all_passed": all(checks.values()),
                              "source_sha256": {n: hashlib.sha256((source / n).read_bytes()).hexdigest()
                                                for n in ("inventory.c", "crypto_engine.c", pathlib.Path(__file__).name)}}, sort_keys=True), flush=True)
        finally:
            for key_home in homes:
                stopped = run(["/usr/local/bin/gpgconf", "--homedir", str(key_home), "--kill", "gpg-agent"])
                assert stopped.returncode == 0
    print("disposable_agents_stopped=PASS scratch_cleanup=PASS", flush=True)


if __name__ == "__main__":
    main()
