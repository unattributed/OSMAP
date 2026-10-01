#!/usr/bin/env python3
"""obsd1 production gateway proof using disposable helpers and loopback SMTP.

The Sent command stores exact submitted bytes in temporary scratch. This does
not claim an actual Dovecot mailbox append or external provider/browser test.
No real mailbox keys, reusable credentials or protected bodies are retained.
"""
import hashlib
import json
import os
import pathlib
import resource
import socket
import subprocess
import tempfile


def main():
    assert socket.gethostname() == "obsd1.blackbagsecurity.com"
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = pathlib.Path(__file__).parent
    binary = pathlib.Path(os.environ["OSMAP_CRYPTO_RUST_TEST_BINARY"])
    assert binary.is_absolute() and binary.resolve() == binary
    test = "http::http_gateway::http_gateway_mail::tests::protected_send_native::native_crypto_gateway_protected_send_roundtrip"
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C"}
    listing = subprocess.run([str(binary), "--list", test], env=env, capture_output=True, timeout=15)
    assert listing.returncode == 0 and (test + ": test").encode() in listing.stdout
    print(json.dumps({"native_test_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "source_sha256": {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                                        for name in ("crypto.c", "crypto_engine.c", "inventory.c", pathlib.Path(__file__).name)}}), flush=True)
    with tempfile.TemporaryDirectory(prefix="osmap-crypto-fixture-") as directory:
        root = pathlib.Path(directory)
        homes = []

        def run(args, data=b"", timeout=90, pass_fds=()):
            return subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env=env, timeout=timeout, pass_fds=pass_fds)

        def gpg(home, args, data=b""):
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b"\n")
            os.close(write_fd)
            try:
                result = run(["/usr/local/bin/gpg", "--no-options", "--homedir", str(home), "--batch",
                              "--pinentry-mode", "loopback", "--passphrase-fd", str(read_fd)] + args,
                             data, pass_fds=(read_fd,))
            finally:
                os.close(read_fd)
            assert result.returncode == 0, "disposable key operation refused"
            return result.stdout

        try:
            worker, engine, inventory_worker = root / "crypto-worker", root / "crypto-engine", root / "inventory-worker"
            for name, path, libs in [("crypto.c", worker, ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"]),
                                     ("crypto_engine.c", engine, []),
                                     ("inventory.c", inventory_worker, ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"])]:
                compiled = run(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include",
                                str(source / name)] + libs + ["-o", str(path)])
                assert compiled.returncode == 0, "native worker compile refused"
            fingerprints = []
            for name in ("alice", "bob"):
                home = root / name
                home.mkdir(mode=0o700)
                homes.append(home)
                gpg(home, ["--quick-generate-key", "Synthetic gateway <gateway@fixture.test>", "rsa3072", "cert,sign", "0"])
                listed = gpg(home, ["--with-colons", "--list-keys"]).decode()
                fingerprint = next(line.split(":")[9] for line in listed.splitlines() if line.startswith("fpr:"))
                fingerprints.append(fingerprint)
                gpg(home, ["--quick-add-key", fingerprint, "rsa3072", "encrypt", "0"])
            for target, origin, fp in [(homes[0], homes[1], fingerprints[1]), (homes[1], homes[0], fingerprints[0])]:
                gpg(target, ["--import"], gpg(origin, ["--export", fp]))
            native_env = dict(env, OSMAP_CRYPTO_NATIVE_WORKER=str(worker), OSMAP_CRYPTO_NATIVE_ENGINE=str(engine),
                              OSMAP_CRYPTO_NATIVE_INVENTORY_WORKER=str(inventory_worker),
                              OSMAP_CRYPTO_NATIVE_ALICE_HOME=str(homes[0]), OSMAP_CRYPTO_NATIVE_BOB_HOME=str(homes[1]),
                              OSMAP_CRYPTO_NATIVE_ALICE_FP=fingerprints[0], OSMAP_CRYPTO_NATIVE_BOB_FP=fingerprints[1])
            result = subprocess.run([str(binary), test, "--exact", "--ignored", "--test-threads=1", "--nocapture"],
                                    env=native_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            print(result.stdout.decode(), flush=True)
            assert result.returncode == 0 and b"1 passed; 0 failed" in result.stdout, "actual native gateway fixture refused"
        finally:
            for home in homes:
                stopped = run(["/usr/local/bin/gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], timeout=15)
                assert stopped.returncode == 0, "disposable agent cleanup refused"
    print("gateway_native_roundtrip=PASS controlled_smtp_sent_parity=PASS decoded_content=PASS replay_no_duplicate=PASS stale_no_dispatch=PASS helper_failure_no_plaintext=PASS disposable_agents_stopped=PASS scratch_cleanup=PASS", flush=True)


if __name__ == "__main__":
    main()
