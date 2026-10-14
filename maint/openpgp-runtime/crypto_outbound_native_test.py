#!/usr/bin/env python3
"""Exact outgoing MIME proof with disposable native keys and bounded cleanup.

The Rust fixture exercises the real worker, composed MIME and receiving pipeline.
Separate principal/client qualification is recorded by crypto_principal_test.py.
No mailbox keys, real message bodies, SMTP delivery or retained key exports.
"""
import hashlib
import json
import os
import pathlib
import re
import socket
import subprocess
import struct
import tempfile
import time
from deployment_unlock import restart_bounded_agent


def main():
    assert socket.gethostname() == "obsd1.blackbagsecurity.com"
    os.umask(0o077)
    source = pathlib.Path(__file__).parent
    binary = pathlib.Path(os.environ["OSMAP_CRYPTO_RUST_TEST_BINARY"])
    assert binary.is_absolute() and binary.resolve() == binary
    test = "protected_submission::native_tests::native_crypto_outbound_submission_roundtrip"
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C"}
    listing = subprocess.run([str(binary), "--list", test], env=env, capture_output=True, timeout=15)
    assert listing.returncode == 0 and (test + ": test").encode() in listing.stdout
    print(json.dumps({"native_test_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "source_sha256": {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                                        for name in ("crypto.c", "crypto_engine.c", "deployment_unlock.py", pathlib.Path(__file__).name)}}), flush=True)
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
            worker, engine = root / "crypto-worker", root / "crypto-engine"
            for name, path, libs in [("crypto.c", worker, ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"]),
                                     ("crypto_engine.c", engine, [])]:
                compiled = run(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include",
                                str(source / name)] + libs + ["-o", str(path)])
                assert compiled.returncode == 0, "native worker compile refused"
            fingerprints = []
            for name in ("alice", "bob", "hidden"):
                home = root / name
                home.mkdir(mode=0o700)
                homes.append(home)
                gpg(home, ["--quick-generate-key", "Synthetic outgoing <outgoing@fixture.test>", "rsa3072", "cert,sign", "0"])
                listed = gpg(home, ["--with-colons", "--list-keys"]).decode()
                fingerprint = next(line.split(":")[9] for line in listed.splitlines() if line.startswith("fpr:"))
                fingerprints.append(fingerprint)
                gpg(home, ["--quick-add-key", fingerprint, "rsa3072", "encrypt", "0"])
            for target in homes:
                for origin, fp in zip(homes, fingerprints):
                    if target != origin:
                        gpg(target, ["--import"], gpg(origin, ["--export", fp]))
            native_env = dict(env, OSMAP_CRYPTO_NATIVE_WORKER=str(worker), OSMAP_CRYPTO_NATIVE_ENGINE=str(engine),
                              OSMAP_CRYPTO_NATIVE_ALICE_HOME=str(homes[0]), OSMAP_CRYPTO_NATIVE_BOB_HOME=str(homes[1]),
                              OSMAP_CRYPTO_NATIVE_HIDDEN_HOME=str(homes[2]),
                              OSMAP_CRYPTO_NATIVE_ALICE_FP=fingerprints[0], OSMAP_CRYPTO_NATIVE_BOB_FP=fingerprints[1],
                              OSMAP_CRYPTO_NATIVE_HIDDEN_FP=fingerprints[2])
            result = subprocess.run([str(binary), test, "--exact", "--ignored", "--test-threads=1", "--nocapture"],
                                    env=native_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            print(result.stdout.decode(), flush=True)
            if result.returncode != 0:
                print(json.dumps({"native_test_exit": result.returncode,
                                  "synthetic_stderr": result.stderr[:16384].decode("utf-8", errors="replace"),
                                  "stderr_truncated": len(result.stderr) > 16384}), flush=True)
            assert result.returncode == 0, "actual native outgoing MIME roundtrip refused"
            # Inspect public packet structure with a fresh empty home: no private
            # key, decryption, mailbox state or provider traffic is involved.
            packet_home = root / "packet-inspection"
            packet_home.mkdir(mode=0o700)
            packets = run(["/usr/local/bin/gpg", "--no-options", "--homedir", str(packet_home),
                           "--batch", "--no-autostart", "--list-only", "--list-packets"],
                          (root / "bcc-ciphertext.asc").read_bytes(), timeout=15)
            assert len(packets.stdout) <= 65536 and len(packets.stderr) <= 65536
            lines = packets.stdout.decode("ascii").splitlines()
            recipient_packets = [line for line in lines if line.startswith(":pubkey enc packet:")]
            assert len(recipient_packets) == 2, "two distinct intended recipient packets required"
            assert all(re.search(r"\bkeyid 0000000000000000\b", line)
                       for line in recipient_packets), "every recipient key identity must be hidden"
            assert packets.returncode == 0, "bounded public packet inspection refused"
            print("encrypted_bcc_pkesk_count=2 all_recipient_keyids_hidden=PASS", flush=True)
            # The same disposable Alice keys distinguish a dead endpoint from
            # missing private material, then exercise the existing repair.
            def worker_operation(code, content, selected=(), signature=b"", expected=True):
                frame = b"OSMC" + bytes([code, len(selected), 0, 0]) + struct.pack(">II", len(content), len(signature))
                frame += b"".join(fp.encode().ljust(64, b"\0") for fp in selected) + content + signature
                response = run([str(worker), str(homes[0]), str(engine)], frame, timeout=15)
                assert len(response.stdout) >= 8
                metadata_size, body_size = struct.unpack(">II", response.stdout[:8])
                assert metadata_size <= 65536 and body_size <= 16 * 1024 * 1024
                assert len(response.stdout) == 8 + metadata_size + body_size
                metadata = json.loads(response.stdout[8:8 + metadata_size])
                body = response.stdout[8 + metadata_size:]
                assert metadata["ok"] == expected and (response.returncode == 0) == expected
                if not expected:
                    assert body == b"" and metadata["error"] == "locked"
                return body

            public_fixture = b"Synthetic stale-agent discriminator.\n"
            signature = worker_operation(3, public_fixture, [fingerprints[0]])
            stopped = run(["/usr/local/bin/gpgconf", "--homedir", str(homes[0]), "--kill", "gpg-agent"], timeout=15)
            assert stopped.returncode == 0
            until = time.monotonic() + 5
            while (homes[0] / "S.gpg-agent").exists():
                assert time.monotonic() < until
                time.sleep(0.02)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as abandoned:
                abandoned.bind(str(homes[0] / "S.gpg-agent"))
            worker_operation(3, public_fixture, [fingerprints[0]], expected=False)
            worker_operation(4, public_fixture, [fingerprints[1]])
            worker_operation(2, public_fixture, signature=signature)
            restart_bounded_agent(homes[0], env, None)
            worker_operation(3, public_fixture, [fingerprints[0]])
            print("stale_private_agent_locked_without_plaintext=PASS stale_public_encrypt_verify=PASS bounded_agent_recovery_sign=PASS", flush=True)
        finally:
            for home in homes:
                stopped = run(["/usr/local/bin/gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], timeout=15)
                assert stopped.returncode == 0, "disposable agent cleanup refused"
    print("outbound_native_roundtrip=PASS disposable_agents_stopped=PASS scratch_cleanup=PASS", flush=True)


if __name__ == "__main__":
    main()
