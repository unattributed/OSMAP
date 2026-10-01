#!/usr/bin/env python3
"""Real GPGME operations in disposable obsd1 key homes; no real keys or mail.

Reports only case names and booleans. The temporary key material and plaintext
never leave scratch, and agents are stopped before removing their own homes.
"""
import base64
import hashlib
import json
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import time


def main():
    assert socket.gethostname() == "obsd1.blackbagsecurity.com"
    os.umask(0o077)
    source = pathlib.Path(__file__).parent
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="osmap-crypto-fixture-") as directory:
        root = pathlib.Path(directory)
        homes = []
        checks = {}
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C", "GNUPGHOME": str(root / "NEVER_DEFAULT")}

        def run(arguments, data=b"", timeout=30, pass_fds=()):
            assert time.monotonic() - started < 420, "overall fixture deadline"
            return subprocess.run(arguments, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env=environment, timeout=timeout, pass_fds=pass_fds)

        def gpg(home, arguments, data=b"", passphrase=""):
            read_fd, write_fd = os.pipe()
            os.write(write_fd, passphrase.encode() + b"\n")
            os.close(write_fd)
            try:
                result = run(["/usr/local/bin/gpg", "--no-options", "--homedir", str(home), "--batch",
                              "--pinentry-mode", "loopback", "--passphrase-fd", str(read_fd)] + arguments, data, 90, (read_fd,))
            finally:
                os.close(read_fd)
            assert result.returncode == 0, "disposable GPG operation refused"
            return result.stdout

        def home(name):
            path = root / name
            path.mkdir(mode=0o700)
            homes.append(path)
            return path

        def fingerprint(path):
            raw = gpg(path, ["--with-colons", "--list-keys"]).decode()
            return next(line.split(":")[9] for line in raw.splitlines() if line.startswith("fpr:"))

        def manifest(path):
            return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in path.rglob("*") if p.is_file()}

        engine = root / "crypto-engine"
        worker = root / "crypto-worker"
        for name, binary, link in [("crypto_engine.c", engine, []), ("crypto.c", worker, ["-L/usr/local/lib", "-lgpgme", "-lgpg-error"])]:
            result = run(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include",
                          str(source / name)] + link + ["-o", str(binary)])
            if result.returncode:
                print(result.stderr.decode(), flush=True)
            assert result.returncode == 0, "C compile refused"

        def operation(path, code, content, fingerprints=(), signature=b"", expected=True):
            before = manifest(path)
            frame = b"OSMC" + bytes([code, len(fingerprints), 0, 0]) + struct.pack(">II", len(content), len(signature))
            frame += b"".join(fp.encode().ljust(64, b"\0") for fp in fingerprints) + content + signature
            result = run([str(worker), str(path), str(engine)], frame, 15)
            assert len(result.stdout) >= 8, "missing typed worker result"
            metadata_size, body_size = struct.unpack(">II", result.stdout[:8])
            assert metadata_size <= 65536 and body_size <= 16 * 1024 * 1024
            assert len(result.stdout) == 8 + metadata_size + body_size
            metadata = json.loads(result.stdout[8:8 + metadata_size])
            assert metadata["ok"] == expected and (result.returncode == 0) == expected, ("operation status", code, result.returncode, metadata)
            assert before == manifest(path), "crypto operation changed key files"
            assert not (root / "NEVER_DEFAULT").exists()
            body = result.stdout[8 + metadata_size:]
            if not expected:
                assert not body, "partial plaintext escaped failed operation"
            return metadata, body

        plaintext = b"Content-Type: text/plain\r\n\r\nSynthetic bounded encrypted fixture.\r\n"
        try:
            alice = home("alice")
            bob = home("bob")
            curve = home("curve")
            locked = home("locked")
            weak = home("weak")
            for path, algorithm in [(alice, "rsa3072"), (bob, "rsa3072"), (curve, "ed25519"), (locked, "rsa3072")]:
                passphrase = "disposable-fixture-lock" if path == locked else ""
                gpg(path, ["--quick-generate-key", "Synthetic Fixture <fixture@fixture.test>", algorithm, "cert,sign", "0"], passphrase=passphrase)
                fp = fingerprint(path)
                gpg(path, ["--quick-add-key", fp, "cv25519" if path == curve else "rsa3072", "encrypt", "0"], passphrase=passphrase)
            afp, bfp, cfp, lfp = map(fingerprint, [alice, bob, curve, locked])
            gpg(alice, ["--import"], gpg(bob, ["--export", bfp]))
            gpg(bob, ["--import"], gpg(alice, ["--export", afp]))

            sign_metadata, signature = operation(alice, 3, plaintext, [afp])
            assert signature.startswith(b"-----BEGIN PGP SIGNATURE-----") and sign_metadata["hash_algorithm"] == 8
            verify_metadata, _ = operation(bob, 2, plaintext, signature=signature)
            assert verify_metadata["signer_fingerprint"] == sign_metadata["signer_fingerprint"]
            checks["rsa_detached_sign_and_verify"] = True
            sha512_signature = gpg(alice, ["--digest-algo", "SHA512", "--armor", "--detach-sign"], plaintext)
            sha512_metadata, _ = operation(bob, 2, plaintext, signature=sha512_signature)
            assert sha512_metadata["hash_algorithm"] == 10
            sha1_signature = gpg(alice, ["--digest-algo", "SHA1", "--armor", "--detach-sign"], plaintext)
            operation(bob, 2, plaintext, signature=sha1_signature, expected=False)
            checks["sha512_verified_and_sha1_refused"] = True
            operation(bob, 2, plaintext + b"tamper", signature=signature, expected=False)
            operation(bob, 2, plaintext, signature=signature + signature, expected=False)
            checks["tamper_and_multiple_signature_refused"] = True
            _, ciphertext = operation(alice, 4, plaintext, [bfp])
            assert ciphertext.startswith(b"-----BEGIN PGP MESSAGE-----")
            metadata, decrypted = operation(bob, 1, ciphertext, [bfp])
            assert decrypted == plaintext and metadata["primary_fingerprint"] == bfp
            operation(alice, 1, ciphertext, [afp], expected=False)
            operation(bob, 1, ciphertext, [afp], expected=False)
            checks["rsa_encrypt_decrypt_and_wrong_account_binding"] = True
            damaged = bytearray(ciphertext)
            offset = damaged.find(b"\n\n") + 2
            damaged[offset + 30] = ord("A") if damaged[offset + 30] != ord("A") else ord("B")
            operation(bob, 1, bytes(damaged), [bfp], expected=False)
            checks["damaged_ciphertext_no_plaintext"] = True
            payload = ciphertext.split(b"\n\n", 1)[1].split(b"-----END", 1)[0]
            binary = base64.b64decode(b"".join(line for line in payload.splitlines() if not line.startswith(b"=")))
            last_tag_changed = binary[:-1] + bytes([binary[-1] ^ 1])
            operation(bob, 1, last_tag_changed, [bfp], expected=False)
            operation(bob, 1, binary[:-1], [bfp], expected=False)
            checks["authentication_tag_tamper_and_truncation_no_plaintext"] = True
            weak_cipher = gpg(alice, ["--cipher-algo", "AES128", "--trust-model", "always", "--armor", "--recipient", bfp, "--encrypt"], plaintext)
            operation(bob, 1, weak_cipher, [bfp], expected=False)
            checks["unqualified_symmetric_cipher_refused"] = True

            _, curve_signature = operation(curve, 3, plaintext, [cfp])
            operation(curve, 2, plaintext, signature=curve_signature)
            _, curve_ciphertext = operation(curve, 4, plaintext, [cfp])
            _, curve_plaintext = operation(curve, 1, curve_ciphertext, [cfp])
            assert curve_plaintext == plaintext
            checks["ed25519_cv25519_interoperability"] = True
            # A real SC primary plus two S subkeys must use only the explicit
            # helper binding, regardless of the engine's newer-key preference.
            gpg(alice, ["--quick-add-key", afp, "rsa3072", "sign", "0"])
            listing = gpg(alice, ["--with-colons", "--list-keys", afp]).decode().splitlines()
            exact_signer = next(listing[index + 1].split(":")[9]
                                for index, line in enumerate(listing)
                                if line.startswith("sub:") and "s" in line.split(":")[11])
            gpg(alice, ["--quick-add-key", afp, "rsa3072", "sign", "0"])
            gpg(bob, ["--import"], gpg(alice, ["--export", afp]))
            bound_metadata, bound_signature = operation(alice, 3, plaintext, [exact_signer])
            assert bound_metadata["signer_fingerprint"] == exact_signer
            verified, _ = operation(bob, 2, plaintext, signature=bound_signature)
            assert verified["signer_fingerprint"] == exact_signer
            primary_metadata, _ = operation(alice, 3, plaintext, [afp])
            assert primary_metadata["signer_fingerprint"] == afp
            checks["exact_signing_subkey_binding_ignores_other_capable_signers"] = True

            if os.environ.get("OSMAP_CRYPTO_RUST_TEST_BINARY"):
                rust_environment = dict(environment,
                                        OSMAP_CRYPTO_NATIVE_WORKER=str(worker),
                                        OSMAP_CRYPTO_NATIVE_ENGINE=str(engine),
                                        OSMAP_CRYPTO_NATIVE_ALICE_HOME=str(alice),
                                        OSMAP_CRYPTO_NATIVE_BOB_HOME=str(bob),
                                        OSMAP_CRYPTO_NATIVE_ALICE_FP=afp,
                                        OSMAP_CRYPTO_NATIVE_BOB_FP=bfp)
                # The separate principal qualification has its own environment
                # and must not be accidentally selected by this fixture filter.
                for test_name in ["openpgp_crypto_runtime::tests::native_crypto_authenticated_service_client", "pgp_mime::native_tests::native_crypto_mime_roundtrip"]:
                    result = subprocess.run([os.environ["OSMAP_CRYPTO_RUST_TEST_BINARY"], test_name, "--exact", "--ignored", "--test-threads=1", "--nocapture"],
                                            env=rust_environment, timeout=120, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    print(result.stdout.decode(), flush=True)
                    assert result.returncode == 0, "native Rust service/MIME integration refused"
                checks["native_rust_service_and_mime_integration"] = True

            run(["/usr/local/bin/gpgconf", "--homedir", str(locked), "--kill", "gpg-agent"])
            operation(locked, 3, plaintext, [lfp], expected=False)
            checks["absent_agent_refused_without_autostart"] = True
            # Start an empty-cache agent without exposing a passphrase to the worker.
            gpg(locked, ["--list-secret-keys"])
            operation(locked, 3, plaintext, [lfp], expected=False)
            checks["locked_agent_refused_without_prompt"] = True
            operation(bob, 2, plaintext, signature=b"malformed", expected=False)
            checks["malformed_detached_signature_refused"] = True

            # Adding a second weak capable subkey cannot trigger GnuPG preference
            # selection after a strong candidate has passed preflight.
            gpg(weak, ["--quick-generate-key", "Synthetic Weak <weak@fixture.test>", "rsa3072", "cert,sign", "0"])
            wfp = fingerprint(weak)
            gpg(weak, ["--quick-add-key", wfp, "rsa3072", "encrypt", "0"])
            gpg(weak, ["--quick-add-key", wfp, "rsa2048", "encrypt", "0"])
            operation(weak, 4, plaintext, [wfp], expected=False)
            checks["multiple_and_weak_capable_subkeys_refused"] = True

            weak_primary = home("weak-primary")
            gpg(weak_primary, ["--quick-generate-key", "Synthetic Weak Primary <weak-primary@fixture.test>", "rsa1024", "cert", "0"])
            wpfp = fingerprint(weak_primary)
            gpg(weak_primary, ["--quick-add-key", wpfp, "rsa3072", "sign", "0"])
            gpg(weak_primary, ["--quick-add-key", wpfp, "rsa3072", "encrypt", "0"])
            key_rows = gpg(weak_primary, ["--with-colons", "--list-keys"]).decode().splitlines()
            strong_signer = next(key_rows[i + 1].split(":")[9] for i, row in enumerate(key_rows) if row.startswith("sub:") and "s" in row.split(":")[11])
            raw_signature = gpg(weak_primary, ["--local-user", strong_signer + "!", "--digest-algo", "SHA256", "--armor", "--detach-sign"], plaintext)
            signature_file = root / "weak-primary-signature.asc"
            signature_file.write_bytes(raw_signature)
            gpg(weak_primary, ["--verify", str(signature_file), "-"], plaintext)
            operation(weak_primary, 3, plaintext, [strong_signer], expected=False)
            operation(weak_primary, 2, plaintext, signature=raw_signature, expected=False)
            operation(weak_primary, 4, plaintext, [wpfp], expected=False)
            raw_ciphertext = gpg(weak_primary, ["--trust-model", "always", "--cipher-algo", "AES256", "--recipient", wpfp, "--encrypt"], plaintext)
            assert gpg(weak_primary, ["--decrypt"], raw_ciphertext) == plaintext
            operation(weak_primary, 1, raw_ciphertext, [wpfp], expected=False)
            checks["weak_primary_with_strong_signing_encryption_subkeys_refused"] = True

            incompatible = home("incompatible-curve")
            gpg(incompatible, ["--quick-generate-key", "Synthetic Curve <curve@fixture.test>", "nistp256", "cert,sign", "0"])
            ifp = fingerprint(incompatible)
            operation(incompatible, 3, plaintext, [ifp], expected=False)
            checks["unqualified_curve_refused"] = True
            expired = home("expired")
            gpg(expired, ["--faked-system-time", "20000101T000000", "--quick-generate-key", "Synthetic Expired <expired@fixture.test>", "ed25519", "cert,sign", "1d"])
            efp = fingerprint(expired)
            operation(expired, 3, plaintext, [efp], expected=False)
            checks["expired_key_refused"] = True
            revoked = home("revoked")
            gpg(revoked, ["--quick-generate-key", "Synthetic Revoked <revoked@fixture.test>", "ed25519", "cert,sign", "0"])
            rfp = fingerprint(revoked)
            revocation = (revoked / "openpgp-revocs.d" / (rfp + ".rev")).read_bytes()
            revocation = revocation[revocation.index(b":-----BEGIN PGP PUBLIC KEY BLOCK-----"):].replace(b":-----BEGIN", b"-----BEGIN", 1)
            gpg(revoked, ["--import"], revocation)
            operation(revoked, 3, plaintext, [rfp], expected=False)
            checks["revoked_key_refused"] = True

            outside = root / "outsider"
            outside.write_text("synthetic outside confinement")
            # Test mode is a separately compiled probe invoking the exact worker
            # path validation/confinement implementation, not a stub.
            probe_source = root / "probe.c"
            probe_source.write_text('#define main crypto_worker_main\n#include "' + str((source / "crypto.c").resolve()) + '"\n#undef main\n#include <fcntl.h>\n#include <sys/wait.h>\nstatic int child(char **argv){pid_t p=fork();if(p<0)return -1;if(!p){char *args[]={argv[2],"--homedir",argv[1],"--no-default-keyring","--keyring",argv[5],"--list-keys",0};execv(argv[2],args);_exit(99);}int status;if(waitpid(p,&status,0)!=p||!WIFEXITED(status)||WEXITSTATUS(status)==99)return -1;return WEXITSTATUS(status);}\nint main(int argc,char **argv){status_callback(0,"DECRYPTION_INFO","0 9 0");if(cipher_ok)return 7;cipher_seen=0;status_callback(0,"DECRYPTION_INFO","0 9 3");if(cipher_ok)return 8;cipher_seen=0;status_callback(0,"DECRYPTION_INFO","2 9 0 1");if(cipher_ok)return 9;status_failed=0;status_callback(0,"VALIDSIG","fingerprint date 1 0 4 0 1 8 00");if(status_failed)return 10;valid_signature_seen=0;status_callback(0,"VALIDSIG","fingerprint date 1 0 4 0 1 10 00");if(status_failed)return 11;valid_signature_seen=0;status_callback(0,"VALIDSIG","fingerprint date 1 0 6 0 1 8 00");if(!status_failed)return 12;valid_signature_seen=0;status_failed=0;status_callback(0,"VALIDSIG","fingerprint date 1 0 4 0 1 2 00");if(!status_failed)return 13;if(argc!=6||!trusted_paths(argv[1],argv[2])||child(argv)!=0||!confine(argv[1],argv[2],1))return 1;if(open(argv[3],O_RDONLY)>=0)return 2;if(open(argv[4],O_RDONLY)>=0)return 3;return child(argv)>0?0:4;}\n')
            probe = root / "probe"
            result = run(["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-I/usr/local/include", str(probe_source), "-L/usr/local/lib", "-lgpgme", "-lgpg-error", "-o", str(probe)])
            assert result.returncode == 0
            private_key = next((alice / "private-keys-v1.d").glob("*.key"))
            result = run([str(probe), str(alice), str(engine), str(outside), str(private_key), str(bob / "pubring.kbx")])
            assert result.returncode == 0
            checks["outside_private_key_and_other_account_keyring_denied_in_worker_and_engine_child"] = True
            checks["missing_integrity_unknown_aead_and_cipher_compliance_status_refused"] = True
            checks["v4_sha256_sha512_status_only_unsupported_signature_packet_version_refused"] = True
            print(json.dumps({"checks": checks, "all_passed": all(checks.values())}, sort_keys=True), flush=True)
        finally:
            for path in homes:
                run(["/usr/local/bin/gpgconf", "--homedir", str(path), "--kill", "gpg-agent"])
    print("disposable_agents_stopped=PASS scratch_cleanup=PASS", flush=True)


if __name__ == "__main__":
    main()
