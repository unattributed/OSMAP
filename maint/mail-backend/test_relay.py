#!/usr/bin/env python3
"""Focused protocol/authority controls for the Unix-to-SSH byte relay."""

import importlib.util
import base64
import hashlib
import hmac
import json
import os
import signal
import time
import pathlib
import pwd
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from argparse import Namespace


SOURCE = pathlib.Path(__file__).with_name("relay.py")
SPEC = importlib.util.spec_from_file_location("osmap_mail_backend_relay", SOURCE)
relay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relay)


def _accept_owned_child(listener, child_work, absolute):
    """Test-only fork lifetime; reserve cleanup inside one original deadline.

    PID ownership is established here and never supplied by a caller. Nondefault
    SIGCHLD refuses before fork. No signal follows direct-child reap, and no
    fresh cleanup deadline or broad group signal is used.
    """
    if signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL:
        raise RuntimeError("native peer reap ownership unavailable")
    if absolute-time.monotonic()<=.1:
        raise TimeoutError("native peer deadline unavailable")
    pid=os.fork()
    if pid==0:
        try:
            listener.close()
            child_work()
            os._exit(0)
        except BaseException:
            os._exit(1)
    reaped=False;accepted=None
    def left():
        remaining=absolute-time.monotonic()-.1
        if remaining<=0:raise TimeoutError("native peer operation expired")
        return remaining
    try:
        listener.settimeout(min(2,left()))
        accepted,_=listener.accept()
        while True:
            left()
            done,status=os.waitpid(pid,os.WNOHANG)
            if done==pid:
                reaped=True
                if os.waitstatus_to_exitcode(status)!=0:
                    raise RuntimeError("native peer child failed")
                left()
                result=accepted;accepted=None
                return result,status
            time.sleep(min(.005,left()))
    finally:
        if accepted is not None:accepted.close()
        if not reaped:
            done,_=os.waitpid(pid,os.WNOHANG)
            if done==pid:reaped=True
            else:
                # The direct child remains unreaped, so this numeric PID still
                # belongs to this exact fork. Never target an inherited group.
                try:os.kill(pid,signal.SIGKILL)
                except ProcessLookupError:pass
                while time.monotonic()<absolute:
                    done,_=os.waitpid(pid,os.WNOHANG)
                    if done==pid:
                        reaped=True;break
                    time.sleep(min(.005,max(0,absolute-time.monotonic())))
                if not reaped:raise RuntimeError("native peer child cleanup unconfirmed")


class RelayTests(unittest.TestCase):
    @staticmethod
    def document_request(action="read"):
        payload = {
            "account": "alice@example.test",
            "operation": {"action": action, "id": "a" * 32, "location": {
                "mailbox": "OSMAP.Documents", "uid": 7,
                "mailbox_guid": "b" * 32, "message_guid": "c" * 32,
            }},
            "issued_at": 100, "expires_at": 160, "nonce": "d" * 32,
        }
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        signature = hmac.new(b"synthetic-documents-relay-fixture-key", relay.DOCUMENTS_PREFIX + encoded, hashlib.sha256).hexdigest()
        return relay.DOCUMENTS_PREFIX + json.dumps({"payload": payload, "signature": signature}, separators=(",", ":")).encode()

    def pump_document(self, request, output_program, *, documents=True, fragments=False):
        client, server = socket.socketpair()
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; data=sys.stdin.buffer.read();\n" + output_program],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        errors = []
        def work():
            try:
                # Local tests inject peer facts; production uses native getpeereid.
                relay.authorize_peer(server, 1001, lambda _: (1001, 1001))
                relay.pump(server, child, *relay.PURPOSE_LIMITS["mailbox"], documents=documents)
            except (OSError, relay.RelayError) as error:
                errors.append(error)
            finally:
                server.close()
        worker = threading.Thread(target=work)
        worker.start()
        output = bytearray()
        try:
            if fragments:
                for offset in range(0, len(request), 7):
                    client.sendall(request[offset:offset + 7])
            else:
                client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            while True:
                try:
                    chunk = client.recv(65536)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
            worker.join(timeout=22)
            self.assertFalse(worker.is_alive())
        finally:
            client.close()
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=2)
            if child.stdin and not child.stdin.closed:
                child.stdin.close()
            child.stdout.close()
        return bytes(output), errors

    def test_documents_classifier_is_closed_and_read_only(self):
        request = self.document_request()
        self.assertTrue(relay.documents_read_request(request))
        malformed = json.loads(request[len(relay.DOCUMENTS_PREFIX):])
        malformed["payload"]["operation"]["location"]["uid"] = True
        bad_uid = relay.DOCUMENTS_PREFIX + json.dumps(malformed).encode()
        for invalid in [
            b"operation=message_view\n", request + b"\noperation=message_view\n",
            request.replace(b'"action":"read"', b'"action":"append"'),
            request.replace(b'"action":"read"', b'"action":"read","action":"read"'),
            request.replace(b'"OSMAP.Documents"', b'"INBOX"'), bad_uid,
            request.replace(b'"location":{', b'"unknown":true,"location":{'),
            request + b" " * relay.DOCUMENTS_READ_REQUEST_LIMIT,
        ]:
            self.assertFalse(relay.documents_read_request(invalid), invalid[:32])
        self.assertEqual(relay.PURPOSE_LIMITS["mailbox"], (relay.MAILBOX_REQUEST_LIMIT, 1024 * 1024, 20.0))
        self.assertEqual(relay.DOCUMENTS_RESPONSE_LIMIT, 13989208)

    def test_exact_ten_mib_binary_document_through_actual_relay_pump(self):
        program = """
import base64,hashlib,hmac,json
assert data.startswith(b'documents-v1\\n')
request=json.loads(data[len(b'documents-v1\\n'):])
payload=json.dumps(request['payload'],separators=(',',':')).encode()
assert hmac.compare_digest(request['signature'],hmac.new(b'synthetic-documents-relay-fixture-key',b'documents-v1\\n'+payload,hashlib.sha256).hexdigest())
assert request['payload']['operation']['action']=='read'
body=bytes(range(256))*40960
response={'request_hash':hashlib.sha256(payload).hexdigest(),'nonce':request['payload']['nonce'],'outcome':{'result':'body','body_b64':base64.b64encode(body).decode(),'size':len(body),'sha256':hashlib.sha256(body).hexdigest()}}
sys.stdout.buffer.write(json.dumps(response,separators=(',',':')).encode());sys.stdout.buffer.flush()
"""
        request = self.document_request()
        output, errors = self.pump_document(request, program, fragments=True)
        self.assertFalse(errors, errors)
        self.assertGreater(len(output), 1024 * 1024)
        self.assertLessEqual(len(output), relay.DOCUMENTS_RESPONSE_LIMIT)
        response = json.loads(output)
        body = base64.b64decode(response["outcome"]["body_b64"], validate=True)
        self.assertEqual(len(body), 10 * 1024 * 1024)
        self.assertEqual(body, bytes(range(256)) * 40960)
        self.assertEqual(hashlib.sha256(body).hexdigest(), response["outcome"]["sha256"])

    def test_ordinary_append_mixed_duplicate_and_auth_cannot_get_documents_response_cap(self):
        request = self.document_request()
        for data, enabled in [
            (b"operation=message_view\n", True),
            (self.document_request("append"), True),
            (request + b"\noperation=message_view\n", True),
            (request.replace(b'"action":"read"', b'"action":"read","action":"read"'), True),
            (request, False),
        ]:
            with self.subTest(data=data[:32], enabled=enabled):
                _, errors = self.pump_document(data, "sys.stdout.buffer.write(b'x'*(1024*1024+1));sys.stdout.buffer.flush()", documents=enabled)
                self.assertTrue(any("response byte limit" in str(error) for error in errors), errors)

    def test_documents_response_cap_is_finite(self):
        _, errors = self.pump_document(self.document_request(), f"sys.stdout.buffer.write(b'x'*{relay.DOCUMENTS_RESPONSE_LIMIT + 1});sys.stdout.buffer.flush()")
        self.assertTrue(any("response byte limit" in str(error) for error in errors), errors)

    def test_ssh_argv_is_static_and_purpose_scoped(self):
        values = {
            "identity": pathlib.Path("/private/mailbox.key"),
            "known_hosts": pathlib.Path("/private/known_hosts"),
            "control_path": pathlib.Path("/private/mailbox-control.sock"),
            "remote_host": "155.138.144.113",
        }
        command = relay.ssh_argv(Namespace(**values))
        self.assertEqual(command[0], "/usr/bin/ssh")
        self.assertEqual(command[-2:], ["_osmap@155.138.144.113", "osmap-relay"])
        self.assertIn("ControlPath=/private/mailbox-control.sock", command)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("ClearAllForwardings=yes", command)
        self.assertIn("PasswordAuthentication=no", command)
        self.assertIn("IdentityAgent=none", command)
        self.assertNotIn("-L", command)
        self.assertNotIn("-R", command)

    def test_peer_uid_is_mandatory_before_ssh(self):
        local, remote = socket.socketpair()
        try:
            relay.authorize_peer(local, 1001, lambda _sock: (1001, 1001))
            with self.assertRaisesRegex(relay.RelayError, "not authorized"):
                relay.authorize_peer(local, 1001, lambda _sock: (1002, 1001))
        finally:
            local.close()
            remote.close()

    def test_full_duplex_half_close_preserves_binary_payload(self):
        client, server = socket.socketpair()
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; data=sys.stdin.buffer.read(); "
             "sys.stdout.buffer.write(data[::-1]); sys.stdout.buffer.flush()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        errors = []

        def work():
            try:
                relay.pump(server, child, 2 * 1024 * 1024, 2 * 1024 * 1024, 5)
            except Exception as error:
                errors.append(error)
            finally:
                server.close()

        thread = threading.Thread(target=work)
        thread.start()
        payload = (bytes(range(256)) * 4096) + b"\x00\xff\x00"
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        output = bytearray()
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            output.extend(chunk)
        thread.join(timeout=7)
        client.close()
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors, errors)
        self.assertEqual(bytes(output), payload[::-1])
        self.assertEqual(child.wait(timeout=2), 0)
        child.stdout.close()

    def test_request_cap_refuses_oversized_input(self):
        client, server = socket.socketpair()
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        try:
            client.sendall(b"12345")
            client.shutdown(socket.SHUT_WR)
            with self.assertRaisesRegex(relay.RelayError, "request byte limit"):
                relay.pump(server, child, 4, 100, 3)
        finally:
            client.close()
            server.close()
            child.terminate()
            child.wait(timeout=2)
            child.stdin.close()
            child.stdout.close()

    def test_response_cap_refuses_oversized_remote_output(self):
        client, server = socket.socketpair()
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.buffer.read(); "
             "sys.stdout.buffer.write(b'abcde'); sys.stdout.buffer.flush()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        try:
            client.shutdown(socket.SHUT_WR)
            with self.assertRaisesRegex(relay.RelayError, "response byte limit"):
                relay.pump(server, child, 100, 4, 3)
        finally:
            client.close()
            server.close()
            child.wait(timeout=2)
            child.stdout.close()

    def test_stale_listener_and_nonprivate_control_dir_refused(self):
        if os.geteuid() == 0:
            self.skipTest("configuration must run as unprivileged bridge owner")
        with tempfile.TemporaryDirectory() as root:
            base = pathlib.Path(root)
            listen_dir = base / "run"
            control_dir = base / "control"
            listen_dir.mkdir(mode=0o750)
            control_dir.mkdir(mode=0o700)
            identity = base / "mailbox"
            identity.write_text("fixture")
            identity.chmod(0o600)
            hosts = base / "known_hosts"
            hosts.write_text("fixture")
            hosts.chmod(0o600)
            config = Namespace(
                purpose="mailbox", listen=str(listen_dir / "mailbox.sock"),
                identity=str(identity), known_hosts=str(hosts),
                control_path=str(control_dir / "mailbox-ssh.sock"),
                remote_host="mail.blackbagsecurity.com", trusted_uid=1001,
            )
            relay.validate_config(config)
            control_dir.chmod(0o750)
            with self.assertRaisesRegex(relay.RelayError, "owner-only"):
                relay.validate_config(config)
            control_dir.chmod(0o700)
            config.listen.touch()
            with self.assertRaisesRegex(relay.RelayError, "already exists"):
                relay.validate_config(config)

    def test_cross_purpose_ssh_material_is_refused(self):
        if os.geteuid() == 0:
            self.skipTest("configuration must run as unprivileged bridge owner")
        with tempfile.TemporaryDirectory() as root:
            base = pathlib.Path(root)
            run_dir = base / "run"
            control_dir = base / "control"
            run_dir.mkdir(mode=0o750)
            control_dir.mkdir(mode=0o700)
            identity = base / "auth"
            identity.write_text("fixture")
            identity.chmod(0o600)
            hosts = base / "known_hosts"
            hosts.write_text("fixture")
            hosts.chmod(0o600)
            config = Namespace(
                purpose="auth", listen=str(run_dir / "auth.sock"),
                identity=str(identity), known_hosts=str(hosts),
                control_path=str(control_dir / "mailbox-ssh.sock"),
                remote_host="mail.blackbagsecurity.com", trusted_uid=1001,
            )
            with self.assertRaisesRegex(relay.RelayError, "match relay purpose"):
                relay.validate_config(config)

    @unittest.skipUnless(sys.platform.startswith("openbsd"), "native getpeereid is OpenBSD-only")
    def test_native_getpeereid_positive_and_different_uid_negative(self):
        if os.geteuid() != 0:
            self.skipTest("cross-principal native control requires root")
        import signal
        import time
        self.assertEqual(signal.getsignal(signal.SIGCHLD), signal.SIG_DFL)
        other = pwd.getpwnam("_osmap")
        self.assertNotEqual(other.pw_uid, os.geteuid())
        absolute = time.monotonic() + 10
        def left(cap):
            remaining = min(cap, absolute - time.monotonic() - .1)
            self.assertGreater(remaining, 0)
            return remaining
        # The socket fixture is separate from the private root-owned code stage;
        # only this explicitly created path admits the different UID traversal.
        with tempfile.TemporaryDirectory(prefix="osmap-relay-peer-", dir="/tmp") as root:
            os.chmod(root, 0o711)
            path = str(pathlib.Path(root) / "peer.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            accepted = None
            listener.bind(path)
            os.chmod(path, 0o777)
            listener.listen(2)
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as positive:
                    positive.settimeout(left(2))
                    positive.connect(path)
                    listener.settimeout(left(2))
                    accepted, _ = listener.accept()
                    relay.authorize_peer(accepted, 0)
                    self.assertEqual(relay.peer_ids(accepted)[0], 0)
                    accepted.close(); accepted = None
                def negative_child():
                    os.setgroups([])
                    os.setgid(other.pw_gid)
                    os.setuid(other.pw_uid)
                    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as negative:
                        negative.settimeout(left(2))
                        negative.connect(path)
                accepted,status=_accept_owned_child(listener,negative_child,absolute)
                self.assertEqual(relay.peer_ids(accepted)[0],other.pw_uid)
                with self.assertRaisesRegex(relay.RelayError,"not authorized"):
                    relay.authorize_peer(accepted,0)
                self.assertEqual(os.waitstatus_to_exitcode(status),0)
                accepted.close();accepted=None

            finally:
                if accepted is not None:
                    accepted.close()
                listener.close()



@unittest.skipUnless(sys.platform.startswith("openbsd"), "two-host Documents relay qualification is OpenBSD-only")
class NativeDocumentsRelayTests(unittest.TestCase):
    """Opt-in root-owned private fixture; no standard SSH or mail endpoint.

    Root prepares loopback-only standalone SSHD/forced connector and two
    bounded operator forwards. The latter add workstation transit, so this
    measures the fixture transport rather than production TCP topology.
    The primary Documents fixture supplies actual Dovecot bytes and GUIDs.
    """

    def load_fixture(self):
        filename = os.environ.get("OSMAP_DOCUMENTS_NATIVE_RELAY_CONFIG")
        if not filename:
            self.skipTest("explicit private two-host fixture configuration required")
        self.assertEqual(os.geteuid(), 0, "native fixture executor must be root")
        path = pathlib.Path(filename)
        metadata = path.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(metadata.st_uid, 0)
        self.assertEqual(metadata.st_mode & 0o077, 0)
        self.assertEqual(path.resolve(), path)
        self.assertLessEqual(metadata.st_size, 8192)
        config = json.loads(path.read_bytes(), object_pairs_hook=relay._closed_object)
        self.assertEqual(set(config), {"fixture_root", "remote_fixture_root", "loopback_port", "identity", "known_hosts", "control_path", "grant_key", "account", "document_id", "location"})
        root = pathlib.Path(config["fixture_root"])
        self.assertRegex(str(root), r"^/tmp/osmap-s08-documents-[A-Za-z0-9_-]+$")
        self.assertEqual(root.resolve(), root)
        root_stat = root.lstat()
        self.assertTrue(stat.S_ISDIR(root_stat.st_mode))
        self.assertEqual(root_stat.st_uid, 0)
        self.assertEqual(root_stat.st_mode & 0o077, 0)
        self.assertEqual(path.parent, root)
        self.assertRegex(config["remote_fixture_root"], r"^/tmp/osmap-s08-documents-[A-Za-z0-9_-]+$")
        for name in ("identity", "known_hosts", "grant_key"):
            owned = pathlib.Path(config[name])
            self.assertEqual(owned.parent, root)
            self.assertEqual(owned.resolve(), owned)
            relay._regular_file(owned, private=True)
            self.assertEqual(owned.lstat().st_uid, 0)
        self.assertEqual(pathlib.Path(config["identity"]).name, "mailbox")
        self.assertEqual(pathlib.Path(config["control_path"]), root / "mailbox-ssh.sock")
        self.assertFalse(os.path.lexists(config["control_path"]), "fixture starts without an inherited SSH master")
        self.assertIs(type(config["loopback_port"]), int)
        self.assertTrue(1024 <= config["loopback_port"] <= 65535)
        self.assertRegex(config["account"], r"^[A-Za-z0-9_.+@-]+\.test$")
        self.assertRegex(config["document_id"], r"^[0-9a-f]{32}$")
        self.assertGreaterEqual(pathlib.Path(config["grant_key"]).stat().st_size, 32)
        self.assertLessEqual(pathlib.Path(config["grant_key"]).stat().st_size, 128)
        return config

    @staticmethod
    def fixture_ssh_argv(config):
        namespace = Namespace(identity=pathlib.Path(config["identity"]), known_hosts=pathlib.Path(config["known_hosts"]), control_path=pathlib.Path(config["control_path"]), remote_host="127.0.0.1")
        command = relay.ssh_argv(namespace)
        # These two test-only selectors target the standalone fixture SSHD;
        # production relay.ssh_argv and its fixed account/port stay unchanged.
        command[-2:] = ["-p", str(config["loopback_port"]), "root@127.0.0.1", "osmap-relay"]
        return command

    def exchange(self, config, wire, absolute, request_deadline):
        client, server = socket.socketpair()
        child = None
        worker = None
        errors = []
        def work():
            try:
                relay.pump(server, child, *relay.PURPOSE_LIMITS["mailbox"], documents=True)
            except (OSError, relay.RelayError) as error:
                errors.append(error)
            finally:
                server.close()
        output = bytearray()
        # Match the current Rust Documents client's one original five-second
        # budget; a failure is retained, never retried with a fresh allowance.
        def left():
            remaining = request_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("native Documents original request budget expired")
            return remaining
        try:
            relay.authorize_peer(server, 0)  # Native kernel getpeereid, no injection.
            self.assertEqual(relay.peer_ids(server)[0], 0)
            left()
            child = subprocess.Popen(self.fixture_ssh_argv(config), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
            worker = threading.Thread(target=work)
            worker.start()
            client.settimeout(left()); client.sendall(wire); client.shutdown(socket.SHUT_WR)
            while True:
                client.settimeout(left())
                chunk = client.recv(65536)
                if not chunk:
                    break
                self.assertLessEqual(len(output) + len(chunk), relay.DOCUMENTS_RESPONSE_LIMIT)
                output.extend(chunk)
            left()
            self.assertFalse(errors, errors)
            return bytes(output)
        finally:
            had_failure = sys.exc_info()[0] is not None
            finish_expired = False
            client.close()
            if worker is not None and worker.ident is not None:
                worker.join(timeout=max(0, min(1, request_deadline - time.monotonic(), absolute - time.monotonic() - 3)))
            else:
                server.close()
            if child is not None and child.poll() is None and not had_failure:
                # Clean SSH EOF/exit belongs to the same original request,
                # with no fresh wait allowance after response completion.
                remaining = min(request_deadline, absolute - 3) - time.monotonic()
                if remaining <= 0:
                    finish_expired = True
                else:
                    try:
                        child.wait(timeout=remaining)
                    except subprocess.TimeoutExpired:
                        finish_expired = True
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=max(.01, min(1, absolute - time.monotonic() - 2)))
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait(timeout=1)
            if worker is not None and worker.ident is not None:
                worker.join(timeout=1)
                self.assertFalse(worker.is_alive(), "owned relay worker cleanup was not confirmed")
            if child is not None:
                if child.stdin and not child.stdin.closed:
                    child.stdin.close()
                child.stdout.close()
            if not had_failure:
                self.assertFalse(errors, errors)
                finish_expired = finish_expired or time.monotonic() >= request_deadline
                self.assertFalse(finish_expired, "SSH clean exit exceeded the original Documents request budget")
                self.assertEqual(child.returncode, 0, "SSH transport exited nonzero after response")

    def test_native_two_host_private_ssh_helper_exact_ten_mib_and_replay(self):
        config = self.load_fixture()
        began = time.monotonic(); absolute = began + 25
        issued = int(time.time())
        location = {name: config["location"][name] for name in ("mailbox", "uid", "mailbox_guid", "message_guid")}
        payload = {"account": config["account"], "operation": {"action": "read", "id": config["document_id"], "location": location}, "issued_at": issued, "expires_at": issued + 60, "nonce": os.urandom(16).hex()}
        canonical = json.dumps(payload, separators=(",", ":")).encode()
        key = pathlib.Path(config["grant_key"]).read_bytes().rstrip(b"\r\n")
        signature = hmac.new(key, relay.DOCUMENTS_PREFIX + canonical, hashlib.sha256).hexdigest()
        wire = relay.DOCUMENTS_PREFIX + json.dumps({"payload": payload, "signature": signature}, separators=(",", ":")).encode()
        self.assertTrue(relay.documents_read_request(wire))
        read_confirmed = False
        replay_refused = False
        read_elapsed = None
        body_digest = None
        try:
            response = json.loads(self.exchange(config, wire, absolute, began + 5))
            self.assertEqual(response["request_hash"], hashlib.sha256(canonical).hexdigest())
            self.assertEqual(response["nonce"], payload["nonce"])
            outcome = response["outcome"]
            self.assertEqual(outcome["result"], "body")
            self.assertEqual(outcome["size"], 10 * 1024 * 1024)
            body = base64.b64decode(outcome["body_b64"], validate=True)
            expected = bytes(range(256)) * 40960
            self.assertEqual(body, expected)
            body_digest = hashlib.sha256(expected).hexdigest()
            self.assertEqual(outcome["sha256"], body_digest)
            read_elapsed = time.monotonic() - began
            self.assertLess(read_elapsed, 5, "original whole Documents request budget exceeded")
            read_confirmed = True
            replay = json.loads(self.exchange(config, wire, absolute, min(absolute - 5, time.monotonic() + 5)))
            self.assertEqual(replay["request_hash"], response["request_hash"])
            self.assertEqual(replay["nonce"], payload["nonce"])
            self.assertEqual(replay["outcome"], {"result": "failure", "kind": "invalid"})
            replay_refused = True
            self.assertLess(time.monotonic(), absolute - 3)
        finally:
            print(json.dumps({"ten_mib_confirmed": read_confirmed, "confirmed_bytes": 10485760 if read_confirmed else None, "sha256": body_digest, "replay_refused": replay_refused, "client_budget_seconds": 5, "relay_budget_seconds": 20, "read_elapsed_seconds": None if read_elapsed is None else round(read_elapsed, 3), "elapsed_seconds": round(time.monotonic() - began, 3), "routing": "projected loopback via workstation operator forwards; not production TCP topology"}))
            control = pathlib.Path(config["control_path"])
            if control.exists():
                # Only this newly created private fixture master; no standard
                # relay/control socket or inherited numeric PID is touched.
                subprocess.run(["/usr/bin/ssh", "-F", "/dev/null", "-S", str(control), "-O", "exit", "-p", str(config["loopback_port"]), "root@127.0.0.1"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=max(.01, min(2, absolute - time.monotonic())), check=True)
            self.assertFalse(os.path.lexists(control), "private SSH master cleanup not confirmed")


class NativeFixtureLifecycleTests(unittest.TestCase):
    def test_expired_request_budget_does_not_spawn_and_closes_both_sockets(self):
        from unittest.mock import patch
        pair = socket.socketpair()
        native = NativeDocumentsRelayTests()
        with patch.object(socket, "socketpair", return_value=pair), patch.object(relay, "authorize_peer"), patch.object(relay, "peer_ids", return_value=(0, 0)), patch.object(subprocess, "Popen", side_effect=AssertionError("must not spawn")):
            with self.assertRaises(TimeoutError):
                native.exchange({}, b"fixture", time.monotonic() + 1, time.monotonic() - 1)
        self.assertEqual([stream.fileno() for stream in pair], [-1, -1])

    def response_then_exit(self, status):
        from unittest.mock import patch
        command = [sys.executable, "-c", "import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'fixture'); sys.stdout.buffer.flush(); sys.exit(" + str(status) + ")"]
        native = NativeDocumentsRelayTests()
        began = time.monotonic()
        with patch.object(relay, "authorize_peer"), patch.object(relay, "peer_ids", return_value=(0, 0)), patch.object(NativeDocumentsRelayTests, "fixture_ssh_argv", return_value=command):
            # The request keeps its original one-second budget. The fixture's
            # absolute lifetime also includes exchange's three-second cleanup reserve.
            return native.exchange({}, b"fixture", began + 4, began + 1)

    def test_complete_response_followed_by_nonzero_child_exit_is_refused(self):
        with self.assertRaisesRegex(AssertionError, "SSH transport exited nonzero"):
            self.response_then_exit(7)

    def test_complete_response_and_clean_child_exit_are_confirmed(self):
        self.assertEqual(self.response_then_exit(0), b"fixture")

    def test_response_then_hanging_child_uses_original_budget_and_reaps_owner(self):
        from unittest.mock import patch
        command = [sys.executable, "-c", "import os, sys, time; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'fixture'); sys.stdout.buffer.flush(); os.close(1); time.sleep(2)"]
        actual_popen = subprocess.Popen
        owned = []
        def spawn(*args, **kwargs):
            child = actual_popen(*args, **kwargs)
            owned.append(child)
            return child
        native = NativeDocumentsRelayTests()
        began = time.monotonic()
        with patch.object(relay, "authorize_peer"), patch.object(relay, "peer_ids", return_value=(0, 0)), patch.object(NativeDocumentsRelayTests, "fixture_ssh_argv", return_value=command), patch.object(subprocess, "Popen", side_effect=spawn):
            with self.assertRaisesRegex(AssertionError, "SSH clean exit exceeded"):
                native.exchange({}, b"fixture", began + 3, began + .15)
        self.assertLess(time.monotonic() - began, .5)
        self.assertEqual(len(owned), 1)
        self.assertIsNotNone(owned[0].poll())
        with self.assertRaises(ChildProcessError):
            os.waitpid(owned[0].pid, os.WNOHANG)

    def test_spawn_failure_closes_both_sockets_without_process_signal(self):
        from unittest.mock import patch
        pair = socket.socketpair()
        native = NativeDocumentsRelayTests()
        config = {"identity": "/fixture/mailbox", "known_hosts": "/fixture/known_hosts", "control_path": "/fixture/mailbox-ssh.sock", "loopback_port": 41008}
        with patch.object(socket, "socketpair", return_value=pair), patch.object(relay, "authorize_peer"), patch.object(relay, "peer_ids", return_value=(0, 0)), patch.object(subprocess, "Popen", side_effect=OSError("synthetic spawn failure")), patch.object(os, "kill", side_effect=AssertionError("no owned process")):
            with self.assertRaisesRegex(OSError, "synthetic spawn failure"):
                native.exchange(config, b"fixture", time.monotonic() + 1, time.monotonic() + .5)
        self.assertEqual([stream.fileno() for stream in pair], [-1, -1])


class OwnedPeerBoundsTests(unittest.TestCase):
    def exchange(self,mode):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            path=str(pathlib.Path(directory)/'peer.sock')
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(path);listener.listen(1)
            child_pid=[];signals=[]
            actual_fork=os.fork;actual_kill=os.kill
            def fork():
                pid=actual_fork()
                if pid>0:child_pid.append(pid)
                return pid
            def kill(pid,sig):
                signals.append((pid,sig));return actual_kill(pid,sig)
            def child():
                if mode=='failed':raise RuntimeError('public preconnect failure')
                if mode=='hang':time.sleep(2);return
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:peer.connect(path)
            began=time.monotonic();accepted=None
            try:
                with patch.object(os,'fork',side_effect=fork),patch.object(os,'kill',side_effect=kill):
                    if mode=='positive':accepted,_=_accept_owned_child(listener,child,began+.35)
                    else:
                        with self.assertRaises(TimeoutError):_accept_owned_child(listener,child,began+.35)
                self.assertLess(time.monotonic()-began,.55)
                self.assertEqual(len(child_pid),1)
                with self.assertRaises(ChildProcessError):os.waitpid(child_pid[0],os.WNOHANG)
                return signals,child_pid[0]
            finally:
                if accepted is not None:accepted.close()
                listener.close()
    def test_actual_child_failure_before_connect_is_finite_and_reaped_without_stale_signal(self):
        signals,_=self.exchange('failed');self.assertEqual(signals,[])
    def test_actual_child_hang_before_connect_kills_only_unreaped_owner_inside_original_deadline(self):
        signals,pid=self.exchange('hang');self.assertEqual(signals,[(pid,signal.SIGKILL)])
    def test_actual_positive_child_connects_and_reaps_without_signal(self):
        signals,_=self.exchange('positive');self.assertEqual(signals,[])
    def test_expired_deadline_and_auto_reap_refuse_before_fork(self):
        from unittest.mock import patch
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            with patch.object(os,'fork',side_effect=AssertionError):
                with self.assertRaises(TimeoutError):_accept_owned_child(listener,lambda:None,time.monotonic())
                with patch.object(signal,'getsignal',return_value=signal.SIG_IGN):
                    with self.assertRaises(RuntimeError):_accept_owned_child(listener,lambda:None,time.monotonic()+1)
        finally:listener.close()


if __name__ == "__main__":
    unittest.main()
