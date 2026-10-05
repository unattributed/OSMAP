#!/usr/bin/env python3
"""Focused protocol/authority controls for the Unix-to-SSH byte relay."""

import importlib.util
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
