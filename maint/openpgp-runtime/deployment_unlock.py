#!/usr/bin/env python3
"""Interactively warm only the provisioned development Duncan mailbox agent.

Run as root from the operator's real SSH terminal. Pinentry reads that terminal
itself; this script never reads a passphrase. No workstation signing agent is
used. Terminal ownership is restored even after cancellation/failure.
"""
import os
import pathlib
import pwd
import resource
import signal
import socket
import stat
import subprocess
import time

HOME = pathlib.Path("/var/lib/osmap-gpg/accounts/duncan")
PRIMARY = "E401B0FDCA3A712DE8E15BB23DAB198EA2E96BBE"
SIGNER = "83A5689C7C52CE43DB88C8A5322909FC05BF68BB"
CACHE_SECONDS = 300


def require_stopped_helpers(env, run=subprocess.run):
    for service in ("osmap_crypto", "osmap_public_inventory", "osmap_public_admin"):
        result = run(["/usr/sbin/rcctl", "check", service], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     env=env, timeout=15)
        assert result.returncode == 1, "stop OpenPGP helpers before mailbox agent replacement"


def restart_bounded_agent(home, env, demote, run=subprocess.run):
    # An existing socket does not establish the agent's cache policy. Replace
    # the stopped-service account agent rather than reuse an unqualified TTL.
    stopped = run(["/usr/local/bin/gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL, env=env, cwd=home,
                  preexec_fn=demote, timeout=15)
    assert stopped.returncode == 0, "mailbox agent stop refused"
    until = time.monotonic() + 5
    while (home / "S.gpg-agent").exists():
        assert time.monotonic() < until, "mailbox agent socket did not close"
        time.sleep(0.02)
    agent = run(["/usr/local/bin/gpg-agent", "--no-options", "--homedir", str(home),
                 "--pinentry-program", "/usr/local/bin/pinentry-curses",
                 "--default-cache-ttl", str(CACHE_SECONDS),
                 "--max-cache-ttl", str(CACHE_SECONDS), "--no-allow-external-cache", "--daemon"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=env, cwd=home,
                preexec_fn=demote, timeout=15)
    assert agent.returncode == 0, "bounded mailbox agent startup refused"


def main():
    assert os.geteuid() == 0 and socket.gethostname() == "obsd1.blackbagsecurity.com"
    assert os.isatty(0), "use the operator SSH terminal, not a captured tool/log session"
    tty = pathlib.Path(os.ttyname(0))
    original = tty.lstat()
    assert stat.S_ISCHR(original.st_mode) and not tty.is_symlink()
    assert (original.st_dev, original.st_ino) == (os.fstat(0).st_dev, os.fstat(0).st_ino)
    helper = pwd.getpwnam("_osmapgpg")
    assert HOME.resolve() == HOME and HOME.stat().st_uid == helper.pw_uid and HOME.stat().st_mode & 0o777 == 0o700
    for name in ("gpg.conf", "common.conf", "gpg-agent.conf"):
        assert not (HOME / name).exists()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C", "HOME": str(HOME), "GNUPGHOME": str(HOME), "GPG_TTY": str(tty)}
    require_stopped_helpers(env)

    def demote():
        os.initgroups(helper.pw_name, helper.pw_gid)
        os.setgid(helper.pw_gid)
        os.setuid(helper.pw_uid)

    def gpg(arguments, data=None, capture=False):
        result = subprocess.run(["/usr/local/bin/gpg", "--no-options", "--homedir", str(HOME), "--no-autostart"] + arguments,
                                input=data, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                env=env, cwd=HOME, preexec_fn=demote, timeout=300)
        assert result.returncode == 0, "mailbox key operation refused"
        return result.stdout

    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)

    handlers = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGHUP)}
    try:
        for signum in handlers:
            signal.signal(signum, interrupted)
        # Grant only this tty to this temporary interactive helper operation.
        os.fchown(0, helper.pw_uid, helper.pw_gid)
        os.fchmod(0, 0o600)
        restart_bounded_agent(HOME, env, demote)
        listed = gpg(["--batch", "--with-colons", "--list-secret-keys", PRIMARY], capture=True).decode()
        fingerprints = [line.split(":")[9] for line in listed.splitlines() if line.startswith("fpr:")]
        assert PRIMARY in fingerprints and SIGNER in fingerprints, "matching mailbox secret key has not been imported"
        gpg(["--local-user", SIGNER + "!", "--digest-algo", "SHA256", "--detach-sign", "--output", "/dev/null", "/dev/null"])
        ciphertext = gpg(["--batch", "--trust-model", "always", "--cipher-algo", "AES256", "--recipient", PRIMARY, "--encrypt"], b"Disposable mailbox unlock check.\n", capture=True)
        assert len(ciphertext) < 65536
        gpg(["--output", "/dev/null", "--decrypt"], ciphertext)
        print("mailbox_signing_and_decryption_agent_warmed=PASS")
    finally:
        os.fchown(0, original.st_uid, original.st_gid)
        os.fchmod(0, stat.S_IMODE(original.st_mode))
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    main()
