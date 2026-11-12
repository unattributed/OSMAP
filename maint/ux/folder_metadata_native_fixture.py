#!/usr/bin/env python3
"""Disposable obsd1-only two-account USER-protocol qualification; no live userdb."""
import json, os, pathlib, socket, subprocess, tempfile, threading

TRANSCRIPT = b'N1 NAMESPACE\r\nL1 LIST "" "*" RETURN (CHILDREN SPECIAL-USE)\r\nZ1 LOGOUT\r\n'

def main():
    assert socket.gethostname() == 'obsd1.blackbagsecurity.com'
    assert os.getuid() == 1000
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='osmap-folder-userdb-') as temporary:
        root = pathlib.Path(temporary)
        for name in ('run', 'state', 'alice', 'bob'):
            (root / name).mkdir()
        for user, folder in [('alice', 'AliceOnly'), ('bob', 'BobOnly')]:
            for part in ('cur', 'new', 'tmp'):
                (root / user / 'Maildir' / part).mkdir(parents=True)
                (root / user / 'Maildir' / ('.' + folder) / part).mkdir(parents=True)
        conf = root / 'dovecot.conf'
        conf.write_text(f'''base_dir = {root}/run
state_dir = {root}/state
mail_location = maildir:~/Maildir
mail_uid = {os.getuid()}
mail_gid = {os.getgid()}
first_valid_uid = {os.getuid()}
protocols =
listen = 127.0.0.1
ssl = no
mail_plugins =
stats_writer_socket_path =
auth_socket_path = {root}/userdb
log_path = {root}/native.log
info_log_path = {root}/native.log
namespace inbox {{
 inbox = yes
 separator =
}}
''')
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(root / 'userdb')); listener.listen(4); listener.settimeout(.2)
        stop = threading.Event(); queries = []; errors = []
        def serve():
            while not stop.is_set():
                try: conn, _ = listener.accept()
                except socket.timeout: continue
                with conn:
                    conn.settimeout(3)
                    conn.sendall(f'VERSION\t1\t2\nSPID\t{os.getpid()}\n'.encode())
                    try:
                        stream = conn.makefile('rb')
                        while True:
                            line = stream.readline(4097)
                            if not line: break
                            assert len(line) <= 4096
                            fields = line.decode().rstrip('\n').split('\t')
                            if fields[0] == 'VERSION': continue
                            assert fields[0] == 'USER' and len(fields) >= 4
                            ident, account = fields[1:3]; queries.append(account)
                            assert ident.isdigit()
                            users = {'alice@fixture.test':'alice', 'bob@fixture.test':'bob'}
                            if account not in users: reply = f'NOTFOUND\t{ident}\n'
                            else:
                                reply = f'USER\t{ident}\t{account}\tuid={os.getuid()}\tgid={os.getgid()}\thome={root / users[account]}\n'
                            conn.sendall(reply.encode())
                    except Exception as error: errors.append(type(error).__name__)
        thread = threading.Thread(target=serve); thread.start()
        def run(account, missing=False):
            args = ['/usr/local/bin/doveadm', '-c', str(conf), 'exec', 'imap', '-o', 'stats_writer_socket_path=', '-o', 'auth_socket_path=' + str(root / ('missing' if missing else 'userdb')), '-u', account]
            result = subprocess.run(args, input=TRANSCRIPT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin'})
            assert len(result.stdout) <= 512*1024 and len(result.stderr) <= 512*1024
            return result
        try:
            alice = run('alice@fixture.test'); bob = run('bob@fixture.test')
            unknown = run('unknown@fixture.test'); missing = run('alice@fixture.test', True)
            checks = {'alice_ok':alice.returncode == 0 and b'AliceOnly' in alice.stdout and b'BobOnly' not in alice.stdout,
                      'bob_ok':bob.returncode == 0 and b'BobOnly' in bob.stdout and b'AliceOnly' not in bob.stdout,
                      'unknown_refused':unknown.returncode != 0 and b'* PREAUTH' not in unknown.stdout,
                      'missing_refused':missing.returncode != 0 and b'* PREAUTH' not in missing.stdout,
                      'exact_userdb_queries':queries == ['alice@fixture.test','bob@fixture.test','unknown@fixture.test'],
                      'no_server_errors':not errors}
            print(json.dumps({'checks':checks, 'codes':[x.returncode for x in (alice,bob,unknown,missing)], 'query_count':len(queries)}, sort_keys=True))
            for label, result in [('alice',alice),('bob',bob)]:
                print(label + '_transcript_hex=' + result.stdout.hex())

            assert all(checks.values())
        finally:
            stop.set(); thread.join(4); listener.close(); assert not thread.is_alive()
    print('fixture_cleanup=PASS')
if __name__ == '__main__': main()
