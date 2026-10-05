import unittest
from authoritative_password import AuthoritativePasswordAdapter as Adapter, Refused, Unconfirmed

OLD='{BLF-CRYPT}$2y$05$'+'A'*53
NEW='{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$'+'S'*22+'$'+'B'*43
ACCOUNT='alice@example.test'
STAMP='20261004170000'
PASSPHRASE='long synthetic passphrase'

class Executor:
    def __init__(self): self.calls=[]; self.responses=[]
    def __call__(self, program, args, stdin, seconds, limit):
        self.calls.append((program,args,stdin,seconds,limit))
        value=self.responses.pop(0)
        if isinstance(value, Exception): raise value
        return value
    def row(self): return (0,(OLD.encode().hex().upper()+'\t'+STAMP+'\t1\t1\n').encode(),b'')
    def receipt(self): return (0,('1\n'+NEW.encode().hex().upper()+'\t20261004170001\n').encode(),b'')

class PasswordTests(unittest.TestCase):
    def setUp(self): self.executor=Executor(); self.adapter=Adapter(self.executor)
    def snapshot(self):
        self.executor.responses=[self.executor.row()]
        return self.adapter.read(ACCOUNT)
    def test_policy_accepts_paste_unicode_no_composition_rules(self):
        for value in ['x'*15, 'x'*128, 'é'*128, '🙂'*128, ' '*15]:
            Adapter.validate_new('previous',value,value)
    def test_policy_refuses_bounds_controls_mismatch_unchanged(self):
        for value in ['x'*14,'x'*129,'x'*15+'\n','x'*15+'\x7f','x'*15+'\x85']:
            with self.assertRaises(Refused): Adapter.validate_new('previous',value,value)
        with self.assertRaises(Refused): Adapter.validate_new(PASSPHRASE,PASSPHRASE,PASSPHRASE)
        with self.assertRaises(Refused): Adapter.validate_new('previous',PASSPHRASE,PASSPHRASE+'x')
    def test_authoritative_read_private_repr_and_stdin(self):
        row=self.snapshot()
        self.assertNotIn(OLD,repr(row)); self.assertNotIn(ACCOUNT,repr(row))
        call=self.executor.calls[0]
        self.assertEqual(call[0],'/usr/local/bin/mariadb'); self.assertEqual(call[3:],(10,4096))
        self.assertNotIn(ACCOUNT,str(call[1])); self.assertNotIn(ACCOUNT,call[2].decode())
    def test_real_generated_cas_query_and_database_receipt_only(self):
        row=self.snapshot();self.executor.responses=[(0,(NEW+'\n').encode(),b''),self.executor.receipt()]
        receipt=self.adapter.replace(row,ACCOUNT,'previous',PASSPHRASE,PASSPHRASE)
        self.assertTrue(receipt.credential_written);self.assertFalse(receipt.sessions_revoked)
        self.assertEqual(receipt.changed_at,'20261004170001')
        hashcall,sqlcall=self.executor.calls[-2:]
        self.assertEqual(hashcall[1],('-O','pw','-s','ARGON2ID'))
        self.assertEqual(hashcall[2],(PASSPHRASE+'\n'+PASSPHRASE+'\n').encode())
        self.assertNotIn(PASSPHRASE,str(hashcall[1]));self.assertNotIn(PASSPHRASE,sqlcall[2].decode())
        query=sqlcall[2].decode()
        for term in ['START TRANSACTION','AND active=1','AND BINARY password=BINARY','AND modified=STR_TO_DATE','SELECT ROW_COUNT()','COMMIT']:
            self.assertIn(term,query)
        self.assertNotIn(OLD,query);self.assertNotIn(NEW,query);self.assertNotIn(ACCOUNT,query)
    def test_foreign_target_and_invalid_password_never_dispatch_writer(self):
        row=self.snapshot();before=len(self.executor.calls)
        with self.assertRaises(Refused):self.adapter.replace(row,'bob@example.test','previous',PASSPHRASE,PASSPHRASE)
        with self.assertRaises(Refused):self.adapter.replace(row,ACCOUNT,'previous','short','short')
        self.assertEqual(len(self.executor.calls),before)
    def test_stale_cas_does_not_claim_write_or_session_revocation(self):
        row=self.snapshot();self.executor.responses=[(0,(NEW+'\n').encode(),b''),(0,('0\n'+OLD.encode().hex().upper()+'\t'+STAMP+'\n').encode(),b'')]
        with self.assertRaises(Refused): self.adapter.replace(row,ACCOUNT,'previous',PASSPHRASE,PASSPHRASE)
        self.assertEqual(len(self.executor.calls),3)
    def test_ambiguous_timeout_or_malformed_receipt_never_retries(self):
        for response in [TimeoutError('synthetic'),(1,b'',b'private diagnostics'),(0,b'1\n',b''),(0,b'2\nunknown\n',b''),(0,b'1\nwrong\t20261004170001\n',b'')]:
            self.executor=Executor();self.adapter=Adapter(self.executor);row=self.snapshot()
            self.executor.responses=[(0,(NEW+'\n').encode(),b''),response]
            with self.assertRaises(Unconfirmed) as context:self.adapter.replace(row,ACCOUNT,'previous',PASSPHRASE,PASSPHRASE)
            self.assertNotIn('private',str(context.exception));self.assertEqual(len(self.executor.calls),3)
    def test_read_rejects_unknown_duplicate_disabled_scheme_and_bad_stamp(self):
        for text in ['',self.executor.row()[1].decode()*2,'00\t'+STAMP+'\t0\t1\n','00\t'+STAMP+'\t1\t1\n',OLD.encode().hex().upper()+'\t20269999999999\t1\t1\n']:
            self.executor.responses=[(0,text.encode(),b'')]
            with self.assertRaises(Refused):self.adapter.read(ACCOUNT)
    def test_shell_shaped_account_refused_before_executor(self):
        for account in [ACCOUNT+"'; DROP TABLE mailbox;--",'../alice','alice@example.test\n','alice@example.test`id`']:
            with self.assertRaises(Refused):self.adapter.read(account)
        self.assertEqual(self.executor.calls,[])
    def test_bad_native_hash_refuses_sql_write(self):
        row=self.snapshot();self.executor.responses=[(0,b'unknown hash\n',b'')]
        with self.assertRaises(Refused):self.adapter.replace(row,ACCOUNT,'previous',PASSPHRASE,PASSPHRASE)
        self.assertEqual(len(self.executor.calls),2)

class HardeningTests(unittest.TestCase):
    def test_invalid_unicode_is_typed_refusal(self):
        with self.assertRaises(Refused):Adapter.validate_new('old',chr(0xD800)*15,chr(0xD800)*15)
    def test_forged_snapshot_hash_is_refused_before_hash_or_sql(self):
        from authoritative_password import Snapshot
        executor=Executor();adapter=Adapter(executor)
        row=Snapshot(ACCOUNT,'unsupported',STAMP,True)
        with self.assertRaises(Refused):adapter.replace(row,ACCOUNT,'old',PASSPHRASE,PASSPHRASE)
        self.assertEqual(len(executor.calls),0)
    def test_old_bcrypt_output_is_not_accepted_for_new_password(self):
        executor=Executor();adapter=Adapter(executor);executor.responses=[executor.row()]
        row=adapter.read(ACCOUNT);executor.responses=[(0,(OLD+'\n').encode(),b'')]
        with self.assertRaises(Refused):adapter.replace(row,ACCOUNT,'old',PASSPHRASE,PASSPHRASE)
        self.assertEqual(len(executor.calls),2)
    def test_native_executor_disallows_extra_commands_and_bounds(self):
        from authoritative_password import NativeExecutor
        executor=NativeExecutor()
        for command,args,stdin,seconds,limit in [('/bin/sh',('-c','true'),b'',10,4096),
          (Adapter.SQL_PROGRAM,Adapter.SQL_ARGS,b'x'*16385,10,4096),
          (Adapter.SQL_PROGRAM,Adapter.SQL_ARGS,b'',11,4096),
          (Adapter.HASH_PROGRAM,('pw','-s','BLF-CRYPT'),b'',10,4096)]:
            with self.assertRaises(Refused):executor(command,args,stdin,seconds,limit)

class NativeTransportTests(unittest.TestCase):
    def execute(self,script,data=b'public synthetic transport'):
        import sys
        from unittest.mock import patch
        from authoritative_password import NativeExecutor
        with patch.object(Adapter,'SQL_PROGRAM',sys.executable),patch.object(Adapter,'SQL_ARGS',('-c',script)):
            return NativeExecutor()(sys.executable,('-c',script),data,10,4096)
    def test_actual_subprocess_stdin_and_bounded_stdout(self):
        code,out,err=self.execute('import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())')
        self.assertEqual(code,0);self.assertEqual(out,b'public synthetic transport');self.assertEqual(err,b'')
    def test_actual_child_flood_is_killed_and_refused(self):
        for script in ["import sys; sys.stdout.buffer.write(b'x'*10000)","import sys; sys.stderr.buffer.write(b'x'*10000)"]:
            with self.assertRaises(Refused):self.execute(script)
    def test_actual_deadline_kills_owned_child(self):
        import sys,time
        from unittest.mock import patch
        from authoritative_password import NativeExecutor
        script='import time; time.sleep(30)'
        start=time.monotonic()
        with patch.object(Adapter,'SQL_PROGRAM',sys.executable),patch.object(Adapter,'SQL_ARGS',('-c',script)),patch.object(Adapter,'LIMIT_SECONDS',0.1):
            with self.assertRaises(TimeoutError):NativeExecutor()(sys.executable,('-c',script),b'public synthetic',0.1,4096)
        self.assertLess(time.monotonic()-start,2)

if __name__=='__main__':unittest.main()
