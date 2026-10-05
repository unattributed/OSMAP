"""Mutation-only primary verifier on the original owned operation budget.

No startup/relay/browser route imports this component. Native syntax is preserved
from admission; actual mail-host authentication/confinement remains unqualified.
Credentials enter stdin only; captured diagnostics never leave this function.
"""
import os
import selectors
import subprocess
import time
import unicodedata
from authoritative_password import AuthoritativePasswordAdapter, Refused
from operation_budget import OperationBudget

PROGRAM='/usr/local/bin/doveadm'
ARGS=('-o','stats_writer_socket_path=','auth','test','-x','service=imap')
LIMIT=4096
PHASE_SECONDS=25
RESERVE=.05

class NativePrimaryVerifier:
    def __init__(self, canonical_account, budget):
        self._account=AuthoritativePasswordAdapter._account(canonical_account)
        if type(budget) is not OperationBudget:
            raise Refused('mutation primary dependency unavailable')
        self._budget=budget
        self._uncertain=False
        self._retained=[]

    def _command(self):
        return (PROGRAM,)+ARGS+(self._account,)

    @staticmethod
    def _password(value):
        if type(value) is not str or any(unicodedata.category(c)=='Cc' for c in value):
            raise Refused('mutation primary unavailable')
        try:raw=value.encode('utf-8')
        except UnicodeError:raise Refused('mutation primary unavailable') from None
        if not 1<=len(raw)<=1024:raise Refused('mutation primary unavailable')
        return raw+b'\n'

    @staticmethod
    def _result(code,output):
        try:
            lines=output.decode('utf-8','strict').splitlines()
            succeeded=any('auth succeeded' in line for line in lines)
            failed=any('auth failed' in line for line in lines)
            users=[line.strip()[5:].strip() for line in lines if line.strip().startswith('user=')]
        except (UnicodeError,ValueError):raise Refused('mutation primary unavailable') from None
        if succeeded and failed:raise Refused('mutation primary acknowledgement unavailable')
        if code==77 and failed and not succeeded:return False,users
        if code==0 and succeeded and not failed:return True,users
        raise Refused('mutation primary acknowledgement unavailable')

    def __call__(self,account,password):
        if self._uncertain or account!=self._account:
            raise Refused('mutation primary unavailable')
        pending=self._password(password)
        if not self._budget.inherited_group():
            raise Refused('mutation primary process ownership unavailable')
        seconds=self._budget.cap_seconds(PHASE_SECONDS)
        if seconds<=RESERVE:raise Refused('mutation primary deadline unavailable')
        deadline=time.monotonic()+seconds-RESERVE
        child=None
        output=bytearray();total=0
        try:
            child=subprocess.Popen(self._command(),stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,
                start_new_session=False,env={'PATH':'/usr/local/bin:/usr/bin:/bin','LC_ALL':'C'})
            with selectors.DefaultSelector() as selector:
                for pipe in (child.stdin,child.stdout,child.stderr):os.set_blocking(pipe.fileno(),False)
                selector.register(child.stdin,selectors.EVENT_WRITE,'input')
                selector.register(child.stdout,selectors.EVENT_READ,'output')
                selector.register(child.stderr,selectors.EVENT_READ,'error')
                while selector.get_map():
                    remaining=min(deadline-time.monotonic(),self._budget.remaining()-RESERVE)
                    if remaining<=0:raise Refused('mutation primary deadline unavailable')
                    for key,_ in selector.select(min(remaining,.01)):
                        pipe=key.fileobj
                        try:
                            if key.data=='input':
                                pending=pending[os.write(pipe.fileno(),pending):]
                                if not pending:selector.unregister(pipe);pipe.close()
                            else:
                                data=os.read(pipe.fileno(),4096)
                                if not data:selector.unregister(pipe);pipe.close()
                                total+=len(data)
                                if total>LIMIT:raise Refused('mutation primary output unavailable')
                                if key.data=='output':output.extend(data)
                        except BlockingIOError:continue
                self._budget.remaining()
                remaining=min(deadline-time.monotonic(),self._budget.remaining()-RESERVE)
                if remaining<=0:raise Refused('mutation primary deadline unavailable')
                code=child.wait(timeout=remaining)
            accepted,users=self._result(code,bytes(output))
            if accepted and users!=[self._account]:raise Refused('mutation primary identity unavailable')
            self._budget.remaining()
            return accepted
        except Exception:raise Refused('mutation primary unavailable') from None
        finally:
            if child is not None:
                if child.returncode is None:
                    try:
                        child.kill();child.wait(timeout=self._budget.remaining());self._budget.remaining()
                    except Exception:self._uncertain=True;self._retained.append(child)
                for pipe in (child.stdin,child.stdout,child.stderr):
                    if not pipe.closed:pipe.close()
                if self._uncertain:raise Refused('mutation primary cleanup unconfirmed') from None
                # The final return follows descriptor cleanup on the same budget.
                self._budget.remaining()
