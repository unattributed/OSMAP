"""Test-only actual supervised guarded worker and private control descriptors.

All keys/credentials, SQL/primary and proxy/IMAP responses are public source
projections. Native factories, provider traffic and operator files are unused.
Only parent-selected private TEST witness metadata is retained, without frames.
"""
import json,os,socket,sys,time
from io import BytesIO
from pathlib import Path
if __name__=='__main__':sys.path.insert(0,str(Path(__file__).resolve().parent))
from account_mutation_entry import _dispatch
from account_mutation_supervisor import _Bootstrap,_directory
from account_mutation_worker import MutationWorker
from authoritative_password import AuthoritativePasswordAdapter
from mail_session_containment import MailSessionContainment,SmtpProxyControl,SmtpTerminationScope
from prepared_password import PreparedPasswordCoordinator
from smtp_guarded_builder import GuardedSmtpBinding
import test_smtp_mutation_containment as fixtures

KEY=fixtures.fixtures.KEY;SESSION=fixtures.fixtures.SESSION_KEY

def main():
    parent=Path(os.environ['OSMAP_TEST_GUARDED_SMTP_WITNESS_ROOT'])
    fd=_directory(parent,os.getuid());os.close(fd)
    witness=parent/'worker-witness.json';report={'stage':'initial','sql_calls':0,'captures':0}
    def publish():
        fd=os.open(witness,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w')as out:json.dump(report,out,sort_keys=True)
    case=fixtures.MutationContainment('runTest');case.setUp()
    case.f.supervisor._monotonic=time.monotonic
    case.f.supervisor._clock_millis=lambda:int(time.time()*1000)
    case.now=lambda:int(time.time())
    boot=_Bootstrap(KEY,SESSION,case.f.authority.accounts,os.getuid())
    binding=GuardedSmtpBinding(boot,case.f.authority,case.endpoint,clock_millis=lambda:int(time.time()*1000))
    alice,front,upstream=case.local.channel(case.alice);bob,_,_=case.local.channel(case.bob,2)
    def original_builder(*_args):raise AssertionError('legacy builder forbidden')
    def build(original,frame,budget,authorize):
        case.guarded=original;case.budget=budget
        case.namespace,case.topology=case.f.routing.admit(budget)
        proxy=SmtpProxyControl(case.alice,case.namespace,case.proxy,budget)
        mail=MailSessionContainment(case.alice,case.imap,budget,SmtpTerminationScope.REQUIRED,proxy_control=proxy,topology=case.topology)
        coordinator=PreparedPasswordCoordinator(case.local.store,AuthoritativePasswordAdapter(case.execute_sql,before_write=mail.before_write),authorize,
            lambda *_:True,lambda *_:True,mail.ready,mail.finish,case.now,mail.invalidate_changed_auth)
        result=binding.compose(coordinator,original,frame,budget)
        case.dependencies.append(result.containment_ready.__self__)
        report.update(stage='built-before-pending',owned_group=budget.inherited_group(),
            pid=os.getpid(),group=os.getpgrp(),
            intent_lock=str(case.journal._paths(case.alice)[0]),
            intent_record=str(case.journal._paths(case.alice)[1]),
            epoch_record=str(case.local.store._paths(case.alice)[1]),
            original_deadline_millis=original.budget.deadline_millis)
        publish();return result
    worker=MutationWorker(KEY,boot.accounts,case.journal,case.local.store,original_builder,
        lambda *_:False,case.now,time.monotonic,session_key=SESSION,guarded_builder=build)
    stream=socket.socket(fileno=os.dup(1))
    try:
        size=int.from_bytes(sys.stdin.buffer.read(4),'big')
        if not 0<size<=12288:raise ValueError
        raw=sys.stdin.buffer.read(size+1)
        if len(raw)!=size:raise ValueError
        _dispatch(worker,boot,BytesIO(size.to_bytes(4,'big')+raw),stream)
        report['dispatch_complete']=True
    finally:
        stream.close();case.thread.join(2)
        report.update(stage='final',sql_calls=case.sql.sql_updates,
            captures=int(bool(case.dependencies and case.dependencies[0]._client is not None)),alice_closed=alice.closed,bob_closed=bob.closed,
            active_epoch=case.epoch()['epoch'],epoch_state=case.epoch()['state'],
            owned_descriptor_closed=not case.dependencies or case.dependencies[0]._client is None or case.dependencies[0]._client._stream.fileno()==-1,
            control_uncertain=getattr(case.local.registry,'_control_uncertain',False),
            broker_results=len(case.listener_results))
        report['saslend_eof']=False
        if alice.closed:
            front.settimeout(.2);upstream.settimeout(.2)
            report['saslend_eof']=front.recv(1)==b''and upstream.recv(1)==b''
        publish();case.doCleanups()

if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit(1)from None
