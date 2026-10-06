"""Fixture-only supervised child sharing a parent-owned broker and epoch root.

Private role keys arrive on a supervisor-born pipe and are never retained.
SQL/hash/current-primary and external proxy/IMAP remain explicit public test
projections. This does not enable or replace a native worker factory.
"""
import argparse,json,os,selectors,socket,stat,sys,time
from pathlib import Path
if __name__=='__main__':sys.path.insert(0,str(Path(__file__).resolve().parent))
from account_epoch import EpochStore
from account_mutation_entry import _dispatch
from account_mutation_supervisor import _Bootstrap,_directory
from account_mutation_worker import MutationWorker,IntentStore,Unavailable
from account_mutation_codec import key_valid
from authoritative_password import AuthoritativePasswordAdapter,Refused,Unconfirmed
from mail_session_containment import MailSessionContainment,SmtpProxyControl,SmtpTerminationScope,OperatorOwnedSmtpTopology
from prepared_password import PreparedPasswordCoordinator
from smtp_auth_control_service import ControlTopologyAdmission
from smtp_control_authorization import ControlAuthority
from smtp_mutation_containment import PrivateControlEndpoint
from smtp_guarded_builder import GuardedSmtpBinding
import test_required_mail_containment as sql_projection

BOOT_LIMIT=16384
ACCOUNTS=frozenset(('alice@fixture.invalid','bob@fixture.invalid'))
FIELDS=frozenset(('version','root','key','session_key','control_key','metadata'))

def read_bootstrap(fd):
    if type(fd)is not int or not 3<=fd<=1024:raise Refused('fixture bootstrap descriptor')
    info=os.fstat(fd)
    if not stat.S_ISFIFO(info.st_mode)or info.st_uid!=os.geteuid():raise Refused('fixture bootstrap custody')
    data=bytearray();deadline=time.monotonic()+1
    try:
        os.set_blocking(fd,False)
        with selectors.DefaultSelector()as selector:
            selector.register(fd,selectors.EVENT_READ)
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise Refused('fixture bootstrap deadline')
                if not selector.select(min(.1,remaining)):continue
                part=os.read(fd,4096)
                if not part:break
                data.extend(part)
                if len(data)>BOOT_LIMIT:raise Refused('fixture bootstrap cap')
    finally:os.close(fd)
    value=json.loads(data,object_pairs_hook=EpochStore._unique)
    if type(value)is not dict or set(value)!=FIELDS or type(value['version'])is not int or value['version']!=1:
        raise Refused('fixture bootstrap shape')
    keys=[]
    for name in ('key','session_key','control_key'):
        if type(value[name])is not str or len(value[name])!=64:raise Refused('fixture bootstrap key')
        key=bytes.fromhex(value[name]);key_valid(key);keys.append(key)
    if len(set(keys))!=3:raise Refused('fixture bootstrap key purpose')
    if type(value['root'])is not str:raise Refused('fixture bootstrap root')
    root=Path(value['root']);directory=_directory(root,os.geteuid());os.close(directory)
    metadata=value['metadata']
    if type(metadata)is not dict or set(metadata)!={'master','services','global_auth','frontend','filter'}:
        raise Refused('fixture bootstrap metadata')
    if any(type(v)is not str or not 0<len(v.encode('ascii'))<=16384 for v in metadata.values()):
        raise Refused('fixture bootstrap metadata')
    return root,keys,{k:v.encode('ascii')for k,v in metadata.items()}

def run(fd):
    root,keys,metadata=read_bootstrap(fd);key,session,control=keys
    store=EpochStore(root/'epoch',os.geteuid());journal=IntentStore(root/'mutation-intents',os.geteuid())
    report={'stage':'startup','sql_calls':0,'capture':False};path=root/'shared-worker-report.json'
    def publish():
        out=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(out,'w')as handle:json.dump(report,handle,sort_keys=True)
    publish()
    config=root/'proxy'/'dovecot.conf'
    def metadata_executor(program,args,data,seconds,limit):
        if data!=b''or limit!=16384 or not 0<seconds<=10:raise Refused('fixture metadata selector')
        selectors={(OperatorOwnedSmtpTopology.PROGRAM,a):n for n,a in OperatorOwnedSmtpTopology.COMMANDS.items()}
        selectors.update({('/usr/local/bin/doveconf',('-c',str(config),'-n')):'frontend',('/sbin/pfctl',('-a','*','-sr')):'filter'})
        name=selectors.get((program,args))
        if name is None:raise Refused('fixture metadata selector')
        return 0,metadata[name],b''
    routing=ControlTopologyAdmission(root/'bootstrap',os.geteuid(),metadata_executor)
    bootstrap=_Bootstrap(key,session,ACCOUNTS,os.geteuid())
    authority=ControlAuthority(control,ACCOUNTS)
    binding=GuardedSmtpBinding(bootstrap,authority,PrivateControlEndpoint(root/'control'/'control.sock',os.geteuid()),clock_millis=lambda:int(time.time()*1000))
    sql=sql_projection.RequiredTests('runTest');sql.calls=[];sql.sql_updates=0;sql.hash_hook=None;sql.flush_hook=None
    dependencies=[];clock=lambda:int(time.time())
    def original_builder(*_args):raise Refused('fixture legacy builder unavailable')
    def build(original,frame,budget,authorize):
        namespace,topology=routing.admit(budget);account=original.budget.request.action.account
        own=(account+' submission 127.0.0.1 127.0.0.1 2525\n').encode();header=b'username proto src ip dest ip port\n'
        proxy_results=[(0,header+own,b''),(0,b'1 connections kicked\n',b''),(0,header,b'')]
        imap_results=[(0,MailSessionContainment.WHO_HEADER,b''),(0,b'0 cache entries flushed\n',b''),(68,b'no users kicked\n',b''),(0,MailSessionContainment.WHO_HEADER,b'')]
        def proxy(*_args):report['last_operation']='proxy';return proxy_results.pop(0)
        def imap(*_args):report['last_operation']='imap';return imap_results.pop(0)
        proxy_control=SmtpProxyControl(account,namespace,proxy,budget)
        mail=MailSessionContainment(account,imap,budget,SmtpTerminationScope.REQUIRED,proxy_control=proxy_control,topology=topology)
        def SQL(*args):
            report['last_operation']='SQL'
            if args[0]==AuthoritativePasswordAdapter.SQL_PROGRAM and args[2].startswith(b'START TRANSACTION;'):
                if store._read(store._paths(account)[1])['state']!='pending'or dependencies[-1]._state!='captured':
                    raise Refused('fixture SQL before capture')
            return sql.sql(*args)
        coordinator=PreparedPasswordCoordinator(store,AuthoritativePasswordAdapter(SQL,before_write=mail.before_write),authorize,
            lambda *_:True,lambda *_:True,mail.ready,mail.finish,clock,mail.invalidate_changed_auth)
        coordinator=binding.compose(coordinator,original,frame,budget);dependencies.append(coordinator.containment_ready.__self__)
        report.update(stage='built-before-pending',pid=os.getpid(),group=os.getpgrp(),owned_group=budget.inherited_group(),deadline_millis=original.budget.deadline_millis)
        publish();return coordinator
    worker=MutationWorker(key,ACCOUNTS,journal,store,original_builder,lambda *_:False,clock,time.monotonic,
        session_key=session,guarded_builder=build)
    stream=socket.socket(fileno=os.dup(1))
    try:
        _dispatch(worker,bootstrap,sys.stdin.buffer,stream);report['dispatch_complete']=True
    except Exception as error:
        report['failure_kind']=type(error).__name__ if type(error)in (Refused,Unconfirmed,Unavailable,ValueError,AssertionError,AttributeError)else 'other'
        raise
    finally:
        stream.close();report.update(stage='final',sql_calls=sql.sql_updates,capture=bool(dependencies and dependencies[0]._client is not None),
            owned_descriptor_closed=not dependencies or dependencies[0]._client is None or dependencies[0]._client._stream.fileno()==-1)
        publish()

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--fixture-bootstrap-fd',type=int,required=True);args=parser.parse_args()
    try:run(args.fixture_bootstrap_fd)
    except Exception:raise SystemExit(1)from None
