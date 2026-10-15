"""Fixed read-only OpenBSD SMTP process/TCP ownership producer.

Metadata custody is not complete ingress, backend peer or broker qualification.
The native entry accepts only the existing fixed-root v2 routing authority; it
creates no listener and changes no native activation flag. No wire selector can
choose programs, principals, the master pidfile or trusted process ancestry.
"""
from dataclasses import dataclass
import os
import math
import selectors
import subprocess
from pathlib import Path
import pwd
import re
import socket
import stat
import sys
import time

from account_mutation_supervisor import AUTHORITY
from authoritative_password import Refused
from mail_session_containment import (ContainmentExecutor,OperatorOwnedProxyNamespace,
                                     OperatorOwnedSmtpTopology)
from operation_budget import OperationBudget
from smtp_topology import FixedSmtpRouting,PrivateRoutingPlan

PS='/bin/ps'
FSTAT='/usr/bin/fstat'
MASTER=Path('/usr/local/libexec/postfix/master')
SMTPD=Path('/usr/local/libexec/postfix/smtpd')
PIDFILE=Path('/var/spool/postfix/pid/master.pid')
PS_FIELDS='pid=,ppid=,pgid=,uid=,gid=,lstart=,comm='
LIMIT=65536


def _require(value):
    if not value:raise Refused('SMTP native process authority unavailable')


@dataclass(frozen=True,repr=False)
class NativeSmtpIdentity:
    process: tuple
    master: tuple
    descriptor: int
    pcb: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int

    def projection(self):
        return self.process[0],self.local_address,self.local_port,self.remote_port


class _MetadataExecutor(ContainmentExecutor):
    # Exact unreaped handles are retained. Any unconfirmed cleanup stops later
    # native metadata admissions in this process; never retries an old PID.
    _retained=[]
    _quarantined=False
    def __init__(self,budget,pids):
        # The existing transport must inherit the supervised original group.
        # It may kill only its own Popen child; outer custody owns descendants.
        _require(type(budget)is OperationBudget and budget.inherited_group()and not self._retained and not self._quarantined)
        self._budget=budget;self._output_limit=LIMIT
        self._commands={(PS,('-p',str(pid),'-o',PS_FIELDS))for pid in pids}
        self._commands.update((FSTAT,('-n','-p',str(pid)))for pid in pids)
    def _allows(self,program,args):return (program,args)in self._commands

    def pair(self,program,arguments,deadline):
        # Two independent exact queries within ONE observation boundary. One
        # selector thread shares the original clock/budget; no worker timers,
        # shell, broad enumeration or cached metadata replaces either query.
        _require(program in (PS,FSTAT)and type(arguments)is tuple and len(arguments)==2
                 and arguments[0]!=arguments[1]and all(type(a)is tuple and self._allows(program,a)for a in arguments)
                 and type(deadline)in (int,float)and math.isfinite(deadline)
                 and 0<deadline-time.monotonic()<=0.5 and self._budget.inherited_group()
                 and not self._retained and not self._quarantined)
        reserve=.01;work=deadline-reserve
        children=[];output=[bytearray(),bytearray()];error=[bytearray(),bytearray()]
        codes=[];selector=None;uncertain=False
        try:
            for args in arguments:
                self._budget.remaining();_require(time.monotonic()<work)
                children.append(subprocess.Popen((program,)+args,stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,close_fds=True,
                    start_new_session=False,env={'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C'}))
            selector=selectors.DefaultSelector()
            for index,child in enumerate(children):
                for pipe,kind in ((child.stdout,'out'),(child.stderr,'err')):
                    os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ,(index,kind))
            while selector.get_map():
                remaining=min(work-time.monotonic(),self._budget.remaining())
                if remaining<=0:raise TimeoutError
                for key,_ in selector.select(min(remaining,.01)):
                    try:data=os.read(key.fd,4096)
                    except BlockingIOError:continue
                    if not data:selector.unregister(key.fileobj);key.fileobj.close();continue
                    index,kind=key.data;dest=output[index]if kind=='out'else error[index]
                    dest.extend(data)
                    if len(dest)>LIMIT:raise Refused('SMTP native metadata output unavailable')
            for child in children:
                remaining=min(work-time.monotonic(),self._budget.remaining())
                if remaining<=0:raise TimeoutError
                codes.append(child.wait(timeout=remaining))
            self._budget.remaining();_require(time.monotonic()<work)
            return tuple((codes[i],bytes(output[i]),bytes(error[i]))for i in range(2))
        finally:
            if selector is not None:
                try:selector.close()
                except BaseException:uncertain=True
            # Every returned child remains owned through disposition, including
            # second-spawn/selector/read exceptions. Cleanup never renews .5s.
            for child in children:
                try:
                    if child.poll()is None:
                        child.kill()
                        remaining=min(deadline-time.monotonic(),self._budget.remaining())
                        if remaining<0:remaining=0
                        child.wait(timeout=remaining)
                except BaseException:
                    # Retain only this actual handle; block new admissions.
                    if child not in self._retained:self._retained.append(child)
                    uncertain=True
                finally:
                    for pipe in (child.stdout,child.stderr):
                        try:
                            if not pipe.closed:pipe.close()
                        except BaseException:uncertain=True
            if uncertain:
                type(self)._quarantined=True
                raise Refused('SMTP native metadata cleanup unconfirmed')from None

    def inspect_tail(self,inspector,rows,pids,deadline):
        # Both PS-before rows have already validated. Only child PS-after may
        # overlap the unfinished master FSTAT. Master PS-after still follows
        # BOTH first FSTAT validations, and final child FSTAT still follows
        # BOTH PS-after validations. These cross-PID intervals are authority.
        _require(type(inspector)is NativeSmtpPeerInspector and inspector._budget is self._budget
                 and type(pids)is tuple and len(pids)==2 and pids[0]!=pids[1]
                 and type(rows)is dict and set(rows)==set(pids)
                 and rows[pids[0]]==inspector._master
                 and type(deadline)in (int,float)and math.isfinite(deadline)
                 and 0<deadline-time.monotonic()<=.5 and self._budget.inherited_group()
                 and not self._retained and not self._quarantined)
        master,child=pids;programs=dict(inspector._files_custody)
        queries={'master_fstat':(FSTAT,('-n','-p',str(master))),
                 'child_fstat':(FSTAT,('-n','-p',str(child))),
                 'master_after':(PS,('-p',str(master),'-o',PS_FIELDS)),
                 'child_after':(PS,('-p',str(child),'-o',PS_FIELDS)),
                 'child_final':(FSTAT,('-n','-p',str(child)))}
        reserve=.01;work=deadline-reserve;children=[];active={};launched=set();done=set()
        selector=None;uncertain=False;connection=None
        def launch(name):
            program,args=queries[name]
            _require(name not in launched and len(active)<2 and self._allows(program,args))
            self._budget.remaining();_require(time.monotonic()<work)
            process=subprocess.Popen((program,)+args,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,close_fds=True,
                start_new_session=False,env={'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C'})
            # Retain the actual handle before any registration can fail.
            children.append(process);launched.add(name)
            active[name]={'child':process,'out':bytearray(),'err':bytearray(),'pipes':2}
            for pipe,kind in ((process.stdout,'out'),(process.stderr,'err')):
                os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ,(name,kind))
        try:
            selector=selectors.DefaultSelector();launch('master_fstat');launch('child_fstat')
            while active:
                remaining=min(work-time.monotonic(),self._budget.remaining())
                if remaining<=0:raise TimeoutError
                for key,_ in selector.select(min(remaining,.01)):
                    try:data=os.read(key.fd,4096)
                    except BlockingIOError:continue
                    name,kind=key.data;state=active[name]
                    if not data:
                        selector.unregister(key.fileobj);key.fileobj.close();state['pipes']-=1
                    else:
                        state[kind].extend(data)
                        if len(state[kind])>LIMIT:raise Refused('SMTP native metadata output unavailable')
                for name,state in tuple(active.items()):
                    if state['pipes']:continue
                    remaining=min(work-time.monotonic(),self._budget.remaining())
                    if remaining<=0:raise TimeoutError
                    code=state['child'].wait(timeout=remaining)
                    raw=inspector._checked((code,bytes(state['out']),bytes(state['err'])),self._budget,deadline)
                    if name=='master_fstat':
                        inspector._fstat(raw,master,'master',programs[str(MASTER)][0])
                    elif name=='child_fstat':
                        connection=inspector._fstat(raw,child,'smtpd',programs[str(SMTPD)][0],inspector._namespace._backend_port)
                    elif name in ('master_after','child_after'):
                        pid=master if name=='master_after'else child
                        _require(inspector._rows(raw,(pid,))[pid]==rows[pid])
                    else:
                        _require(name=='child_final'and inspector._fstat(raw,child,'smtpd',
                            programs[str(SMTPD)][0],inspector._namespace._backend_port)==connection)
                    done.add(name);del active[name]
                if 'child_fstat'in done and 'child_after'not in launched:launch('child_after')
                if {'master_fstat','child_fstat'}<=done and 'master_after'not in launched:launch('master_after')
                if {'master_after','child_after'}<=done and 'child_final'not in launched:launch('child_final')
            _require(done==set(queries)and connection is not None and time.monotonic()<work)
            self._budget.remaining();return connection
        finally:
            if selector is not None:
                try:selector.close()
                except BaseException:uncertain=True
            for process in children:
                try:
                    if process.poll()is None:
                        process.kill()
                        remaining=min(deadline-time.monotonic(),self._budget.remaining())
                        process.wait(timeout=max(0,remaining))
                except BaseException:
                    if process not in self._retained:self._retained.append(process)
                    uncertain=True
                finally:
                    for pipe in (process.stdout,process.stderr):
                        try:
                            if not pipe.closed:pipe.close()
                        except BaseException:uncertain=True
            if uncertain:
                type(self)._quarantined=True
                raise Refused('SMTP native metadata cleanup unconfirmed')from None


class NativeSmtpPeerInspector:
    @staticmethod
    def _identity(info):
        return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,
                info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

    @classmethod
    def _file(cls,path,*,program=False):
        _require(path.is_absolute()and path.resolve(strict=True)==path)
        parents=[]
        for parent in path.parents:
            info=parent.lstat()
            _require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022)
            parents.append(cls._identity(info)[:5])
        info=path.lstat()
        _require(stat.S_ISREG(info.st_mode)and info.st_uid==0 and info.st_nlink in ((1,2)if path==Path(FSTAT)else(1,))
                 and not info.st_mode&0o022 and info.st_size>0
                 and (not program or info.st_mode&0o111))
        return cls._identity(info),tuple(parents)

    @classmethod
    def _files(cls):
        return tuple((str(path),cls._file(path,program=True))for path in (Path(PS),Path(FSTAT),MASTER,SMTPD))

    @staticmethod
    def _principal():
        value=pwd.getpwnam('_postfix')
        _require(value.pw_name=='_postfix'and type(value.pw_uid)is int and type(value.pw_gid)is int
                 and 0<value.pw_uid<2**32-1 and 0<value.pw_gid<2**32-1)
        return value.pw_uid,value.pw_gid

    @classmethod
    def _master_pid(cls):
        before=cls._file(PIDFILE)
        _require(before[0][6]<=128 and not before[0][4]&0o077)
        fd=os.open(PIDFILE,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            _require(cls._identity(os.fstat(fd))==before[0])
            raw=os.read(fd,129)
            _require(cls._identity(os.fstat(fd))==before[0]and cls._file(PIDFILE)==before
                     and len(raw)==before[0][6])
        finally:os.close(fd)
        match=re.fullmatch(rb' *([1-9][0-9]{0,9})\n',raw)
        _require(match is not None and 1<int(match[1])<=2**31-1)
        return int(match[1]),before

    @staticmethod
    def _rows(raw,pids):
        _require(type(raw)is bytes and 0<len(raw)<=LIMIT and b'\0'not in raw)
        try:
            rows={}
            for line in raw.decode('ascii').splitlines():
                fields=line.split();_require(len(fields)==11)
                numbers=tuple(int(value)for value in fields[:5])
                _require(all(re.fullmatch(r'0|[1-9][0-9]{0,9}',value)for value in fields[:5])
                         and all(0<=value<=2**31-1 for value in numbers[:3])
                         and all(0<=value<2**32-1 for value in numbers[3:])
                         and numbers[0]in pids and numbers[0]not in rows
                         and re.fullmatch(r'(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([1-9]|[12][0-9]|3[01]) ([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] [0-9]{4}',' '.join(fields[5:10])))
                rows[numbers[0]]=numbers+(tuple(fields[5:10]),fields[10])
            _require(set(rows)==set(pids));return rows
        except (ValueError,UnicodeError):raise Refused('SMTP native process metadata refused')from None

    @staticmethod
    def _fstat(raw,pid,service,binary,port=None):
        _require(type(raw)is bytes and 0<len(raw)<=LIMIT and b'\0'not in raw)
        try:lines=raw.decode('ascii').splitlines()
        except UnicodeError:raise Refused('SMTP native descriptor metadata refused')from None
        _require(1<=len(lines)<=256 and lines[0].split()==['USER','CMD','PID','FD','DEV','INUM','MODE','R/W','SZ|DV'])
        text=[];connections=[];descriptors=set()
        user='root'if service=='master'else'_postfix'
        for line in lines[1:]:
            fields=line.split();_require(len(fields)>=4 and fields[:3]==[user,service,str(pid)])
            if fields[3]=='text':
                match=re.fullmatch(re.escape(user)+r'\s+'+service+r'\s+'+str(pid)+r'\s+text\s+(\d+),\s*(\d+)\s+(\d+)\s+([0-7]+)\s+.*',line)
                _require(match is not None)
                text.append((int(match[1]),int(match[2]),int(match[3]),int(match[4],8)))
            if port is None or 'tcp'not in fields:continue
            _require(len(fields)in (9,11)and re.fullmatch(r'[0-9]{1,10}\*',fields[3])is not None
                     and int(fields[3][:-1])<=2**31-1 and fields[4:7]==['internet','stream','tcp']
                     and re.fullmatch(r'0x[0-9a-fA-F]{1,16}',fields[7])is not None)
            descriptor=int(fields[3][:-1]);_require(descriptor not in descriptors);descriptors.add(descriptor)
            _require(fields[8]=='127.0.0.1:'+str(port))
            if len(fields)==9:continue  # Listener metadata cannot authorize a channel.
            match=re.fullmatch(r'127\.0\.0\.1:([1-9][0-9]{0,4})',fields[10])
            _require(fields[9]=='<--'and match is not None and 1024<=int(match[1])<=65535)
            connections.append((descriptor,fields[7],'127.0.0.1',port,'127.0.0.1',int(match[1])))
        _require(text==[(os.major(binary[0]),os.minor(binary[0]),binary[1],binary[4])])
        _require(port is None or len(connections)==1)
        return connections[0]if port is not None else text[0]

    @staticmethod
    def _query(executor,program,args,budget,deadline):
        seconds=min(deadline-time.monotonic(),budget.cap_seconds(0.5));_require(seconds>0)
        result=executor(program,args,b'',seconds,LIMIT)
        return NativeSmtpPeerInspector._checked(result,budget,deadline)

    @staticmethod
    def _checked(result,budget,deadline):
        budget.remaining();_require(time.monotonic()<deadline)
        _require(type(result)is tuple and len(result)==3 and type(result[0])is int and result[0]==0
                 and type(result[1])is bytes and len(result[1])<=LIMIT and type(result[2])is bytes and not result[2])
        return result[1]

    @classmethod
    def _process_rows(cls,executor,pids,budget,deadline):
        # OpenBSD ps -p selects ONE pid (atol), not a comma-separated list.
        # Both snapshots use the same original absolute phase and budget.
        _require(type(pids)is tuple and len(pids)==2 and pids[0]!=pids[1])
        arguments=tuple(('-p',str(pid),'-o',PS_FIELDS)for pid in pids)
        results=executor.pair(PS,arguments,deadline)
        _require(type(results)is tuple and len(results)==2)
        rows={}
        for pid,result in zip(pids,results):
            rows.update(cls._rows(cls._checked(result,budget,deadline),(pid,)))
        return rows

    @classmethod
    def _read(cls,namespace,topology,budget):
        _require(type(namespace)is OperatorOwnedProxyNamespace and type(topology)is OperatorOwnedSmtpTopology
                 and type(budget)is OperationBudget and budget.inherited_group()and topology._namespace is namespace
                 and topology._budget is budget and topology._certificate_version==2
                 and type(topology._routing_plan)is PrivateRoutingPlan
                 and topology._routing_plan.bound_to(namespace,budget)
                 and namespace._backend_address=='127.0.0.1'and 1024<=namespace._backend_port<=65535)
        topology.recheck(budget)
        value=cls();value._namespace=namespace;value._topology=topology;value._budget=budget
        value._files_custody=cls._files();value._postfix=cls._principal()
        value._master_pid_value,value._pidfile=cls._master_pid()
        executor=_MetadataExecutor(budget,(value._master_pid_value,));deadline=time.monotonic()+budget.cap_seconds(0.5)
        args=('-p',str(value._master_pid_value),'-o',PS_FIELDS)
        row=cls._rows(cls._query(executor,PS,args,budget,deadline),(value._master_pid_value,))[value._master_pid_value]
        _require(row[:5]==(value._master_pid_value,1,value._master_pid_value,0,0)and row[-1]=='master')
        programs=dict(value._files_custody)
        cls._fstat(cls._query(executor,FSTAT,('-n','-p',str(row[0])),budget,deadline),row[0],'master',programs[str(MASTER)][0])
        _require(cls._rows(cls._query(executor,PS,args,budget,deadline),(row[0],))[row[0]]==row)
        value._master=row;value._current(budget,deadline);return value

    def _current(self,budget,deadline):
        _require(budget is self._budget and self._topology._budget is budget
                 and self._topology._namespace is self._namespace
                 and self._topology._routing_plan.bound_to(self._namespace,budget))
        budget.remaining();_require(time.monotonic()<deadline)
        _require(self._files()==self._files_custody and self._principal()==self._postfix
                 and self._master_pid()==(self._master[0],self._pidfile))
        self._namespace.recheck(budget)
        _require(self._topology._read()[0]==self._topology._captured)
        routing=self._topology._routing_plan
        routing.recheck(budget)
        budget.remaining();_require(time.monotonic()<deadline)

    def __call__(self,*_args):
        # Native inspection requires the same original budget, not a callback
        # that could mint a new one from the numeric absolute deadline.
        raise Refused('SMTP native original budget required')

    def inspect(self,pid,deadline,budget):
        _require(type(pid)is int and 1<pid<=2**31-1 and type(budget)is OperationBudget
                 and budget is self._budget and type(deadline)in (int,float)and time.monotonic()<deadline
                 and deadline-time.monotonic()<=0.5)
        self._current(budget,deadline)
        pids=(self._master[0],pid);executor=_MetadataExecutor(budget,pids)
        rows=self._process_rows(executor,pids,budget,deadline);child=rows[pid]
        _require(rows[self._master[0]]==self._master and child[1:5]==(self._master[0],self._master[0],*self._postfix)and child[-1]=='smtpd')
        connection=executor.inspect_tail(self,rows,pids,deadline)
        self._current(budget,deadline)
        return NativeSmtpIdentity(child,self._master,*connection)

    @classmethod
    def native(cls,namespace,topology,budget):
        _require(os.geteuid()==0 and sys.platform.startswith('openbsd')and socket.gethostname()==AUTHORITY
                 and type(namespace)is OperatorOwnedProxyNamespace and namespace._owner==0
                 and type(topology)is OperatorOwnedSmtpTopology
                 and type(topology._routing_plan)is PrivateRoutingPlan
                 and topology._routing_plan._root==FixedSmtpRouting.ROOT and topology._routing_plan._owner==0)
        return cls._read(namespace,topology,budget)


@dataclass(frozen=True,repr=False)
class _ChannelOwnership:
    authority: object
    inspector: NativeSmtpPeerInspector
    budget: OperationBudget


@dataclass(frozen=True,repr=False)
class NativeSmtpOwnership:
    """Shared startup custody; every AUTH retains its own original inspector.

    No startup budget survives in native custody. The trusted broker prepares
    exactly once before forwarding credentials; publication can neither prepare
    a replacement nor renew an expired channel. Bindings live on their original
    budget, avoiding a global cache that could retain completed channels.
    """
    _routing: object
    _startup_custody: tuple

    @staticmethod
    def _custody(inspector):
        _require(type(inspector)is NativeSmtpPeerInspector)
        topology=inspector._topology;namespace=inspector._namespace;routing=topology._routing_plan
        return (inspector._files_custody,inspector._postfix,inspector._master,inspector._pidfile,
                namespace._captured,namespace._fingerprint,topology._captured,
                routing._root,routing._owner,routing._captured)

    @classmethod
    def _read(cls,inspector,routing):
        from smtp_auth_control_service import ControlTopologyAdmission
        _require(type(inspector)is NativeSmtpPeerInspector and type(routing)is ControlTopologyAdmission
                 and routing.root==inspector._topology._routing_plan._root
                 and routing.owner==inspector._topology._routing_plan._owner)
        inspector._current(inspector._budget,time.monotonic()+inspector._budget.cap_seconds(0.5))
        routing.recheck()
        return cls(routing,cls._custody(inspector))

    def __call__(self,*_args):
        raise Refused('SMTP prepared original ownership required')

    def prepare(self,budget):
        _require(type(budget)is OperationBudget and budget.inherited_group()
                 and not hasattr(budget,'_smtp_channel_ownership'))
        budget.remaining()
        namespace,topology=self._routing.admit(budget)
        inspector=NativeSmtpPeerInspector._read(namespace,topology,budget)
        _require(self._custody(inspector)==self._startup_custody)
        budget.remaining()
        binding=_ChannelOwnership(self,inspector,budget)
        budget._smtp_channel_ownership=binding
        return binding

    def prepared(self,budget):
        _require(type(budget)is OperationBudget)
        binding=getattr(budget,'_smtp_channel_ownership',None)
        _require(type(binding)is _ChannelOwnership and binding.authority is self
                 and binding.budget is budget and binding.inspector._budget is budget)
        budget.remaining()
        return binding.inspector

    @classmethod
    def native(cls,namespace,topology,budget):
        from smtp_auth_control_service import ControlTopologyAdmission
        inspector=NativeSmtpPeerInspector.native(namespace,topology,budget)
        routing=ControlTopologyAdmission(FixedSmtpRouting.ROOT,0)
        return cls._read(inspector,routing)
