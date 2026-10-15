"""Finite source-owned metadata projections and real local lifecycle sockets.

No native command, service, backend peer or ingress qualification is inferred.
The connected TCP syntax matches the retained zero-protocol Toronto observation;
child text/loader and actual composed inspector remain native NOT RUN.
"""
import os
import sys
import subprocess
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from authoritative_password import Refused
from operation_budget import OperationBudget
from smtp_auth_lifecycle import OwnedSmtpPeerAuthority
import smtp_native_peer as native
import test_smtp_control_service as service_fixtures

HEADER=b'USER CMD PID FD DEV INUM MODE R/W SZ|DV\n'


class NativePeerTests(unittest.TestCase):
    def setUp(self):
        self.case=service_fixtures.ServiceTests('runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.fixture=self.case.fixture;self.budget=self.fixture.budget
        self.namespace,self.topology=self.case.routing.admit(self.budget)
        owned=patch.object(self.budget,'inherited_group',return_value=True);owned.start();self.addCleanup(owned.stop)
        self.master=b'777 1 777 0 0 Thu Oct 1 14:33:31 2026 master\n'
        self.child=('123 777 777 '+str(os.getuid())+' '+str(os.getgid())+' Thu Oct 15 14:19:43 2026 smtpd\n').encode()
        self.fd=14;self.pcb='0xffff800000d2b900';self.after_hook=None;self.tcp_hook=None;self.tcp_calls=0;self.ps_calls=0;self.calls=[]
        # Fixed public-program projections. Real paths and running child text
        # will require the separately reviewed native execution, not these rows.
        self.programs=tuple((str(p),((os.makedev(4,3),ino,0,7,0o100755,1,100,1,1),()))
            for p,ino in ((Path(native.PS),1),(Path(native.FSTAT),2),(native.MASTER,259311),(native.SMTPD,259323)))
        self.pidfile=((1,2,0,0,0o100600,1,33,1,1),())
        for method,value in (('_files',self.programs),('_master_pid',(777,self.pidfile)),('_principal',(os.getuid(),os.getgid()))):
            self.patch=patch.object(native.NativeSmtpPeerInspector,method,return_value=value);self.patch.start();self.addCleanup(self.patch.stop)
        self.execute_patch=patch.object(native._MetadataExecutor,'__call__',autospec=True,side_effect=self.execute)
        self.execute_patch.start();self.addCleanup(self.execute_patch.stop)
        pair=patch.object(native._MetadataExecutor,'pair',autospec=True,
            side_effect=lambda executor,program,arguments,deadline:tuple(
                self.execute(executor,program,args,b'',min(.5,deadline-time.monotonic()),native.LIMIT)for args in arguments))
        pair.start();self.addCleanup(pair.stop)
        tail=patch.object(native._MetadataExecutor,'inspect_tail',autospec=True,side_effect=self.execute_tail)
        tail.start();self.addCleanup(tail.stop)
        self.inspector=native.NativeSmtpPeerInspector._read(self.namespace,self.topology,self.budget)
        self.fixture.registry._authority=OwnedSmtpPeerAuthority((os.getuid(),os.getgid()),(os.getuid(),os.getgid()),2525,self.inspector)
        self.ps_calls=0;self.calls=[]

    def fstat(self,pid):
        if pid==777:return HEADER+b'root master 777 text 4,3 259311 100755 r 100\n'
        return HEADER+b'_postfix smtpd 123 text 4,3 259323 100755 r 100\n'+(
            '_postfix smtpd 123 '+str(self.fd)+'* internet stream tcp '+self.pcb+' 127.0.0.1:2525 <-- 127.0.0.1:3130\n').encode()

    def execute(self,executor,program,args,raw,seconds,limit):
        self.assertTrue(executor._allows(program,args));self.assertIs(executor._budget,self.budget)
        self.assertEqual((raw,limit),(b'',65536));self.assertGreater(seconds,0);self.assertLessEqual(seconds,.5)
        self.calls.append((program,args))
        if program==native.PS:
            self.ps_calls+=1
            if self.after_hook and self.ps_calls==3:self.after_hook()
            # Match OpenBSD ps.c: -p uses atol(optarg), singular KERN_PROC_PID.
            selected=int(args[1].split(',',1)[0])
            data=self.master if selected==777 else self.child if selected==123 else b''
        else:
            if int(args[-1])==123:
                self.tcp_calls+=1
                if self.tcp_hook and self.tcp_calls%2==0:self.tcp_hook()
            data=self.fstat(int(args[-1]))
        return 0,data,b''

    def execute_tail(self,executor,inspector,rows,pids,deadline):
        # Existing projected-identity controls retain all old validation paths;
        # the separate real-child scheduler control exercises the new transport.
        programs=dict(inspector._files_custody);master,child=pids
        def query(program,args):
            result=self.execute(executor,program,args,b'',min(.5,deadline-time.monotonic()),native.LIMIT)
            return inspector._checked(result,self.budget,deadline)
        inspector._fstat(query(native.FSTAT,('-n','-p',str(master))),master,'master',programs[str(native.MASTER)][0])
        connection=inspector._fstat(query(native.FSTAT,('-n','-p',str(child))),child,'smtpd',programs[str(native.SMTPD)][0],inspector._namespace._backend_port)
        for pid in pids:
            native._require(inspector._rows(query(native.PS,('-p',str(pid),'-o',native.PS_FIELDS)),(pid,))[pid]==rows[pid])
        native._require(inspector._fstat(query(native.FSTAT,('-n','-p',str(child))),child,'smtpd',programs[str(native.SMTPD)][0],inspector._namespace._backend_port)==connection)
        return connection

    def test_openbsd_singular_pid_selectors_preserve_original_snapshot_authority(self):
        deadline=time.monotonic()+.5
        identity=self.inspector.inspect(123,deadline,self.budget)
        self.assertEqual(identity.projection(),(123,'127.0.0.1',2525,3130))
        queries=[args for program,args in self.calls if program==native.PS]
        self.assertEqual(queries,[('-p',str(pid),'-o',native.PS_FIELDS)for pid in (777,123,777,123)])
        executor=native._MetadataExecutor(self.budget,(777,123))
        self.assertFalse(executor._allows(native.PS,('-p','777,123','-o',native.PS_FIELDS)))
        self.assertFalse(executor._allows(native.PS,('-p','124','-o',native.PS_FIELDS)))
        self.assertFalse(executor._allows(native.PS,('-ax','-o',native.PS_FIELDS)))
        # The existing row parser still rejects missing/foreign PID authority.
        for raw,pids in ((b'',(123,)),(self.master,(123,))):
            with self.subTest(refusal='missing_or_foreign'):
                with self.assertRaises(Refused):native.NativeSmtpPeerInspector._rows(raw,pids)
        # A changed birth between the two snapshots must still refuse.
        self.ps_calls=0
        self.after_hook=lambda:setattr(self,'child',self.child.replace(b'14:19:43',b'14:19:44'))
        with self.assertRaises(Refused):self.inspector.inspect(123,time.monotonic()+.5,self.budget)

    def test_exact_native_identity_registered_and_published_on_same_original_budget(self):
        channel,front,_=self.fixture.channel()
        self.assertIs(type(channel.identity),native.NativeSmtpIdentity)
        self.assertEqual(channel.identity.projection(),(123,'127.0.0.1',2525,3130))
        self.assertEqual((channel.identity.descriptor,channel.identity.pcb),(14,self.pcb))
        self.assertTrue(self.fixture.registry.publish(channel,self.fixture.registry.verified(channel,b'OK\t1\tuser='+service_fixtures.fixtures.ALICE.encode()+b'\n')))
        front.settimeout(.2);self.assertTrue(front.recv(4096).startswith(b'OK\t1\t'))

    def test_changed_process_birth_refuses_publication_and_closes_channel(self):
        channel,front,_=self.fixture.channel();receipt=self.fixture.registry.verified(channel,b'OK\t1\tuser='+service_fixtures.fixtures.ALICE.encode()+b'\n')
        self.child=self.child.replace(b'14:19:43',b'14:19:44')
        with self.assertRaises(Refused):self.fixture.registry.publish(channel,receipt)
        front.settimeout(.2);self.assertEqual(front.recv(1),b'')

    def test_replaced_tcp_descriptor_or_pcb_refuses_publication(self):
        for field in ('fd','pcb'):
            with self.subTest(field=field):
                channel,front,_=self.fixture.channel();receipt=self.fixture.registry.verified(channel,b'OK\t1\tuser='+service_fixtures.fixtures.ALICE.encode()+b'\n')
                if field=='fd':self.fd+=1
                else:self.pcb='0xffff800000d2b901'
                with self.assertRaises(Refused):self.fixture.registry.publish(channel,receipt)
                front.settimeout(.2);self.assertEqual(front.recv(1),b'')

    def test_process_changes_during_capture_or_foreign_ancestry_refuse(self):
        self.after_hook=lambda:setattr(self,'child',self.child.replace(b'14:19:43',b'14:19:44'))
        with self.assertRaises(Refused):self.inspector.inspect(123,time.monotonic()+.5,self.budget)
        self.after_hook=None;self.child=self.child.replace(b'123 777 777',b'123 778 777')
        with self.assertRaises(Refused):self.inspector.inspect(123,time.monotonic()+.5,self.budget)

    def test_descriptor_changes_during_capture_refuse_before_identity(self):
        self.tcp_hook=lambda:setattr(self,'fd',self.fd+1)
        with self.assertRaises(Refused):self.inspector.inspect(123,time.monotonic()+.5,self.budget)

    def test_foreign_fresh_budget_refuses_before_files_commands_or_routing_reads(self):
        foreign=OperationBudget(int(time.time())+60)
        with patch.object(native.NativeSmtpPeerInspector,'_files',side_effect=AssertionError),patch.object(native.NativeSmtpPeerInspector,'_query',side_effect=AssertionError),patch.object(self.inspector._topology._routing_plan,'recheck',side_effect=AssertionError):
            with self.assertRaises(Refused):self.inspector.inspect(123,time.monotonic()+.5,foreign)
            with self.assertRaises(Refused):self.inspector._current(foreign,time.monotonic()+.5)
        self.assertEqual(self.calls,[])

    def test_unowned_budget_refuses_before_any_startup_command(self):
        with patch.object(self.budget,'inherited_group',return_value=False),patch.object(self.topology,'recheck',side_effect=AssertionError):
            with self.assertRaises(Refused):native.NativeSmtpPeerInspector._read(self.namespace,self.topology,self.budget)
            with self.assertRaises(Refused):native._MetadataExecutor(self.budget,(777,123))
        self.assertEqual(self.calls,[])

    def test_expired_original_or_absolute_deadline_refuses_before_commands(self):
        with patch.object(native.NativeSmtpPeerInspector,'_query',side_effect=AssertionError):
            with self.assertRaises(Refused):self.inspector.inspect(123,time.monotonic()-.001,self.budget)
            self.case.clock.now=1300
            with self.assertRaises(Refused):self.inspector.inspect(123,time.monotonic()+.5,self.budget)
        self.assertEqual(self.calls,[])

    def test_connected_metadata_exact_shape_and_ambiguous_or_foreign_tcp_refusal(self):
        # Exact retained native connected shape; executable text remains a
        # source projection because the observation did not export child text.
        binary=dict(self.programs)[str(native.SMTPD)][0]
        positive=self.fstat(123)
        self.assertEqual(native.NativeSmtpPeerInspector._fstat(positive,123,'smtpd',binary,2525)[0],14)
        for raw in (positive+positive.splitlines(keepends=True)[-1],positive.replace(b' <-- ',b' --> '),positive.replace(b'127.0.0.1:3130',b'192.0.2.1:3130'),positive.replace(b'259323',b'259324')):
            with self.subTest(raw=raw):
                with self.assertRaises(Refused):native.NativeSmtpPeerInspector._fstat(raw,123,'smtpd',binary,2525)
        with patch.object(native.sys,'platform','linux'),patch.object(native.NativeSmtpPeerInspector,'_read',side_effect=AssertionError):
            with self.assertRaises(Refused):native.NativeSmtpPeerInspector.native(self.namespace,self.topology,self.budget)


class PerChannelOwnershipTests(unittest.TestCase):
    # Reuse fixture helpers without inheriting and duplicating its nine tests.
    setUp=NativePeerTests.setUp
    fstat=NativePeerTests.fstat
    execute=NativePeerTests.execute
    execute_tail=NativePeerTests.execute_tail
    def fresh(self):
        budget=OperationBudget(int(time.time())+60)
        owned=patch.object(budget,'inherited_group',return_value=True);owned.start();self.addCleanup(owned.stop)
        return budget

    def bridge(self):
        return native.NativeSmtpOwnership._read(self.inspector,self.case.routing)

    def test_two_channels_keep_separate_original_budgets_after_startup_expiry(self):
        startup=self.budget;bridge=self.bridge();self.case.clock.now=1300
        self.fixture.registry._authority=OwnedSmtpPeerAuthority((os.getuid(),os.getgid()),(os.getuid(),os.getgid()),2525,bridge)
        channels=[]
        for account,request in ((service_fixtures.fixtures.ALICE,1),(service_fixtures.fixtures.BOB,2)):
            budget=self.fresh();self.budget=budget;self.fixture.budget=budget
            binding=bridge.prepare(budget)
            channel,front,_=self.fixture.channel(account,request);channels.append(channel)
            self.assertIs(channel.budget,budget);self.assertIs(bridge.prepared(budget),binding.inspector)
            self.assertIsNot(channel.budget,startup)
            line=b'OK\t'+str(request).encode()+b'\tuser='+account.encode()+b'\n'
            self.assertTrue(self.fixture.registry.publish(channel,self.fixture.registry.verified(channel,line)))
            front.settimeout(.2);self.assertEqual(front.recv(4096),line)
        self.assertEqual(len(self.fixture.registry._channels),2)
        self.assertIsNot(channels[0].budget,channels[1].budget)
        self.assertIsNot(bridge.prepared(channels[0].budget),bridge.prepared(channels[1].budget))

    def test_unprepared_foreign_or_repeated_prepare_cannot_renew_channel(self):
        bridge=self.bridge();foreign=self.fresh()
        with patch.object(native.NativeSmtpPeerInspector,'_query',side_effect=AssertionError):
            with self.assertRaises(Refused):bridge.prepared(foreign)
        self.budget=self.fresh();binding=bridge.prepare(self.budget)
        with patch.object(self.case.routing,'admit',side_effect=AssertionError):
            with self.assertRaises(Refused):bridge.prepare(self.budget)
        self.assertIs(bridge.prepared(self.budget),binding.inspector)
        expired=patch.object(self.budget,'remaining',side_effect=Refused('synthetic original expiry'))
        with expired:
            with self.assertRaises(Refused):bridge.prepared(self.budget)

    def test_changed_startup_master_custody_cannot_prepare_new_channel(self):
        bridge=self.bridge();self.budget=self.fresh();self.master=self.master.replace(b'14:33:31',b'14:33:32')
        with self.assertRaises(Refused):bridge.prepare(self.budget)
        self.assertFalse(hasattr(self.budget,'_smtp_channel_ownership'))


class MetadataPairTests(unittest.TestCase):
    def test_tail_preserves_cross_pid_intervals_with_uneven_jobs_and_owned_fault_cleanup(self):
        # Actual local child supervision; only fixed public CLI data/programs
        # are projected. This is not installed OpenBSD latency qualification.
        from types import SimpleNamespace
        class PreviousInspector(native.NativeSmtpPeerInspector):
            # Exact prior phase barriers, retained inline so the repository test
            # never depends on an external evidence directory or Git checkout.
            def inspect(self,pid,deadline,budget):
                native._require(type(pid)is int and 1<pid<=2**31-1 and type(budget)is OperationBudget
                         and budget is self._budget and type(deadline)in (int,float)and time.monotonic()<deadline
                         and deadline-time.monotonic()<=0.5)
                self._current(budget,deadline)
                pids=(self._master[0],pid);executor=native._MetadataExecutor(budget,pids)
                rows=self._process_rows(executor,pids,budget,deadline);child=rows[pid]
                native._require(rows[self._master[0]]==self._master and child[1:5]==(self._master[0],self._master[0],*self._postfix)and child[-1]=='smtpd')
                programs=dict(self._files_custody)
                results=executor.pair(native.FSTAT,tuple(('-n','-p',str(value))for value in pids),deadline)
                native._require(type(results)is tuple and len(results)==2)
                master_raw,child_raw=tuple(self._checked(result,budget,deadline)for result in results)
                self._fstat(master_raw,self._master[0],'master',programs[str(native.MASTER)][0])
                connection=self._fstat(child_raw,pid,'smtpd',programs[str(native.SMTPD)][0],self._namespace._backend_port)
                native._require(self._process_rows(executor,pids,budget,deadline)==rows)
                native._require(self._fstat(self._query(executor,native.FSTAT,('-n','-p',str(pid)),budget,deadline),pid,'smtpd',programs[str(native.SMTPD)][0],self._namespace._backend_port)==connection)
                self._current(budget,deadline)
                return native.NativeSmtpIdentity(child,self._master,*connection)
        previous=SimpleNamespace(NativeSmtpPeerInspector=PreviousInspector,PS=native.PS,FSTAT=native.FSTAT,
            MASTER=native.MASTER,SMTPD=native.SMTPD,PS_FIELDS=native.PS_FIELDS)
        real=subprocess.Popen
        def exercise(module,*,uneven=False,fail_second_tail=False,changed_final=False):
            budget=OperationBudget(int(time.time())+30)
            inspector=object.__new__(module.NativeSmtpPeerInspector)
            master=b'777 1 777 0 0 Thu Oct 1 14:33:31 2026 master\n'
            child=b'123 777 777 507 507 Thu Oct 15 14:19:43 2026 smtpd\n'
            records=module.NativeSmtpPeerInspector._rows(master+child,(777,123))
            inspector._master=records[777];inspector._postfix=(507,507);inspector._budget=budget
            inspector._namespace=SimpleNamespace(_backend_port=2525)
            inspector._files_custody=tuple((str(path),((os.makedev(4,3),ino,0,7,0o100755,1,100,1,1),()))
                for path,ino in ((module.MASTER,259311),(module.SMTPD,259323)))
            events=[];children=[];calls={};validated={};custody=[]
            inspector._current=lambda b,d:custody.append((b,d))
            original_rows=inspector._rows;original_fstat=inspector._fstat
            def rows(raw,pids):
                result=original_rows(raw,pids)
                for pid in pids:
                    key=('ps',pid);validated[key]=validated.get(key,0)+1
                    events.append(('validated',('master'if pid==777 else'child')+('_before'if validated[key]==1 else'_after')))
                return result
            def fstat(raw,pid,*args):
                result=original_fstat(raw,pid,*args);key=('fstat',pid);validated[key]=validated.get(key,0)+1
                events.append(('validated','master_fstat'if pid==777 else'child_fstat'if validated[key]==1 else'child_final'))
                return result
            inspector._rows=rows;inspector._fstat=fstat
            def launch(command,**options):
                program=command[0];pid=int(command[2]if program==module.PS else command[-1])
                self.assertIn(pid,(777,123));self.assertIs(options['shell'],False)
                self.assertTrue(options['close_fds']);self.assertIs(options['start_new_session'],False)
                self.assertEqual(options['env'],{'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C'})
                key=(program,pid);calls[key]=calls.get(key,0)+1
                name=('master'if pid==777 else'child')+('_before'if calls[key]==1 else'_after')if program==module.PS else'master_fstat'if pid==777 else'child_fstat'if calls[key]==1 else'child_final'
                events.append(('launch',name))
                self.assertLessEqual(sum(c.poll()is None for c in children),1)
                if fail_second_tail and name=='child_fstat':raise OSError('fixed local second-tail-spawn')
                if program==module.PS:
                    self.assertEqual(command,(module.PS,'-p',str(pid),'-o',module.PS_FIELDS));raw=master if pid==777 else child
                else:
                    self.assertEqual(command,(module.FSTAT,'-n','-p',str(pid)))
                    raw=HEADER+(b'root master 777 text 4,3 259311 100755 r 100\n'if pid==777 else
                        b'_postfix smtpd 123 text 4,3 259323 100755 r 100\n_postfix smtpd 123 14* internet stream tcp 0xffff800000d2b900 127.0.0.1:2525 <-- 127.0.0.1:3130\n')
                    if changed_final and name=='child_final':raw=raw.replace(b'0xffff800000d2b900',b'0xffff800000d2b901')
                delay=.24 if uneven and name in ('master_fstat','child_after')else .001
                if fail_second_tail and name=='master_fstat':delay=.24
                process=real((sys.executable,'-I','-c','import sys,time;time.sleep(float(sys.argv[1]));sys.stdout.write(sys.argv[2])',str(delay),raw.decode('ascii')),**options)
                children.append(process);return process
            error=None;result=None;deadline=time.monotonic()+.5
            with patch.object(budget,'inherited_group',return_value=True),patch('subprocess.Popen',side_effect=launch),patch.object(module.NativeSmtpPeerInspector,'_rows',staticmethod(rows)):
                try:result=inspector.inspect(123,deadline,budget)
                except (Refused,TimeoutError,OSError)as caught:error=caught
            self.assertTrue(all(c.returncode is not None and c.stdout.closed and c.stderr.closed for c in children))
            self.assertTrue(all(b is budget and d==deadline for b,d in custody))
            return error,result,events,children,custody
        old_error,_,_,_,_=exercise(previous,uneven=True)
        self.assertIsNotNone(old_error)  # Old global barriers exceed same .5s.
        error,result,events,children,custody=exercise(native,uneven=True)
        self.assertIsNone(error);self.assertEqual(result.projection(),(123,'127.0.0.1',2525,3130))
        self.assertEqual(len(children),7);self.assertEqual(len(custody),2)
        positions={event:i for i,event in enumerate(events)}
        for name in ('master_fstat','child_fstat'):
            for before in ('master_before','child_before'):
                self.assertLess(positions[('validated',before)],positions[('launch',name)])
        self.assertLess(positions[('validated','child_fstat')],positions[('launch','child_after')])
        self.assertLess(positions[('launch','child_after')],positions[('validated','master_fstat')])
        for first in ('master_fstat','child_fstat'):
            self.assertLess(positions[('validated',first)],positions[('launch','master_after')])
        for after in ('master_after','child_after'):
            self.assertLess(positions[('validated',after)],positions[('launch','child_final')])
        for mode in ('second_spawn','final_mismatch'):
            with self.subTest(mode=mode):
                error,_,events,children,custody=exercise(native,fail_second_tail=mode=='second_spawn',changed_final=mode=='final_mismatch')
                self.assertIsNotNone(error);self.assertEqual(len(custody),1)
                self.assertEqual(len(children),3 if mode=='second_spawn'else 7)

    def test_original_deadline_pair_preserves_exact_rows_and_reaps_both_children(self):
        # Same sub-.5s cap: two .18s public jobs cannot fit serially. This uses
        # actual owned local children but projects the fixed native command.
        budget=OperationBudget(int(time.time())+30)
        rows={777:b'777 1 777 0 0 Thu Oct 1 14:33:31 2026 master\n',
              123:b'123 777 777 507 507 Thu Oct 15 14:19:43 2026 smtpd\n'}
        real=subprocess.Popen;children=[]
        def launch(command,**options):
            self.assertEqual(command,(native.PS,'-p',command[2],'-o',native.PS_FIELDS))
            pid=int(command[2]);self.assertIn(pid,rows)
            self.assertIs(options['shell'],False);self.assertTrue(options['close_fds'])
            self.assertIs(options['start_new_session'],False)
            child=real((sys.executable,'-I','-c',
                'import sys,time;time.sleep(.18);sys.stdout.write(sys.argv[1])',rows[pid].decode('ascii')),**options)
            children.append(child);return child
        with patch.object(budget,'inherited_group',return_value=True),patch('subprocess.Popen',side_effect=launch):
            executor=native._MetadataExecutor(budget,(777,123))
            deadline=time.monotonic()+.32
            result=native.NativeSmtpPeerInspector._process_rows(executor,(777,123),budget,deadline)
            self.assertEqual(set(result),{777,123});self.assertLess(time.monotonic(),deadline)
        self.assertEqual(len(children),2)
        self.assertTrue(all(c.returncode==0 and c.stdout.closed and c.stderr.closed for c in children))

    def test_second_spawn_failure_disposes_first_and_uncertain_cleanup_quarantines(self):
        budget=OperationBudget(int(time.time())+30);real=subprocess.Popen;children=[]
        def launch(command,**options):
            if children:raise OSError('synthetic fixed second-spawn refusal')
            child=real((sys.executable,'-I','-c','import time;time.sleep(2)'),**options)
            children.append(child);return child
        with patch.object(budget,'inherited_group',return_value=True),patch('subprocess.Popen',side_effect=launch):
            executor=native._MetadataExecutor(budget,(777,123))
            with self.assertRaises(OSError):executor.pair(native.PS,tuple(('-p',str(p),'-o',native.PS_FIELDS)for p in (777,123)),time.monotonic()+.5)
        self.assertEqual(len(children),1);self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
        # Project only unconfirmed wait, no live child is intentionally leaked.
        import io
        class Unconfirmed:
            stdout=io.BytesIO();stderr=io.BytesIO()
            def poll(self):return None
            def kill(self):pass
            def wait(self,timeout):raise subprocess.TimeoutExpired('fixed',timeout)
        pending=Unconfirmed();calls=[pending]
        def refused_second(*args,**kwargs):
            if calls:return calls.pop()
            raise OSError('synthetic second-spawn refusal')
        with patch.object(native._MetadataExecutor,'_retained',[])as retained, \
             patch.object(native._MetadataExecutor,'_quarantined',False), \
             patch.object(budget,'inherited_group',return_value=True),patch('subprocess.Popen',side_effect=refused_second):
            executor=native._MetadataExecutor(budget,(777,123))
            with self.assertRaisesRegex(Refused,'cleanup unconfirmed'):
                executor.pair(native.PS,tuple(('-p',str(p),'-o',native.PS_FIELDS)for p in (777,123)),time.monotonic()+.5)
            self.assertEqual(retained,[pending]);self.assertTrue(native._MetadataExecutor._quarantined)
            with self.assertRaises(Refused):native._MetadataExecutor(budget,(777,123))


if __name__=='__main__':unittest.main(verbosity=2)
