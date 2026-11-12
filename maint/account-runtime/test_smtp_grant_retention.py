"""Actual private bounded journals; synthetic signed authorizations, no host."""
import hashlib,hmac,json,os,unittest
from unittest.mock import patch
from account_guarded_mutation import canonical,payload
from account_mutation_budget import envelope
from account_mutation_codec import encoded,SCHEMA,ACTION
from authoritative_password import Refused
import smtp_auth_control_service as service
import smtp_control_authorization as proof
import test_smtp_control_service as fixtures

class Retention(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.ServiceTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.clock=self.f.clock;self.journal=self.f.journal;self.alice=fixtures.fixtures.ALICE
    def authorization(self,index,sent=None):
        sent=int(self.clock.now*1000)if sent is None else sent;deadline=sent+1000
        source=json.loads(fixtures.guarded(sent=sent,deadline=deadline));value=json.loads(bytes.fromhex(source['budget']['request_hex']))
        value['intent_reference']=f'{index:064x}'
        fields=('account','epoch','intent_reference','session_id','request_id','source','issued','expires','current','new','confirmation')
        value['signature']=hmac.new(fixtures.KEY,encoded([SCHEMA,ACTION,'request',*[value[k]for k in fields]]),hashlib.sha256).hexdigest()
        raw=encoded(value);source['budget']=json.loads(envelope(raw,fixtures.KEY,sent,deadline))
        p=source['session_proof'];p.update(intent_reference=value['intent_reference'],request_sha256=hashlib.sha256(raw).hexdigest(),budget_sha256=hashlib.sha256(canonical(source['budget'])).hexdigest())
        p['signature']=hmac.new(fixtures.SESSION_KEY,payload(p),hashlib.sha256).hexdigest()
        delegated=proof.derive_authorization(encoded(source),fixtures.KEY,fixtures.SESSION_KEY,self.f.authority,int(self.clock.now*1000))
        checked=proof.verify_authorization(delegated,self.f.authority,int(self.clock.now*1000))
        budget=checked.budget(received_mono=self.clock.now,received_millis=int(self.clock.now*1000),monotonic=self.clock,clock_millis=lambda:int(self.clock.now*1000))
        return delegated,checked,budget
    def complete(self,index):
        raw,action,budget=self.authorization(index)
        with self.journal.claim(action,hashlib.sha256(raw).hexdigest(),budget):pass
        return raw
    def record(self):return self.journal._record(self.journal._paths(self.alice)[1])
    def fill(self):
        for index in range(1,33):self.complete(index)
        self.assertEqual(len(self.record()['entries']),32)
    def test_actual32_completion_bounded_until_expiry_then_fresh_signed_grant(self):
        self.fill();raw,action,budget=self.authorization(33)
        with self.assertRaises(Refused):
            with self.journal.claim(action,hashlib.sha256(raw).hexdigest(),budget):self.fail('cap bypass')
        self.clock.now=1001
        try:self.complete(33)
        except Refused:self.fail('fresh signed grant refused after32 completed original deadlines expired')
        record=self.record()
        self.assertEqual(record['version'],2);self.assertEqual(len(record['entries']),1);self.assertEqual(record['entries'][0]['state'],'complete')
        self.assertEqual(record['entries'][0]['deadline_millis'],1002000);self.assertEqual(record['high_water_millis'],1001000)
        self.assertEqual((self.journal.MAX_ENTRIES,self.journal.RECORD_LIMIT),(32,8192));self.assertLessEqual(self.journal._paths(self.alice)[1].stat().st_size,8192)
    def test_expired_original_proof_and_restart_clock_rollback_never_reuse_pruned_grant(self):
        old=self.complete(1);self.clock.now=1001;self.complete(2)
        self.journal=service.ControlGrantStore(self.journal.root,os.getuid());before=self.journal._paths(self.alice)[1].read_bytes()
        with self.assertRaises(Refused):proof.verify_authorization(old,self.f.authority,1001000)
        self.clock.now=1000;action=proof.verify_authorization(old,self.f.authority,1000000)
        budget=action.budget(received_mono=1000,received_millis=1000000,monotonic=self.clock,clock_millis=lambda:1000000)
        with self.assertRaises(Refused):
            with self.journal.claim(action,hashlib.sha256(old).hexdigest(),budget):self.fail('rollback replay')
        self.assertEqual(self.journal._paths(self.alice)[1].read_bytes(),before);self.assertEqual(len(self.f.fixture.registry._cutoffs),0)
    def test_unexpired_complete_replay_refused_after_restart(self):
        old=self.complete(1);self.journal=service.ControlGrantStore(self.journal.root,os.getuid())
        action=proof.verify_authorization(old,self.f.authority,1000000);budget=action.budget(received_mono=1000,received_millis=1000000,monotonic=self.clock,clock_millis=lambda:1000000)
        with self.assertRaises(Refused):
            with self.journal.claim(action,hashlib.sha256(old).hexdigest(),budget):self.fail('same grant')
        self.assertEqual(len(self.record()['entries']),1)
    def test_claimed_and_uncertain_never_expire_or_clear_on_restart(self):
        for wanted in ('claimed','uncertain'):
            parent=self.f.f.root/('journal-'+wanted);parent.mkdir(mode=0o700)
            self.journal=service.ControlGrantStore(parent,os.getuid());self.journal.provision(self.alice);self.clock.now=1000
            raw,action,budget=self.authorization(1);publish=self.journal._publish
            def write(path,value):
                if wanted=='claimed'and value['entries']and value['entries'][-1]['state']=='uncertain':raise OSError('synthetic uncertainty persistence failure')
                return publish(path,value)
            with patch.object(self.journal,'_publish',side_effect=write):
                with self.assertRaises(RuntimeError):
                    with self.journal.claim(action,hashlib.sha256(raw).hexdigest(),budget):raise RuntimeError('synthetic abandoned dispatch')
            self.assertEqual(self.record()['entries'][0]['state'],wanted)
            before=self.journal._paths(self.alice)[1].read_bytes();self.clock.now=1001;self.journal=service.ControlGrantStore(parent,os.getuid());raw,action,budget=self.authorization(2)
            with self.assertRaises(Refused):
                with self.journal.claim(action,hashlib.sha256(raw).hexdigest(),budget):self.fail('unresolved expiry')
            self.assertEqual(self.journal._paths(self.alice)[1].read_bytes(),before)
    def test_legacy_missing_deadline_extra_and_invalid_records_never_recreated(self):
        raw,action,budget=self.authorization(1);path=self.journal._paths(self.alice)[1]
        valid={'version':2,'high_water_millis':0,'entries':[]}
        invalid=({'version':1,'entries':[]},{'version':2,'high_water_millis':True,'entries':[]},{**valid,'extra':1},
            {**valid,'entries':[{'intent':'a'*64,'authorization_sha256':'b'*64,'state':'complete'}]},
            {**valid,'entries':[{'intent':'a'*64,'authorization_sha256':'b'*64,'state':'complete','deadline_millis':0}]})
        for value in invalid:
            self.journal._publish(path,value);before=path.read_bytes()
            with patch.object(self.journal,'_publish')as publish:
                with self.assertRaises(Refused):
                    with self.journal.claim(action,hashlib.sha256(raw).hexdigest(),budget):self.fail('corrupt admission')
                publish.assert_not_called()
            self.assertEqual(path.read_bytes(),before)
    def test_retirement_publish_failure_preserves_original_full_durable_journal(self):
        self.fill();path=self.journal._paths(self.alice)[1];before=path.read_bytes();self.clock.now=1001;raw,action,budget=self.authorization(33)
        with patch.object(self.journal,'_publish',side_effect=OSError('synthetic retirement publication failure')):
            with self.assertRaises(OSError):
                with self.journal.claim(action,hashlib.sha256(raw).hexdigest(),budget):self.fail('unpublished grant')
        self.assertEqual(path.read_bytes(),before);self.journal=service.ControlGrantStore(self.journal.root,os.getuid());self.assertEqual(len(self.record()['entries']),32)
if __name__=='__main__':unittest.main(verbosity=2)
