"""Strict consumer for one startup-only native result."""
import base64,hashlib,importlib.util,json,re,math
from pathlib import Path
from functools import lru_cache


def require(value,code):
    if not value:raise RuntimeError(code)


def inspect(value,code,expiry,packet):
    require(type(value)is dict and value.get('schema')=='osmap-single-host-transport-v1','transport_schema')
    require(type(code)is int and code in (0,1) and value['root_exit']==code
        and value['result']==('COMPLETE'if code==0 else'FAIL')and value['born_child_reaped']is True
        and value['born_group_gone']is True and value['stderr_bytes']==0
        and value['failure']is None,'transport_or_cleanup')
    frames=value['frames'];require(type(frames)is list and len(frames)==4,'four_frames')
    birth1,birth2,ready,actor=frames
    require(birth1['schema']==birth2['schema']=='osmap-single-host-stage-birth-v1'
        and ready['schema']=='osmap-single-host-stage-ready-v1','stage_order')
    require(birth1['frontend']is None and birth1['backend']==birth2['backend']==ready['backend']
        and birth2['frontend']==ready['frontend'],'stage_binding')
    require(all(frame['not_after_utc']==expiry for frame in frames[:3]),'actor_lease_binding')
    require(ready['source_commit']==packet['source_commit']
        and ready['compiler_receipt_sha256']==packet['compiler_receipt_sha256']
        and ready['compiler_source_manifest_sha256']==packet['compiler_source_manifest_sha256']
        and ready['helper_sha256']==packet['helper']['sha256']
        and ready['web_sha256']==packet['web']['sha256']
        and ready['packet_sha256']==hashlib.sha256(json.dumps(packet,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'current_build_binding')
    probe=packet.get('operation')=='confinement-probe'
    require(probe==(actor.get('schema')=='osmap-single-host-confinement-probe-v1')
        and (packet.get('operation')=='password-change')==(actor.get('schema')=='osmap-single-host-controlled-journey-v1'),
        'operation_actor_binding')
    if actor.get('schema')in('osmap-single-host-controlled-journey-v1','osmap-single-host-confinement-probe-v1'):
        if actor.get('native_diagnostic_evidence')is not None:
            require(actor['native_diagnostic_evidence']['record']['execution_admission_sha256']==
                ready.get('admission_sha256'),'native_diagnostic_execution_binding')
        if probe:
            require(code==1 and actor.get('result')=='FAIL'
                and actor.get('start_message_sent')is False
                and type(actor.get('observed_http_requests'))is int and actor['observed_http_requests']==0
                and actor.get('ready_only_qualified')is False
                and type(actor.get('ready_observed'))is bool,'confinement_probe_scope')
            accepted=inspect_mutation_failure(actor,packet)
            accepted.update(operation='confinement-probe',ready_observed=actor['ready_observed'],
                ready_only_qualified=False,observed_http_requests=0,start_message_sent=False)
            return accepted
        if code==1 and actor.get('result')=='FAIL':return inspect_mutation_failure(actor,packet)
        require(code==0,'actor_exit_consistency')
        return inspect_mutation(actor,packet)
    require(code==0,'actor_exit_consistency')
    if actor.get('schema')=='osmap-single-host-admission-v1':
        return inspect_admission(actor,packet)
    require(actor['schema']=='osmap-single-host-startup-v1'and actor['result']=='PASS'
        and actor['functional_result']=='PASS'and actor['disposition']=='CONFIRMED','startup_result')
    require(actor['password_mutation']is False and actor['credential_request_frames']==0
        and all(actor[key]is False for key in('public_service_controls','public_config_writes','relay_operations','credential_values_retained')),'startup_scope')
    require(actor['authoritative_no_write']=={'actual_write_observed':False,
        'Alice_exact17_preserved':True,'Alice_epoch':0,'Alice_state':'active','Alice_changed_at':None,
        'Bob_all17_preserved':True,'Bob_epoch':0,'Bob_state':'active'},'authoritative_no_write')
    expected=('ServiceStartup','ServiceFiles','ServiceAdmission','ServiceAccounts','ServiceStore',
        'AdmissionBind','MutationBind','ParentPrepare','ParentSeal','AcceptanceLoop')
    require(actor['native_stages']=={name:'PASS'for name in expected},'native_stage_chain')
    readiness=actor['service_readiness']
    require(0<readiness['startup_seconds']<5 and readiness['startup_deadline_seconds']==5
        and readiness['paired_sockets_published']is True and readiness['parent_prepare']is True
        and readiness['parent_seal']is True
        and readiness['acceptance_proof']=='AUTHORIZED_UID_CONNECT_EOF_HANDLED_ON_BOTH_SOCKETS'
        and readiness['service_binary_sha256']==packet['helper']['sha256'],'native_readiness')
    require(set(readiness['socket_metadata'])=={'/var/run/osmap-account-admission/admission.sock','/var/run/osmap-account-mutation/mutation.sock'}
        and all(meta['uid']==0 and type(meta['gid'])is int and meta['gid']>0 and type(meta['mode'])is int
            for meta in readiness['socket_metadata'].values()),'socket_custody')
    require(set(readiness['probes'])=={'admission','mutation'}
        and all(set(probe)=={'connected_ms','handled_ms','cleanup_confirmed'}and probe['cleanup_confirmed']is True
            and 0<=probe['connected_ms']<=probe['handled_ms']<12000 for probe in readiness['probes'].values()),'socket_probes')
    owned=actor['owned_effects_report']
    require(all(owned[key]is True for key in('cleanup_confirmed','public_original25_preserved','public_master_preserved','owned_sql_hash_uids_absent')),'owned_cleanup')
    require(type(actor['elapsed_millis'])is int and 0<actor['elapsed_millis']<=300000,'actor_elapsed')
    return {'result':'PASS','disposition':'CONFIRMED','startup_seconds':readiness['startup_seconds'],
        'probes':readiness['probes'],'native_stages':actor['native_stages'],'socket_metadata':readiness['socket_metadata'],
        'source_commit':packet['source_commit'],'compiler_receipt_sha256':packet['compiler_receipt_sha256'],'compiler_source_manifest_sha256':packet['compiler_source_manifest_sha256'],'service_binary_sha256':readiness['service_binary_sha256'],
        'password_mutation':False,'authoritative_no_write':actor['authoritative_no_write'],
        'public_service_operations':False,'cleanup_confirmed':True}


def inspect_admission(actor,packet):
    require(actor['result']=='PASS' and actor['functional_result']=='PASS'
        and actor['disposition']=='CONFIRMED','admission_result')
    require(actor['password_mutation'] is False and actor['mutation_frames']==0
        and actor['admission_frames']==6 and all(actor[k] is False for k in
        ('public_service_controls','public_config_writes','relay_operations','credential_values_retained')),'admission_scope')
    requests=actor['requests']
    cases={'alice_authenticate':('active','alice@osmap-password.invalid',0),
        'alice_admit':('active','alice@osmap-password.invalid',0),
        'alice_wrong_password':('rejected','alice@osmap-password.invalid',None),
        'alice_wrong_epoch':('rejected','alice@osmap-password.invalid',None),
        'bob_authenticate':('active','bob@osmap-password.invalid',0)}
    require(set(requests)==set(cases)|{'invalid_mac'},'admission_cases')
    for name,(status,account,epoch) in cases.items():
        v=requests[name]
        require(v['result']=='PASS' and v['status']==status and v['account']==account
            and v['epoch']==epoch and v['authenticated_response'] is True,'signed_response_'+name)
    for name,v in requests.items():
        require(v['result']=='PASS' and v['cleanup_confirmed'] is True and v['frame_sent'] is True
            and v['caller_uid']==1001 and v['server_peer_uid']==0
            and type(v['round_trip_ms']) in (int,float) and 0<v['round_trip_ms']<30000,'native_boundary_'+name)
    integrity=requests['invalid_mac'];diagnostic=actor['helper_diagnostic']
    require(integrity['status']=='closed' and integrity['authenticated_response'] is False
        and integrity['native_refusal']=='Authentication'
        and diagnostic['helper_trace_stage']=='stock_admission'
        and diagnostic['helper_trace_error']=='Authentication','integrity_refusal')
    accounts={'alice@osmap-password.invalid','bob@osmap-password.invalid'}
    require(actor['authoritative_preservation'] is True and set(actor['baseline'])==accounts
        and actor['baseline']==actor['after'],'authoritative_preservation')
    for account,v in actor['baseline'].items():
        require(v['account']==account and v['epoch']==0 and v['state']=='active'
            and v['changed_at'] is None,'initial_authority')
    require(actor['authoritative_no_write']['actual_write_observed'] is False,'credential_preservation')
    require(actor['stored_sessions']['issuance']=='NOT_RUN'
        and actor['stored_sessions']['existing_controlled_session']=='ABSENT_IN_THIS_FIXTURE','session_scope')
    ready=actor['service_readiness'];owned=actor['owned_effects_report']
    require(ready['parent_prepare'] is True and ready['parent_seal'] is True
        and ready['service_binary_sha256']==packet['helper']['sha256'],'native_service')
    require(all(owned[k] is True for k in ('cleanup_confirmed','public_original25_preserved',
        'public_master_preserved','owned_sql_hash_uids_absent')),'owned_cleanup')
    require(diagnostic['helper_reaped'] is True and diagnostic['helper_exit_code']==0
        and diagnostic['helper_signaled'] is False,'helper_cleanup')
    return {'result':'PASS','disposition':'CONFIRMED','requests':requests,
        'startup_seconds':ready['startup_seconds'],'fixture_overhead_seconds':actor['fixture_overhead_seconds'],
        'authoritative_preservation':True,'stored_sessions':actor['stored_sessions'],
        'source_commit':packet['source_commit'],'service_binary_sha256':packet['helper']['sha256'],
        'password_mutation':False,'cleanup_confirmed':True}


@lru_cache(maxsize=1)
def diagnostic_validators():
    # Source-owned paths only: never import code or select paths from a result.
    root=Path(__file__).resolve().parent
    modules=[]
    for name,leaf in (('diagnostic_actor','sources/backend/local_journey.py'),
            ('diagnostic_frontend','sources/backend/local_frontend.py'),
            ('diagnostic_guardian','sources/frontend/native_http_web_guardian.py')):
        spec=importlib.util.spec_from_file_location(name,root/leaf)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        modules.append(module)
    return tuple(modules)


def inspect_native_diagnostic(actor,packet):
    """Only fixed source-owned diagnostics cross the final result boundary."""
    evidence=actor.get('native_diagnostic_evidence')
    if evidence is None:return None
    require(type(evidence)is dict and set(evidence)=={'record','sha256',
        'readback_verified','recovery_sha256'},'native_diagnostic_evidence_fields')
    require(evidence['readback_verified']is True,'native_diagnostic_readback')
    record=evidence['record']
    require(type(record)is dict and set(record)=={'schema','execution_admission_sha256',
        'source_commit','compiler_source_manifest_sha256','helper_sha256','web_sha256',
        'native_diagnostic'}and record['schema']=='osmap-native-diagnostic-evidence-v1',
        'native_diagnostic_record_fields')
    for value in (evidence['sha256'],evidence['recovery_sha256'],record['execution_admission_sha256']):
        require(type(value)is str and re.fullmatch('[a-f0-9]{64}',value)is not None,
            'native_diagnostic_digest')
    require(record['source_commit']==packet['source_commit']
        and record['compiler_source_manifest_sha256']==packet['compiler_source_manifest_sha256']
        and record['helper_sha256']==packet['helper']['sha256']
        and record['web_sha256']==packet['web']['sha256'],'native_diagnostic_source_binding')
    raw=json.dumps(record,sort_keys=True,separators=(',',':')).encode()
    require(len(raw)<=32768 and hashlib.sha256(raw).hexdigest()==evidence['sha256'],
        'native_diagnostic_integrity')
    _,frontend,guardian=diagnostic_validators()
    frontend.validate_native_diagnostic(record['native_diagnostic'],guardian.validate_diagnostic,guardian.validate_capture)
    observation=record['native_diagnostic']['guardian_diagnostic']
    if observation is not None:
        source=observation['source']
        require(source['binary_sha256']is None or source['binary_sha256']==packet['web']['sha256'],
            'native_diagnostic_binary_binding')
        if 'sources'in packet:
            sources={Path(name).name:hashlib.sha256(base64.b64decode(raw,validate=True)).hexdigest()
                for name,raw in packet['sources'].items()if name.startswith('frontend/')}
            require(source['guardian_sha256']is None or source['guardian_sha256']==
                sources.get('native_http_web_guardian.py'),'native_diagnostic_guardian_binding')
            expected=hashlib.sha256((json.dumps(sources,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()
            require(source['source_manifest_sha256']is None or source['source_manifest_sha256']==expected,
                'native_diagnostic_manifest_binding')
    return evidence


def inspect_cleanup_failures(actor):
    values=actor.get('cleanup_failures',[])
    require(type(values)is list and len(values)<=8,'cleanup_failure_bound')
    actor_module,_,_=diagnostic_validators()
    for value in values:
        require(type(value)is dict and set(value)=={'phase','category','reason'}
            and value['phase']in {'frontend_stop','witness_close','helper_stop',
                'final_authority','owned_disposal','diagnostic_preservation'}
            and value['category']in {'Refused','RuntimeError','OSError','ValueError','TimeoutError',
                'InterruptedError','KeyboardInterrupt','SystemExit','FileNotFoundError','PermissionError','Exception'}
            and value['reason']in actor_module.SAFE_FAILURE_CODES,'cleanup_failure_schema')
    return values


def inspect_mutation_failure(actor,packet):
    """Preserve a bound native failure; confirmation needs independent row proof.

    This reports evidence only. It grants no cleanup or retry authority.
    Missing evidence remains unknown even if the actor claimed clean disposal.
    """
    actor_module,_,_=diagnostic_validators()
    reason=actor.get('failure_reason')
    if type(reason)is not str or reason not in actor_module.SAFE_FAILURE_CODES:
        reason='controlled_journey_failed'
    diagnostic=inspect_native_diagnostic(actor,packet)
    cleanup_failures=inspect_cleanup_failures(actor)
    original_failure={'component':'native_actor','code':reason}
    deficiency='NO_PRESERVED_NATIVE_DIAGNOSTIC'
    completeness='UNAVAILABLE';unknown_cause_reason='NATIVE_CAPTURE_UNAVAILABLE'
    confinement_detail=None;confinement_status='NOT_EMITTED';confinement_code=None
    construction_detail=None;construction_status='NOT_EMITTED'
    if diagnostic is not None:
        native=diagnostic['record']['native_diagnostic']
        guardian=native['guardian_diagnostic'];first=native['first_failure']
        if first is not None:original_failure=first
        # A guardian cancellation observed during shutdown is secondary to an
        # already demonstrated parent READY validation failure. Only replace a
        # closure symptom with its attributable child/guardian failure.
        if (guardian is not None and (first is None or first['code']in
                ('control_eof','CONTROL_IO_FAILED')) and guardian['code']not in
                ('cancelled','guardian_interrupted','UNEXPECTED_SANITIZED')):
            original_failure={key:guardian[key]for key in ('component','stage','operation','code','cause')}
        if original_failure.get('cause')not in (None,'CAUSE_UNKNOWN'):
            unknown_cause_reason=None
        elif guardian is not None and guardian['capture']is not None:
            capture=guardian['capture']
            unknown_cause_reason=('NATIVE_CAPTURE_UNAVAILABLE'if capture['capture_error']is not None
                or not(capture['stdout_eof']and capture['stderr_eof'])else
                'NO_NATIVE_OUTPUT'if capture['stdout_bytes']==capture['stderr_bytes']==0 else
                'NO_ALLOWLISTED_NATIVE_DIAGNOSTIC')
        reason=original_failure.get('cause')if original_failure.get('cause')not in(None,'CAUSE_UNKNOWN')else original_failure['code']
        status=native['guardian_diagnostic_status']
        deficiency=None if status in ('AVAILABLE','NOT_CREATED')else status
        for capture in (native['guardian_capture'],None if guardian is None else guardian['capture']):
            if capture is not None and (capture['capture_error']is not None or
                    not(capture['stdout_eof']and capture['stderr_eof'])):
                deficiency='CAPTURE_INCOMPLETE'
        if guardian is not None and guardian['capture'] is not None:
            capture=guardian['capture']
            confinement_status=capture.get('confinement_status','NOT_EMITTED')
            confinement_detail=capture.get('confinement_detail')
            if confinement_status=='AVAILABLE':
                confinement_code='native_confinement_'+confinement_detail['stage']
            elif confinement_status!='NOT_EMITTED':
                deficiency='CONFINEMENT_DETAIL_'+confinement_status
            construction_status=capture.get('construction_status','NOT_EMITTED')
            construction_detail=capture.get('construction_detail')
            if construction_status not in ('AVAILABLE','NOT_EMITTED'):
                deficiency='CONSTRUCTION_DETAIL_'+construction_status
        completeness='COMPLETE'if deficiency is None else'INCOMPLETE'
    accounts={'alice@osmap-password.invalid','bob@osmap-password.invalid'}
    baseline=actor.get('initial_authority_digests',{});final=actor.get('final_authority',{})
    intents=actor.get('durable_intents',{});owned=actor.get('owned_effects_report',{})
    helper=actor.get('helper_diagnostic',{})
    no_write=(actor.get('mutation_submission_started')is False
        and type(actor.get('mutation_requests'))is int and actor['mutation_requests']==0
        and actor.get('proven_before_submission_no_write')is True
        and type(baseline)is dict and type(final)is dict and type(intents)is dict
        and set(baseline)==set(final)==set(intents)==accounts)
    if no_write:
        for account in accounts:
            row=final[account];intent=intents[account];pin=baseline[account]
            no_write=no_write and type(pin)is str and re.fullmatch('[a-f0-9]{64}',pin)is not None
            no_write=no_write and type(row)is dict and row.get('account')==account \
                and type(row.get('row_count'))is int and row['row_count']==1 \
                and row.get('row_sha256')==pin and type(row.get('epoch'))is int \
                and row['epoch']==0 and row.get('state')=='active'and row.get('changed_at')is None
            no_write=no_write and type(intent)is dict and intent.get('pending_intent')is False \
                and type(intent.get('epoch'))is int \
                and type(intent.get('used_intent_count'))is int and intent=={'epoch':0,
                    'state':'active','changed_at':None,'pending_intent':False,'used_intent_count':0}
    cleanup=(actor.get('disposition')=='CONFIRMED'and no_write
        and all(actor.get(k)is False for k in ('installed_qualification','slice_complete',
            'public_service_controls','public_config_writes','relay_operations','credential_values_retained'))
        and not actor.get('cleanup_failures')and type(owned)is dict
        and all(owned.get(k)is True for k in ('cleanup_confirmed','public_original25_preserved',
            'public_master_preserved','owned_sql_hash_uids_absent'))
        and actor.get('frontend_cleanup')=={'requests_stopped':True,'disposed':True}
        and all(actor['frontend_cleanup'][k]is True for k in ('requests_stopped','disposed'))
        and type(helper)is dict and helper.get('helper_reaped')is True
        and type(helper.get('helper_exit_code'))is int and helper['helper_exit_code']==0
        and helper.get('helper_signaled')is False)
    return {'result':'FAIL','functional_result':'FAIL','failure_reason':reason,
        'original_failure':original_failure,'native_diagnostic_evidence':diagnostic,
        'diagnostic_completeness':completeness,'diagnostic_deficiency':deficiency,
        'unknown_cause_reason':unknown_cause_reason,
        'confinement_code':confinement_code,'confinement_detail':confinement_detail,
        'confinement_status':confinement_status,
        'construction_status':construction_status,'construction_detail':construction_detail,
        'diagnostic_preservation':'READBACK_VERIFIED'if diagnostic is not None else'UNAVAILABLE',
        'cleanup_failures':cleanup_failures,
        'credential_mutation_submission_state':'NOT_SUBMITTED'if no_write else'UNKNOWN_OR_SUBMITTED',
        'authoritative_state_certainty':'CONFIRMED_NO_WRITE'if no_write else'UNKNOWN',
        'disposition':'CONFIRMED'if cleanup else'UNCERTAIN',
        'reported_disposition':actor.get('disposition'),'cleanup_confirmed':bool(cleanup),
        'password_mutation':False if no_write else None,
        'proven_before_submission_no_write':bool(no_write),
        'mutation_requests':actor.get('mutation_requests'),
        'final_authority':final,'durable_intents':intents,
        'http_failure_scalars':actor.get('http_failure_scalars'),
        'actual_http_report':actor.get('actual_http_report'),'timings':actor.get('timings'),
        'source_commit':packet['source_commit'],
        'service_binary_sha256':packet['helper']['sha256'],
        'web_binary_sha256':packet['web']['sha256'],
        'installed_qualification':False,'slice_complete':False}


def inspect_mutation(actor,packet):
    """Consume root observations plus the guarded HTTP journey after disposal."""
    require(actor['result']=='PASS' and actor['functional_result']=='PASS'
        and actor['disposition']=='CONFIRMED','mutation_result')
    diagnostic=inspect_native_diagnostic(actor,packet)
    require(diagnostic is not None,'mutation_diagnostic_missing')
    require(all(actor[k] is False for k in ('installed_qualification','slice_complete',
        'public_service_controls','public_config_writes','relay_operations','credential_values_retained')),
        'mutation_scope')
    require(actor['mutation_submission_started'] is True
        and type(actor['mutation_requests'])is int and actor['mutation_requests']==1
        and type(actor['observed_http_requests'])is int
        and actor['observed_http_requests']==18,
        'mutation_submission')
    proof=actor['mutation_evidence']
    require(type(proof['mutation_requests'])is int and proof['mutation_requests']==1 and all(proof[k] is True for k in
        ('terminal_response_confirmed','old_password_refused','new_password_admitted','bob_account_preserved')),
        'mutation_terminal')
    sessions=proof['alice_sessions'];bob=proof['bob_session'];new=proof['new_alice_session']
    require(type(sessions)is list and len(sessions)==2 and all(type(s['initial_epoch'])is int and s['initial_epoch']==0
        and s['revoked'] is True and s['old_cookie_status']==303 for s in sessions),
        'both_alice_sessions')
    require(type(bob['epoch'])is int and bob['epoch']==0 and bob['preserved'] is True
        and type(new['epoch'])is int and new['epoch']==1,'other_session_epochs')
    ids=[s['session_id_sha256']for s in sessions]+[bob['session_id_sha256'],new['session_id_sha256']]
    require(all(type(v)is str and re.fullmatch('[a-f0-9]{64}',v)for v in ids)
        and len(set(ids))==4,'distinct_persisted_sessions')
    snapshots=actor['authoritative_snapshots']
    require(set(snapshots)=={'SNAPSHOT_A0','SNAPSHOT_A1','SNAPSHOT_B0','SNAPSHOT_B1'},'authority_set')
    before,after,b0,b1=[snapshots[k]for k in('SNAPSHOT_A0','SNAPSHOT_A1','SNAPSHOT_B0','SNAPSHOT_B1')]
    for v,account in ((before,'alice'),(after,'alice'),(b0,'bob'),(b1,'bob')):
        require(v['account']==account+'@osmap-password.invalid' and type(v['row_count'])is int and v['row_count']==1
            and type(v['epoch'])is int
            and all(type(v[k])is str and re.fullmatch('[a-f0-9]{64}',v[k])for k in
                ('row_sha256','noncredential_sha256','password_sha256')),'authority_shape')
    require(before['state']=='active' and before['epoch']==0 and before['changed_at']is None
        and after['state']=='active' and after['epoch']==1
        and type(after['changed_at'])is str and re.fullmatch('[0-9]{14}',after['changed_at'])
        and after['changed_at']==after['sql_changed_at']==actor['known_write_time']
        and after['sql_changed_at']!=before['sql_changed_at']
        and before['row_sha256']!=after['row_sha256']
        and before['password_sha256']!=after['password_sha256']
        and before['noncredential_sha256']==after['noncredential_sha256'],'authoritative_change')
    require(b0==b1 and b1['state']=='active' and b1['epoch']==0 and b1['changed_at']is None,'bob_authority')
    require(actor['final_authority']=={after['account']:after,b1['account']:b1},'final_authority')
    require(all(type(v['epoch'])is int and type(v['used_intent_count'])is int
        and v['pending_intent']is False for v in actor['durable_intents'].values()),'durable_intent_types')
    require(actor['durable_intents']=={after['account']:{'epoch':1,'state':'active',
        'changed_at':after['changed_at'],'pending_intent':False,'used_intent_count':1},
        b1['account']:{'epoch':0,'state':'active','changed_at':None,'pending_intent':False,
            'used_intent_count':0}},'single_durable_mutation_intent')
    mail=actor['mail_witness']
    require(mail['result']=='PASS' and all(mail[k]is True for k in ('bob_mail_projection_preserved',
        'bob_home_absent','bob_mail_absent','public_cache_zero','public_original25_preserved',
        'public_master_preserved')) and type(mail['bob_projection_sha256'])is str
        and re.fullmatch('[a-f0-9]{64}',mail['bob_projection_sha256'])
        and mail['external_sessions_terminated']is False
        and mail['flush_performed']is False,'mail_cache_witness')
    native=actor['actual_http_report']
    require(native['schema']=='osmap-http-password-runtime-v1' and native['handled_connections']==18
        and native['alice_epoch0_refused']is True and native['alice_epoch1_admitted']==1
        and native['bob_epoch0_admitted']==0,'native_http_result')
    require(all(actor['milestones'][k]['result']=='PASS' for k in
        ('milestone1','milestone2','milestone3','milestone4')),'milestone_result')
    ready=actor['milestones']['milestone1']
    require(ready['parent_prepare']is True and ready['parent_seal']is True
        and ready['service_binary_sha256']==packet['helper']['sha256'],'native_service')
    owned=actor['owned_effects_report'];helper=actor['helper_diagnostic']
    require(all(owned[k]is True for k in ('cleanup_confirmed','public_original25_preserved',
        'public_master_preserved','owned_sql_hash_uids_absent'))
        and actor['frontend_cleanup']=={'requests_stopped':True,'disposed':True}
        and helper['helper_reaped']is True and helper['helper_exit_code']==0
        and helper['helper_signaled']is False,'mutation_cleanup')
    timings=actor['timings']
    require(all(type(timings[k])in(int,float) and math.isfinite(timings[k]) and timings[k]>=0
        for k in ('authentication_seconds','totp_wait_seconds','mutation_seconds',
            'authoritative_verification_seconds','cleanup_seconds')),'mutation_timings')
    return {'result':'PASS','disposition':'CONFIRMED','password_mutation':True,
        'native_diagnostic_evidence':diagnostic,
        'mutation_requests':1,'authoritative_snapshots':snapshots,'mutation_evidence':proof,
        'mail_witness':mail,'timings':timings,'cleanup_confirmed':True,
        'source_commit':packet['source_commit'],'service_binary_sha256':packet['helper']['sha256'],
        'web_binary_sha256':packet['web']['sha256'],'installed_qualification':False,'slice_complete':False}
