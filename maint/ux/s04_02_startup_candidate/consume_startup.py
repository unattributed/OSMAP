"""Strict consumer for one startup-only native result."""
import hashlib,json


def require(value,code):
    if not value:raise RuntimeError(code)


def inspect(value,code,expiry,packet):
    require(type(value)is dict and value.get('schema')=='osmap-single-host-transport-v1','transport_schema')
    require(code==0 and value['result']=='COMPLETE'and value['born_child_reaped']is True
        and value['born_group_gone']is True and value['root_exit']==0 and value['stderr_bytes']==0
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
