"""Strict consumer for one startup-only native result."""


def require(value,code):
    if not value:raise RuntimeError(code)


def inspect(value,code,expiry):
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
        and readiness['service_binary_sha256']=='7cd4cba76f27c34060c8ddbf843a1a2d71a06e64675c708327a1861b7bdb3092','native_readiness')
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
        'source_commit':'b4bc371bd645ea009e4d257b269c73bd7294c8e9','service_binary_sha256':readiness['service_binary_sha256'],
        'password_mutation':False,'authoritative_no_write':actor['authoritative_no_write'],
        'public_service_operations':False,'cleanup_confirmed':True}
