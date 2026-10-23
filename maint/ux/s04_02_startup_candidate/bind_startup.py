"""Bind current signed build receipts to the startup-only sources."""
import base64,hashlib,importlib.util,json,os,re,stat,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parent
HISTORICAL=Path('/home/foo/Downloads/osmap-ux-s04/t03-progressive-20261023/milestone1-startup145')
REPO=Path('/home/foo/Workspace/OSMAP')
BUILD_SOURCE_COMMIT='77f63794d3f60e4003db157eada39f4bd4222b6a'
REUSED_HELPER_SHA256='8f1ed891c8349863db59a95ba1e3d4908bc62ba7d583ea8634d3259262ab3559'
SIGNER='F55E404E91A0753701F91B01A7228D3FB5084B34'


def require(value,code):
    if not value:raise RuntimeError(code)


def private(path,cap=4*1024*1024):
    m=path.lstat();require(stat.S_ISREG(m.st_mode)and m.st_uid==os.geteuid()and m.st_nlink==1
        and stat.S_IMODE(m.st_mode)==0o600 and 0<m.st_size<=cap,'private_input_custody')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=(m.st_dev,m.st_ino,m.st_mode,m.st_uid,m.st_gid,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
        ident=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        require(ident(os.fstat(fd))==before,'private_open');raw=os.read(fd,cap+1)
        require(len(raw)==m.st_size and ident(os.fstat(fd))==before and ident(path.lstat())==before,'private_continuity');return raw
    finally:os.close(fd)


def repository_source(path,cap=2*1024*1024):
    m=path.lstat();require(stat.S_ISREG(m.st_mode)and m.st_uid==os.geteuid()
        and m.st_nlink==1 and not m.st_mode&0o002 and 0<m.st_size<=cap,
        'repository_source_custody')
    identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        require(identity(os.fstat(fd))==identity(m),'repository_source_open')
        raw=os.read(fd,cap+1)
        require(len(raw)==m.st_size and identity(os.fstat(fd))==identity(m)
            and identity(path.lstat())==identity(m),'repository_source_changed')
        return raw
    finally:os.close(fd)


def source_packet():
    retained=private(HISTORICAL/'startup-bound-packet.json')
    require(hashlib.sha256(retained).hexdigest()=='c903271b7a535a1f92465216fd47189af6727efa35d207e106793db646fbf313',
        'retained_packet_pin')
    envelope=json.loads(retained)
    require(set(envelope)=={'root_source','packet'}and type(envelope['packet'])is dict,
        'retained_packet_shape')
    value=envelope['packet']
    spec=importlib.util.spec_from_file_location('candidate_stage_root',ROOT/'stage_root.py')
    stage_root=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage_root)
    sources={}
    for name,pin in stage_root.SOURCE_PINS.items():
        path=ROOT/'startup_only.py'if name=='backend/startup_only.py'else ROOT/'sources'/name
        raw=repository_source(path)
        require(hashlib.sha256(raw).hexdigest()==pin,'candidate_source_pin_'+name.replace('/','_'))
        sources[name]=base64.b64encode(raw).decode()
    value['sources']=sources
    return value


def checked_build(receipt_path,manifest_path,*,working=True):
    """Check retained compiler evidence against the exact signed Rust inputs."""
    receipt_raw=private(Path(receipt_path));manifest_raw=private(Path(manifest_path))
    receipt=json.loads(receipt_raw);manifest=json.loads(manifest_raw)
    require(receipt.get('native_result')=='PASS'and receipt.get('remote_disposition')=='CONFIRMED',
        'compiler_not_complete')
    build=receipt['result'];manifest_sha=hashlib.sha256(manifest_raw).hexdigest()
    source_commit=receipt['signed_base_commit']
    require(type(source_commit)is str and re.fullmatch('[a-f0-9]{40}',source_commit)
        and source_commit==build['signed_base_commit'],
        'compiler_source_identity')
    require(receipt['source_manifest_sha256']==build['source_manifest_sha256']==manifest_sha,
        'compiler_manifest_binding')
    require(build['source_before']is True and build['source_after']is True
        and build['cleanup_uncertain']is False and build['scratch_gone']is True
        and build['application_executed']is False
        and build['tests_executed']is False,'compiler_custody')
    spec=importlib.util.spec_from_file_location('bound_build_current',ROOT/'build_current.py')
    compiler=importlib.util.module_from_spec(spec);spec.loader.exec_module(compiler)
    result,disposition=compiler.inspect_receipt(build,receipt['ssh_code'],{
        'signed_base_commit':source_commit,'build_kind':build.get('build_kind','pair'),
        'source_count':len(manifest),'hashes':{'manifest.json':manifest_sha,
            'source.tar.gz':build['archive_sha256']}})
    require(result=='PASS'and disposition=='CONFIRMED'
        and receipt['local_transport_reaped']is True and receipt['local_transport_group_gone']is True,
        'compiler_transport_custody')
    verified=subprocess.run(['git','verify-commit','--raw',source_commit],cwd=REPO,
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    require(verified.returncode==0 and ('[GNUPG:] VALIDSIG '+SIGNER+' ').encode()in verified.stderr,
        'signed_build_source')
    required=set(subprocess.check_output(['git','ls-tree','-r','--name-only',source_commit,
        '--','src','Cargo.toml','Cargo.lock'],cwd=REPO,timeout=5).decode().splitlines())
    require(type(manifest)is dict and required<=set(manifest)
        and type(build['source_count'])is int and build['source_count']==len(manifest),
        'compiler_source_set')
    for name,pin in manifest.items():
        require(type(name)is str and not Path(name).is_absolute()and '..'not in Path(name).parts
            and type(pin)is str and re.fullmatch('[a-f0-9]{64}',pin),'compiler_manifest_entry')
        committed=subprocess.check_output(['git','show',source_commit+':'+name],cwd=REPO,timeout=5)
        require(hashlib.sha256(committed).hexdigest()==pin,'compiler_signed_input_changed')
        if working:
            require(hashlib.sha256(repository_source(REPO/name)).hexdigest()==pin,'compiler_input_changed')
    return receipt,build,manifest,manifest_sha,hashlib.sha256(receipt_raw).hexdigest()


def test_only_helper_reuse(current,previous):
    """Permit only the named timing fixture difference, never product drift."""
    require(set(current)==set(previous),'helper_source_set_changed')
    changed={name for name in current if current[name]!=previous[name]}
    require(changed=={'src/http/password_tests.rs'},'helper_non_test_source_changed')
    # src/http.rs is identical in both manifests and checked against the current
    # working and signed bytes. This exact declaration scopes its sole include.
    http=repository_source(REPO/'src/http.rs').decode('utf-8')
    include='include!("http/password_tests.rs");'
    marker='#[cfg(test)]\nmod tests {'
    require(http.count(include)==1 and http.count(marker)==1,'helper_test_module_binding')
    prefix,tests=http.split(marker)
    require(include not in prefix and re.search(
        r'\bmod password_tests\s*\{\s*include!\("http/password_tests\.rs"\);\s*\}',tests),
        'helper_test_include_binding')
    # This is the already reviewed, unchanged signed module prefix, not a
    # general Rust parser. Its nested module declarations must remain open at
    # the include; all non-fixture bytes already match the old signed manifest.
    include_at=tests.index(include)
    require(tests[:include_at].count('{')>tests[:include_at].count('}'),
        'helper_test_scope_binding')


def current_build(receipt_path,manifest_path,*,helper_receipt_path=None,helper_manifest_path=None):
    receipt,build,manifest,manifest_sha,receipt_sha=checked_build(receipt_path,manifest_path)
    split=build.get('build_kind','pair')=='libtest-only'
    require((helper_receipt_path is not None)==(helper_manifest_path is not None),
        'helper_receipt_pair_required')
    require(split==(helper_receipt_path is not None),'helper_receipt_selection')
    helper=build
    if split:
        old_receipt,helper,old_manifest,old_manifest_sha,old_receipt_sha=checked_build(
            helper_receipt_path,helper_manifest_path,working=False)
        require(old_receipt['signed_base_commit']==BUILD_SOURCE_COMMIT
            and helper.get('build_kind','pair')=='pair'
            and helper['native_helper_binary']['sha256']==REUSED_HELPER_SHA256,
            'qualified_helper_selection')
        test_only_helper_reuse(manifest,old_manifest)
    fields={'path','sha256','size','dev','ino','uid','gid','mode','nlink','cargo_profile',
        'cargo_target_kind','profile_test','source_count','tests_executed','application_executed'}
    pins={}
    for label,key in(('helper','native_helper_binary'),('web','native_test_binary')):
        artifact=(helper if label=='helper'else build)[key]
        require(fields<=set(artifact)and artifact['source_count']==len(manifest),'compiler_artifact_binding')
        pins[label]={name:artifact[name]for name in fields}
    if split:
        pins.update(helper_source_commit=old_receipt['signed_base_commit'],
            helper_compiler_source_manifest_sha256=old_manifest_sha,
            helper_compiler_receipt_sha256=old_receipt_sha)
    return pins,manifest_sha,receipt_sha,receipt['signed_base_commit']


def packet(receipt_path=None,manifest_path=None,*,helper_receipt_path=None,helper_manifest_path=None):
    require(receipt_path is not None and manifest_path is not None,'current_build_receipt_required')
    pins,manifest_sha,receipt_sha,source_commit=current_build(receipt_path,manifest_path,
        helper_receipt_path=helper_receipt_path,helper_manifest_path=helper_manifest_path)
    value=source_packet()
    # Historical bytes supply only the independently rechecked public config.
    # Every executable build identity is replaced from current compiler evidence.
    value.update(source_commit=source_commit,compiler_source_manifest_sha256=manifest_sha,
        compiler_receipt_sha256=receipt_sha,**pins)
    return value
