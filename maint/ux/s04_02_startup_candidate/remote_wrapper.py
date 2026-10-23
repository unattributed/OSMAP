"""Fixed foo transport keeper for a hash-admitted root staging/journey actor."""
import base64,hashlib,json,os,re,selectors,signal,socket,stat,subprocess,sys,time
from pathlib import Path
ROOT_SOURCE_SHA256='eedd9003ecf068850a0851140354fa3866c5e968f82028e7d4edc66bb572507d'
STOPS={signal.SIGALRM,signal.SIGHUP,signal.SIGTERM,signal.SIGINT}
START=time.monotonic();END=START+630
PYTHON=Path('/usr/local/bin/python3')
PYTHON_TARGET=re.compile(r'python3\.[0-9]{1,2}\Z')
class Refused(Exception):pass
def require(ok,code):
    if not ok:raise Refused(code)
def interrupted(_number,_frame):raise Refused('wrapper_interrupted')
def file_identity(m):
    return(m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
def trusted(path):
    q=Path(path)
    for parent in q.parents:
        m=parent.lstat();require(stat.S_ISDIR(m.st_mode)and m.st_uid==0 and not m.st_mode&0o022,'program_parent')
    m=q.lstat();require(stat.S_ISREG(m.st_mode)and m.st_uid==0 and m.st_nlink==1 and not m.st_mode&0o022 and m.st_mode&0o111,'program_custody')
def select_python(alias=PYTHON,running=None,owner=0,ancestor_owners=(0,),version=None):
    """Admit one relative package alias and its regular sibling target."""
    try:
        require(isinstance(alias,Path)and alias.is_absolute(),'python_alias_path')
        for parent in alias.parents:
            m=parent.lstat();require(stat.S_ISDIR(m.st_mode)and m.st_uid in ancestor_owners and not m.st_mode&0o022,'python_parent_custody')
        before=alias.lstat();target_name=os.readlink(alias)if stat.S_ISLNK(before.st_mode)else''
        require(stat.S_ISLNK(before.st_mode)and before.st_uid==owner and before.st_nlink==1
            and PYTHON_TARGET.fullmatch(target_name)is not None,'python_alias_custody')
        target=alias.parent/target_name
        require(target.resolve(strict=True)==target,'python_target_chain')
        for parent in target.parents:
            m=parent.lstat();require(stat.S_ISDIR(m.st_mode)and m.st_uid in ancestor_owners and not m.st_mode&0o022,'python_target_parent_custody')
        prior=target.lstat()
        require(stat.S_ISREG(prior.st_mode)and prior.st_uid==owner and prior.st_nlink==1
            and not prior.st_mode&0o022 and not prior.st_mode&0o6000 and prior.st_mode&0o111
            and 0<prior.st_size<=64*1024*1024,'python_target_custody')
        fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:require(file_identity(os.fstat(fd))==file_identity(prior),'python_target_open')
        finally:os.close(fd)
        selected=Path(sys.executable if running is None else running).resolve(strict=True)
        require(selected==target,'python_running_identity')
        actual=sys.version_info[:3]if version is None else tuple(version)
        require(len(actual)==3 and all(type(x)is int for x in actual)
            and (3,9)<=actual[:2]<(4,0),'python_incompatible')
        require(callable(getattr(signal,'pthread_sigmask',None))and callable(getattr(os,'waitid',None))
            and all(hasattr(os,name)for name in('WNOWAIT','WNOHANG','WEXITED'))
            and hasattr(str,'removesuffix'),'python_features')
        require(file_identity(alias.lstat())==file_identity(before)and os.readlink(alias)==target_name
            and file_identity(target.lstat())==file_identity(prior),'python_selection_changed')
        return {'entrypoint':str(alias),'resolved_path':str(target),'version':list(actual),
            'identity':{'dev':prior.st_dev,'ino':prior.st_ino,'uid':prior.st_uid,'gid':prior.st_gid,
                'mode':stat.S_IMODE(prior.st_mode),'nlink':prior.st_nlink,'size':prior.st_size},
            'features':['pthread_sigmask','waitid','WNOWAIT','removesuffix']}
    except Refused:raise
    except BaseException as error:
        raise Refused('python_selection_'+type(error).__name__)from None
def spawn_actor(data,source,previous):
    """Select the fixed interpreter before the privileged actor can exist."""
    interpreter=select_python()
    child=subprocess.Popen(('/usr/bin/doas','-n','/usr/local/bin/python3','-I','-c',source.decode()),cwd='/',stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,start_new_session=True,preexec_fn=lambda:signal.pthread_sigmask(signal.SIG_SETMASK,previous),env={'PATH':'/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/home/foo','LC_ALL':'C'})
    return interpreter,child
def main():
    os.umask(0o077)
    for number in STOPS:signal.signal(number,interrupted)
    signal.alarm(630)
    identity=(socket.gethostname(),os.uname().sysname,os.uname().machine,os.getuid(),os.geteuid())
    require(identity==('obsd1.blackbagsecurity.com','OpenBSD','amd64',1000,1000),'foo_target')
    require(len(sys.argv)==1,'no_arguments')
    raw=sys.stdin.buffer.read(4*1024*1024+1);require(0<len(raw)<=4*1024*1024,'transport_bound');value=json.loads(raw)
    require(set(value)=={'root_source','packet'},'transport_fields');source=base64.b64decode(value['root_source'],validate=True)
    require(hashlib.sha256(source).hexdigest()==ROOT_SOURCE_SHA256,'root_source_pin')
    data=json.dumps(value['packet'],sort_keys=True,separators=(',',':')).encode();require(len(data)<=3*1024*1024,'root_packet_bound')
    trusted('/usr/bin/doas')
    child=None;out=[bytearray(),bytearray()];offset=0;reaped=gone=False;failure=None
    previous=signal.pthread_sigmask(signal.SIG_BLOCK,STOPS)
    try:
        interpreter,child=spawn_actor(data,source,previous)
    finally:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
    try:
        with selectors.DefaultSelector()as poll:
            for pipe,event,kind in((child.stdin,selectors.EVENT_WRITE,-1),(child.stdout,selectors.EVENT_READ,0),(child.stderr,selectors.EVENT_READ,1)):
                os.set_blocking(pipe.fileno(),False);poll.register(pipe,event,kind)
            while poll.get_map():
                require(time.monotonic()<END-5,'wrapper_io_deadline')
                for key,_ in poll.select(.05):
                    try:
                        if key.data==-1:
                            if offset<len(data):offset+=os.write(key.fd,data[offset:offset+8192])
                            if offset==len(data):poll.unregister(key.fileobj);key.fileobj.close()
                        else:
                            part=os.read(key.fd,8192)
                            if not part:poll.unregister(key.fileobj)
                            else:out[key.data].extend(part);require(len(out[key.data])<=(262144 if key.data==0 else 8192),'wrapper_output_bound')
                    except BlockingIOError:continue
            while os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is None:
                require(time.monotonic()<END-5,'wrapper_exit_deadline');time.sleep(.02)
    except BaseException as e:failure=str(e)if type(e)is Refused else type(e).__name__
    finally:
        mask=signal.pthread_sigmask(signal.SIG_BLOCK,STOPS)
        try:
            # This exact born direct child remains unreaped here. No PID/SID
            # from a historical receipt or foreign-session lookup is used.
            if os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is None:
                try:os.killpg(child.pid,signal.SIGTERM)
                except(ProcessLookupError,PermissionError):pass
            try:child.wait(timeout=max(.001,END-time.monotonic()));reaped=True
            except subprocess.TimeoutExpired:pass
            if reaped:
                try:os.killpg(child.pid,0)
                except ProcessLookupError:gone=True
                except PermissionError:pass
        finally:
            for pipe in(child.stdin,child.stdout,child.stderr):
                if not pipe.closed:pipe.close()
            signal.pthread_sigmask(signal.SIG_SETMASK,mask)
    # Only parsed JSON frames from the secret-excluding actor are exported.
    frames=[]
    try:
        require(out[0].endswith(b'\n'),'actor_frame_termination')
        for line in bytes(out[0]).splitlines():
            item=json.loads(line);require(type(item)is dict and item.get('schema')in('osmap-single-host-stage-birth-v1','osmap-single-host-stage-ready-v1','osmap-single-host-stage-refusal-v1','osmap-single-host-startup-v1'),'actor_frame_schema');frames.append(item)
        require(len(frames)<=5,'actor_frame_count')
    except BaseException:frames=[];failure=failure or'actor_frames_refused'
    result={'schema':'osmap-single-host-transport-v1','result':'COMPLETE'if failure is None and reaped and gone and child.returncode==0 and not out[1]else'FAIL','root_exit':child.returncode,'born_child_reaped':reaped,'born_group_gone':gone,'frames':frames,'failure':failure,'interpreter':interpreter,'stdout_sha256':hashlib.sha256(out[0]).hexdigest(),'stderr_sha256':hashlib.sha256(out[1]).hexdigest(),'stderr_bytes':len(out[1]),'elapsed_millis':int((time.monotonic()-START)*1000)}
    print(json.dumps(result,sort_keys=True));return 0 if result['result']=='COMPLETE'else 1
if __name__=='__main__':
    try:code=main()
    except BaseException as error:
        print(json.dumps({'schema':'osmap-single-host-transport-v1','result':'REFUSED','failure':str(error)if type(error)is Refused else type(error).__name__,'frames':[],'born_child_reaped':False,'born_group_gone':False}));code=1
    finally:signal.alarm(0)
    raise SystemExit(code)
