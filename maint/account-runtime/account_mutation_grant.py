"""Disabled fixed connector grant: endpoint reachability is not action authority.

The helper keeps all bootstrap keys/config private. Only a dedicated root-owned
purpose namespace grants search/connect to the configured connector group; it
never grants directory write. No group, user, socket parent or grant is created.
"""
from dataclasses import dataclass
import grp
import json
import os
from pathlib import Path
import pwd
import stat

from account_epoch import EpochStore
from account_mutation_supervisor import AUTHORITY,PURPOSE,ROOT,_Bootstrap,_directory,_private
from account_mutation_worker import Unavailable

NATIVE_CONNECTOR_GRANT_QUALIFIED=False
CONNECTOR='_osmap'
GROUP='_osmapmutation'
NAMESPACE=Path('/var/run/osmap-account-mutation')
SOCKET=NAMESPACE/'mutation.sock'


@dataclass(frozen=True,repr=False)
class _ConnectorGrant:
    path:Path
    owner:int
    connector_uid:int
    connector_gid:int

    def __post_init__(self):
        if (not isinstance(self.path,Path) or not self.path.is_absolute()
                or self.path.name!='mutation.sock'
                or any(type(v) is not int or not 0<=v<=2**32-1
                       for v in (self.owner,self.connector_uid,self.connector_gid))
                or self.connector_uid==0 or self.connector_gid==0):
            raise Unavailable('mutation connector grant unavailable')

    @classmethod
    def _read(cls,root,owner,bootstrap,identity):
        if type(bootstrap) is not _Bootstrap:
            raise Unavailable('mutation connector grant unavailable')
        fd=_directory(root,owner)
        try:
            config=json.loads(_private(fd,'connector-grant.json',owner,4096),
                              object_pairs_hook=EpochStore._unique)
            if (type(config) is not dict or set(config)!={
                    'version','authority','purpose','connector','group','trusted_relay_uid'}
                    or type(config['version']) is not int or config['version']!=1
                    or config['authority']!=AUTHORITY or config['purpose']!=PURPOSE
                    or config['connector']!=CONNECTOR or config['group']!=GROUP
                    or type(config['trusted_relay_uid']) is not int
                    or config['trusted_relay_uid']!=bootstrap.trusted_relay_uid):
                raise ValueError
            uid,gid=identity(config['trusted_relay_uid'])
            if uid!=bootstrap.trusted_relay_uid:raise ValueError
            return cls(SOCKET,owner,uid,gid)
        except Exception:
            raise Unavailable('mutation connector grant unavailable') from None
        finally:os.close(fd)

    @staticmethod
    def _native_identity(expected_uid):
        connector=pwd.getpwnam(CONNECTOR);group=grp.getgrnam(GROUP)
        # Source uses the fixed group name; no guessed numeric GID is installed.
        # Primary and supplementary members are checked in-process only, with
        # bounded inventory and no account rows/names emitted or retained.
        users=pwd.getpwall()
        if (len(users)>4096 or connector.pw_uid!=expected_uid
                or connector.pw_uid==0 or group.gr_gid==0
                or set(group.gr_mem)!={CONNECTOR}
                or any(p.pw_gid==group.gr_gid and p.pw_name!=CONNECTOR for p in users)
                or group.gr_gid not in os.getgrouplist(CONNECTOR,connector.pw_gid)):
            raise Unavailable('mutation connector principal unavailable')
        return connector.pw_uid,group.gr_gid

    @classmethod
    def native(cls,bootstrap):
        # Refusal precedes files, users/groups and socket namespace access.
        if not NATIVE_CONNECTOR_GRANT_QUALIFIED:
            raise Unavailable('native mutation connector grant unavailable')
        if os.geteuid()!=0:
            raise Unavailable('mutation connector grant owner unavailable')
        return cls._read(ROOT,0,bootstrap,cls._native_identity)

    def open_namespace(self):
        path=self.path.parent
        if path.resolve()!=path:raise Unavailable('mutation grant ancestry unavailable')
        for ancestor in path.parents:
            m=ancestor.lstat()
            if (not stat.S_ISDIR(m.st_mode) or m.st_uid not in (0,self.owner)
                    or m.st_mode&0o022 or ancestor.resolve()!=ancestor):
                raise Unavailable('mutation grant ancestry unavailable')
        before=path.lstat()
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            after=os.fstat(fd)
            if (not stat.S_ISDIR(after.st_mode) or after.st_uid!=self.owner
                    or after.st_gid!=self.connector_gid
                    or stat.S_IMODE(after.st_mode)!=0o710
                    or (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino)):
                raise Unavailable('mutation connector namespace unavailable')
            return fd
        except Exception:
            os.close(fd);raise

    def _current_namespace(self,fd):
        held=os.fstat(fd);current=self.path.parent.lstat()
        if (self.path.parent.resolve()!=self.path.parent
                or (held.st_dev,held.st_ino)!=(current.st_dev,current.st_ino)
                or current.st_uid!=self.owner or current.st_gid!=self.connector_gid
                or stat.S_IMODE(current.st_mode)!=0o710):
            raise Unavailable('mutation connector namespace changed')

    def publish(self,fd,inode):
        self._current_namespace(fd)
        m=self.path.lstat()
        if (not stat.S_ISSOCK(m.st_mode) or m.st_nlink!=1 or m.st_uid!=self.owner
                or (m.st_dev,m.st_ino)!=inode):
            raise Unavailable('mutation connector socket changed')
        os.chown(self.path,self.owner,self.connector_gid,follow_symlinks=False)
        os.chmod(self.path,0o660,follow_symlinks=False)
        self.verify(fd,inode)

    def verify(self,fd,inode):
        self._current_namespace(fd)
        m=self.path.lstat()
        if (not stat.S_ISSOCK(m.st_mode) or m.st_nlink!=1 or m.st_uid!=self.owner
                or m.st_gid!=self.connector_gid or stat.S_IMODE(m.st_mode)!=0o660
                or (m.st_dev,m.st_ino)!=inode):
            raise Unavailable('mutation connector socket unavailable')
