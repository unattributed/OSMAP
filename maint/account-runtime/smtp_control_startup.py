"""Read-only fixed broker key custody, available before its socket exists.

This loader creates neither provision nor endpoint and does not qualify a native
broker. The private reader is shared with the guarded mutation binding; only the
fixed native entry chooses the authoritative root and owner.
"""
from dataclasses import dataclass
import os
import socket
import sys
from account_mutation_codec import key_valid
from account_mutation_supervisor import _Bootstrap,ROOT,AUTHORITY,_directory,_private
from authoritative_password import Refused
from operation_budget import OperationBudget
from smtp_control_authorization import ControlAuthority

CONTROL_KEY_NAME='smtp-control.key'
_FILES=('config.json','mutation.key','session-proof.key',CONTROL_KEY_NAME)

@dataclass(frozen=True,repr=False)
class ControlStartup:
    bootstrap: _Bootstrap
    authority: ControlAuthority
    _custody: tuple

    def __post_init__(self):
        if (type(self.bootstrap)is not _Bootstrap or type(self.authority)is not ControlAuthority
                or self.authority.accounts!=self.bootstrap.accounts
                or self.authority.key in (self.bootstrap.mutation_key,self.bootstrap.session_key)):
            raise Refused('SMTP control startup authority unavailable')
        key_valid(self.bootstrap.mutation_key);key_valid(self.bootstrap.session_key)
        if self.bootstrap.mutation_key==self.bootstrap.session_key:
            raise Refused('SMTP control startup keys unavailable')

    @staticmethod
    def _identity(info):
        return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,
                info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

    @classmethod
    def _read(cls,bootstrap,root,owner,budget):
        # Private source/test seam, not a wire-selected path or identity.
        if type(bootstrap)is not _Bootstrap or type(budget)is not OperationBudget:
            raise Refused('SMTP control startup authority unavailable')
        descriptor=None
        try:
            budget.remaining();descriptor=_directory(root,owner)
            root_identity=cls._identity(os.fstat(descriptor))[:5]
            before=tuple(cls._identity(os.stat(name,dir_fd=descriptor,follow_symlinks=False))for name in _FILES)
            # Independently bind the complete account set and both original
            # purpose keys to this exact private directory before control use.
            if _Bootstrap._read(root,owner)!=bootstrap:
                raise Refused('SMTP control bootstrap changed')
            budget.remaining()
            control=_private(descriptor,CONTROL_KEY_NAME,owner,1024)
            authority=ControlAuthority(control,bootstrap.accounts)
            value=cls(bootstrap,authority,(root,owner,root_identity,before))
            after=tuple(cls._identity(os.stat(name,dir_fd=descriptor,follow_symlinks=False))for name in _FILES)
            if (before!=after or cls._identity(os.fstat(descriptor))[:5]!=root_identity
                    or cls._identity(root.lstat())[:5]!=root_identity):
                raise Refused('SMTP control startup custody changed')
            budget.remaining()
            return value
        except Exception:
            raise Refused('SMTP control startup unavailable')from None
        finally:
            if descriptor is not None:os.close(descriptor)

    def recheck(self,budget):
        root,owner,root_identity,files=self._custody
        current=type(self)._read(self.bootstrap,root,owner,budget)
        if (current._custody!=(root,owner,root_identity,files)
                or current.authority!=self.authority):
            raise Refused('SMTP control startup changed')

    @classmethod
    def native(cls,bootstrap,budget):
        # Fixed public native authority; no endpoint, file or socket is created.
        # This is key custody only: all service/native qualification flags stay
        # closed in the actual broker and mutation endpoint factories.
        if (type(bootstrap)is not _Bootstrap or type(budget)is not OperationBudget
                or os.geteuid()!=0 or not sys.platform.startswith('openbsd')
                or socket.gethostname()!=AUTHORITY):
            raise Refused('native SMTP control startup unavailable')
        return cls._read(bootstrap,ROOT,0,budget)
