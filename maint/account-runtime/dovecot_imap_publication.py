"""Fixed Dovecot policy/final-publication service, native qualification closed."""
import hmac
import json
import math
import os
import re
import selectors
import socket
import time

from authoritative_password import Refused
from dovecot_auth_epoch import EpochPolicyFence
from dovecot_imap_peer import NativeImapPeerInspector, bounded_who
from mail_session_containment import MailSessionContainment

NATIVE_IMAP_PUBLICATION_QUALIFIED=False
FINAL_SOCKET='/var/run/osmap-account/imap-publication.sock'


def observed_imap_registration(account,pid,deadline):
    """One fixed read-only who command; queued CONNECT is never sufficient."""
    left=deadline-time.monotonic()
    if not 0<left<=EpochPolicyFence.CALLBACK_SECONDS:return False
    result=bounded_who(account,deadline)
    if (type(result)is not tuple or len(result)!=3 or result[0]!=0
            or type(result[0])is not int or type(result[1])is not bytes
            or type(result[2])is not bytes or result[2]
            or len(result[1])>4096 or not result[1].startswith(MailSessionContainment.WHO_HEADER)
            or not result[1].endswith(b'\n') or b'\r'in result[1] or b'\x00'in result[1]):return False
    rows=result[1][len(MailSessionContainment.WHO_HEADER):].splitlines()
    matches=0
    for row in rows:
        fields=row.split(b'\t')
        if (len(fields)!=5 or fields[0]!=account.encode('ascii')
                or fields[2]!=b'imap' or not re.fullmatch(rb'[1-9][0-9]{0,9}',fields[1])
                or int(fields[1])>2**32-1
                or not re.fullmatch(rb'\([1-9][0-9]*(?: [1-9][0-9]*)*\)',fields[3])
                or not re.fullmatch(rb'\([A-Fa-f0-9:. ]*\)',fields[4])):return False
        pids=[int(v)for v in fields[3][1:-1].split(b' ')]
        if (len(set(pids))!=len(pids)or any(v>=2**31 for v in pids)
                or int(fields[1])!=len(pids)):return False
        matches+=pid in pids
    return matches==1 and time.monotonic()<deadline


class FixedPublicationEndpoint:
    """Only trusted startup supplies roles/key/inspector and owned listeners.

    The native inspector must independently bind the claimed PID to this exact
    accepted connection, live single-client IMAP process and installed source
    custody. A UID or caller-supplied PID alone cannot supply that authority.
    Native serving requires the concrete kernel inspector, whose native factory
    remains closed until current installed custody and race qualify.
    """
    def __init__(self,fence,api_key,inspect_peer,*,registration=observed_imap_registration):
        if (type(fence)is not EpochPolicyFence or type(api_key)is not bytes
                or not re.fullmatch(rb'[a-f0-9]{64}',api_key)
                or not callable(getattr(inspect_peer,'admit',None))
                or not callable(getattr(inspect_peer,'validate',None))or not callable(registration)):
            raise Refused('IMAP publication startup unavailable')
        self._fence=fence;self._api_key=api_key
        self._inspect_peer=inspect_peer;self._registration=registration

    def policy(self,body,api_key,command,*,original_deadline=None):
        if (type(api_key)is not bytes or not hmac.compare_digest(api_key,self._api_key)
                or command not in ('allow','report')or type(body)is not bytes
                or not 1<=len(body)<=4096):return EpochPolicyFence.DENY
        try:
            value=json.loads(body,object_pairs_hook=self._fence._store._unique)
            if type(value)is not dict or type(value.get('login'))is not str:return EpochPolicyFence.DENY
            # Explicit outside-scope transparency. The final plugin is enabled
            # only for the same operator-managed accounts. Policy transport
            # may fail open ONLY with that mandatory final managed-account hook.
            if value['login']not in self._fence._accounts:return EpochPolicyFence.ALLOW
            if command=='report':return EpochPolicyFence.DENY
            # Fixed passdb field is absent/empty before lookup, 'after' after.
            if value.get('phase')=='':value['phase']='before'
            return self._fence.allow(json.dumps(value,separators=(',',':')).encode(),original_deadline=original_deadline)
        except Exception:return EpochPolicyFence.DENY

    def final(self,stream,body,binding,deadline):
        if type(body)is not bytes or len(body)>1024:return b'NO\n'
        match=re.fullmatch(rb'PUBLISH\t([a-z0-9@._+-]{1,254})\t([A-Za-z0-9/+_=.-]{1,128})\t([01])\t([1-9][0-9]{0,9})\n',body)
        if match is None:return b'NO\n'
        account,session,tls,pid=match.groups();pid=int(pid)
        if not 1<pid<2**31:return b'NO\n'
        if self._inspect_peer.validate(binding,stream,pid,account.decode(),deadline,fresh=False)is not True:return b'NO\n'
        request=json.dumps({'login':account.decode(),'protocol':'imap',
            'session_id':session.decode(),'tls':tls==b'1','pid':pid},separators=(',',':')).encode()
        def observed(account,pid,ticket_deadline):
            # Both same-session peer custody and acknowledged anvil membership
            # must be current while the durable epoch lock excludes the writer.
            if self._inspect_peer.validate(binding,stream,pid,account,deadline)is not True:return False
            return self._registration(account,pid,min(ticket_deadline,deadline))is True
        return b'OK\n'if self._fence.publish_imap(request,observed,original_deadline=deadline)else b'NO\n'

    @staticmethod
    def _read(stream,limit,end,*,until=None,length=None):
        raw=bytearray()
        while length is None or len(raw)<length:
            left=end-time.monotonic()
            if left<=0:raise TimeoutError
            stream.settimeout(left)
            part=stream.recv(min(1024,limit+1-len(raw),length-len(raw)if length is not None else 1024))
            if not part:raise Refused('IMAP publication framing unavailable')
            raw.extend(part)
            if len(raw)>limit:raise Refused('IMAP publication framing unavailable')
            if until is not None and raw.endswith(until):break
        return bytes(raw)

    def connection(self,stream,kind,*,original_deadline=None):
        began=time.monotonic();end=began+EpochPolicyFence.CALLBACK_SECONDS
        if original_deadline is not None:
            if (type(original_deadline)not in (int,float)or not math.isfinite(original_deadline)
                    or not 0<original_deadline-began<=EpochPolicyFence.CALLBACK_SECONDS):
                stream.close();raise Refused('IMAP publication original deadline unavailable')
            end=min(end,original_deadline)
        try:
            if kind=='final':
                # Wrong kernel peer/process closes with zero reads and writes.
                binding=self._inspect_peer.admit(stream,end)
                raw=self._read(stream,1024,end,until=b'\n')
                reply=self.final(stream,raw,binding,end)
            elif kind=='policy':
                # Bytewise header intake avoids consuming unknown body bytes.
                header=bytearray()
                while not header.endswith(b'\r\n\r\n'):
                    header.extend(self._read(stream,1,end,length=1))
                    if len(header)>8192:raise Refused('policy headers unavailable')
                lines=bytes(header).split(b'\r\n')
                method=re.fullmatch(rb'POST /epoch/\?command=(allow|report) HTTP/1\.[01]',lines[0])
                if method is None:raise Refused('policy request unavailable')
                headers={}
                for line in lines[1:-2]:
                    key,separator,value=line.partition(b':')
                    key=key.lower()
                    if not separator or key in headers:raise Refused('policy headers unavailable')
                    headers[key]=value.strip(b' ')
                if b'transfer-encoding'in headers or not re.fullmatch(rb'[1-9][0-9]{0,3}',headers.get(b'content-length',b'')):
                    raise Refused('policy framing unavailable')
                length=int(headers[b'content-length'])
                body=self._read(stream,4096,end,length=length)
                result=self.policy(body,headers.get(b'x-osmap-policy',b''),method[1].decode(),original_deadline=end)
                reply=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '+str(len(result)).encode()+b'\r\n\r\n'+result
            else:raise Refused('publication role unavailable')
            left=end-time.monotonic()
            if left<=0:raise TimeoutError
            stream.settimeout(left);stream.sendall(reply)
        finally:stream.close()

    def serve(self,policy_listener,final_listener,stop):
        # Only PublicationService owns native bootstrap/listener continuity.
        # Direct source-fixture endpoint injection never supplies native entry.
        raise Refused('managed IMAP publication composition required')
