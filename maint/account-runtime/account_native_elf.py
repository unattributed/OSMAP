"""Bounded ELF dependency inspection; reads bytes, never executes a target."""
import re
import struct
from authoritative_password import Refused as BaseRefused
HEADER=struct.Struct('<16sHHIQQQIHHHHHH')
PROGRAM=struct.Struct('<IIQQQQQQ')
DYNAMIC=struct.Struct('<qQ')
STRING_TABLE_CAP=1024*1024
UINT64_MAX=(1<<64)-1
class Refused(BaseRefused):
    def __init__(self,reason,guard_token,segment=None):
        super().__init__(reason);self.guard_token=guard_token
        self.segment=None if segment is None else dict(zip(
            ('type','flags','offset','vaddr','paddr','filesz','memsz','align'),segment))
def span(start,size,token,segment=None):
    if start>UINT64_MAX-size:raise Refused('native ELF unsigned span unavailable',token,segment)
    return start+size
RPATHS=frozenset(('/usr/lib','/usr/local/lib','/usr/local/lib/dovecot'))

def dependencies(raw):
    if type(raw)is not bytes or not HEADER.size<=len(raw)<=64*1024*1024:
        raise Refused('native ELF bounds unavailable','E001')
    h=HEADER.unpack_from(raw)
    if (h[0][:7]!=b'\x7fELF\x02\x01\x01' or h[1]not in (2,3) or h[2]!=62 or
            h[3]!=1 or h[8]!=HEADER.size or h[9]!=PROGRAM.size or not 1<=h[10]<=64 or
            h[5]<HEADER.size or h[5]+h[9]*h[10]>len(raw)):
        raise Refused('native ELF ABI unavailable','E002')
    segments=[PROGRAM.unpack_from(raw,h[5]+i*PROGRAM.size) for i in range(h[10])]
    for p in segments:
        if p[2]+p[5]>len(raw) or p[5]>p[6]:raise Refused('native ELF segment unavailable','E003',p)
        span(p[2],p[5],'E101',p)
        if p[0] in (1,2):span(p[3],p[6],'E102',p)
    dynamic=[p for p in segments if p[0]==2]
    if len(dynamic)!=1 or not dynamic[0][5] or dynamic[0][5]%DYNAMIC.size or dynamic[0][5]>4096*DYNAMIC.size:
        raise Refused('native ELF dynamic section unavailable','E004')
    p=dynamic[0]
    file_end=span(p[3],p[5],'E103',p);memory_end=span(p[3],p[6],'E104',p)
    loads=[load for load in segments if load[0]==1 and load[3]<=p[3]
        and file_end<=span(load[3],load[5],'E105',load)
        and memory_end<=span(load[3],load[6],'E106',load)]
    if len(loads)!=1:raise Refused('native ELF dynamic mapping unavailable','E107',p)
    load=loads[0]
    if load[2]+p[3]-load[3]!=p[2]:raise Refused('native ELF dynamic offset mapping unavailable','E108',p)
    tags=[];terminated=False
    for offset in range(p[2],p[2]+p[5],DYNAMIC.size):
        tag,value=DYNAMIC.unpack_from(raw,offset)
        if tag==0:terminated=True;break
        tags.append((tag,value))
    if not terminated:raise Refused('native ELF dynamic terminator unavailable','E005')
    strings=[v for t,v in tags if t==5];sizes=[v for t,v in tags if t==10]
    if len(strings)!=1 or len(sizes)!=1 or not 1<=sizes[0]<=STRING_TABLE_CAP:
        raise Refused('native ELF strings unavailable','E006')
    string_end=span(strings[0],sizes[0],'E109')
    mappings=[p[2]+strings[0]-p[3] for p in segments if p[0]==1 and p[3]<=strings[0] and string_end<=span(p[3],p[5],'E110',p)]
    if len(mappings)!=1:raise Refused('native ELF string mapping unavailable','E007')
    table=raw[mappings[0]:mappings[0]+sizes[0]]
    def string(offset):
        if offset>=len(table):raise Refused('native ELF string offset unavailable','E008')
        end=table.find(b'\0',offset)
        if end<0 or not 1<=end-offset<=512:raise Refused('native ELF string bound unavailable','E009')
        try:return table[offset:end].decode('ascii','strict')
        except UnicodeError:raise Refused('native ELF string encoding unavailable','E010') from None
    needed=[];paths=[]
    for tag,value in tags:
        if tag==1:
            name=string(value)
            if len(name)>128 or not re.fullmatch(r'lib[A-Za-z0-9_.+-]+\.so(?:\.[0-9]+)*',name) or name in needed:
                raise Refused('native ELF soname unavailable','E011')
            needed.append(name)
        if tag in (15,29):
            parts=string(value).split(':')
            if any(p not in RPATHS for p in parts) or any(p in paths for p in parts):
                raise Refused('native ELF library search authority unavailable','E012')
            paths.extend(parts)
    if not 1<=len(needed)<=64:raise Refused('native ELF dependency count unavailable','E013')
    return {'needed':tuple(needed),'search_paths':tuple(paths)}
