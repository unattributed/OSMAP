"""Static ELF parser discriminators; no native host/library claim."""
import struct,sys,unittest
from pathlib import Path
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R))
import account_native_elf as m
from authoritative_password import Refused

def binary(name=b'libc.so.102.2',rpath=b'/usr/lib',terminate=True):
 strings=b'\0'+name+b'\0'+rpath+b'\0';tags=[(5,0x1000+320),(10,len(strings)),(1,1),(29,len(name)+2)]
 if terminate:tags.append((0,0))
 d=b''.join(m.DYNAMIC.pack(*x) for x in tags);size=320+len(strings)
 header=m.HEADER.pack(b'\x7fELF\x02\x01\x01'+b'\0'*9,3,62,1,0,64,0,0,64,56,2,0,0,0)
 ph=m.PROGRAM.pack(1,5,0,0x1000,0x1000,size,size,4096)+m.PROGRAM.pack(2,6,192,0x1000+192,0x1000+192,len(d),len(d),8)
 raw=bytearray(size);raw[:64]=header;raw[64:176]=ph;raw[192:192+len(d)]=d;raw[320:]=strings;return bytes(raw)
class ElfTests(unittest.TestCase):
 def test_public_needed_and_closed_fixed_search_paths(self):self.assertEqual(m.dependencies(binary()),{'needed':('libc.so.102.2',),'search_paths':('/usr/lib',)})
 def test_wrong_arch_endian_and_segment_bounds_refuse(self):
  for raw in (b'',b'\0'*64,binary()[:200],binary()[:5]+b'\x02'+binary()[6:]):
   with self.assertRaises(Refused):m.dependencies(raw)
 def test_missing_dynamic_terminator_refuses(self):
  with self.assertRaises(Refused):m.dependencies(binary(terminate=False))
 def test_path_soname_and_untrusted_loader_path_refuse(self):
  for name,path in ((b'../../operator.so',b'/usr/lib'),(b'private token',b'/usr/lib'),(b'libc.so.1',b'$ORIGIN'),(b'libc.so.1',b'/tmp'),(b'libc.so.1',b'/usr/lib:/')):
   with self.assertRaises(Refused):m.dependencies(binary(name,path))
 def test_real_local_system_binary_is_inspected_without_execution(self):
  # Linux fixture only; neither OpenBSD SONAMEs nor installed graph are inferred.
  raw=Path('/usr/bin/true').read_bytes();value=m.dependencies(raw)
  self.assertIn('libc.so.6',value['needed']);self.assertEqual(value['search_paths'],())

elf=m
CAP=1024*1024
def image(change=None):
    strings = b'\x00libc.so.102.2\x00/usr/lib\x00'
    tags = b''.join((elf.DYNAMIC.pack(*r) for r in [(5, 4096 + 400), (10, len(strings)), (1, 1), (29, len(b'libc.so.102.2') + 2), (0, 0)]))
    size = 400 + len(strings)
    rows = [(1, 5, 0, 4096, 4096, size, size, 4096), (2, 6, 256, 4352, 4352, len(tags), len(tags), 8)]
    if change:
        rows = change(rows)
    raw = bytearray(size)
    raw[:64] = elf.HEADER.pack(b'\x7fELF\x02\x01\x01' + b'\x00' * 9, 3, 62, 1, 0, 64, 0, 0, 64, 56, len(rows), 0, 0, 0)
    for i, row in enumerate(rows):
        raw[64 + i * 56:120 + i * 56] = elf.PROGRAM.pack(*row)
    offset = rows[1][2]
    raw[offset:offset + len(tags)] = tags
    raw[400:] = strings
    return bytes(raw)
def edited(rows, index, **fields):
    names = ('type', 'flags', 'offset', 'vaddr', 'paddr', 'filesz', 'memsz', 'align')
    row = list(rows[index])
    for name, value in fields.items():
        row[names.index(name)] = value
    result = list(rows)
    result[index] = tuple(row)
    return result
class MappingTests(unittest.TestCase):

    def refused(self, raw, token):
        with self.assertRaises(elf.Refused) as caught:
            elf.dependencies(raw)
        self.assertEqual(caught.exception.guard_token, token)

    def test_coherent_positive_fixture_remains_readable(self):
        self.assertEqual(elf.dependencies(image())['needed'], ('libc.so.102.2',))

    def test_unmapped_dynamic_virtual_span_is_refused(self):
        self.refused(image(lambda rows: edited(rows, 1, vaddr=3735879680, paddr=3735879680)), 'E107')

    def test_dynamic_file_offset_must_match_virtual_mapping(self):
        self.refused(image(lambda rows: edited(rows, 1, offset=272)), 'E108')

    def test_duplicate_covering_load_mappings_are_refused(self):
        self.refused(image(lambda rows: rows + [(1, 6, 256, 4352, 4352, 80, 80, 8)]), 'E107')

    def test_dynamic_must_fit_entire_file_backed_load(self):
        self.refused(image(lambda rows: edited(rows, 0, filesz=320)), 'E107')

    def test_dynamic_must_fit_entire_load_memory(self):
        self.refused(image(lambda rows: edited(rows, 1, memsz=400)), 'E107')

    def test_virtual_span_unsigned_overflow_is_refused(self):
        self.refused(image(lambda rows: edited(rows, 1, vaddr=(1 << 64) - 16, paddr=(1 << 64) - 16)), 'E102')

    def test_string_span_unsigned_overflow_is_refused(self):
        raw = bytearray(image())
        raw[256:272] = elf.DYNAMIC.pack(5, (1 << 64) - 16)
        self.refused(bytes(raw), 'E109')
def table_image(size, *, tail=False, missing_terminator=False, short_load=False):
    table = bytearray(size)
    name = b'libc.so.102.2'
    table[1:1 + len(name) + 1] = name + b'\x00'
    offset = 1
    if tail:
        name = b'libtail.so.1'
        offset = size - len(name) - 1
        table[offset:] = name + b'\x00'
        if missing_terminator:
            table[-1] = ord('X')
    tags = b''.join((elf.DYNAMIC.pack(*row) for row in ((5, 4096 + 512), (10, size), (1, offset), (0, 0))))
    total = 512 + size
    raw = bytearray(total)
    raw[:64] = elf.HEADER.pack(b'\x7fELF\x02\x01\x01' + b'\x00' * 9, 3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    raw[64:120] = elf.PROGRAM.pack(1, 5, 0, 4096, 4096, total - (1 if short_load else 0), total, 4096)
    raw[120:176] = elf.PROGRAM.pack(2, 6, 256, 4352, 4352, len(tags), len(tags), 8)
    raw[256:256 + len(tags)] = tags
    raw[512:] = table
    return bytes(raw)
class CapTests(unittest.TestCase):

    def refused(self, raw, token):
        with self.assertRaises(elf.Refused) as caught:
            elf.dependencies(raw)
        reasons = {'E011': 'native ELF strings unavailable', 'E012': 'native ELF string mapping unavailable', 'E014': 'native ELF string bound unavailable', 'E107': 'native ELF dynamic mapping unavailable'}
        self.assertEqual(str(caught.exception), reasons[token])

    def test_actual_declared71242_sized_table_is_positive(self):
        self.assertEqual(elf.dependencies(table_image(71242))['needed'], ('libc.so.102.2',))

    def test_exact1MiB_boundary_and_tail_reference_positive(self):
        self.assertEqual(elf.dependencies(table_image(CAP))['needed'], ('libc.so.102.2',))
        self.assertEqual(elf.dependencies(table_image(CAP, tail=True))['needed'], ('libtail.so.1',))

    def test_cap_plus_one_is_refused(self):
        self.refused(table_image(CAP + 1), 'E011')

    def test_full_string_span_cannot_extend_past_file_backed_load(self):
        self.refused(table_image(71242, short_load=True), 'E012')

    def test_changed_tail_without_NUL_is_refused(self):
        self.refused(table_image(71242, tail=True, missing_terminator=True), 'E014')

    def test_dynamic_mapping_guard_is_not_waived_for_large_table(self):
        raw = bytearray(table_image(71242))
        row = list(elf.PROGRAM.unpack_from(raw, 120))
        row[3] = row[4] = 3735879680
        raw[120:176] = elf.PROGRAM.pack(*row)
        self.refused(bytes(raw), 'E107')
if __name__=='__main__':unittest.main(verbosity=2)
