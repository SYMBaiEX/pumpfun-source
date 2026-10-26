#!/usr/bin/env python3
"""Verify a finite static CFG and exact saved ELF slices; never execute an ELF."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent


def check(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Elf:
    """Minimal ELF64-LE reader with explicit VA-to-file mapping."""
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        b = self.data
        check(b[:6] == b'\x7fELF\x02\x01', 'expected ELF64 little-endian')
        section_offset = struct.unpack_from('<Q', b, 40)[0]
        entry_size, count, names_index = struct.unpack_from('<HHH', b, 58)
        check(entry_size == 64 and names_index < count, 'ELF section layout')
        self.sections = [struct.unpack_from('<IIQQQQIIQQ', b, section_offset+i*entry_size)
                         for i in range(count)]
        names = self.sections[names_index]
        strings = b[names[4]:names[4]+names[5]]
        self.named = {strings[s[0]:].split(b'\0', 1)[0].decode(): s
                      for s in self.sections}
        self.text = self.named['.text']
        self.symbols = []
        for name in ('.symtab', '.dynsym'):
            if name not in self.named:
                continue
            section = self.named[name]
            table = self.sections[section[6]]
            strings = b[table[4]:table[4]+table[5]]
            check(section[9] == 24, 'symbol record size')
            for offset in range(section[4], section[4]+section[5], 24):
                n, info, _, index, value, size = struct.unpack_from('<IBBHQQ', b, offset)
                if info & 15 == 2 and size:
                    self.symbols.append(dict(name=strings[n:].split(b'\0', 1)[0].decode(),
                                             start=value, size=size, section=index))
        self.relocations = {}
        if '.rel.dyn' in self.named:
            section = self.named['.rel.dyn']
            check(section[9] == 16, 'relocation record size')
            for offset in range(section[4], section[4]+section[5], 16):
                address, info = struct.unpack_from('<QQ', b, offset)
                self.relocations[address] = dict(type=info & 0xffffffff,
                                                 symbol_index=info >> 32)

    def window(self, start, size):
        choices = [s for s in self.sections
                   if s[1] != 8 and s[2] & 2 and s[3] <= start and start+size <= s[3]+s[5]]
        check(len(choices) == 1, 'unique allocated file-backed mapping')
        section = choices[0]
        offset = section[4]+start-section[3]
        data = self.data[offset:offset+size]
        check(len(data) == size, 'complete window')
        relocations = [dict(offset=at-start, **value)
                       for at, value in sorted(self.relocations.items())
                       if start <= at < start+size]
        return data, dict(section_va=section[3], section_file_offset=section[4],
                          section_bytes=section[5], file_offset=offset), relocations


def instructions(data):
    check(len(data) % 8 == 0, 'instruction alignment')
    result = {}
    index = 0
    while index < len(data):
        op, registers, displacement, immediate = struct.unpack_from('<BBhi', data, index)
        width = 16 if op == 0x18 else 8
        check(index+width <= len(data), 'truncated LDDW')
        if width == 16:
            check(data[index+8:index+12] == bytes(4), 'LDDW continuation header')
        result[index] = dict(op=op, registers=registers, displacement=displacement,
                             immediate=immediate, width=width)
        index += width
    return result


def leaf_cfg(data, relocations):
    check(not relocations, 'leaf has relocations')
    decoded = instructions(data)
    # This finite certificate admits only observed ALU64, LDDW and JMP64 forms.
    # No memory access, syscall, direct/indirect call or implicit target is allowed.
    alu = {0xbf, 0x5f, 0x4f, 0xb7, 0x67, 0xc7}
    conditional = {0x2d, 0x15, 0x65, 0x6d, 0x1d, 0xcd}
    edges = {}
    for offset, item in decoded.items():
        op = item['op']
        check(item['registers'] & 15 <= 10 and item['registers'] >> 4 <= 10,
              'invalid register')
        if op == 0x95:
            check(item['registers'] == item['displacement'] == item['immediate'] == 0,
                  'malformed EXIT')
            successors = []
        elif op == 0x05 or op in conditional:
            target = offset+8+item['displacement']*8
            successors = [target] if op == 0x05 else [offset+8, target]
        else:
            check(op in alu or op == 0x18, 'unsupported leaf opcode')
            successors = [offset+item['width']]
        check(all(target in decoded for target in successors),
              'branch/fallthrough outside body or into LDDW continuation')
        edges[offset] = sorted(set(successors))
    reachable = set()
    pending = [0]
    while pending:
        offset = pending.pop()
        if offset not in reachable:
            reachable.add(offset)
            pending.extend(edges[offset])
    check(reachable == set(decoded), 'unreachable decoded instruction')
    # Acyclicity and EXIT-only sinks establish termination for every local path.
    active, complete = set(), set()

    def visit(offset):
        check(offset not in active, 'cycle in leaf CFG')
        if offset in complete:
            return
        active.add(offset)
        for target in edges[offset]:
            visit(target)
        check(edges[offset] or decoded[offset]['op'] == 0x95, 'non-EXIT sink')
        active.remove(offset)
        complete.add(offset)

    visit(0)
    return dict(bytes=len(data), instruction_slots=len(data)//8,
                decoded_instructions=len(decoded), reachable_instructions=len(reachable),
                conditional_branches=sum(i['op'] in conditional for i in decoded.values()),
                unconditional_branches=sum(i['op'] == 0x05 for i in decoded.values()),
                exits=[offset for offset, i in decoded.items() if i['op'] == 0x95],
                edges=[dict(offset=offset, successors=targets) for offset, targets in edges.items()],
                calls=0, memory_accesses=0, relocations=0, all_local_paths_reach_exit=True)


def calls(data, start):
    result = []
    for offset, item in instructions(data).items():
        if item['op'] in (0x85, 0x8d):
            check(item['op'] == 0x85 and item['registers'] == 0x10,
                  'unexpected non-relative or indirect call')
            result.append(dict(offset=offset, target=start+offset+8+item['immediate']*8,
                               signed_immediate=item['immediate']))
    return result


def normalize(data, relocations):
    normalized = bytearray(data)
    for offset, item in instructions(data).items():
        if item['op'] == 0x85 and item['registers'] == 0x10:
            normalized[offset+4:offset+8] = bytes(4)
    for item in relocations:
        offset = item['offset']
        check(item['type'] == 8 and item['symbol_index'] == 0 and data[offset] == 0x18,
              'unsupported relocation normalization')
        normalized[offset+4:offset+8] = bytes(4)
        normalized[offset+12:offset+16] = bytes(4)
    return bytes(normalized)


def verify(root=None):
    manifest = json.loads((HERE/'manifest.json').read_text())
    for name, expected in manifest.items():
        check(digest((HERE/name).read_bytes()) == expected, 'package digest: '+name)
    inputs = json.loads((HERE/'inputs.json').read_text())
    windows = {}
    for key, item in inputs['windows'].items():
        data = (HERE/item['file']).read_bytes()
        check(len(data) == item['bytes'] and digest(data) == item['sha256'], 'window identity')
        windows[key] = data
    if root is not None:
        images = {}
        for side, item in inputs['artifacts'].items():
            image = Elf(root/item['path'])
            check(digest(image.data) == item['sha256'] and len(image.data) == item['bytes'],
                  'whole artifact identity: '+side)
            images[side] = image
        for key, item in inputs['windows'].items():
            actual, mapping, relocations = images[item['side']].window(item['start'], item['bytes'])
            check(actual == windows[key] and mapping == item['mapping'] and
                  relocations == item['relocations'], 'live window mapping: '+key)
        symbol = inputs['candidate_symbol']
        check(symbol in images['symbols'].symbols, 'actual candidate STT_FUNC extent')
        symbol_bytes, _, _ = images['symbols'].window(symbol['start'], symbol['size'])
        check(symbol_bytes == windows['candidate-leaf'], 'selected and symbol leaf bytes')
        check(images['original'].text[3]+images['original'].text[5] ==
              inputs['original_terminal_extent']['end'], 'actual original terminal .text extent')
        status = json.loads((root/'repro/status.json').read_text())['pump_fees']
        check(status['candidate_sha256'] == inputs['artifacts']['candidate']['sha256'] and
              status['candidate_artifact'] == inputs['artifacts']['candidate']['path'] and
              status['symbols_sha256'] == inputs['artifacts']['symbols']['sha256'],
              'current Fees selection changed')
        prior = inputs['prior_inventory']
        check(digest((root/prior['path']).read_bytes()) == prior['sha256'], 'prior inventory binding')
    original = windows['original-leaf']
    candidate = windows['candidate-leaf']
    check(original == candidate, 'leaf raw equality')
    cfg = leaf_cfg(original, inputs['windows']['original-leaf']['relocations'])
    check(cfg == leaf_cfg(candidate, inputs['windows']['candidate-leaf']['relocations']),
          'same complete leaf CFG')
    callers = []
    for pair in inputs['callers']:
        o, c = (inputs['windows'][pair[side]] for side in ('original', 'candidate'))
        od, cd = windows[pair['original']], windows[pair['candidate']]
        check(normalize(od, o['relocations']) == normalize(cd, c['relocations']),
              'complete caller normalized bytes')
        check(o['relocations'] == c['relocations'], 'caller relocation pattern')
        oc, cc = calls(od, o['start']), calls(cd, c['start'])
        check(oc == pair['original_calls'] and cc == pair['candidate_calls'], 'complete signed calls')
        check([i['offset'] for i in oc] == [i['offset'] for i in cc], 'call offsets')
        leaf_offset = [i['offset'] for i in oc if i['target'] ==
                       inputs['windows']['original-leaf']['start']]
        check(leaf_offset == [232], 'unique original terminal edge')
        check([i['offset'] for i in cc if i['target'] ==
               inputs['windows']['candidate-leaf']['start']] == [232], 'candidate terminal edge')
        for i, (original_call, candidate_call) in enumerate(zip(oc, cc)):
            relation = inputs['target_pairs'][str(i)]
            ow, cw = (inputs['windows'][relation[side]] for side in ('original', 'candidate'))
            check(original_call['target'] == ow['start'] and candidate_call['target'] == cw['start'],
                  'actual caller/callee relation')
            check(ow['relocations'] == cw['relocations'] and
                  normalize(windows[relation['original']], ow['relocations']) ==
                  normalize(windows[relation['candidate']], cw['relocations']),
                  'complete immediate-target normalized bodies')
        callers.append(dict(name=pair['name'], original_start=o['start'], candidate_start=c['start'],
                            bytes=len(od), complete_direct_calls=len(oc), leaf_call_offset=232,
                            raw_equal=od == cd, normalized_equal=True,
                            complete_immediate_target_bodies_supported=True))
    result = dict(leaf_sha256=digest(original), cfg=cfg, callers=callers,
                  full_binary_equality=False, transitive_call_data_equivalence_proven=False,
                  historical_original_function_boundary_proven=False)
    check(result == json.loads((HERE/'measurements.json').read_text()), 'saved measurement replay')
    return result


def self_test():
    inputs = json.loads((HERE/'inputs.json').read_text())
    good = (HERE/inputs['windows']['original-leaf']['file']).read_bytes()
    cases = []

    def rejected(name, data, relocations=None):
        try:
            leaf_cfg(data, relocations or [])
        except ValueError:
            cases.append(name)
        else:
            raise ValueError('mutation accepted: '+name)

    for name, offset, instruction in [
        ('call', 0, struct.pack('<BBhi', 0x85, 0x10, 0, 0)),
        ('memory load', 0, struct.pack('<BBhi', 0x79, 0, 0, 0)),
        ('outward branch', 64, struct.pack('<BBhi', 0x05, 0, 100, 0)),
        ('LDDW continuation target', 64, struct.pack('<BBhi', 0x05, 0, -8, 0)),
        ('cycle', 64, struct.pack('<BBhi', 0x05, 0, -1, 0)),
        ('terminal fallthrough', 264, struct.pack('<BBhi', 0xb7, 0, 0, 0)),
        ('invalid register', 104, struct.pack('<BBhi', 0xbf, 0xff, 0, 0)),
    ]:
        mutated = bytearray(good)
        mutated[offset:offset+8] = instruction
        rejected(name, bytes(mutated))
    rejected('relocation', good, [dict(offset=0, type=8, symbol_index=0)])
    check(len(cases) == 8, 'mutation coverage')
    return cases


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, help='also verify current whole ELF inputs and mappings')
    parser.add_argument('--self-test', action='store_true', help='reject eight in-memory CFG mutations')
    args = parser.parse_args()
    result = verify(args.repository.resolve() if args.repository else None)
    print(json.dumps(dict(result=result, live_artifacts_verified=args.repository is not None,
                          rejected_mutations=self_test() if args.self_test else []), indent=2))
