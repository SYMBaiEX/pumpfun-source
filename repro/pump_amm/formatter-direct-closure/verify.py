#!/usr/bin/env python3
"""Check a fixed AMM formatter group directly against the selected ELF files."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


ARTIFACTS = {
    'original': ('evidence/original/pump_amm/deployed.so',
                 '6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7'),
    'candidate': ('repro/pump_amm/owner6048-v144/main/candidate.so',
                  '09bee0dfd751dc6ae0240bbac262933c6bda6e0c94aa643f82c57f2956c3a117'),
    'symbols': ('repro/pump_amm/owner6048-v144/main/unstripped.so',
                'f6e504317ba774325c0ba682e2529c7f18d1ae645a0d7aa239de557729dd0cb4'),
}
# Original bounds are inferred windows, not recovered historical symbols.
WINDOWS = {
    'pad_integral': (1132800, 1074592, 1544),
    'write_prefix': (1134344, 1076136, 184),
    'do_count_chars': (1142448, 1083480, 1472),
}
CALL_ROLES = {224: 'write_prefix', 432: 'do_count_chars',
              496: 'write_prefix', 912: 'write_prefix', 1336: 'write_prefix'}
OPCODES = {0x05, 0x07, 0x0f, 0x15, 0x18, 0x1d, 0x1f, 0x2d, 0x2f,
           0x4f, 0x55, 0x57, 0x5d, 0x5f, 0x61, 0x62, 0x63, 0x65, 0x67,
           0x71, 0x72, 0x73, 0x77, 0x79, 0x7b, 0x85, 0x8d, 0x95,
           0xa5, 0xa7, 0xad, 0xb7, 0xbf, 0xc7}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Elf:
    """Only the ELF64 little-endian sections/symbols needed by this fixed proof."""
    def __init__(self, data):
        self.data = data
        require(data[:6] == b'\x7fELF\x02\x01', 'not ELF64 little-endian')
        header = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
        require((header[1], header[6], header[10]) == (263, 0, 64),
                'unexpected sBPF ELF machine, flags or section-entry size')
        self.sections = [struct.unpack_from('<IIQQQQIIQQ', data, header[5] + i * 64)
                         for i in range(header[11])]
        names = self.section_data(self.sections[header[12]])
        self.named = {names[s[0]:].split(b'\0')[0].decode(): s for s in self.sections}

    def section_data(self, section):
        offset, length = section[4:6]
        require(offset + length <= len(self.data), 'section exceeds file')
        return self.data[offset:offset + length]

    def text(self, address, size):
        section = self.named['.text']
        require(size > 0 and section[3] <= address and
                address + size <= section[3] + section[5], 'window outside .text')
        offset = section[4] + address - section[3]
        return self.data[offset:offset + size]

    def function_symbols(self):
        result = []
        for section in self.sections:
            if section[1] != 2:  # SHT_SYMTAB
                continue
            require(section[9] == 24, 'unexpected symbol-entry size')
            names = self.section_data(self.sections[section[6]])
            table = self.section_data(section)
            for offset in range(0, len(table), 24):
                name, info, _, index, address, size = struct.unpack_from('<IBBHQQ', table, offset)
                if info & 15 == 2 and index and size:
                    result.append((address, size, names[name:].split(b'\0')[0].decode()))
        return result

    def relocations_in(self, start, size):
        result = []
        for section in self.sections:
            if section[1] not in (4, 9):  # SHT_RELA, SHT_REL
                continue
            stride = 24 if section[1] == 4 else 16
            require(section[9] == stride, 'unexpected relocation-entry size')
            table = self.section_data(section)
            for offset in range(0, len(table), stride):
                address = struct.unpack_from('<Q', table, offset)[0]
                if start <= address < start + size:
                    result.append(address)
        return result


def analyze(body):
    """Retain every record/edge. No branch feasibility or memory model is assumed."""
    require(len(body) % 8 == 0, 'unaligned window')
    records = []
    pc = 0
    while pc < len(body):
        opcode, registers, offset, immediate = struct.unpack_from('<BBhi', body, pc)
        upper = None
        if opcode == 0x18:
            require(pc + 16 <= len(body) and body[pc + 8:pc + 12] == bytes(4),
                    'invalid LDDW continuation')
            upper = struct.unpack_from('<i', body, pc + 12)[0]
        records.append([pc, opcode, registers, offset, immediate, upper])
        pc += 16 if opcode == 0x18 else 8
    starts = {r[0] for r in records}
    edges, direct, indirect, exits, memory = [], [], [], [], []
    for pc, opcode, registers, offset, immediate, upper in records:
        require(opcode in OPCODES, 'unsupported opcode')
        require(registers & 15 <= 10 and registers >> 4 <= 10, 'invalid register')
        if opcode == 0x95:
            require((registers, offset, immediate) == (0, 0, 0), 'noncanonical EXIT')
            exits.append(pc)
            continue
        if opcode == 0x85:
            require(registers == 0x10 and offset == 0, 'not a source-1 relative CALL')
            direct.append({'offset': pc, 'target_relative': pc + 8 + 8 * immediate})
        elif opcode == 0x8d:
            require(registers == 0 and offset == 0 and 0 <= immediate <= 10,
                    'unexpected v0 CALL_REG encoding')
            indirect.append({'offset': pc, 'register': immediate})
        elif opcode & 7 == 5:
            require(opcode & 0xf0 in (0x00, 0x10, 0x20, 0x30, 0x40, 0x50,
                                     0x60, 0x70, 0xa0, 0xb0, 0xc0, 0xd0),
                    'unsupported jump opcode')
            target = pc + 8 + 8 * offset
            require(0 <= target < len(body), 'branch escapes window')
            edges.append([pc, target])
            if opcode == 0x05:
                continue
        following = pc + (16 if opcode == 0x18 else 8)
        require(following < len(body), 'fallthrough escapes window')
        edges.append([pc, following])
        if opcode & 7 in (1, 2, 3):
            memory.append({'offset': pc, 'opcode': opcode,
                           'registers': registers, 'displacement': offset})
    require(exits, 'no local EXIT')
    require(all(target in starts for _, target in edges), 'branch into LDDW continuation')
    reached, pending = set(), [0]
    successors = {}
    for source, target in edges:
        successors.setdefault(source, []).append(target)
    while pending:
        pc = pending.pop()
        if pc not in reached:
            reached.add(pc)
            pending.extend(successors.get(pc, []))
    require(len(reached) == len(records), 'unreachable records require separate treatment')
    return {'records': records, 'edges': edges,
            'direct_calls': direct, 'indirect_calls': indirect,
            'exits': exits, 'memory_operations': memory,
            'all_records_syntactically_reachable': True}


def compare_group(original, candidate):
    analyses, differences = {}, {}
    for role in WINDOWS:
        left, right = original[role], candidate[role]
        require(len(left) == len(right) == WINDOWS[role][2], 'wrong complete window length')
        a, b = analyze(left), analyze(right)
        require(len(a['records']) == len(b['records']), 'different record counts')
        changed = [x[0] for x, y in zip(a['records'], b['records']) if x != y]
        require(changed == ([432] if role == 'pad_integral' else []),
                'unexpected differing instruction records: ' + role)
        for field in ('edges', 'indirect_calls', 'exits', 'memory_operations'):
            require(a[field] == b[field], 'different local structure: ' + role)
        if role != 'pad_integral':
            require(not a['direct_calls'], 'child has an unclosed direct call')
        if role == 'do_count_chars':
            require(not a['indirect_calls'], 'leaf has an indirect call')
        if role == 'pad_integral':
            for side, analysis in enumerate((a, b)):
                actual = {c['offset']: c['target_relative'] + WINDOWS[role][side]
                          for c in analysis['direct_calls']}
                expected = {site: WINDOWS[target][side] for site, target in CALL_ROLES.items()}
                require(actual == expected, 'direct call target does not close to corresponding child')
        analyses[role] = {'original': a, 'candidate': b}
        differences[role] = changed
    return analyses, differences


def verify(root):
    images = {}
    for role, (name, expected) in ARTIFACTS.items():
        data = (root / name).read_bytes()
        require(digest(data) == expected, 'artifact hash mismatch: ' + name)
        images[role] = Elf(data)
    status = json.loads((root / 'repro/status.json').read_text())['pump_amm']
    require((status['candidate_artifact'], status['candidate_sha256']) == ARTIFACTS['candidate'],
            'AMM selection changed; proof needs explicit rebinding')
    capture = json.loads((root / 'evidence/original/pump_amm/capture.json').read_text())
    require(capture['payload_sha256'] == ARTIFACTS['original'][1], 'capture binding changed')
    symbols = images['symbols'].function_symbols()
    bodies, rows = {'original': {}, 'candidate': {}}, {}
    for role, (old, new, size) in WINDOWS.items():
        names = [name for address, length, name in symbols if (address, length) == (new, size)]
        require(len(names) == 1 and role in names[0], 'candidate symbol extent mismatch: ' + role)
        for side, address in (('original', old), ('candidate', new)):
            bodies[side][role] = images[side].text(address, size)
            require(not images[side].relocations_in(address, size), 'relocation within code window')
        require(images['symbols'].text(new, size) == bodies['candidate'][role],
                'symbol ELF code differs from selected stripped ELF')
        rows[role] = {'original_address': old, 'candidate_address': new, 'bytes': size,
                      'candidate_symbol': names[0],
                      'original_sha256': digest(bodies['original'][role]),
                      'candidate_sha256': digest(bodies['candidate'][role])}
    analyses, differences = compare_group(bodies['original'], bodies['candidate'])
    return {'status': 'PASS', 'scope': 'three fixed windows and their five direct call sites',
            'artifacts': ARTIFACTS, 'windows': rows, 'analyses': analyses,
            'differing_record_offsets': differences,
            'new_builds': 0, 'target_executions': 0,
            'limits': ['Original function names/boundaries remain inferred.',
                       'Eight indirect call sites across parent and prefix remain unresolved.',
                       'Reachability is syntactic; memory validity, aliases, loop termination and output are not proved.',
                       'No authentic source/recipe recovery, status promotion or whole-program equality.']}


def summary(result):
    out = {key: value for key, value in result.items() if key != 'analyses'}
    out['structure'] = {}
    for role, sides in result['analyses'].items():
        a = sides['original']
        out['structure'][role] = {
            'instruction_records_per_image': len(a['records']),
            'local_edges_per_image': len(a['edges']),
            'lddw_records_per_image': sum(row[1] == 0x18 for row in a['records']),
            'memory_operations_per_image': len(a['memory_operations']),
            'direct_calls_per_image': len(a['direct_calls']),
            'indirect_calls_per_image': len(a['indirect_calls']),
            'exit_offsets': a['exits'],
            'all_records_syntactically_reachable': True,
        }
    return out


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--full', action='store_true', help='include every raw record and local CFG edge')
    args = parser.parse_args()
    result = verify(args.repo.resolve())
    print(json.dumps(result if args.full else summary(result), indent=2))
