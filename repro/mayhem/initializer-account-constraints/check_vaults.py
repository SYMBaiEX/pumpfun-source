#!/usr/bin/env python3
"""Compare genuine unsigned initializer failures with varied existing vault data."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.repo.resolve() / 'repro/behavioral-recovery/scripts/mayhem_initialize_state_differential.py'
    spec = importlib.util.spec_from_file_location('initializer_fixture', source)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    edits = {
        'wrong-mint': lambda data: bytes(fixture.ADMIN.pubkey()) + data[32:],
        'wrong-authority': lambda data: data[:32] + bytes(fixture.ADMIN.pubkey()) + data[64:],
        'uninitialized': lambda data: data[:108] + b'\x00' + data[109:],
        'frozen': lambda data: data[:108] + b'\x02' + data[109:],
        'invalid-state': lambda data: data[:108] + b'\x03' + data[109:],
        'short-data': lambda data: data[:-1],
        'empty-data': lambda data: b'',
    }

    class VaultFixture(fixture.Fixture):
        def _tokacct(self, mint, owner):
            return edit(super()._tokacct(mint, owner))

    rows = []
    original = args.repo.resolve() / 'evidence/original/mayhem/deployed.so'
    before = hashlib.sha256(args.candidate.read_bytes()).hexdigest()
    for name, edit in edits.items():
        case = {'name': name, 'stage': 5}
        left = VaultFixture(original).execute(case)
        right = VaultFixture(args.candidate).execute(case)
        fields = ['error', 'anchor_error', 'state_created']
        rows.append({'case': case, 'original': left, 'candidate': right,
                     'equal': all(left[key] == right[key] for key in fields)})
    assert hashlib.sha256(args.candidate.read_bytes()).hexdigest() == before
    report = {'candidate_sha256': before, 'original_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
              'fixture_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
              'case_count': len(rows), 'mismatches': [row['case']['name'] for row in rows if not row['equal']],
              'scope': 'Seven existing-vault data variants; original signer/PDA checks remain enforced. No standalone success or exhaustive validation claimed.',
              'cases': rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as output:
        output.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'cases': len(rows), 'mismatches': report['mismatches']}))
    raise SystemExit(bool(report['mismatches']))


if __name__ == '__main__':
    main()
