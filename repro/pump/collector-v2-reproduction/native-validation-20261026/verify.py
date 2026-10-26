#!/usr/bin/env python3
"""Check sealed guarded-build receipts without running native tools or programs."""
import gzip
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
RECIPE = HERE.parent
TESTED = ROOT / 'repro/pump/cto-shared6093-v2-signed-acceptance'
GUARD = '0c39f18a1a71e2c31cc9a07deac4418a1701454718df98caa812705f84520e3e'
PROFILE = '(version 1)(allow default)(deny network*)'
EXPECTED = {
    'executable': (1590856, 'fdfdb5f27af9b8c22effd48ea523c06bd037ceedf49df0da8178cad19eed38f5', 'candidate.so'),
    'unstripped': (2174728, '1e088e9add0218ebf6745a7f7557a4dc55dc68e86ec97790584db7f169c14bc3', 'unstripped.so'),
}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name):
    path = HERE / 'receipts' / name
    data = path.read_bytes()
    return json.loads(gzip.decompress(data) if name.endswith('.gz') else data)


def main():
    manifest = json.loads((HERE / 'manifest.json').read_text())
    require((HERE / 'manifest.sha256').read_text() == sha(HERE / 'manifest.json') + '\n', 'manifest seal')
    actual = {p.relative_to(HERE).as_posix() for p in HERE.rglob('*')
              if p.is_file() and p.name not in ('manifest.json', 'manifest.sha256')}
    require(actual == set(manifest['files']), 'publication membership')
    for name, row in manifest['files'].items():
        path = HERE / name
        require(not Path(name).is_absolute() and '..' not in Path(name).parts and not path.is_symlink(), 'unsafe member')
        require(path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], 'publication bytes: ' + name)
    for name, digest in manifest['recipe_sha256'].items():
        require(sha(RECIPE / name) == digest, 'recipe changed: ' + name)
    sources = json.loads((TESTED / 'build-input-source37.json').read_text())
    require(len(sources) == 37, 'source37 membership')
    for name, digest in sources.items():
        require(sha(TESTED / 'build-input-source' / name) == digest, 'source input: ' + name)
    preparation = load('preparation.json')
    require(preparation['status'] == 'PASS' and preparation['source37'] == sources and
            preparation['sdk_install_inputs_unchanged'], 'preparation failed')
    comparison = load('comparisons.json')
    require(comparison['status'] == 'PASS' and len(comparison['runs']) == 2 and
            comparison['original_deployed_byte_identity_claimed'] is False, 'comparison scope')
    for prefix, comparison_row in zip(('', 'repeat-'), comparison['runs']):
        reproduction = load(prefix + 'reproduction.json')
        attempt = load(prefix + 'build-attempt.json.gz')
        require(reproduction['status'] == 'PASS' and reproduction['guarded_command_returncode'] == 0 and
                reproduction['build_sbf_returncode'] == 0 and reproduction['helper_returncode'] is None and
                reproduction['inputs_unchanged'], 'native acceptance')
        require(reproduction['inputs']['source37'] == sources and
                attempt['source_sha256'] == attempt['source_after_sha256'] == sources and
                attempt['source_unchanged'] and attempt['returncode'] == 0, 'compiled input binding')
        require(reproduction['inputs']['sdk_install_inputs'] == preparation['sdk_install_inputs'],
                'prepared installer inputs changed')
        require(reproduction['network_guard'] == {'executable': '/usr/bin/sandbox-exec', 'sha256': GUARD,
                                                'profile': PROFILE}, 'guard identity')
        require(reproduction['command'][:3] == ['/usr/bin/sandbox-exec', '-p', PROFILE] and
                reproduction['command'][3:] == reproduction['helper_command'], 'guarded command')
        require(reproduction['reproducer_sha256'] == manifest['recipe_sha256']['reproduce.py'] and
                reproduction['inputs']['sdk_install_inputs']['checker_sha256'] ==
                manifest['recipe_sha256']['offline_inputs.py'], 'executed recipe binding')
        log = gzip.decompress((HERE / 'receipts' / (prefix + 'build.log.gz')).read_bytes())
        require(hashlib.sha256(log).hexdigest() == attempt['build_log_sha256'], 'raw build log')
        for name, (size, digest, file) in EXPECTED.items():
            output = reproduction['outputs'][name]
            require(output == {'bytes': size, 'sha256': digest, 'whole_file_equal': True}, 'output identity')
            require(comparison_row['outputs'][name] == {'bytes': size, 'sha256': digest,
                                                       'literal_byte_equal_to_tested': True}, 'literal comparison receipt')
            golden = TESTED / 'artifacts' / file
            require(golden.stat().st_size == size and sha(golden) == digest, 'tested artifact')
    probe = load('guard-probe.json.gz')
    require(probe['status'] == 'PASS' and probe['guard_sha256'] == GUARD and probe['profile'] == PROFILE,
            'network control identity')
    require(len(probe['observations']) == 8 and probe['controls_allowed'] == probe['guarded_attempts_denied'] == 4,
            'network control counts')
    seen = set()
    for row in probe['observations']:
        seen.add((row['transport'], row['descendant'], row['guarded']))
        require(row['returncode'] == 0, 'network probe process failed')
        if row['guarded']:
            require(row['probe']['sent'] is False and row['probe']['errno'] in (1, 13) and
                    row['server_received'] is None, 'network was not denied')
        else:
            require(row['probe'] == {'sent': True} and row['server_received'] == 'collector-guard-control',
                    'positive control failed')
    require(seen == {(transport, child, guard) for transport in ('TCP', 'UDP')
                     for child in (False, True) for guard in (False, True)}, 'network control coverage')
    host = load('host-identity.json')
    require(host['guard_sha256'] == GUARD and host['apple-verification']['returncode'] == 0, 'Apple guard observation')
    qualification = load('qualification-summary.json')
    require(qualification['differential_cases'] == 9269 and qualification['surfpool_comparisons'] == 1024 and
            qualification['surfpool_signed_transactions'] == 2048 and qualification['failures'] == [],
            'new qualification summary')
    require(qualification['candidate_sha256'] == EXPECTED['executable'][1] and
            qualification['runtime_normalization_unchanged'] and qualification['runtime_input_hashes_unchanged'] == 300,
            'qualification input binding')
    executions = load('qualification-execution-index.json.gz')
    require(len(executions) == 70 and all(row['status'] == 'PASS' and row['returncode'] == 0
                                        for row in executions), 'qualification child receipts')
    require(sum(row['cases'] for row in executions if row['kind'] == 'differential') == 9217 and
            sum(row['cases'] for row in executions if row['kind'] == 'surfpool') == 1024,
            'qualification count binding')
    supplemental = {row['name']: row['cases'] for row in executions if row['kind'] == 'supplemental'}
    require(supplemental == {'two-curve': 20, 'nested-original': 16, 'nested-candidate': 16,
                             'route-original': 16, 'route-candidate': 16}, 'supplemental coverage')
    # Original-only nested/route runs are controls, not additional comparisons.
    extra = sum(supplemental[name] for name in ('two-curve', 'nested-candidate', 'route-candidate'))
    require(extra == 52 and 9217 + extra == qualification['differential_cases'], 'comparison total')
    crypto = load('qualification-crypto.json.gz')
    require(qualification['crypto'] == {name: crypto[name] for name in ('transaction_fields', 'signature_fields')},
            'crypto field totals')
    require(len(crypto['unique_transaction_hashes']) == len(set(crypto['unique_transaction_hashes'])) ==
            qualification['unique_signed_payloads'] == 3003, 'distinct payload count')
    print(json.dumps({'status': 'PASS', 'fresh_guarded_builds': 2, 'tested_outputs_per_build': 2,
                      'guard_controls': 8, 'native_tools_executed_by_verifier': 0,
                      'original_deployment_identity_claimed': False}))


if __name__ == '__main__':
    main()
