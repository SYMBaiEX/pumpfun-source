"""Authenticate current local SDK install caches and the OS network guard.

These are newly observed local input identities, not official release or
historical build provenance. This module never executes a tool or fetches data.
"""
import hashlib
import json
import os
from pathlib import Path
import stat

CONTROLS = Path(__file__).resolve().parent / 'install-cache-identity'
CACHE_SEAL = '704222a8ab95bb0f09ddba93b9d6c9411c2553d0a378b92ccb6354342f8254a0'
SANDBOX = Path('/usr/bin/sandbox-exec')
SANDBOX_SHA = 'fd89e1f6e6d822fcc0f3844bd11fecdc9b68f705f80c32f4334bc23913d5451b'
# Separately observed Apple-signed input on macOS 27.2 build 26B5101f.
SANDBOX_MACOS_27_2_SHA = '0c39f18a1a71e2c31cc9a07deac4418a1701454718df98caa812705f84520e3e'
NETWORK_PROFILE = '(version 1)(allow default)(deny network*)'
REQUIRED_PLATFORM = ('rust/bin/rustc', 'rust/lib/librustc_driver-701c94505f05bbc4.dylib',
                     'llvm/bin/llvm-objcopy')


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        value = hashlib.file_digest(stream, 'sha256').hexdigest()
    return value


def checked(path, expected):
    require(path.is_file() and not path.is_symlink(), 'missing or linked input: ' + str(path))
    require(digest(path) == expected, 'input hash mismatch: ' + str(path))


def inventories(controls=CONTROLS):
    checked(controls / 'manifest.json', CACHE_SEAL)
    require((controls / 'manifest.sha256').read_text() == CACHE_SEAL + '\n', 'cache seal spelling differs')
    manifest = json.loads((controls / 'manifest.json').read_text())
    require(set(manifest) == {'REPORT.md', 'collection.json', 'platform-tools-v1.52.json',
                              'criterion-v2.3.2-darwin.json'}, 'cache control membership differs')
    for name, row in manifest.items():
        path = controls / name
        checked(path, row['sha256'])
        require(path.stat().st_size == row['bytes'], 'cache control size differs: ' + name)
    return {name: json.loads((controls / name).read_text()) for name in
            ('platform-tools-v1.52.json', 'criterion-v2.3.2-darwin.json')}


def tree_state(root):
    """Walk without following member symlinks, retaining all directory entries."""
    actual = {}
    pending = [root]
    while pending:
        for path in pending.pop().iterdir():
            info = path.lstat()
            mode = info.st_mode
            name = path.relative_to(root).as_posix()
            if stat.S_ISLNK(mode):
                kind = 'symlink'
            elif stat.S_ISREG(mode):
                kind = 'regular'
            elif stat.S_ISDIR(mode):
                kind = 'directory'
                pending.append(path)
            else:
                raise ValueError('unsupported cache entry: ' + name)
            actual[name] = (kind, stat.S_IMODE(mode), info.st_size, info.st_mtime_ns,
                            info.st_ctime_ns, info.st_ino, info.st_dev)
    return actual


def verify_tree(root, inventory, required=()):
    require(root.is_dir() and os.access(root, os.R_OK | os.X_OK), 'missing or unreadable cache root: ' + str(root))
    root = root.resolve(strict=True)
    for name, row in inventory.items():
        path = Path(name)
        require(name and not path.is_absolute() and '..' not in path.parts,
                'unsafe cache inventory path: ' + name)
        require(row['type'] in ('regular', 'symlink', 'directory'), 'unsupported inventory type: ' + name)
    before = tree_state(root)
    require({name: row[0] for name, row in before.items()} ==
            {name: row['type'] for name, row in inventory.items()}, 'cache membership differs: ' + str(root))
    for name, row in inventory.items():
        path = root / name
        require(before[name][1] == row['mode'], 'cache mode differs: ' + name)
        if row['type'] == 'regular':
            require(row['mode'] & 0o444 and os.access(path, os.R_OK), 'unreadable cache file: ' + name)
            require(before[name][2] == row['bytes'], 'cache size differs: ' + name)
            checked(path, row['sha256'])
        elif row['type'] == 'directory':
            require(row['mode'] & 0o444 and row['mode'] & 0o111 and
                    os.access(path, os.R_OK | os.X_OK), 'unreadable cache directory: ' + name)
        else:
            require(os.readlink(path) == row['target'], 'cache link target differs: ' + name)
            require(row['resolved_inside'] is True and path.resolve(strict=False).is_relative_to(root),
                    'cache link escapes tree: ' + name)
            require(path.exists() == row['resolved_exists'], 'cache link existence differs: ' + name)
    for name in required:
        row = inventory.get(name, {})
        require(row.get('type') == 'regular', 'required tool missing from inventory: ' + name)
        if name in ('rust/bin/rustc', 'llvm/bin/llvm-objcopy'):
            require(row['mode'] & 0o111 and os.access(root / name, os.X_OK), 'required tool not executable: ' + name)
    require(before == tree_state(root), 'cache changed while checking: ' + str(root))
    return {'resolved_root': str(root), 'entries': len(inventory),
            'regular_files': sum(row['type'] == 'regular' for row in inventory.values()),
            'symlinks': sum(row['type'] == 'symlink' for row in inventory.values())}


def sandbox_identity():
    require(SANDBOX.is_file() and not SANDBOX.is_symlink(), 'missing or linked input: ' + str(SANDBOX))
    observed = digest(SANDBOX)
    require(observed in (SANDBOX_SHA, SANDBOX_MACOS_27_2_SHA), 'input hash mismatch: ' + str(SANDBOX))
    require(SANDBOX.stat().st_mode & 0o111 and os.access(SANDBOX, os.X_OK), 'network guard not executable')
    return {'executable': str(SANDBOX), 'sha256': observed, 'profile': NETWORK_PROFILE}


def install_inputs(home=None, controls=CONTROLS):
    home = Path.home() if home is None else home
    data = inventories(controls)
    platform = verify_tree(home / '.cache/solana/v1.52/platform-tools',
                           data['platform-tools-v1.52.json'], REQUIRED_PLATFORM)
    criterion = verify_tree(home / '.cache/solana/v2.3.2/criterion',
                            data['criterion-v2.3.2-darwin.json'])
    return {'scope': 'new current local cache identity, not official or historical provenance',
            'cache_control_seal': CACHE_SEAL, 'platform_tools_v1_52': platform,
            'criterion_v2_3_2_darwin': criterion, 'network_guard': sandbox_identity(),
            'checker_sha256': digest(Path(__file__))}


def guarded_command(command):
    guard = sandbox_identity()
    return [guard['executable'], '-p', guard['profile'], *command]
