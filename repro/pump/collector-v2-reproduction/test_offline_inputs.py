"""Synthetic cache fixtures and mocked launches; no native/network executions."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import offline_inputs as o
import reproduce as r
import prepare


class OfflineInputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='collector-offline-input-test-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.platform = self.home / '.cache/solana/v1.52/platform-tools'
        self.criterion = self.home / '.cache/solana/v2.3.2/criterion'
        for root, names in [(self.platform, o.REQUIRED_PLATFORM),
                            (self.criterion, ('include/criterion.h', 'lib/libcriterion.dylib'))]:
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(('inert fixture ' + name).encode())
                path.chmod(0o755 if name in o.REQUIRED_PLATFORM else 0o644)
        (self.criterion / 'lib/alias.dylib').symlink_to('libcriterion.dylib')
        (self.platform / 'dangling-debugger').symlink_to('missing-debugger')
        self.data = {'platform-tools-v1.52.json': self.inventory(self.platform),
                     'criterion-v2.3.2-darwin.json': self.inventory(self.criterion)}
        self.sandbox = self.home / 'sandbox-inert-fixture'
        self.sandbox.write_bytes(b'never executed sandbox fixture')
        self.sandbox.chmod(0o755)
        self.addCleanup(patch.stopall)
        patch.object(o, 'SANDBOX', self.sandbox).start()
        patch.object(o, 'SANDBOX_SHA', o.digest(self.sandbox)).start()

    def inventory(self, root):
        result = {}
        for path in root.rglob('*'):
            info = path.lstat()
            row = {'mode': stat.S_IMODE(info.st_mode)}
            if path.is_symlink():
                row.update(type='symlink', target=os.readlink(path), resolved_inside=True,
                           resolved_exists=path.exists())
            elif path.is_file():
                row.update(type='regular', bytes=info.st_size, sha256=o.digest(path))
            else:
                row.update(type='directory')
            result[path.relative_to(root).as_posix()] = row
        return result

    def validate(self):
        with patch.object(o, 'inventories', return_value=self.data):
            return o.install_inputs(self.home)

    def test_exact_current_control_export_authenticates_without_cache_reads(self):
        data = o.inventories()
        self.assertEqual(len(data['platform-tools-v1.52.json']), 3842)
        self.assertEqual(len(data['criterion-v2.3.2-darwin.json']), 38)

    def test_tampered_control_rejected(self):
        controls = self.home / 'controls'
        controls.mkdir()
        (controls / 'manifest.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            o.inventories(controls)

    def test_exact_trees_and_inside_dangling_link_pass(self):
        result = self.validate()
        self.assertEqual(result['platform_tools_v1_52']['symlinks'], 1)
        self.assertEqual(result['criterion_v2_3_2_darwin']['symlinks'], 1)
        self.assertEqual(result['network_guard']['profile'], '(version 1)(allow default)(deny network*)')

    def test_missing_criterion_fails(self):
        self.criterion.rename(self.criterion.with_name('removed'))
        with self.assertRaisesRegex(ValueError, 'missing or unreadable cache root'):
            self.validate()

    def test_deleted_criterion_after_prepare_fails(self):
        self.validate()
        (self.criterion / 'include/criterion.h').unlink()
        with self.assertRaisesRegex(ValueError, 'membership differs'):
            self.validate()

    def test_unreadable_criterion_fails(self):
        target = self.criterion / 'include/criterion.h'
        real_access = os.access
        with patch.object(o.os, 'access', side_effect=lambda p, m: False if p == target.resolve() else real_access(p, m)):
            with self.assertRaisesRegex(ValueError, 'unreadable cache file'):
                self.validate()

    def test_changed_rustc_driver_or_stripper_fails(self):
        for name in o.REQUIRED_PLATFORM:
            with self.subTest(name=name):
                path = self.platform / name
                previous = path.read_bytes()
                path.write_bytes(b'X' * len(previous))
                with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                    self.validate()
                path.write_bytes(previous)

    def test_size_mode_and_extra_member_fail(self):
        target = self.platform / 'rust/bin/rustc'
        original = target.read_bytes()
        target.write_bytes(original + b'extra')
        with self.assertRaisesRegex(ValueError, 'size differs'):
            self.validate()
        target.write_bytes(original)
        target.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'mode differs'):
            self.validate()
        target.chmod(0o755)
        (self.platform / 'extra').mkdir()
        with self.assertRaisesRegex(ValueError, 'membership differs'):
            self.validate()

    def test_changed_or_escaping_link_fails(self):
        link = self.criterion / 'lib/alias.dylib'
        link.unlink()
        link.symlink_to('../../../outside')
        with self.assertRaisesRegex(ValueError, 'link target differs'):
            self.validate()
        self.data['criterion-v2.3.2-darwin.json']['lib/alias.dylib']['target'] = '../../../outside'
        with self.assertRaisesRegex(ValueError, 'escapes tree'):
            self.validate()

    def test_symlink_mode_and_dangling_state_are_pinned(self):
        self.data['platform-tools-v1.52.json']['dangling-debugger']['mode'] ^= 0o100
        with self.assertRaisesRegex(ValueError, 'mode differs'):
            self.validate()
        self.data['platform-tools-v1.52.json']['dangling-debugger']['mode'] ^= 0o100
        self.data['platform-tools-v1.52.json']['dangling-debugger']['resolved_exists'] = True
        with self.assertRaisesRegex(ValueError, 'existence differs'):
            self.validate()

    def test_regular_file_cannot_be_replaced_by_link(self):
        target = self.platform / 'rust/bin/rustc'
        target.unlink()
        target.symlink_to('other-rustc')
        with self.assertRaisesRegex(ValueError, 'membership differs'):
            self.validate()

    def test_required_driver_must_be_present_even_in_smaller_inventory(self):
        name = o.REQUIRED_PLATFORM[1]
        (self.platform / name).unlink()
        del self.data['platform-tools-v1.52.json'][name]
        with self.assertRaisesRegex(ValueError, 'required tool missing'):
            self.validate()

    def test_tree_change_during_hash_check_fails(self):
        actual_digest = o.digest
        def mutate(path):
            value = actual_digest(path)
            if path == (self.platform / o.REQUIRED_PLATFORM[0]).resolve():
                (self.platform / 'added-during-validation').write_text('mutation')
            return value
        with patch.object(o, 'digest', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'changed while checking'):
                self.validate()

    def test_missing_tampered_or_nonexecutable_guard_fails_without_launch(self):
        self.sandbox.write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            o.guarded_command(['never-execute'])
        self.sandbox.unlink()
        with self.assertRaisesRegex(ValueError, 'missing or linked input'):
            o.guarded_command(['never-execute'])
        self.sandbox.write_bytes(b'never executed sandbox fixture')
        self.sandbox.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'not executable'):
            o.guarded_command(['never-execute'])

    def test_additional_exact_guard_pin_records_selected_hash_and_keeps_original(self):
        expected = o.digest(self.sandbox)
        with patch.object(o, 'SANDBOX_SHA', '0' * 64), \
             patch.object(o, 'SANDBOX_MACOS_27_2_SHA', expected):
            self.assertEqual(o.sandbox_identity()['sha256'], expected)
            self.assertEqual(o.guarded_command(['never-execute']),
                             [str(self.sandbox), '-p', o.NETWORK_PROFILE, 'never-execute'])
            self.sandbox.write_bytes(b'unlisted guard')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                o.sandbox_identity()
        self.sandbox.write_bytes(b'never executed sandbox fixture')
        self.assertEqual(o.sandbox_identity()['sha256'], expected)

    def fixture_reproduction(self):
        repo = self.home / 'fixture-repository'
        package = repo / r.PACKAGE
        source = package / 'build-input-source/programs/pump/fixture.rs'
        helper = package / 'build-plan/helpers/scripts/build_partial_candidate.py'
        original = repo / 'evidence/original/pump/deployed.so'
        for path in (source, helper, original):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'plain synthetic fixture, never compiled')
        before = {'source37': {'programs/pump/fixture.rs': o.digest(source)},
                  'helpers': {'scripts/build_partial_candidate.py': o.digest(helper)},
                  'sdk_install_inputs': {'network_guard': o.sandbox_identity()}}
        return repo, original, before

    def test_actual_launch_site_uses_exact_guard_and_preserves_success_receipt(self):
        repo, original, before = self.fixture_reproduction()
        output = self.home / 'result'
        def fake_child(command, **kwargs):
            self.assertEqual(command[:3], [str(self.sandbox), '-p', '(version 1)(allow default)(deny network*)'])
            self.assertEqual(command[3], r.sys.executable)
            build = output / 'build'
            build.mkdir()
            (build / 'build-attempt.json').write_text(json.dumps({'returncode': 0, 'source_unchanged': True,
                'source_sha256': before['source37'], 'source_after_sha256': before['source37']}))
            return type('Result', (), {'returncode': 0})()
        with patch.object(r, 'preflight', return_value=before) as check, \
             patch.object(r, 'ORIGINAL', o.digest(original)), \
             patch.object(r, 'outputs', return_value={}), \
             patch.object(r.subprocess, 'run', side_effect=fake_child) as launch:
            result = r.reproduce(self.home / 'prepared', output, repo)
        launch.assert_called_once()
        self.assertEqual(check.call_count, 2)
        self.assertFalse(check.call_args.kwargs['fresh'])
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['guarded_command_returncode'], 0)
        self.assertIsNone(result['helper_returncode'])
        self.assertEqual(result['command'][3:], result['helper_command'])
        self.assertEqual(result['network_guard'], before['sdk_install_inputs']['network_guard'])

    def test_postcheck_mutation_is_failure_receipt(self):
        repo, original, before = self.fixture_reproduction()
        after = copy.deepcopy(before)
        after['sdk_install_inputs']['network_guard']['sha256'] = 'changed'
        output = self.home / 'failure-result'
        with patch.object(r, 'preflight', side_effect=[before, after]), \
             patch.object(r, 'ORIGINAL', o.digest(original)), \
             patch.object(r, 'outputs', return_value={}), \
             patch.object(r.subprocess, 'run') as launch:
            launch.return_value.returncode = 0
            with self.assertRaisesRegex(ValueError, 'inputs changed during build'):
                r.reproduce(self.home / 'prepared', output, repo)
        result = json.loads((output / 'reproduction.json').read_text())
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('inputs changed', result['error'])
        launch.assert_called_once()

    def test_preparation_rejects_install_inputs_before_any_download_or_native_launch(self):
        with patch.object(prepare.platform, 'system', return_value='Darwin'), \
             patch.object(prepare.platform, 'machine', return_value='arm64'), \
             patch.object(o, 'install_inputs', side_effect=ValueError('missing required cache')), \
             patch.object(prepare, 'acquire') as download, \
             patch.object(prepare.subprocess, 'run') as launch:
            with self.assertRaisesRegex(ValueError, 'missing required cache'):
                prepare.prepare(self.home / 'not-prepared')
        download.assert_not_called()
        launch.assert_not_called()

    def test_invalid_guard_cannot_reach_launch_site(self):
        repo, original, before = self.fixture_reproduction()
        self.sandbox.unlink()
        with patch.object(r, 'preflight', return_value=before), \
             patch.object(r, 'ORIGINAL', o.digest(original)), \
             patch.object(r.subprocess, 'run') as launch:
            with self.assertRaisesRegex(ValueError, 'missing or linked input'):
                r.reproduce(self.home / 'prepared', self.home / 'no-launch', repo)
        launch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
