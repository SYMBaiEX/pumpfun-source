"""Exercise live bindings and failure modes below the whole-image hash gate."""
from pathlib import Path
import json
import struct
import unittest

from verify import ARTIFACTS, WINDOWS, Elf, analyze, compare_group, summary, verify


class FormatterProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[3]
        cls.bodies = {}
        for side, index in (('original', 0), ('candidate', 1)):
            image = Elf((cls.root / ARTIFACTS[side][0]).read_bytes())
            cls.bodies[side] = {role: image.text(bounds[index], bounds[2])
                                for role, bounds in WINDOWS.items()}

    def mutated(self, role, offset, instruction):
        body = bytearray(self.bodies['original'][role])
        body[offset:offset + 8] = instruction
        return bytes(body)

    def test_live_artifacts_symbols_capture_and_current_status(self):
        self.assertEqual(verify(self.root)['status'], 'PASS')

    def test_complete_direct_call_group(self):
        analyses, differences = compare_group(self.bodies['original'], self.bodies['candidate'])
        self.assertEqual(differences['pad_integral'], [432])
        self.assertEqual(len(analyses['pad_integral']['original']['direct_calls']), 5)

    def test_published_measurements_equal_live_result(self):
        saved = json.loads(Path(__file__).with_name('measurements.json').read_text())
        observed = json.loads(json.dumps(summary(verify(self.root))))
        self.assertEqual(observed, saved)

    def test_changed_child_instruction_rejected(self):
        candidate = dict(self.bodies['candidate'])
        body = bytearray(candidate['write_prefix'])
        body[4] = 1
        candidate['write_prefix'] = bytes(body)
        with self.assertRaisesRegex(ValueError, 'differing instruction'):
            compare_group(self.bodies['original'], candidate)

    def test_wrong_corresponding_call_target_rejected(self):
        candidate = dict(self.bodies['candidate'])
        body = bytearray(candidate['pad_integral'])
        immediate = struct.unpack_from('<i', body, 436)[0]
        struct.pack_into('<i', body, 436, immediate + 1)
        candidate['pad_integral'] = bytes(body)
        with self.assertRaisesRegex(ValueError, 'direct call target'):
            compare_group(self.bodies['original'], candidate)

    def test_syscall_is_not_interpreted_as_relative_call(self):
        body = self.mutated('pad_integral', 224, struct.pack('<BBhi', 0x85, 0, 0, 164))
        with self.assertRaisesRegex(ValueError, 'source-1 relative CALL'):
            analyze(body)

    def test_outward_branch_rejected(self):
        body = self.mutated('write_prefix', 48, struct.pack('<BBhi', 0x15, 2, 100, 0))
        with self.assertRaisesRegex(ValueError, 'branch escapes'):
            analyze(body)

    def test_lddw_continuation_is_not_an_instruction_start(self):
        original = self.bodies['original']['do_count_chars']
        row = next(row for row in analyze(original)['records'] if row[1] == 0x18)
        target = row[0] + 8
        body = self.mutated('do_count_chars', 40,
                            struct.pack('<BBhi', 0xad, 0x32, (target - 48) // 8, 0))
        with self.assertRaisesRegex(ValueError, 'branch into LDDW'):
            analyze(body)

    def test_unsupported_opcode_rejected(self):
        body = self.mutated('write_prefix', 0, bytes(8))
        with self.assertRaisesRegex(ValueError, 'unsupported opcode'):
            analyze(body)

    def test_terminal_fallthrough_rejected(self):
        body = self.mutated('do_count_chars', 1464, struct.pack('<BBhi', 0xb7, 0, 0, 0))
        with self.assertRaisesRegex(ValueError, 'fallthrough escapes'):
            analyze(body)


if __name__ == '__main__':
    unittest.main()
