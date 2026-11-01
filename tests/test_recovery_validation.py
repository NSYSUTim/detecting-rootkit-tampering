import copy
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from kicba.reconciliation import IBLT, MultisetFingerprint, token_for_entry
from kicba.recovery_validation import finalize_record, validate_recovery
from finalization.measurement import compare_program_counters, read_program_counters

S1, S2 = 0x0123456789ABCDEF, 0xF0E1D2C3B4A59687


def make_record(left, right, cells=256):
    a = MultisetFingerprint.from_tokens(left).as_tuple()
    b = MultisetFingerprint.from_tokens(right).as_tuple()
    decoded = IBLT.from_tokens(left, cells, S1, S2).subtract(IBLT.from_tokens(right, cells, S1, S2)).decode()
    return {"measurement_valid": True, "verdict": "equal" if a == b else "different",
            "fingerprint_equal": a == b, "kernel_fingerprint": list(a), "visible_fingerprint": list(b),
            "decode_success": decoded.success, "residual_cells": decoded.residual_cells,
            "upstream_only": [[t.key_hash, t.inode, t.d_type] for t in decoded.upstream_only],
            "downstream_only": [[t.key_hash, t.inode, t.d_type] for t in decoded.downstream_only],
            "coverage": {"available": True, "valid": True}}


def counters(misses=0):
    return {"packed_enter": {"id": 11, "prog_tag": "a", "recursion_misses": misses},
            "packed_return": {"id": 12, "prog_tag": "b", "recursion_misses": 0}}


QUALITY = compare_program_counters(counters(), counters())


class RecoveryValidationTests(unittest.TestCase):
    def setUp(self):
        self.x = token_for_entry("entry_00074.txt", 101, 8, S1, S2)
        self.y = token_for_entry("entry_00934.txt", 101, 8, S1, S2)
        self.other = token_for_entry("replacement.txt", 102, 8, S1, S2)

    def test_zero_difference_is_not_an_alarm(self):
        row = finalize_record(make_record([self.x], [self.x]), QUALITY)
        self.assertEqual(row["verdict"], "equal")
        self.assertIs(row["alarm"], False)

    def test_signed_replacement_is_verified(self):
        row = finalize_record(make_record([self.x], [self.other]), QUALITY)
        self.assertIs(row["alarm"], True)
        self.assertIs(row["recovery_verified"], True)

    def test_false_empty_success_is_not_accepted(self):
        raw = make_record([self.x, self.x], [self.y, self.y])
        self.assertTrue(raw["decode_success"])
        row = finalize_record(raw, QUALITY)
        self.assertIs(row["alarm"], True)
        self.assertFalse(row["recovery_verified"])
        self.assertEqual(row["recovery_validation"]["status"], "fingerprint_mismatch")

    def test_unpeelable_repetitions_keep_alarm(self):
        row = finalize_record(make_record([self.x, self.x], []), QUALITY)
        self.assertIs(row["alarm"], True)
        self.assertFalse(row["recovery_verified"])
        self.assertEqual(row["recovery_status"], "unresolved")

    def test_unique_replacement_with_identical_positions_is_unresolved(self):
        raw = make_record([self.x], [self.y])
        self.assertFalse(raw["decode_success"])
        row = finalize_record(raw, QUALITY)
        self.assertIs(row["alarm"], True)
        self.assertFalse(row["recovery_verified"])

    def test_count_or_sign_tampering_fails_the_check(self):
        raw = make_record([self.x], [self.other])
        for key, value in (("upstream_only", []), ("downstream_only", raw["upstream_only"])):
            modified = {**raw, key: value}
            self.assertFalse(finalize_record(modified, QUALITY)["recovery_verified"])

    def test_invalid_measurement_never_becomes_equal_or_alarm(self):
        for raw in (make_record([self.x], [self.x]), make_record([self.x], [])):
            row = finalize_record({**raw, "measurement_valid": False}, QUALITY)
            self.assertEqual(row["verdict"], "invalid")
            self.assertIsNone(row["alarm"])

    def test_program_loss_gate_dominates_equal_fingerprints(self):
        bad = compare_program_counters(counters(), counters(1))
        row = finalize_record(make_record([self.x], [self.x]), bad)
        self.assertEqual(row["verdict"], "invalid")
        self.assertIsNone(row["alarm"])

    def test_return_profile_gate_remains_required(self):
        row = finalize_record({**make_record([self.x], []), "coverage": {"valid": True}}, QUALITY)
        self.assertEqual(row["verdict"], "invalid")

    def test_inputs_and_raw_decode_flag_are_preserved(self):
        raw = make_record([self.x, self.x], [self.y, self.y])
        saved = copy.deepcopy(raw)
        result = finalize_record(raw, QUALITY)
        self.assertEqual(raw, saved)
        self.assertTrue(result["decode_success"])
        self.assertFalse(result["recovery_verified"])

    def test_malformed_fields_are_not_normalized_into_valid_tokens(self):
        for bad in (True, -1, 2**64, "1"):
            checked = validate_recovery([1, 1, 1], [0, 0, 0], [[bad, 1, 8]], [], True, 0)
            self.assertFalse(checked["verified"])

    def test_success_with_residual_cells_is_rejected(self):
        checked = validate_recovery([0, 0, 0], [0, 0, 0], [], [], True, 1)
        self.assertEqual(checked["status"], "invalid_decode_metadata")

    def test_contradictory_equality_is_invalid(self):
        raw = make_record([self.x], [self.x])
        raw["upstream_only"] = [[self.x.key_hash, self.x.inode, self.x.d_type]]
        row = finalize_record(raw, QUALITY)
        self.assertEqual(row["verdict"], "invalid")
        self.assertIsNone(row["alarm"])


class ProgramCounterTests(unittest.TestCase):
    def test_linux_fdinfo_prog_id_field_is_read(self):
        bpf = SimpleNamespace(KPROBE=2, load_func=lambda name, kind: SimpleNamespace(fd=10))
        content = "prog_type:\t2\nprog_id:\t15\nprog_tag:\tabc\nrecursion_misses:\t3\n"
        with patch('finalization.measurement.Path.read_text', return_value=content):
            snapshot = read_program_counters(bpf)
        self.assertEqual(snapshot['packed_enter']['id'], 15)
        self.assertEqual(snapshot['packed_return']['recursion_misses'], 3)

    def test_same_program_no_loss_is_valid(self):
        self.assertTrue(QUALITY["valid"])

    def test_loss_reset_identity_change_and_missing_data_are_invalid(self):
        reset = counters(); reset["packed_enter"]["recursion_misses"] = 2
        changed = counters(); changed["packed_return"]["id"] = 15
        for first, last in ((counters(), counters(1)), (reset, counters()),
                            (counters(), changed), (None, counters()), (counters(), {})):
            with self.subTest(first=first, last=last):
                self.assertFalse(compare_program_counters(first, last)["valid"])

    def test_boolean_counter_is_not_zero(self):
        wrong = counters(); wrong["packed_enter"]["recursion_misses"] = False
        self.assertFalse(compare_program_counters(wrong, counters())["available"])


if __name__ == "__main__":
    unittest.main()
