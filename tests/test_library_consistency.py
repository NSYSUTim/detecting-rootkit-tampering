"""Regressions for complete, same-stream S-L observations and verified recovery."""

import unittest

from kicba.library_consistency import compare_entries, parse_application_output, parse_syscall_trace


SEEDS = 0x0123456789ABCDEF, 0xF0E1D2C3B4A59687


def call(name=b"a", inode=10, fd=3):
    encoded = "".join(f"\\x{byte:02x}" for byte in name)
    length = (20 + len(name) + 7) // 8 * 8
    return (f'getdents64({fd}, [{{d_ino={inode}, d_off=1, d_reclen={length}, '
            f'd_type=DT_REG, d_name="{encoded}"}}], 32768) = {length}\n')


EOF = "getdents64(3, [], 32768) = 0\n"


class LibraryConsistencyTests(unittest.TestCase):
    def test_complete_paginated_listing_preserves_bytes_and_repeated_eof(self):
        rows, calls = parse_syscall_trace(call() + call(b"byte-\xff", 11) + EOF + EOF)
        self.assertEqual(rows, [(b"a", 10, 8), (b"byte-\xff", 11, 8)])
        self.assertEqual(calls, 4)

    def test_incomplete_mixed_and_truncated_traces_are_rejected(self):
        for trace in (call(), call(fd=4) + EOF, EOF + call() + EOF,
                      call().replace("d_type=DT_REG", "...") + EOF,
                      call().replace("= 24", "= 25") + EOF):
            with self.subTest(trace=trace), self.assertRaises(ValueError):
                parse_syscall_trace(trace)

    def test_early_library_close_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_application_output("PID 42\nENTRY 10 8 61\nEND early_close\n")

    def test_normal_and_equal_count_substitution(self):
        original = [(b"visible", 10, 8), (b"target", 11, 8)]
        normal = compare_entries(original, list(reversed(original)), SEEDS)
        self.assertEqual(normal["verdict"], "equal")
        altered = compare_entries(original, [(b"visible", 10, 8), (b"changed", 11, 8)], SEEDS)
        self.assertEqual(altered["syscall_fingerprint"][0], altered["application_fingerprint"][0])
        self.assertTrue(altered["alarm"])
        self.assertTrue(altered["recovery_verified"])
        self.assertEqual(len(altered["upstream_only"]), 1)
        self.assertEqual(len(altered["downstream_only"]), 1)

    def test_duplicate_tokens_do_not_produce_false_verified_recovery(self):
        repeated = [(b"same", 11, 8)] * 2
        result = compare_entries(repeated, [], SEEDS)
        self.assertTrue(result["alarm"])
        self.assertFalse(result["decode_success"])
        self.assertFalse(result["recovery_verified"])


if __name__ == "__main__":
    unittest.main()
