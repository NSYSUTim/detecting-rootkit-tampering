"""Reject cross-call false positives and preserve established identity verdicts."""
import copy
import importlib
import unittest

from kicba.reconciliation import token_for_entry
from phase2.oracle import SEED1, SEED2


class CallCompletionTests(unittest.TestCase):
    def finalize(self, row):
        try:
            module = importlib.import_module('kicba.call_completion')
        except ModuleNotFoundError:
            self.fail('per-call completion behavior is not implemented')
        return module.finalize_call_record(row)

    def record(self, *, eof_rejected=0, earlier_rejected=1):
        token = token_for_entry(b'candidate', 123, 8, SEED1, SEED2)
        stats = {'outer_entries': 2 + earlier_rejected + eof_rejected,
                 'accepted_entries': 2, 'rejected_entries': earlier_rejected + eof_rejected}
        return {'verdict': 'equal', 'measurement_valid': True, 'alarm': False,
                'recovery_verified': False, 'kernel_stats': stats, 'userspace': {'syscalls': 2},
                'call_coverage': {'available': True, 'valid': True, 'reasons': []},
                'call_observation': {
                    'enters': 2, 'exits': 2, 'active': 0, 'pair_errors': 0,
                    'outside_entries': 0, 'outside_returns': 0,
                    'completed_entries': stats['outer_entries'],
                    'completed_accepted': 2, 'completed_rejected': stats['rejected_entries'],
                    'positive_calls': 1, 'zero_calls': 1, 'negative_calls': 0,
                    'last_return': 0, 'last_entries': eof_rejected,
                    'last_accepted': 0, 'last_rejected': eof_rejected,
                    'witness_valid': int(bool(eof_rejected)), 'fd_seen': 1,
                    'name_hex': b'candidate'.hex(),
                    'token': [token.key_hash, token.inode, token.d_type]}}

    def test_same_call_rejection_and_zero_return_adds_completion_alert(self):
        row = self.record(eof_rejected=1)
        before = copy.deepcopy(row)
        result = self.finalize(row)
        self.assertEqual(row, before)
        self.assertTrue(result['completion_anomaly'])
        self.assertEqual(result['verdict'], 'completion_anomaly')
        self.assertTrue(result['alarm'])
        self.assertEqual(result['identity_verdict'], 'equal')
        self.assertFalse(result['identity_alarm'])
        self.assertEqual(result['rejected_entry']['name_hex'], b'candidate'.hex())
        self.assertIsNone(result['total_missing_count'])

    def test_rejection_then_legitimate_deletion_before_eof_does_not_alert(self):
        result = self.finalize(self.record())
        self.assertFalse(result['completion_anomaly'])
        self.assertEqual(result['completion_status'], 'no_anomaly_observed')
        self.assertEqual(result['verdict'], 'equal')
        self.assertFalse(result['alarm'])
        self.assertIsNone(result['rejected_entry'])

    def test_normal_acceptance_and_resends_do_not_alert(self):
        for rejected in (0, 1, 100):
            with self.subTest(rejected=rejected):
                result = self.finalize(self.record(earlier_rejected=rejected))
                self.assertFalse(result['alarm'])
                self.assertTrue(result['completion_valid'])

    def test_new_quality_failure_cannot_erase_identity_alarm_or_recovery(self):
        for fault in ('missing', 'pair', 'coverage', 'witness'):
            row = self.record(eof_rejected=1)
            row.update(verdict='different', alarm=True, recovery_verified=True,
                       upstream_only=[[1, 2, 8]], downstream_only=[])
            if fault == 'missing':
                del row['call_observation']
            elif fault == 'pair':
                row['call_observation']['exits'] = 1
            elif fault == 'coverage':
                row['call_coverage']['valid'] = False
            else:
                row['call_observation']['token'][0] ^= 1
            with self.subTest(fault=fault):
                result = self.finalize(row)
                self.assertEqual(result['verdict'], 'different')
                self.assertTrue(result['alarm'])
                self.assertTrue(result['recovery_verified'])
                self.assertFalse(result['completion_valid'])
                self.assertEqual(result['upstream_only'], [[1, 2, 8]])

    def test_missing_new_evidence_cannot_be_called_overall_normal(self):
        row = self.record()
        del row['call_observation']
        result = self.finalize(row)
        self.assertEqual(result['identity_verdict'], 'equal')
        self.assertEqual(result['verdict'], 'inconclusive')
        self.assertIsNone(result['alarm'])
        self.assertFalse(result['completion_valid'])

    def test_corrupt_counts_missing_eof_and_unpaired_events_are_inconclusive(self):
        changes = [('enters', 1), ('active', 1), ('pair_errors', 1),
                   ('outside_entries', 1), ('outside_returns', 1),
                   ('completed_entries', 99), ('last_entries', 9),
                   ('last_accepted', 1), ('zero_calls', 0), ('negative_calls', 1),
                   ('last_return', -22), ('fd_seen', 0), ('enters', True)]
        for key, value in changes:
            row = self.record()
            row['call_observation'][key] = value
            with self.subTest(key=key):
                result = self.finalize(row)
                self.assertFalse(result['completion_valid'])
                self.assertEqual(result['verdict'], 'inconclusive')
                self.assertIsNone(result['alarm'])

    def test_bad_witness_does_not_create_an_alarm(self):
        for change in ('absent', 'name', 'token', 'flag'):
            row = self.record(eof_rejected=1)
            observation = row['call_observation']
            if change == 'absent':
                observation['witness_valid'] = 0
            elif change == 'name':
                observation['name_hex'] = '00'
            elif change == 'flag':
                observation['witness_valid'] = True
            else:
                observation['token'][0] ^= 1
            with self.subTest(change=change):
                self.assertEqual(self.finalize(row)['verdict'], 'inconclusive')

    def test_original_invalid_measurement_is_never_promoted(self):
        row = self.record(eof_rejected=1)
        row.update(verdict='invalid', measurement_valid=False, alarm=None)
        result = self.finalize(row)
        self.assertEqual(result['verdict'], 'invalid')
        self.assertIsNone(result['alarm'])
        self.assertFalse(result['completion_valid'])

    def test_both_alarm_reasons_and_verified_identity_recovery_are_retained(self):
        row = self.record(eof_rejected=1)
        row.update(verdict='different', alarm=True, recovery_verified=True)
        result = self.finalize(row)
        self.assertEqual(result['alarm_reasons'], ['identity_difference', 'completion_anomaly'])
        self.assertTrue(result['recovery_verified'])

    def test_unreadable_quality_is_inconclusive_without_erasing_identity_alarm(self):
        for identity in ('equal', 'different'):
            row = self.record()
            row.update(verdict=identity, alarm=identity == 'different')
            row['call_coverage'] = None
            with self.subTest(identity=identity):
                result = self.finalize(row)
                self.assertFalse(result['completion_valid'])
                self.assertEqual(result['verdict'], 'different' if identity == 'different' else 'inconclusive')


class CallCoverageTests(unittest.TestCase):
    def snapshot(self):
        return {'enter': {'id': 12, 'event_id': 820, 'prog_tag': 'abcd', 'recursion_misses': 0},
                'exit': {'id': 13, 'event_id': 819, 'prog_tag': 'cdef', 'recursion_misses': 0}}

    def test_new_program_miss_or_identity_change_refuses_completion_check(self):
        from kicba.call_completion import compare_call_coverage
        for label, field, value in [('enter', 'recursion_misses', 1), ('exit', 'id', 22),
                                     ('exit', 'event_id', 900), ('enter', 'prog_tag', 'ffff')]:
            before = self.snapshot()
            after = copy.deepcopy(before)
            after[label][field] = value
            with self.subTest(label=label, field=field):
                self.assertFalse(compare_call_coverage(before, after)['valid'])

    def test_stable_new_program_counters_are_usable(self):
        from kicba.call_completion import compare_call_coverage
        result = compare_call_coverage(self.snapshot(), self.snapshot())
        self.assertTrue(result['available'])
        self.assertTrue(result['valid'])

    def test_missing_or_malformed_counter_is_not_zero(self):
        from kicba.call_completion import compare_call_coverage
        for value in (None, True, -1):
            before = self.snapshot()
            before['enter']['recursion_misses'] = value
            with self.subTest(value=value):
                self.assertFalse(compare_call_coverage(before, self.snapshot())['valid'])


if __name__ == '__main__':
    unittest.main()
