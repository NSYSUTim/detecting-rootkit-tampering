"""Retained exact-observation timing gate, independent of external tools."""
import unittest
from scripts.verify_scan_cost import assess_normal

class ScanCostEligibilityTests(unittest.TestCase):
    def test_exact_normal_observation(self):
        fp = [3, 11, 17]
        row = {'returncode': 0, 'result': {'benchmark': {'scan_to_verdict_ns': 10},
            'verdict': 'equal', 'recovery_validation': {'verified': True},
            'upstream_only': [], 'downstream_only': [], 'kernel_fingerprint': fp,
            'userspace': dict(zip(('count', 'sum1', 'sum2'), fp))}}
        self.assertTrue(assess_normal(row, 'ours', fp, set(), None)['eligible'])
        row['result']['kernel_fingerprint'] = [3, 12, 17]
        self.assertFalse(assess_normal(row, 'ours', fp, set(), None)['eligible'])

if __name__ == '__main__': unittest.main()
