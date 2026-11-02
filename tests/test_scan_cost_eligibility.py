"""Prevent invalid or incomplete observations from entering speed rankings."""
import unittest
from pathlib import Path
from comparison.scan_cost.run import assess,fingerprint


class EligibilityTests(unittest.TestCase):
    def setUp(self):
        self.rows=[{'name_hex':b'a'.hex(),'inode':1,'d_type':8}]
        self.fixture=Path('/example')

    def test_equal_uses_actual_recovery_check(self):
        r={'verdict':'equal','recovery_verified':False,'recovery_status':'no_difference_observed',
           'recovery_validation':{'verified':True},'kernel_fingerprint':fingerprint(self.rows),
           'userspace':dict(zip(('count','sum1','sum2'),fingerprint(self.rows))),
           'upstream_only':[],'downstream_only':[],'benchmark':{'scan_to_verdict_ns':100}}
        self.assertTrue(assess({'returncode':0,'result':r},'ours',self.fixture,self.rows,self.rows)['eligible'])
        r['recovery_validation']['verified']=False
        self.assertFalse(assess({'returncode':0,'result':r},'ours',self.fixture,self.rows,self.rows)['eligible'])

    def go(self,produced,returned,elapsed=100):
        row={'returncode':0,'result':{'results':[{'cell':'hidden_file','status':0,'findings':[]}]}}
        m={'scan_to_verdict_ns':elapsed,'views':[{'produced':produced,'returned':returned}]}
        return assess(row,'zygarde_4m',self.fixture,self.rows,self.rows,m)

    def test_same_count_wrong_names_is_incomplete(self):
        self.assertFalse(self.go({'b':True},{'a':True})['eligible'])
        self.assertTrue(self.go({'a':True},{'a':True})['eligible'])

    def test_zero_or_missing_time_is_not_ranked(self):
        for elapsed in (None,0,-1,True):
            self.assertFalse(self.go({'a':True},{'a':True},elapsed)['eligible'])

    def test_empty_or_missing_views_are_not_ranked(self):
        row={'returncode':0,'result':{'results':[{'cell':'hidden_file','status':0}]}}
        for views in (None,[]):
            self.assertFalse(assess(row,'zygarde_4m',self.fixture,self.rows,self.rows,
                {'scan_to_verdict_ns':100,'views':views})['eligible'])


if __name__=='__main__':unittest.main()
