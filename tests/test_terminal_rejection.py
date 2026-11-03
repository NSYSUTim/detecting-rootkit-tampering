import copy
import unittest
from kicba.reconciliation import token_for_entry
from phase2.oracle import SEED1,SEED2
from kicba.terminal_rejection import finalize_terminal_record

class TerminalRejectionTests(unittest.TestCase):
    def record(self,accepted=0):
        token=token_for_entry(b'candidate',123,8,SEED1,SEED2)
        return {'verdict':'equal','measurement_valid':True,'alarm':False,
            'kernel_stats':{'outer_entries':3,'accepted_entries':2,'rejected_entries':1},
            'terminal_observation':{'returns':3,'last_accepted':accepted,'witness_valid':1,
                'name_hex':b'candidate'.hex(),'token':[token.key_hash,token.inode,token.d_type]}}

    def test_terminal_false_adds_alert_without_inventing_identity_difference(self):
        row=self.record();before=copy.deepcopy(row);result=finalize_terminal_record(row)
        self.assertEqual(row,before)
        self.assertEqual(result['verdict'],'terminal_rejection')
        self.assertEqual(result['identity_verdict'],'equal')
        self.assertTrue(result['alarm']);self.assertFalse(result['identity_alarm'])
        self.assertEqual(result['rejected_entry']['name_hex'],b'candidate'.hex())
        self.assertIsNone(result['total_missing_count'])
        self.assertFalse(result['recovery_verified'])

    def test_resend_then_accept_has_no_terminal_alert(self):
        result=finalize_terminal_record(self.record(1))
        self.assertFalse(result['alarm']);self.assertEqual(result['verdict'],'equal')
        self.assertIsNone(result['rejected_entry'])

    def test_identity_alarm_and_recovery_survive(self):
        row=self.record(1);row.update(verdict='different',alarm=True,recovery_verified=True,
            upstream_only=[[1,2,3]],downstream_only=[])
        result=finalize_terminal_record(row)
        self.assertTrue(result['identity_alarm']);self.assertTrue(result['alarm'])
        self.assertTrue(result['recovery_verified'])
        self.assertEqual(result['upstream_only'],row['upstream_only'])

    def test_invalid_quality_is_never_promoted(self):
        row=self.record();row.update(verdict='invalid',measurement_valid=False,alarm=None)
        result=finalize_terminal_record(row)
        self.assertEqual(result['verdict'],'invalid');self.assertIsNone(result['alarm'])

    def test_missing_malformed_and_wrong_identity_are_invalid(self):
        for change in ('absent','returns','flag','name','token'):
            row=self.record()
            if change=='absent':del row['terminal_observation']
            elif change=='returns':row['terminal_observation']['returns']=2
            elif change=='flag':row['terminal_observation']['last_accepted']=True
            elif change=='name':row['terminal_observation']['name_hex']='00'
            else:row['terminal_observation']['token'][0]^=1
            with self.subTest(change=change):
                r=finalize_terminal_record(row)
                self.assertEqual(r['verdict'],'invalid');self.assertIsNone(r['alarm'])

    def test_both_signals_remain_distinct(self):
        row=self.record();row.update(verdict='different',alarm=True,recovery_verified=True)
        result=finalize_terminal_record(row)
        self.assertEqual(result['alarm_reasons'],['identity_difference','terminal_rejection'])
        self.assertTrue(result['recovery_verified'])

if __name__=='__main__':unittest.main()
