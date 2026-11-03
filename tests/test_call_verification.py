"""The publication verifier must reject corrupted historical gate claims."""
import unittest
from call_completion.summarize import verify_identity


class PublicationGateTests(unittest.TestCase):
    def row(self):
        events={'available':True,'valid':True,'reasons':[],
                'per_event':{'fixture':{'missed_delta':0}}}
        program={'recursion_misses_delta':0,'program_id_before':1,'program_id_after':1,
                 'prog_tag_before':'abc','prog_tag_after':'abc'}
        return {'measurement_valid':True,'verdict':'equal','alarm':False,'fingerprint_equal':True,
                'kernel_fingerprint':[1,42,99],'visible_fingerprint':[1,42,99],
                'decode_success':True,'residual_cells':0,'upstream_only':[],'downstream_only':[],
                'recovery_verified':False,'recovery_status':'no_difference_observed',
                'coverage':events,'entry_coverage':events,
                'program_coverage':{'available':True,'valid':True,'reasons':[],
                    'per_program':{'packed_enter':dict(program),'packed_return':dict(program)}}}

    def test_corrupt_decode_metadata_cannot_keep_equal_publication_claim(self):
        for field,value in (('decode_success',False),('residual_cells',1),('recovery_verified',True)):
            row=self.row();row[field]=value
            with self.subTest(field=field),self.assertRaises(AssertionError):verify_identity(row)

    def test_missed_program_cannot_be_hidden_by_valid_boolean(self):
        row=self.row();row['program_coverage']['per_program']['packed_enter']['recursion_misses_delta']=1
        with self.assertRaises(AssertionError):verify_identity(row)

    def test_consistent_original_identity_and_recovery_gate_is_accepted(self):
        verify_identity(self.row())


if __name__=='__main__':unittest.main()
