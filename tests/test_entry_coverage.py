import unittest
from pathlib import Path
import sys
from unittest.mock import Mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from finalization.tracefs_measurement import compare_entry_window,CompleteMeasurement


def snapshot(hits=10,missed=0,event='entry',identity='42'):
    return dict(event=event,id=identity,definition=['p:kprobes/entry filldir64'],
                profile=f'{event} {hits} {missed}\n')


class EntryCoverageTests(unittest.TestCase):
    def test_normal_counter_window(self):
        d=compare_entry_window(snapshot(),snapshot(20))
        self.assertTrue(d['valid']);self.assertEqual(d['per_event']['entry']['hits_delta'],10)

    def test_real_or_injected_miss_invalidates(self):
        self.assertFalse(compare_entry_window(snapshot(),snapshot(20,1))['valid'])

    def test_counter_reset_is_not_clamped(self):
        d=compare_entry_window(snapshot(),snapshot(1))
        self.assertFalse(d['valid']);self.assertEqual(d['per_event']['entry']['hits_delta'],-9)

    def test_missing_profile_is_not_zero(self):
        last=snapshot();last['profile']='other 20 0\n'
        d=compare_entry_window(snapshot(),last)
        self.assertFalse(d['available']);self.assertFalse(d['valid'])

    def test_recreated_event_rejected(self):
        self.assertFalse(compare_entry_window(snapshot(),snapshot(identity='43'))['valid'])

    def test_definition_changed_rejected(self):
        last=snapshot();last['definition']=['p:kprobes/entry another_function']
        self.assertFalse(compare_entry_window(snapshot(),last)['valid'])

    def test_ambiguous_definition_rejected(self):
        first=snapshot();first['definition']*=2
        self.assertFalse(compare_entry_window(first,first)['valid'])

    def test_bad_entry_quality_dominates_both_verdicts(self):
        for verdict in ('equal','different'):
            row={'verdict':verdict,'measurement_valid':True,'alarm':verdict=='different',
                 'recovery_verified':True}
            out=CompleteMeasurement._apply(row,{'available':True,'valid':False})
            self.assertEqual(out['verdict'],'invalid');self.assertIsNone(out['alarm'])
            self.assertEqual(row['verdict'],verdict)

    def test_good_entry_quality_preserves_alarm(self):
        out=CompleteMeasurement._apply({'verdict':'different','alarm':True},dict(available=True,valid=True))
        self.assertTrue(out['alarm'])

    def test_missing_entry_counter_prevents_scan(self):
        tool=CompleteMeasurement(Mock(implementation='packed'));tool._snapshot=Mock(side_effect=OSError('missing'))
        row=tool.scan(Path('unused'))
        self.assertEqual(row['verdict'],'invalid');tool.base.scan.assert_not_called()


if __name__=='__main__':unittest.main()
