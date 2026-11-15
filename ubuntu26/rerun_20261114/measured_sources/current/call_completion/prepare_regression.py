"""Derive a new native runner; do not rewrite the withdrawn trial's sources."""
import difflib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADDITIONAL = '''
        # New-branch faults are separate from the still-valid identity result.
        for fault in ('bad_pair_count', 'detached_enter', 'detached_exit'):
            for state in ('normal', 'getdents_substitution'):
                load(state)
                try:
                    with new_call_measurement(probe=PROBE) as base:
                        if fault.startswith('detached_'):
                            label = fault.split('_')[1]
                            base.bpf.detach_tracepoint(tp='syscalls:sys_'+label+'_getdents64')
                        else:
                            original_reader=base._packed_telemetry
                            def bad_pair(pid):
                                row=original_reader(pid);row['call_observation']['exits']+=1;return row
                            base._packed_telemetry=bad_pair
                        scan(CallMeasurement(base),static,kind=fault,state=state,buffer=4096)
                finally:unload(state)
        # The original entry and return miss gates must still refuse judgment.
        fault_modules=list(Path('/home/kicba/closure_20261102').rglob('kicba_entry_fault.ko'))
        if not fault_modules:raise RuntimeError('previously validated entry fault fixture unavailable')
        fault_module=fault_modules[0]
        save(a.output/'entry_fault_fixture.json',{'path':str(fault_module),'sha256':sha(fault_module)})
        subprocess.run(['insmod',str(fault_module)],check=True,capture_output=True)
        try:
            with new_call_measurement(probe=PROBE) as base:
                checked=CallMeasurement(base)
                scan(checked,static,kind='entry_fault_control_before',buffer=4096)
                original_scan=base.scan
                def inject(*args,**kwargs):
                    Path('/sys/module/kicba_entry_fault/parameters/trigger').write_text('10\\n')
                    return original_scan(*args,**kwargs)
                base.scan=inject
                try:scan(checked,static,kind='entry_probe_miss',buffer=4096)
                finally:base.scan=original_scan
                scan(checked,static,kind='entry_fault_control_after',buffer=4096)
        finally:subprocess.run(['rmmod','kicba_entry_fault'],check=True,capture_output=True)
        pressure=fixture(a.output/'pressure',4096)
        with new_call_measurement(probe=PROBE,maxactive=1) as base:
            processes=[base.begin(pressure,4096) for _ in range(16)]
            for row in CallMeasurement(base).collect_started(processes):
                emit(output,dict(row,kind='return_probe_pressure'))
'''


def main():
    original=(ROOT/'terminal_rejection/run_regression.py').read_text()
    changed=original.replace('from terminal_rejection.measurement import new_terminal_measurement,TerminalMeasurement',
        'from call_completion.measurement import new_call_measurement,CallMeasurement')
    changed=changed.replace('new_terminal_measurement','new_call_measurement').replace('TerminalMeasurement','CallMeasurement')
    changed=changed.replace("('terminal_rejection','src/kicba')", "('call_completion','src/kicba')")
    changed=changed.replace("ROOT/'terminal_rejection/enum_gated'", "ROOT/'call_completion/enum_gated'")
    changed=changed.replace('missing_terminal_telemetry','missing_call_telemetry').replace('omit_terminal','omit_call')
    changed=changed.replace("row.pop('terminal_observation',None)", "row.pop('call_observation',None)")
    marker="        save(a.output/'cleanup.json'"
    assert changed.count(marker)==1
    changed=changed.replace(marker,ADDITIONAL+'\n'+marker,1)
    changed=changed.replace("'completed':True})", "'all_research_modules_absent':not bool(cases.loaded() & cases.OWN),'completed':True})")
    target=ROOT/'call_completion/run_regression.py'
    target.write_text(changed,encoding='utf-8',newline='\n')
    (target.parent/'regression_runner.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),
        changed.splitlines(True),fromfile='terminal_rejection/run_regression.py',tofile='call_completion/run_regression.py')),
        encoding='utf-8',newline='\n')


if __name__=='__main__':main()
