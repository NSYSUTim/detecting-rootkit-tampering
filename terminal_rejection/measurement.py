"""Native collector retaining the old identity check and adding a terminal signal."""
import ctypes as ct
import os
from pathlib import Path
import time
import uuid
from phase2.measurement import Measurement,legacy
from finalization.tracefs_measurement import CompleteMeasurement,write_probe_command,entry_snapshot,compare_entry_window
from kicba.terminal_rejection import finalize_terminal_record

ROOT=Path(__file__).resolve().parents[1]

class TerminalBase(Measurement):
    def __init__(self,implementation='packed',*,probe,cells=256,maxactive=256,attach=False):
        if implementation!='packed':raise ValueError('packed instrumentation required')
        super().__init__('parse',cells=cells,maxactive=maxactive,attach=False,probe=probe)
        self.implementation='packed'
        self.bpf=legacy.BPF(src_file=str(ROOT/'terminal_rejection/bpf.c'),cflags=[
            '-I'+str(ROOT/'phase2'),'-I'+str(ROOT/'collector'),'-Wno-macro-redefined'])
        if attach:self.attach()

    def _packed_telemetry(self,pid):
        result=super()._packed_telemetry(pid)
        state=self.bpf['state_by_pid'].get(self.key(pid))
        if state is None:return result
        length=int(state.terminal_last.name_length)
        name=bytes(state.terminal_name)[:length]
        result['terminal_observation']={'returns':int(state.terminal_returns),
            'last_accepted':int(state.terminal_last_accepted),'witness_valid':int(state.terminal_witness_valid),
            'name_hex':name.hex(),'token':[int(state.terminal_last.key_hash),int(state.terminal_last.inode),int(state.terminal_last.d_type)]}
        result['state_value_bytes']=ct.sizeof(self.bpf['state_by_pid'].Leaf)
        return result

def new_terminal_measurement(*,probe,cells=256,maxactive=256):
    from bcc.libbcc import lib
    class TerminalTracefs(TerminalBase):
        def __init__(self):
            self.entry_event='kicba_terminal_'+str(os.getpid())+'_'+uuid.uuid4().hex[:8]
            self.entry_fd=None;self.entry_created=False;self.return_attached=False
            super().__init__(probe=probe,cells=cells,maxactive=maxactive)
            try:self.attach()
            except BaseException:self.close();raise
        def attach(self):
            if self.attached:raise RuntimeError('already attached')
            function=self.bpf.load_func('packed_enter',self.bpf.KPROBE)
            write_probe_command('p:kprobes/'+self.entry_event+' filldir64\n');self.entry_created=True
            fd=lib.bpf_attach_tracepoint(function.fd,b'kprobes',self.entry_event.encode('ascii'))
            if fd<0:raise RuntimeError('tracefs terminal attachment failed')
            self.entry_fd=fd
            self.bpf.attach_kretprobe(event='filldir64',fn_name='packed_return',maxactive=self.maxactive)
            self.return_attached=True;self.attached=True
            first=entry_snapshot(self.entry_event)
            if not compare_entry_window(first,first)['valid']:raise RuntimeError('entry profile unavailable')
        def detach(self):
            errors=[]
            if self.return_attached:
                try:self.bpf.detach_kretprobe(event='filldir64')
                except Exception as e:errors.append(str(e))
                self.return_attached=False
            if self.entry_fd is not None:
                if lib.bpf_close_perf_event_fd(self.entry_fd)!=0:errors.append('entry perf close failed')
                self.entry_fd=None
            if self.entry_created:
                try:write_probe_command('-:kprobes/'+self.entry_event+'\n');self.entry_created=False
                except Exception as e:errors.append(str(e))
            self.attached=False
            if errors:raise RuntimeError('; '.join(errors))
        def close(self):
            try:self.detach()
            finally:
                if self.bpf is not None:self.bpf.cleanup()
    return TerminalTracefs()

class TerminalMeasurement(CompleteMeasurement):
    def scan(self,directory,buffer=65536,dump=None):
        start=time.monotonic_ns()
        result=finalize_terminal_record(super().scan(directory,buffer,dump))
        result['wall_with_all_checks_ns']=time.monotonic_ns()-start
        return result

    def collect_started(self,processes):
        return [finalize_terminal_record(r) for r in super().collect_started(processes)]
