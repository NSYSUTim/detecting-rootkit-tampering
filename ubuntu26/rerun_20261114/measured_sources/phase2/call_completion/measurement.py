"""Preserve accepted-item measurement and qualify syscall completion separately."""
import ctypes as ct
import os
from pathlib import Path
import time
import uuid

from phase2.measurement import Measurement, legacy
from finalization.tracefs_measurement import CompleteMeasurement, write_probe_command, entry_snapshot, compare_entry_window, TRACE
from kicba.call_completion import finalize_call_record, compare_call_coverage

ROOT = Path(__file__).resolve().parents[1]
CALL_FIELDS = ('enters', 'exits', 'active', 'pair_errors', 'outside_entries', 'outside_returns',
               'completed_entries', 'completed_accepted', 'completed_rejected',
               'positive_calls', 'zero_calls', 'negative_calls', 'last_return',
               'last_entries', 'last_accepted', 'last_rejected', 'witness_valid', 'fd_seen')


class CallBase(Measurement):
    def __init__(self, *, probe, cells=256, maxactive=256):
        super().__init__('parse', cells=cells, maxactive=maxactive, attach=False, probe=probe)
        self.implementation = 'packed'
        self.bpf = legacy.BPF(src_file=str(ROOT/'call_completion/bpf.c'), cflags=[
            '-I'+str(ROOT/'phase2'), '-I'+str(ROOT/'collector'), '-Wno-macro-redefined'])

    def _packed_telemetry(self, pid):
        result = super()._packed_telemetry(pid)
        state = self.bpf['state_by_pid'].get(self.key(pid))
        if state is None:
            return result
        call = state.completion
        observation = {name: int(getattr(call, name)) for name in CALL_FIELDS}
        length = int(call.rejected.name_length)
        observation.update(name_hex=bytes(call.rejected_name)[:min(length, 256)].hex(),
                           token=[int(call.rejected.key_hash), int(call.rejected.inode), int(call.rejected.d_type)])
        result.update(call_observation=observation, state_value_bytes=ct.sizeof(self.bpf['state_by_pid'].Leaf))
        return result


def new_call_measurement(*, probe, cells=256, maxactive=256):
    from bcc.libbcc import lib

    class CallTracefs(CallBase):
        def __init__(self):
            self.entry_event = 'kicba_completion_'+str(os.getpid())+'_'+uuid.uuid4().hex[:8]
            self.entry_fd = None
            self.entry_created = self.return_attached = False
            super().__init__(probe=probe, cells=cells, maxactive=maxactive)
            try:
                self.attach()
            except BaseException:
                self.close()
                raise

        def attach(self):
            if self.attached:
                raise RuntimeError('already attached')
            function = self.bpf.load_func('packed_enter', self.bpf.KPROBE)
            write_probe_command('p:kprobes/'+self.entry_event+' filldir64\n')
            self.entry_created = True
            fd = lib.bpf_attach_tracepoint(function.fd, b'kprobes', self.entry_event.encode('ascii'))
            if fd < 0:
                raise RuntimeError('completion collector entry attachment failed')
            self.entry_fd = fd
            self.bpf.attach_kretprobe(event='filldir64', fn_name='packed_return', maxactive=self.maxactive)
            self.return_attached = self.attached = True
            first = entry_snapshot(self.entry_event)
            if not compare_entry_window(first, first)['valid']:
                raise RuntimeError('entry profile unavailable')

        def detach(self):
            errors = []
            if self.return_attached:
                try:
                    self.bpf.detach_kretprobe(event='filldir64')
                except Exception as error:
                    errors.append(str(error))
                self.return_attached = False
            if self.entry_fd is not None:
                if lib.bpf_close_perf_event_fd(self.entry_fd) != 0:
                    errors.append('entry perf close failed')
                self.entry_fd = None
            if self.entry_created:
                try:
                    write_probe_command('-:kprobes/'+self.entry_event+'\n')
                    self.entry_created = False
                except Exception as error:
                    errors.append(str(error))
            self.attached = False
            if errors:
                raise RuntimeError('; '.join(errors))

        def close(self):
            try:
                self.detach()
            finally:
                if self.bpf is not None:
                    self.bpf.cleanup()

    return CallTracefs()


def read_call_counters(bpf):
    result = {}
    for label in ('enter', 'exit'):
        event = 'sys_'+label+'_getdents64'
        function = bpf.load_func('tracepoint__syscalls__'+event, bpf.TRACEPOINT)
        values = {}
        for line in Path('/proc/self/fdinfo/'+str(function.fd)).read_text().splitlines():
            if ':' not in line:
                continue
            key, value = (part.strip() for part in line.split(':', 1))
            if key in ('prog_id', 'prog_tag', 'recursion_misses'):
                label_key = 'id' if key == 'prog_id' else key
                if label_key in values:
                    raise ValueError('duplicate syscall program counter')
                values[label_key] = value
        for key in ('id', 'recursion_misses'):
            if key not in values or not values[key].isascii() or not values[key].isdigit():
                raise ValueError('syscall program counter unavailable')
            values[key] = int(values[key])
        if 'prog_tag' not in values:
            raise ValueError('syscall program tag unavailable')
        values['event_id'] = int((TRACE/'events/syscalls'/event/'id').read_text())
        result[label] = values
    return result


class CallMeasurement(CompleteMeasurement):
    def _call_snapshot(self):
        return read_call_counters(self.base.bpf)

    def _first(self):
        try:
            return self._call_snapshot(), None
        except Exception as error:
            return None, str(error)

    def _quality(self, first, error):
        if first is not None:
            try:
                return compare_call_coverage(first, self._call_snapshot())
            except Exception as last_error:
                error = str(last_error)
        return dict(available=False, valid=False, reasons=[error])

    def scan(self, directory, buffer=65536, dump=None):
        start = time.monotonic_ns()
        first, error = self._first()
        row = super().scan(directory, buffer, dump)
        row['call_coverage'] = self._quality(first, error)
        result = finalize_call_record(row)
        result['wall_with_all_checks_ns'] = time.monotonic_ns()-start
        result['implementation'] = 'per_call_completion_20261103'
        return result

    def collect_started(self, processes):
        start = time.monotonic_ns()
        first, error = self._first()
        rows = super().collect_started(processes)
        quality = self._quality(first, error)
        results = [finalize_call_record(dict(row, call_coverage=quality)) for row in rows]
        for row in results:
            row['group_wall_with_all_checks_ns'] = time.monotonic_ns()-start
            row['implementation'] = 'per_call_completion_20261103'
        return results
