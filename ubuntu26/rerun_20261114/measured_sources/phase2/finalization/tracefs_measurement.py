"""Explicit tracefs entry attachment with observed per-event miss counters.

The original packed BPF program and historical measurement classes are retained.
This module changes the entry attachment backend and adds its validity window.
"""
from __future__ import annotations

import os
from pathlib import Path
import time
import uuid

from finalization.measurement import CheckedMeasurement
from phase1.coverage import compare_window


TRACE=Path('/sys/kernel/debug/tracing')


def write_probe_command(command):
    # Text append streams seek to EOF; tracefs files reject that seek.
    fd=os.open(str(TRACE/'kprobe_events'),os.O_WRONLY|os.O_APPEND)
    try:
        data=command.encode('ascii')
        if os.write(fd,data)!=len(data):raise OSError('short tracefs command write')
    finally:os.close(fd)


def entry_snapshot(event, trace=TRACE):
    definitions=[line for line in (trace/'kprobe_events').read_text().splitlines()
                 if line.split()[0].split('/')[-1]==event]
    return {'event':event,'definition':definitions,
            'id':(trace/'events/kprobes'/event/'id').read_text().strip(),
            'profile':(trace/'kprobe_profile').read_text()}


def compare_entry_window(first,last):
    result=compare_window(first.get('profile'),last.get('profile'),[first.get('event')])
    if (first.get('event')!=last.get('event') or len(first.get('definition',[]))!=1
            or first.get('definition')!=last.get('definition') or not first.get('id')
            or first.get('id')!=last.get('id')):
        result['valid']=False
        result['reasons'].append('entry_probe_identity_changed')
    result['scope']='tracefs entry event hits/nmissed; program recursion and return checks are separate'
    return result


def new_measurement(*,probe,cells=256,maxactive=256):
    """Load the frozen packed program, explicitly attach its entry via tracefs."""
    from bcc.libbcc import lib
    from phase2.measurement import Measurement

    class TracefsMeasurement(Measurement):
        def __init__(self):
            self.entry_event='kicba_entry_'+str(os.getpid())+'_'+uuid.uuid4().hex[:8]
            self.entry_fd=None;self.entry_created=False;self.return_attached=False
            super().__init__('packed',probe=probe,cells=cells,maxactive=maxactive,attach=False)
            try:self.attach()
            except BaseException:
                self.close();raise

        def attach(self):
            if self.attached:raise RuntimeError('already attached')
            start=time.monotonic_ns()
            function=self.bpf.load_func('packed_enter',self.bpf.KPROBE)
            write_probe_command('p:kprobes/'+self.entry_event+' filldir64\n')
            self.entry_created=True
            fd=lib.bpf_attach_tracepoint(function.fd,b'kprobes',self.entry_event.encode('ascii'))
            if fd<0:raise RuntimeError('tracefs entry BPF attachment failed')
            self.entry_fd=fd
            self.bpf.attach_kretprobe(event='filldir64',fn_name='packed_return',maxactive=self.maxactive)
            self.return_attached=True;self.attached=True
            # Required counter must exist before exposing a usable scanner.
            first=entry_snapshot(self.entry_event)
            if not compare_entry_window(first,first)['valid']:
                raise RuntimeError('entry profile unavailable immediately after attach')
            return time.monotonic_ns()-start

        def detach(self):
            errors=[]
            if self.return_attached:
                try:self.bpf.detach_kretprobe(event='filldir64')
                except Exception as error:errors.append(str(error))
                self.return_attached=False
            if self.entry_fd is not None:
                if lib.bpf_close_perf_event_fd(self.entry_fd)!=0:errors.append('entry perf fd close failed')
                self.entry_fd=None
            if self.entry_created:
                try:
                    write_probe_command('-:kprobes/'+self.entry_event+'\n')
                    self.entry_created=False
                except Exception as error:errors.append(str(error))
            self.attached=False
            if errors:raise RuntimeError('; '.join(errors))

        def close(self):
            try:self.detach()
            finally:
                if self.bpf is not None:self.bpf.cleanup()

    return TracefsMeasurement()


class CompleteMeasurement:
    def __init__(self,base):
        self.base=base;self.checked=CheckedMeasurement(base)

    def _snapshot(self):return entry_snapshot(self.base.entry_event)

    @staticmethod
    def _apply(row,quality):
        result=dict(row);result['entry_coverage']=quality
        if quality.get('available') is not True or quality.get('valid') is not True:
            result['pre_entry_gate_verdict']=result.get('verdict')
            result.update(verdict='invalid',measurement_valid=False,alarm=None,
                          recovery_verified=False,recovery_status='not_assessed')
        result['implementation']='tracefs_entry_checked_20261102'
        return result

    def scan(self,directory,buffer=65536,dump=None):
        start=time.monotonic_ns()
        try:first=self._snapshot()
        except (OSError,ValueError) as error:
            return self._apply({},dict(available=False,valid=False,reasons=[str(error)]))
        row=self.checked.scan(directory,buffer,dump)
        try:quality=compare_entry_window(first,self._snapshot())
        except (OSError,ValueError) as error:quality=dict(available=False,valid=False,reasons=[str(error)])
        result=self._apply(row,quality)
        result['wall_with_all_checks_ns']=time.monotonic_ns()-start
        return result

    def collect_started(self,processes):
        start=time.monotonic_ns()
        try:first=self._snapshot()
        except (OSError,ValueError) as error:
            for process in processes:
                if process.poll() is None:process.kill()
                process.communicate()
            return [self._apply({},dict(available=False,valid=False,reasons=[str(error)])) for _ in processes]
        rows=self.checked.collect_started(processes)
        try:quality=compare_entry_window(first,self._snapshot())
        except (OSError,ValueError) as error:quality=dict(available=False,valid=False,reasons=[str(error)])
        results=[self._apply(row,quality) for row in rows]
        for row in results:row['group_wall_with_all_checks_ns']=time.monotonic_ns()-start
        return results
