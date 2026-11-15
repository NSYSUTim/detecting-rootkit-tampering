"""Unprivileged aggregate Windows CPU/memory sampler for lab cost observations."""
import argparse,ctypes,json,time
from ctypes import wintypes as W
from datetime import datetime,timezone
from pathlib import Path


class Memory(ctypes.Structure):
    _fields_=[('length',W.DWORD),('load',W.DWORD)]+[(n,ctypes.c_ulonglong) for n in
        ('total_physical','available_physical','total_page','available_page','total_virtual','available_virtual','extended')]


def counters():
    values=[W.FILETIME() for _ in range(3)]
    if not ctypes.windll.kernel32.GetSystemTimes(*[ctypes.byref(v) for v in values]):raise ctypes.WinError()
    return [(v.dwHighDateTime<<32)|v.dwLowDateTime for v in values]


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--stop',type=Path,required=True)
    args=p.parse_args();last=counters()
    with args.output.open('x',encoding='utf-8',newline='\n') as stream:
        for _ in range(1800):
            if args.stop.exists():break
            time.sleep(1);now=counters();idle,kernel,user=[b-a for a,b in zip(last,now)];last=now
            memory=Memory();memory.length=ctypes.sizeof(memory)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):raise ctypes.WinError()
            row={'recorded_at_utc':datetime.now(timezone.utc).isoformat(),
                 'cpu_percent':100*(1-idle/(kernel+user)) if kernel+user else None,
                 'available_memory_mib':memory.available_physical/2**20,'api':'GetSystemTimes/GlobalMemoryStatusEx'}
            stream.write(json.dumps(row)+'\n');stream.flush()


if __name__=='__main__':main()
