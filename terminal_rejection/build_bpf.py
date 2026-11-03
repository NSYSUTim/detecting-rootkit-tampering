"""Derive terminal instrumentation from the immutable packed source."""
import difflib
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def build():
    source=(ROOT/'phase2/bpf_packed.c').read_text()
    changed=source.replace('#include "name_hash.h"','#include "../phase2/name_hash.h"')
    changed=changed.replace('    struct packed_cell cells[256];',
        '    struct packed_cell cells[256];\n'
        '    u64 terminal_returns;\n'
        '    u32 terminal_last_accepted, terminal_witness_valid;\n'
        '    struct packed_token terminal_last;\n'
        '    char terminal_name[256];')
    changed=changed.replace('        s->pending_valid = 0;',
        '        s->pending_valid = 0;\n        s->terminal_witness_valid = 0;')
    changed=changed.replace('        s->pending_valid = 1;',
        '        s->pending_valid = 1;\n        __builtin_memcpy(s->terminal_name, raw, sizeof(raw));')
    changed=changed.replace('    if (PT_REGS_RC(ctx)) {',
        '    s->terminal_returns++;\n'
        '    s->terminal_last_accepted = PT_REGS_RC(ctx) ? 1 : 0;\n'
        '    s->terminal_witness_valid = s->pending_valid;\n'
        '    s->terminal_last = s->pending;\n'
        '    if (PT_REGS_RC(ctx)) {')
    target=ROOT/'terminal_rejection/bpf.c';target.write_text(changed,encoding='utf-8',newline='\n')
    (target.parent/'bpf.patch').write_text(''.join(difflib.unified_diff(source.splitlines(True),
        changed.splitlines(True),fromfile='phase2/bpf_packed.c',tofile='terminal_rejection/bpf.c')),encoding='utf-8',newline='\n')
    lock={'source':'phase2/bpf_packed.c','source_sha256':hashlib.sha256((ROOT/'phase2/bpf_packed.c').read_bytes()).hexdigest(),
          'derived':'terminal_rejection/bpf.c','derived_sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
    (target.parent/'BPF_DERIVATION.json').write_text(json.dumps(lock,indent=2),encoding='utf-8',newline='\n')
    print(json.dumps(lock))
if __name__=='__main__':build()
