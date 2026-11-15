"""Derive per-call instrumentation while retaining accepted-item accumulation."""
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

STRUCT = '''
struct completion_state {
    u64 enters, exits, pair_errors, outside_entries, outside_returns;
    u64 completed_entries, completed_accepted, completed_rejected;
    u64 positive_calls, zero_calls, negative_calls;
    u64 current_entries, current_accepted, current_rejected;
    s64 last_return;
    u64 last_entries, last_accepted, last_rejected;
    u64 pending_name_address, target_fd;
    u32 active, fd_seen, witness_valid, pad;
    struct packed_token rejected;
    char rejected_name[256];
};
'''

HELPERS = '''
static __always_inline void completion_callback(struct packed_state *s, struct pt_regs *ctx)
{
    struct completion_state *c = &s->completion;
    if (!c->active) {
        c->outside_returns++;
        return;
    }
    if (PT_REGS_RC(ctx)) {
        c->current_accepted++;
    } else {
        long copied;
        c->current_rejected++;
        c->witness_valid = 0;
        c->rejected = s->pending;
        if (s->pending_valid) {
            copied = bpf_probe_read_kernel_str(c->rejected_name, sizeof(c->rejected_name),
                                               (void *)c->pending_name_address);
            if (copied == s->pending.name_length + 1)
                c->witness_valid = 1;
        }
    }
}

TRACEPOINT_PROBE(syscalls, sys_enter_getdents64)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    struct packed_state *s = state_by_pid.lookup(&pid);
    if (!s || s->enabled != 1)
        return 0;
    struct completion_state *c = &s->completion;
    c->enters++;
    if (c->active || s->depth)
        c->pair_errors++;
    if (c->fd_seen && c->target_fd != args->fd)
        c->pair_errors++;
    c->target_fd = args->fd;
    c->fd_seen = 1;
    c->active = 1;
    c->current_entries = 0;
    c->current_accepted = 0;
    c->current_rejected = 0;
    c->witness_valid = 0;
    c->rejected.name_length = 0;
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_getdents64)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    struct packed_state *s = state_by_pid.lookup(&pid);
    if (!s || s->enabled != 1)
        return 0;
    struct completion_state *c = &s->completion;
    c->exits++;
    if (!c->active || s->depth)
        c->pair_errors++;
    c->last_return = args->ret;
    c->last_entries = c->current_entries;
    c->last_accepted = c->current_accepted;
    c->last_rejected = c->current_rejected;
    c->completed_entries += c->current_entries;
    c->completed_accepted += c->current_accepted;
    c->completed_rejected += c->current_rejected;
    if (args->ret > 0)
        c->positive_calls++;
    else if (args->ret == 0)
        c->zero_calls++;
    else
        c->negative_calls++;
    c->active = 0;
    return 0;
}
'''


def build():
    source = (ROOT / 'phase2/bpf_packed.c').read_text()
    changed = source.replace('#include "name_hash.h"', '#include "../phase2/name_hash.h"')
    changed = changed.replace('struct packed_state {', STRUCT + '\nstruct packed_state {', 1)
    changed = changed.replace('    struct packed_cell cells[256];',
                              '    struct packed_cell cells[256];\n    struct completion_state completion;', 1)
    changed = changed.replace('static __always_inline void update_cell', HELPERS + '\nstatic __always_inline void update_cell', 1)
    changed = changed.replace('        s->stats.outer_entries++;', '''        s->stats.outer_entries++;
        if (s->completion.active)
            s->completion.current_entries++;
        else
            s->completion.outside_entries++;
        s->completion.pending_name_address = (u64)name;''', 1)
    marker = '    if (s->depth)\n        return 0;\n    if (PT_REGS_RC(ctx)) {'
    assert changed.count(marker) == 1
    changed = changed.replace(marker, marker.replace('    if (PT_REGS_RC(ctx)) {',
        '    completion_callback(s, ctx);\n    if (PT_REGS_RC(ctx)) {'), 1)
    target = ROOT / 'call_completion/bpf.c'
    target.write_text(changed, encoding='utf-8', newline='\n')
    (target.parent / 'bpf.patch').write_text(''.join(difflib.unified_diff(source.splitlines(True),
        changed.splitlines(True), fromfile='phase2/bpf_packed.c', tofile='call_completion/bpf.c')),
        encoding='utf-8', newline='\n')
    lock = {'source': 'phase2/bpf_packed.c', 'source_sha256': hashlib.sha256((ROOT/'phase2/bpf_packed.c').read_bytes()).hexdigest(),
            'derived': 'call_completion/bpf.c', 'derived_sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
    (target.parent/'BPF_DERIVATION.json').write_text(json.dumps(lock, indent=2), encoding='utf-8', newline='\n')
    print(json.dumps(lock))


if __name__ == '__main__':
    build()
