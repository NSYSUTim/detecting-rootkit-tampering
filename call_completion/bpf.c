#include <uapi/linux/ptrace.h>
#include "../collector/d9_reconciliation_hash.h"
#include "../phase2/name_hash.h"

struct packed_token { u64 key_hash; u64 inode; u32 d_type; u32 name_length; };
struct packed_fingerprint { u64 count; u64 sum1; u64 sum2; };
struct packed_cell { s32 count; u32 pad; u64 key_xor; u64 inode_xor; u64 type_xor; u64 check_xor; };
struct packed_stats {
    u64 outer_entries, accepted_entries, rejected_entries;
    u64 name_read_errors, invalid_name_lengths, pending_update_failures;
    u64 fingerprint_update_failures, iblt_update_failures, return_underflows;
    u64 name_read_checksum;
};

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

struct packed_state {
    u64 seed1, seed2;
    u32 cell_count, enabled, depth, pending_valid;
    struct packed_token pending;
    struct packed_fingerprint fp;
    struct packed_stats stats;
    struct packed_cell cells[256];
    struct completion_state completion;
};

/* The controller pre-registers this value before releasing the scanner. */
BPF_HASH(state_by_pid, u32, struct packed_state, 256);


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

static __always_inline void update_cell(struct packed_state *s, u32 index, u64 check)
{
    struct packed_cell *cell = &s->cells[index & 255U];
    cell->count++;
    cell->key_xor ^= s->pending.key_hash;
    cell->inode_xor ^= s->pending.inode;
    cell->type_xor ^= s->pending.d_type;
    cell->check_xor ^= check;
}

int packed_enter(struct pt_regs *ctx)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    struct packed_state *s = state_by_pid.lookup(&pid);
    if (!s || s->enabled != 1)
        return 0;
    if (s->depth == 0) {
        const char *name = (const char *)PT_REGS_PARM2(ctx);
        int name_length = (int)PT_REGS_PARM3(ctx);
        u64 inode = (u64)PT_REGS_PARM5(ctx);
        u32 d_type = (u32)PT_REGS_PARM6(ctx) & 15U;
        char raw[256] = {};
        u64 value;
        long copied;
        s->stats.outer_entries++;
        if (s->completion.active)
            s->completion.current_entries++;
        else
            s->completion.outside_entries++;
        s->completion.pending_name_address = (u64)name;
        s->pending_valid = 0;
        if (name_length < 0 || name_length > 255) {
            s->stats.invalid_name_lengths++;
            goto increment_depth;
        }
        copied = bpf_probe_read_kernel_str(raw, sizeof(raw), name);
        if (copied < name_length + 1) {
            s->stats.name_read_errors++;
            goto increment_depth;
        }
        s->stats.name_read_checksum += (u64)(unsigned char)raw[0] + (u64)copied;
        value = d9_entry_hash_begin(s->seed1);
        D9_HASH_EIGHT(0); D9_HASH_EIGHT(8); D9_HASH_EIGHT(16); D9_HASH_EIGHT(24);
        D9_HASH_EIGHT(32); D9_HASH_EIGHT(40); D9_HASH_EIGHT(48); D9_HASH_EIGHT(56);
        D9_HASH_EIGHT(64); D9_HASH_EIGHT(72); D9_HASH_EIGHT(80); D9_HASH_EIGHT(88);
        D9_HASH_EIGHT(96); D9_HASH_EIGHT(104); D9_HASH_EIGHT(112); D9_HASH_EIGHT(120);
        D9_HASH_EIGHT(128); D9_HASH_EIGHT(136); D9_HASH_EIGHT(144); D9_HASH_EIGHT(152);
        D9_HASH_EIGHT(160); D9_HASH_EIGHT(168); D9_HASH_EIGHT(176); D9_HASH_EIGHT(184);
        D9_HASH_EIGHT(192); D9_HASH_EIGHT(200); D9_HASH_EIGHT(208); D9_HASH_EIGHT(216);
        D9_HASH_EIGHT(224); D9_HASH_EIGHT(232); D9_HASH_EIGHT(240); D9_HASH_EIGHT(248);
        s->pending.key_hash = d9_entry_hash_finish(value, inode, d_type, name_length, s->seed1, s->seed2);
        s->pending.inode = inode;
        s->pending.d_type = d_type;
        s->pending.name_length = name_length;
        s->pending_valid = 1;
    }
increment_depth:
    s->depth++;
    return 0;
}

int packed_return(struct pt_regs *ctx)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    struct packed_state *s = state_by_pid.lookup(&pid);
    if (!s || s->enabled != 1)
        return 0;
    if (s->depth == 0) {
        s->stats.return_underflows++;
        return 0;
    }
    s->depth--;
    if (s->depth)
        return 0;
    completion_callback(s, ctx);
    if (PT_REGS_RC(ctx)) {
        if (!s->pending_valid) {
            s->stats.pending_update_failures++;
        } else {
            u32 count = s->cell_count;
            u32 mask, first, second, third;
            u64 check;
            s->fp.count++;
            s->fp.sum1 += s->pending.key_hash;
            s->fp.sum2 += d9_fingerprint_second(s->pending.key_hash, s->pending.inode, s->pending.d_type);
            s->stats.accepted_entries++;
            if (count < 4 || count > 256 || (count & (count - 1U))) {
                s->stats.iblt_update_failures++;
                goto clear_pending;
            }
            mask = (count - 1U) & 255U;
            first = d9_position_1(s->pending.key_hash, s->seed1, mask);
            second = d9_position_2(s->pending.key_hash, s->seed2, mask, first);
            third = d9_position_3(s->pending.key_hash, s->seed1, s->seed2, mask, first, second);
            check = d9_token_check(s->pending.key_hash, s->pending.inode, s->pending.d_type, s->seed1, s->seed2);
            update_cell(s, first, check);
            update_cell(s, second, check);
            update_cell(s, third, check);
        }
    } else {
        s->stats.rejected_entries++;
    }
clear_pending:
    s->pending_valid = 0;
    return 0;
}
