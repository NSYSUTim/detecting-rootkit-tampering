"""Qualify a per-getdents64 completion check without suppressing identity alarms.

This detects an observed return-protocol anomaly, not malicious intent or the
complete set of directory entries beyond a rejected callback.
"""
from .reconciliation import token_for_entry

DEFAULT_SEEDS = (0x0123456789ABCDEF, 0xF0E1D2C3B4A59687)


def compare_call_coverage(before, after):
    result = {'available': False, 'valid': False, 'reasons': [], 'per_program': {},
              'scope': 'syscall tracepoint identities, program recursion misses and per-scan call accounting'}
    try:
        for name in ('enter', 'exit'):
            a, b = before[name], after[name]
            for item in (a, b):
                if (type(item['id']) is not int or item['id'] <= 0
                        or type(item['event_id']) is not int or item['event_id'] <= 0
                        or not isinstance(item['prog_tag'], str) or not item['prog_tag']
                        or type(item['recursion_misses']) is not int or item['recursion_misses'] < 0):
                    raise ValueError('invalid syscall program identity/counter')
            if (a['id'], a['prog_tag'], a['event_id']) != (b['id'], b['prog_tag'], b['event_id']):
                result['reasons'].append('syscall_program_or_event_changed:' + name)
            delta = b['recursion_misses'] - a['recursion_misses']
            result['per_program'][name] = dict(before=a, after=b, recursion_misses_delta=delta)
            if delta != 0:
                result['reasons'].append('syscall_program_missed_or_counter_reset:' + name)
        result.update(available=True, valid=not result['reasons'])
    except (KeyError, TypeError, ValueError) as error:
        result['reasons'].append(str(error))
    return result


def _natural(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError('invalid nonnegative integer')
    return value


def finalize_call_record(record):
    result = dict(record)
    result.update(identity_verdict=record.get('verdict'), identity_alarm=record.get('alarm'),
                  completion_valid=False, completion_status='not_assessed',
                  completion_anomaly=False, rejected_entry=None, total_missing_count=None,
                  alarm_reasons=[], completion_rule_version='per_call_2026-11-03')
    if record.get('verdict') == 'invalid' or record.get('measurement_valid') is not True:
        result.update(verdict='invalid', measurement_valid=False, alarm=None)
        return result
    identity_alarm = record.get('verdict') == 'different' and record.get('alarm') is True
    if identity_alarm:
        result['alarm_reasons'] = ['identity_difference']
    try:
        if record.get('verdict') not in ('equal', 'different'):
            raise ValueError('unknown original identity verdict')
        if record.get('alarm') is not (record['verdict'] == 'different'):
            raise ValueError('inconsistent original identity verdict')
        quality = record['call_coverage']
        if (not isinstance(quality, dict) or quality.get('available') is not True
                or quality.get('valid') is not True):
            raise ValueError('syscall coverage unavailable or invalid')
        observation, stats = record['call_observation'], record['kernel_stats']
        names = ('enters', 'exits', 'active', 'pair_errors', 'outside_entries', 'outside_returns',
                 'completed_entries', 'completed_accepted', 'completed_rejected',
                 'positive_calls', 'zero_calls', 'negative_calls',
                 'last_entries', 'last_accepted', 'last_rejected', 'fd_seen')
        values = {name: _natural(observation[name]) for name in names}
        syscalls = _natural(record['userspace']['syscalls'])
        if syscalls < 1 or values['enters'] != syscalls or values['exits'] != syscalls:
            raise ValueError('scanner and tracepoint call counts disagree')
        if any(values[n] for n in ('active', 'pair_errors', 'outside_entries', 'outside_returns')):
            raise ValueError('unpaired or ungrouped callback events')
        for name, original in (('completed_entries', 'outer_entries'),
                               ('completed_accepted', 'accepted_entries'),
                               ('completed_rejected', 'rejected_entries')):
            if values[name] != _natural(stats[original]):
                raise ValueError('per-call and original callback counts disagree')
        if values['completed_entries'] != values['completed_accepted'] + values['completed_rejected']:
            raise ValueError('inconsistent completed callback counts')
        if (values['fd_seen'] != 1 or values['zero_calls'] != 1 or values['negative_calls'] != 0
                or values['positive_calls'] != syscalls - 1
                or type(observation['last_return']) is not int or observation['last_return'] != 0):
            raise ValueError('no qualified final zero-return call')
        if values['last_entries'] != values['last_accepted'] + values['last_rejected']:
            raise ValueError('inconsistent final-call callback counts')
        for last, total in (('last_entries', 'completed_entries'),
                            ('last_accepted', 'completed_accepted'),
                            ('last_rejected', 'completed_rejected')):
            if values[last] > values[total]:
                raise ValueError('final-call count exceeds complete scan count')
        anomaly = values['last_rejected'] > 0 and values['last_accepted'] == 0
        if anomaly:
            if type(observation['witness_valid']) is not int or observation['witness_valid'] != 1:
                raise ValueError('rejected witness unavailable')
            name, token = bytes.fromhex(observation['name_hex']), observation['token']
            if not 1 <= len(name) <= 255 or b'\0' in name or b'/' in name:
                raise ValueError('malformed rejected name')
            if not isinstance(token, (list, tuple)) or len(token) != 3:
                raise ValueError('malformed rejected identity')
            key_hash, inode, kind = (_natural(v) for v in token)
            if kind > 255:
                raise ValueError('invalid file type')
            seed1, seed2 = record.get('configuration', DEFAULT_SEEDS)[:2]
            if token_for_entry(name, inode, kind, seed1, seed2).key_hash != key_hash:
                raise ValueError('rejected name/identity mismatch')
            result['rejected_entry'] = dict(name_hex=name.hex(), inode=inode, d_type=kind,
                                           key_hash=key_hash, scope='rejected attempt in the zero-return call; unseen suffix unknown')
        result.update(completion_valid=True, completion_anomaly=anomaly,
                      completion_status='anomaly_observed' if anomaly else 'no_anomaly_observed')
        if anomaly:
            result['alarm_reasons'].append('completion_anomaly')
            result['alarm'] = True
            if not identity_alarm:
                result['verdict'] = 'completion_anomaly'
        return result
    except (KeyError, TypeError, ValueError, IndexError) as error:
        result.update(completion_status='inconclusive', completion_error=str(error))
        if not identity_alarm:
            result.update(verdict='inconclusive', alarm=None)
        return result
