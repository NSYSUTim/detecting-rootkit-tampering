"""Combine an identity verdict with a separately labelled terminal observation."""
from .reconciliation import token_for_entry

DEFAULT_SEEDS=(0x0123456789ABCDEF,0xF0E1D2C3B4A59687)

def finalize_terminal_record(record):
    result=dict(record)
    result.update(identity_verdict=record.get('verdict'),identity_alarm=record.get('alarm'),
                  terminal_rejection=False,rejected_entry=None,total_missing_count=None,
                  alarm_reasons=[],terminal_rule_version='2026-11-03')
    if record.get('verdict')=='invalid' or record.get('measurement_valid') is not True:
        result.update(verdict='invalid',measurement_valid=False,alarm=None,recovery_verified=False)
        return result
    try:
        observation=record['terminal_observation'];stats=record['kernel_stats']
        returns=observation['returns'];flag=observation['last_accepted']
        if type(returns) is not int or returns<1 or returns!=stats['outer_entries']:
            raise ValueError('outer entry/return totals disagree')
        if type(flag) is not int or flag not in (0,1):raise ValueError('invalid last return flag')
        if record['verdict'] not in ('equal','different'):raise ValueError('invalid identity verdict')
        if flag==0:
            if type(observation['witness_valid']) is not int or observation['witness_valid']!=1:
                raise ValueError('rejected witness unavailable')
            name=bytes.fromhex(observation['name_hex']);token=observation['token']
            if not 1<=len(name)<=255 or b'\0' in name or b'/' in name:
                raise ValueError('invalid rejected name')
            if len(token)!=3 or any(type(v) is not int for v in token):raise ValueError('invalid token')
            if not 0<=token[0]<2**64 or not 0<=token[1]<2**64 or not 0<=token[2]<256:
                raise ValueError('token out of range')
            seed1,seed2=record.get('configuration',DEFAULT_SEEDS)[:2]
            expected=token_for_entry(name,token[1],token[2],seed1,seed2)
            if expected.key_hash!=token[0]:raise ValueError('rejected name/token mismatch')
            result.update(terminal_rejection=True,rejected_entry={
                'name_hex':name.hex(),'inode':token[1],'d_type':token[2],
                'key_hash':token[0],'scope':'last rejected attempt, not the complete missing set'})
        reasons=[]
        if record['verdict']=='different':reasons.append('identity_difference')
        if result['terminal_rejection']:reasons.append('terminal_rejection')
        result.update(alarm=bool(reasons),alarm_reasons=reasons)
        if record['verdict']=='equal' and result['terminal_rejection']:
            result.update(verdict='terminal_rejection',recovery_verified=False)
        return result
    except (KeyError,TypeError,ValueError,IndexError) as error:
        result.update(verdict='invalid',measurement_valid=False,alarm=None,
                      recovery_verified=False,terminal_error=str(error))
        return result
