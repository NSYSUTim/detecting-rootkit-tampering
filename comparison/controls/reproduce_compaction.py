"""Bounded user-mode demonstration of the old fixture's overlapping-copy bug."""
import json,struct


def entry(name,inode,kind=8):
    name=name.encode();length=(19+len(name)+1+7)&~7
    return struct.pack('<QqHB',inode,0,length,kind)+name+b'\0'*(length-19-len(name))


def compact(raw,cache_length):
    data=bytearray(raw);input_offset=output_offset=0;steps=0
    while input_offset<len(raw):
        steps+=1
        if steps>20:raise RuntimeError('fixture stopped making progress')
        length=struct.unpack_from('<H',data,input_offset+16)[0]
        if length<20 or input_offset+length>len(raw):return {'invalid_input':True}
        name=bytes(data[input_offset+19:input_offset+length]).split(b'\0')[0]
        if name.startswith(b'd8_hidden_'):input_offset+=length;continue
        data[output_offset:output_offset+length]=data[input_offset:input_offset+length]
        advance=length if cache_length else struct.unpack_from('<H',data,input_offset+16)[0]
        output_offset+=advance;input_offset+=advance
    return {'input_bytes':len(raw),'output_bytes':output_offset,
            'out_of_bounds_copy':output_offset>len(raw),'output_hex':bytes(data[:output_offset]).hex()}


def demonstrate():
    records=[entry('.',1,4),entry('..',2,4),entry('d8_hidden_0000',3),entry('a'*76,4,4),entry('ordinary',5)]
    raw=b''.join(records);old=compact(raw,False);fixed=compact(raw,True)
    expected=b''.join(records[:2]+records[3:])
    passed=old['out_of_bounds_copy'] and not fixed['out_of_bounds_copy'] and bytes.fromhex(fixed['output_hex'])==expected
    return {'scope':'offline control-fixture byte transformation; no detector or VM denominator',
            'old':old,'fixed':fixed,'passed':passed}


if __name__=='__main__':
    result=demonstrate();print(json.dumps(result,indent=2));raise SystemExit(0 if result['passed'] else 1)
