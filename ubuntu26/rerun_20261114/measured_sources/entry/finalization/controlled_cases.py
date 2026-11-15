"""Locked existing output fixtures shared by native confirmation and comparison."""
import hashlib
import json
from pathlib import Path
import platform
import subprocess

from phase2.oracle import ACTIONS,transform,identities,difference,SEED1,SEED2

STATES=('normal','reorder','insert','grow','shrink','inode','type','remove',
        'filldir_hiding','getdents_hiding','policy_filter','getdents_substitution')
OWN={'phase2_transform','kicba_d7_hiding','kicba_d8_getdents_hiding',
     'kicba_d8_getdents_policy','kicba_d9_getdents_substitute','kicba_entry_fault'}
NAMES=('phase2_subject','d9_swap_a_0000','d8_hidden_0000','d8_policy_0000','ordinary_a','ordinary_b')


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def loaded():return {line.split()[0] for line in Path('/proc/modules').read_text().splitlines()}


def module_for(state,base,first):
    modules=Path(base)/'phase2/bin'/platform.release()
    if state=='normal':return None,[]
    if state in ACTIONS:return modules/'phase2_transform.ko',['mode='+str(ACTIONS.index(state))]
    if state=='filldir_hiding':return modules/'kicba_d7_hiding.ko',['counter_comm=d9_enum_probe','magic_word=d8_hidden_']
    if state=='getdents_substitution':return modules/'kicba_d9_getdents_substitute.ko',['target_comm=d9_enum_probe']
    name='kicba_d8_getdents_'+('hiding' if state=='getdents_hiding' else 'policy')
    args=['target_comm=d9_enum_probe']
    if state=='getdents_hiding':args.append('match_prefix=d8_hidden_')
    else:args.append('policy_authorized=1')
    return Path(first)/'attack_variants/d8_getdents_controls'/(name+'.ko'),args


def audit(state,base,first):
    path,_=module_for(state,base,first)
    if path is None:return {}
    directory=Path('/sys/module')/path.stem/'parameters'
    counters={}
    for p in directory.iterdir():
        value=p.read_text().strip()
        if value.isascii() and value.isdigit():counters[p.name]=int(value)
    return counters


def delta(before,after):return {key:after[key]-before[key] for key in before}


def load(state,base,first):
    path,args=module_for(state,base,first)
    if path is not None:subprocess.run(['insmod',str(path),*args],capture_output=True,check=True)


def unload(state,base,first):
    path,_=module_for(state,base,first)
    if path is not None and path.stem in loaded():subprocess.run(['rmmod',path.stem],capture_output=True,check=True)


def expected(original,state,exercised=True):
    if not exercised:return [dict(r) for r in original]
    if state in ACTIONS:return transform(original,state)
    if state in ('filldir_hiding','getdents_hiding','policy_filter'):
        prefix=b'd8_policy_' if state=='policy_filter' else b'd8_hidden_'
        return [dict(r) for r in original if not bytes.fromhex(r['name_hex']).startswith(prefix)]
    result=[dict(r) for r in original]
    for row in result:
        name=bytes.fromhex(row['name_hex'])
        if name.startswith(b'd9_swap_a_'):row['name_hex']=(b'd9_swap_b_'+name[len(b'd9_swap_a_'):]).hex()
    return result


def exact_capture(probe,directory,buffer,dump):
    command=[str(probe),str(directory),str(buffer),'256',str(SEED1),str(SEED2),'2',str(dump)]
    process=subprocess.run(command,input='\n',text=True,capture_output=True,timeout=30)
    rows=[json.loads(line) for line in dump.read_text().splitlines()] if dump.exists() else []
    return {'returncode':process.returncode,'stdout':process.stdout,'stderr':process.stderr,'rows':rows}


def module_hashes(base,first):
    locks={str(Path(base)):json.loads((Path(base)/'phase2/CONFIRMATION_LOCK.json').read_text())['source_sha256'],
           str(Path(first)):json.loads((Path(first)/'phase1/CONFIRMATION_LOCK.json').read_text())['source_sha256']}
    result={}
    for state in STATES:
        path,_=module_for(state,base,first)
        if path is None:continue
        owner=Path(first) if Path(first) in path.parents else Path(base)
        name=path.relative_to(owner).as_posix();digest=sha(path)
        if locks[str(owner)].get(name)!=digest:raise RuntimeError('locked module differs: '+str(path))
        result[str(path)]=digest
    return result
