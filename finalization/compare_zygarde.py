"""Paired fixed-version file-cell comparison, keeping each observation."""
import argparse,json,os,platform,random,shutil,signal,subprocess,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
for d in (ROOT,ROOT/'src'):sys.path.insert(0,str(d))
from finalization import controlled_cases as cases
from phase2.run_campaign import manifest


def execute(command,output,tag,env=None,stdin=None):
    metrics=output/(tag+'.time')
    start=time.monotonic_ns()
    stdout_path=output/(tag+'.stdout');stderr_path=output/(tag+'.stderr')
    timeout=False
    with stdout_path.open('x') as stdout,stderr_path.open('x') as stderr:
        process=subprocess.Popen(['/usr/bin/time','-o',str(metrics),'-f','%e,%U,%S,%M',*command],
            stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,text=True,env=env,start_new_session=True)
        try:process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            timeout=True
            os.killpg(process.pid,signal.SIGQUIT if '--cells' in command else signal.SIGTERM)
            try:process.wait(timeout=2)
            except subprocess.TimeoutExpired:pass
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait()
    elapsed=time.monotonic_ns()-start
    result={'returncode':process.returncode,'wall_ns':elapsed,'command':command,'timeout':timeout}
    try:
        lines=metrics.read_text().splitlines();values=lines[-1].split(',')
        result.update(time_seconds=float(values[0]),user_seconds=float(values[1]),
                      system_seconds=float(values[2]),maxrss_kib=int(values[3]))
    except (ValueError,IndexError,OSError):result['metrics_error']=True
    try:result['result']=json.loads(stdout_path.read_text())
    except ValueError:result['json_error']=True
    return result


def zygarde_target(row,fixture):
    results=row.get('result',{}).get('results',[])
    cell=next((c for c in results if c.get('cell')=='hidden_file'),{})
    relevant=[f for f in cell.get('findings',[]) if f.get('details',{}).get('directory')==str(fixture)]
    return {'valid':row['returncode'] in (0,2) and cell.get('status') in (0,2),
            'alarm':bool(relevant),'target_findings':relevant,
            'other_findings':[f for f in cell.get('findings',[]) if f not in relevant],
            'cell_status':cell.get('status')}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--base',type=Path,required=True)
    p.add_argument('--first',type=Path,required=True);p.add_argument('--official',type=Path,required=True)
    p.add_argument('--adapter',type=Path,required=True);p.add_argument('--boot-index',type=int,required=True)
    args=p.parse_args()
    if os.geteuid()!=0 or platform.release()!='6.8.0-138-generic':raise RuntimeError('wrong native environment')
    if cases.loaded()&cases.OWN:raise RuntimeError('research module already loaded')
    if cases.sha(args.official)!='04e4f9c0160a208671f106f0a0f8d1bbe020f785925af0b98be0910994467389':raise RuntimeError('wrong official binary')
    args.output.mkdir(exist_ok=False);module_hashes=cases.module_hashes(args.base,args.first)
    # Same basename for the existing fixtures' comm filter; bytes are unchanged.
    executables={}
    for name,path in [('official',args.official),('adapter',args.adapter)]:
        directory=args.output/name;directory.mkdir();target=directory/'d9_enum_probe'
        shutil.copyfile(path,target);target.chmod(0o700);executables[name]=target.resolve()
    probe=args.base/'phase1/bin/d9_enum_probe';fixture=(args.output/'fixture').resolve();fixture.mkdir()
    if any((fixture/name).exists() for name in cases.NAMES):raise RuntimeError('test filename already exists')
    for name in cases.NAMES:(fixture/name).touch(exist_ok=False)
    original=manifest(fixture)
    sources={p.relative_to(ROOT).as_posix():cases.sha(p) for p in [Path(__file__),ROOT/'finalization/controlled_cases.py',ROOT/'scan_directory.py',ROOT/'finalization/tracefs_measurement.py',ROOT/'finalization/COMPLETION_PROTOCOL_20261102.md',ROOT/'finalization/COMPARISON_AMENDMENT_20261102.md']}
    meta={'kernel':platform.release(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'boot_index':args.boot_index,'fixture':str(fixture),'original':original,'module_sha256':module_hashes,
        'official_sha256':cases.sha(args.official),'adapter_sha256':cases.sha(args.adapter),'sources':sources,
        'random_seed':2026110200+args.boot_index,'prototype_zygarde_source':'08ccebd8fdcc28c56dc6251cad0683b7c9344bd1'}
    (args.output/'manifest.json').write_text(json.dumps(meta,indent=2))
    rng=random.Random(meta['random_seed']);rows=[];controls=[];adapter_rows=[];cost=[]
    try:
        with (args.output/'functional.jsonl').open('x') as stream:
            for state in cases.STATES:
                cases.load(state,args.base,args.first)
                try:
                    before=cases.audit(state,args.base,args.first)
                    control=cases.exact_capture(probe,fixture,4096,args.output/f'control_{state}.jsonl')
                    changes=cases.delta(before,cases.audit(state,args.base,args.first))
                    target=cases.expected(original,state)
                    up,down=cases.difference(original,target)
                    old_names={bytes.fromhex(r['name_hex']) for r in original}
                    new_names={bytes.fromhex(r['name_hex']) for r in target}
                    expected_name_loss=bool(old_names-new_names)
                    control.update(state=state,changes=changes,
                        output_matches=cases.identities(control['rows'])==cases.identities(target))
                    controls.append(control)
                    for repeat in range(5):
                        order=['ours','zygarde'];rng.shuffle(order)
                        for method in order:
                            tag=f'{state}_{repeat}_{method}'
                            before=cases.audit(state,args.base,args.first)
                            if method=='ours':
                                command=['python3',str(ROOT/'scan_directory.py'),str(fixture),'--probe',str(probe),'--buffer-size','4096']
                            else:command=[str(executables['official']),'--cells','hidden_file','--no-isolation','--json']
                            env=dict(os.environ,PATH=str(fixture)+':'+os.environ.get('PATH','/usr/bin:/bin'))
                            row=execute(command,args.output,tag,env)
                            changes=cases.delta(before,cases.audit(state,args.base,args.first))
                            if method=='ours':
                                result=row.get('result',{})
                                assessment={'valid':result.get('verdict') in ('equal','different'),
                                    'alarm':result.get('alarm'),'exact_recovery':result.get('upstream_only')==up and result.get('downstream_only')==down,
                                    'recovery_verified':result.get('recovery_validation',{}).get('verified')}
                            else:assessment=zygarde_target(row,fixture)
                            row.update(state=state,repeat=repeat,method=method,changes=changes,
                                expected_identity_difference=bool(up or down),expected_name_loss=expected_name_loss,
                                common_scope=state not in ('insert','inode','type'),assessment=assessment)
                            stream.write(json.dumps(row)+'\n');stream.flush();rows.append(row)
                    # The source adapter must agree with the unmodified release on target findings.
                    env=dict(os.environ,KICBA_BENCH_DIR=str(fixture),KICBA_AUDIT_PATH=str(args.output/f'adapter_{state}.audit.jsonl'))
                    row=execute([str(executables['adapter']),'--cells','hidden_file','--no-isolation','--json'],args.output,'adapter_'+state,env)
                    row.update(state=state,assessment=zygarde_target(row,fixture),expected_name_loss=expected_name_loss)
                    adapter_rows.append(row)
                finally:cases.unload(state,args.base,args.first)
        # Per-directory cold-process latency with matching target scopes.
        for size in (128,4096,65536):
            directory=args.output/('cost_'+str(size));directory.mkdir()
            for i in range(size):(directory/f'entry_{i:08d}').touch()
            for repeat in range(6):
                order=['ours','zygarde_adapter'];rng.shuffle(order)
                for method in order:
                    env=None
                    if method=='ours':
                        command=['python3',str(ROOT/'scan_directory.py'),str(directory),'--probe',str(probe)]
                    else:
                        command=[str(executables['adapter']),'--cells','hidden_file','--no-isolation','--json']
                        env=dict(os.environ,KICBA_BENCH_DIR=str(directory))
                    row=execute(command,args.output,f'cost_{size}_{repeat}_{method}',env)
                    result=row.get('result',{})
                    row.update(size=size,repeat=repeat,method=method,warmup=repeat==0,
                        valid=(result.get('verdict')=='equal' if method=='ours' else zygarde_target(row,directory)['valid']))
                    cost.append(row)
            # Audit counts separately; never include instrumentation I/O in the cost samples.
            env=dict(os.environ,KICBA_BENCH_DIR=str(directory),KICBA_AUDIT_PATH=str(args.output/f'cost_{size}.audit.jsonl'))
            execute([str(executables['adapter']),'--cells','hidden_file','--no-isolation','--json'],args.output,f'cost_{size}_audit',env)
        for name,data in [('controls.json',controls),('adapter.json',adapter_rows),('cost.json',cost)]:
            (args.output/name).write_text(json.dumps(data,indent=2))
        summary={'functional_observations':len(rows),'controls_passed':all(c['returncode']==0 and c['output_matches'] for c in controls),
            'execution_invalid':sum(not r['assessment']['valid'] for r in rows),'methods':{},
            'adapter_agrees_each_state':all(r['assessment']['valid'] and all(
                q['assessment']['alarm']==r['assessment']['alarm'] for q in rows if q['state']==r['state'] and q['method']=='zygarde') for r in adapter_rows),
            'cost_observations':len(cost),'cost_valid':sum(r['valid'] for r in cost)}
        for method in ('ours','zygarde'):
            common=[r for r in rows if r['method']==method and r['common_scope'] and r['assessment']['valid']]
            positive=[r for r in common if r['expected_name_loss']];negative=[r for r in common if not r['expected_name_loss']]
            summary['methods'][method]={'common_positive':len(positive),'common_detected':sum(r['assessment']['alarm'] is True for r in positive),
                'common_negative':len(negative),'common_false_alerts':sum(r['assessment']['alarm'] is True for r in negative),
                'identity_only_results':{state:[r['assessment']['alarm'] for r in rows if r['method']==method and r['state']==state] for state in ('insert','inode','type')}}
        summary['execution_passed']=(summary['controls_passed'] and summary['execution_invalid']==0 and summary['cost_valid']==36)
        (args.output/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
        return 0 if summary['execution_passed'] else 1
    finally:
        for state in cases.STATES:cases.unload(state,args.base,args.first)
        for name in cases.NAMES:
            path=fixture/name
            if path.exists():path.unlink()


if __name__=='__main__':raise SystemExit(main())
