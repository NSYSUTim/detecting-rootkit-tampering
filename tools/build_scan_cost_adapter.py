"""Build an additive, instrumented adapter from the pinned original sources."""
import argparse,difflib,hashlib,json,os,shutil,subprocess
from pathlib import Path

PIN='08ccebd8fdcc28c56dc6251cad0683b7c9344bd1'
EXPECTED={'cells/file/file.go':'bb10c2cd0463e2643e488db9603cb5fd596d2e6ddf06ca565bdfa13d47dc6930',
          'internal/canary/canary.go':'ddcd74c56ac54918f10763d36a4b660d30c7fbfae83a0003ba0b88a9e0d75321',
          'internal/core/runner.go':'f98401a33369b996bee0c61a25c10b589107819b4ba13c3c06bf761ea7437eb0'}
HELPER=r'''package core

import (
    "encoding/json"
    "fmt"
    "os"
    "strconv"
    "time"

    "github.com/cilium/ebpf"
)

type benchmarkView struct {
    Directory string `json:"directory"`
    Produced map[string]bool `json:"produced"`
    Returned map[string]bool `json:"returned"`
}
type benchmarkRun struct {
    Started time.Time
    ScanNS int64
    Views []benchmarkView
    RingBytes uint32
}
var activeBenchmark *benchmarkRun

func BenchmarkRing(spec *ebpf.CollectionSpec) error {
    value := os.Getenv("KICBA_BENCH_RING_BYTES")
    if value == "" { return nil }
    size, err := strconv.ParseUint(value, 10, 32)
    if err != nil || size < 4096 || size & (size-1) != 0 {
        return fmt.Errorf("invalid benchmark ring capacity")
    }
    spec.Maps["events"].MaxEntries = uint32(size)
    return nil
}

func BenchmarkStart(ringBytes uint32) func() {
    target := os.Getenv("KICBA_BENCH_METRICS")
    if target == "" { return func() {} }
    state := &benchmarkRun{RingBytes:ringBytes}
    activeBenchmark = state
    state.Started = time.Now()
    return func() {
        state.ScanNS = time.Since(state.Started).Nanoseconds()
    }
}

func benchmarkResultStart() func() {
    state := activeBenchmark
    if state == nil { return func() {} }
    target := os.Getenv("KICBA_BENCH_METRICS")
    start := time.Now()
    return func() {
        decisionNS := time.Since(start).Nanoseconds()
        elapsed := state.ScanNS + decisionNS
        activeBenchmark = nil
        // Stop first. Serialization and its file I/O are never in the sample.
        f, err := os.OpenFile(target,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
        if err == nil {
            err = json.NewEncoder(f).Encode(map[string]interface{}{
                "scan_to_verdict_ns":elapsed,"scan_ns":state.ScanNS,"decision_postprocess_ns":decisionNS,"ring_bytes":state.RingBytes,
                "views":state.Views,"scope":"ready observation through scan, name comparison, canary checks and verdict; report IO and detach excluded"})
            if closeErr := f.Close(); err == nil { err = closeErr }
        }
        if err != nil { fmt.Fprintf(os.Stderr,"benchmark metrics: %v\n",err) }
    }
}

func BenchmarkView(dir string, produced,returned map[string]bool) {
    if activeBenchmark != nil {
        activeBenchmark.Views = append(activeBenchmark.Views,benchmarkView{dir,produced,returned})
    }
}
'''


def change(value,old,new):
    if value.count(old)!=1:raise RuntimeError('source anchor changed: '+old[:60])
    return value.replace(old,new)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('upstream','work','go','cache','module-cache','output','metadata'):
        p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args();args.metadata.mkdir(parents=True,exist_ok=True)
    original={n:(args.upstream/n).read_bytes() for n in EXPECTED}
    for n,digest in EXPECTED.items():
        if hashlib.sha256(original[n]).hexdigest()!=digest:raise RuntimeError('wrong upstream '+n)
    shutil.copytree(args.upstream,args.work)
    name='cells/file/file.go';value=original[name].decode()
    value=change(value,'\tvar objs objects','\tif err := core.BenchmarkRing(spec); err != nil { return err }\n\tvar objs objects')
    value=change(value,'\tlisted, hidden, stashed := 0, 0, 0','\tfinishBenchmark := core.BenchmarkStart(spec.Maps["events"].MaxEntries)\n\tdefer finishBenchmark()\n\tlisted, hidden, stashed := 0, 0, 0')
    value=change(value,'\treturn produced, returned, nil','\tcore.BenchmarkView(dir, produced, returned)\n\treturn produced, returned, nil')
    value=change(value,'func scanDirs() []string {','func scanDirs() []string {\n if target := os.Getenv("KICBA_BENCH_DIR"); target != "" { return []string{target} }')
    (args.work/name).write_bytes(value.encode())
    name='internal/canary/canary.go';value=original[name].decode()
    value=change(value,'const FileDir = "/tmp"','var FileDir = benchmarkFileDir()\nfunc benchmarkFileDir() string {\n if target := os.Getenv("KICBA_BENCH_DIR"); target != "" { return target }; return "/tmp"\n}')
    value=change(value,'type File struct {\n\tPath string\n}','type File struct {\n\tPath string\n borrowed bool\n}')
    value=change(value,'func CreateFile(dir string) (*File, error) {','func CreateFile(dir string) (*File, error) {\n if existing := os.Getenv("KICBA_BENCH_CANARY"); existing != "" {\n  if os.Getenv("KICBA_BENCH_DIR") != dir || filepath.Dir(existing) != filepath.Clean(dir) { return nil, fmt.Errorf("benchmark canary outside target") }\n  info, err := os.Lstat(existing); if err != nil { return nil, err }; if !info.Mode().IsRegular() { return nil, fmt.Errorf("benchmark canary not regular") }\n  return &File{Path:existing,borrowed:true},nil\n }')
    value=change(value,'func (f *File) Remove() { os.Remove(f.Path) }','func (f *File) Remove() { if !f.borrowed { os.Remove(f.Path) } }')
    (args.work/name).write_bytes(value.encode())
    name='internal/core/runner.go';value=original[name].decode()
    value=change(value,'\terr := c.Run(ctx, env, rec)','\terr := c.Run(ctx, env, rec)\n finishBenchmarkResult := benchmarkResultStart()\n defer finishBenchmarkResult()')
    (args.work/name).write_bytes(value.encode());(args.work/'internal/core/benchmark.go').write_bytes(HELPER.encode())
    changed=[*EXPECTED,'internal/core/benchmark.go']
    formatter=args.go.parent/('gofmt.exe' if args.go.suffix.lower()=='.exe' else 'gofmt')
    subprocess.run([str(formatter),'-w',*[str(args.work/n) for n in changed]],check=True)
    patch='';hashes={}
    for n in changed:
        before=original.get(n,b'');after=(args.work/n).read_bytes()
        hashes[n]={'before_sha256':hashlib.sha256(before).hexdigest() if before else None,'after_sha256':hashlib.sha256(after).hexdigest()}
        patch+=''.join(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),
            fromfile='a/'+n if before else '/dev/null',tofile='b/'+n))
    (args.metadata/'adapter.patch').write_bytes(patch.encode())
    bpf_files={n.relative_to(args.upstream).as_posix():hashlib.sha256(n.read_bytes()).hexdigest()
        for n in (args.upstream/'cells/file').glob('file*') if n.suffix in ('.c','.o')}
    assert all(hashlib.sha256((args.work/n).read_bytes()).hexdigest()==v for n,v in bpf_files.items())
    env=dict(os.environ,GOOS='linux',GOARCH='amd64',CGO_ENABLED='0',GOTOOLCHAIN='local',
        GOCACHE=str(args.cache),GOMODCACHE=str(args.module_cache))
    subprocess.run([str(args.go),'build','-trimpath','-ldflags=-s -w','-o',str(args.output),'./cmd/zygarde'],cwd=args.work,env=env,check=True)
    meta={'upstream_commit':PIN,'go':subprocess.check_output([str(args.go),'version'],text=True).strip(),
        'sources':hashes,'unchanged_bpf_files':bpf_files,'binary_sha256':hashlib.sha256(args.output.read_bytes()).hexdigest(),
        'configurations':{'default_ring_bytes':4194304,'expanded_ring_bytes':33554432},
        'algorithm_unchanged':True,'shared_existing_canary_only_for_benchmark':True}
    (args.metadata/'BUILD.json').write_bytes((json.dumps(meta,indent=2)+'\n').encode())
    print(json.dumps(meta))


if __name__=='__main__':main()
