"""Check S-L consistency for one complete listing by a controlled readdir64 application."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
from kicba.library_consistency import compare_entries, parse_application_output, parse_syscall_trace


def observe(directory, workspace, preload, probe, cells):
    environment = dict(os.environ)
    environment.pop("LD_PRELOAD", None)
    environment.pop("LD_AUDIT", None)
    if probe is None:
        probe = workspace / "library_probe"
        compiled = subprocess.run(
            ["gcc", "-O2", "-Wall", "-Wextra", str(ROOT / "collector/library_probe.c"), "-o", str(probe)],
            capture_output=True, text=True, env=environment, timeout=30,
        )
        if compiled.returncode:
            raise ValueError(f"probe compilation failed: {compiled.stderr.strip()}")
    trace = workspace / "getdents64.trace"
    command = ["strace", "-qq", "-v", "-xx", "-s", "256", "-e", "trace=getdents64",
               "-o", str(trace)]
    if preload is not None:
        command.extend(["-E", f"LD_PRELOAD={preload}"])
    command.extend([str(probe), str(directory), "full"])
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, env=environment,
                          start_new_session=True) as child:
        try:
            stdout, stderr = child.communicate("\n", timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise ValueError("controlled listing timed out") from None
    (workspace / "application.txt").write_text(stdout, encoding="ascii")
    (workspace / "application.stderr").write_text(stderr, encoding="utf-8")
    if child.returncode or stderr:
        raise ValueError(f"controlled listing failed (exit {child.returncode}): {stderr.strip()}")
    syscall_entries, call_count = parse_syscall_trace(trace.read_text(encoding="ascii"))
    application_entries, pid = parse_application_output(stdout)
    seeds = secrets.randbits(64), secrets.randbits(64)
    result = compare_entries(syscall_entries, application_entries, seeds, cells)
    result.update(directory=str(directory), pid=pid, getdents64_calls=call_count,
                  kernel=os.uname().release,
                  probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),
                  preload_sha256=hashlib.sha256(preload.read_bytes()).hexdigest() if preload else None)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--preload", type=Path, help="existing test library, applied only to the controlled child")
    parser.add_argument("--probe", type=Path, help="previously compiled collector/library_probe.c")
    parser.add_argument("--output", type=Path, help="new directory for the raw trace, application output, and result")
    parser.add_argument("--cells", type=int, default=256)
    parser.add_argument("--text", action="store_true", help="print a concise human-readable result")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("requires Linux, gcc and strace")
    args.directory = args.directory.resolve()
    if not args.directory.is_dir():
        parser.error("directory does not exist")
    for option in ("preload", "probe"):
        value = getattr(args, option)
        if value is not None:
            value = value.resolve()
            if not value.is_file():
                parser.error(f"{option} file does not exist")
            setattr(args, option, value)
    if args.cells < 4 or args.cells > 16384 or args.cells & (args.cells - 1):
        parser.error("cells must be a power of two between 4 and 16384")
    for tool in ("strace", *(() if args.probe else ("gcc",))):
        if shutil.which(tool) is None:
            parser.error(f"required tool is unavailable: {tool}")
    output_created = False
    try:
        if args.output:
            args.output = args.output.resolve()
            if args.output == args.directory or args.directory in args.output.parents:
                parser.error("store output outside the observed directory")
            args.output.mkdir(parents=True, exist_ok=False)
            output_created = True
            result = observe(args.directory, args.output, args.preload, args.probe, args.cells)
        else:
            with tempfile.TemporaryDirectory(prefix="kicba-sl-") as temporary:
                result = observe(args.directory, Path(temporary), args.preload, args.probe, args.cells)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result = dict(boundary="S-L", measurement_valid=False, verdict="invalid", alarm=None,
                      recovery_verified=False, error=str(error))
    rendered = json.dumps(result, ensure_ascii=True, indent=2)
    if output_created:
        (args.output / "result.json").write_text(rendered + "\n", encoding="utf-8")
    if args.text:
        print(f"S-L: {result['verdict']} | alert={result['alarm']}")
        if result["measurement_valid"]:
            print(f"getdents64 S={result['syscall_fingerprint'][0]} | readdir64 L={result['application_fingerprint'][0]}")
            print(f"IBLT verified recovery={result['recovery_verified']}")
            if result["recovery_verified"]:
                for direction, field in (("S-only", "recovered_syscall_only"), ("L-only", "recovered_application_only")):
                    for item in result[field]:
                        names = ", ".join(bytes.fromhex(name).decode("utf-8", "backslashreplace")
                                          for name in item["observed_name_hex"])
                        print(f"  {direction}: {names} | inode={item['identity'][1]} | d_type={item['identity'][2]}")
        else:
            print(result["error"])
    else:
        print(rendered)
    return 0 if result["measurement_valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
