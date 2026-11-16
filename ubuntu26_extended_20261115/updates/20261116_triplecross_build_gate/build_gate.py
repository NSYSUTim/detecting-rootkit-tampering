"""Attempt to build TripleCross on the guest's kernel 7.0.

The upstream is pinned to Ubuntu 21.04 / kernel 5.11 and ships its own
vmlinux.h for that kernel, its own libbpf, its own bpftool. We do NOT
modify the sources; we only run the project's own Makefile and record
what happens. This is a build GATE: the result (pass or fail with full
stderr) is the primary evidence.

If build succeeds we then record the kit/tckit artifact SHAs. Load and
hiding gates are separate scripts.
"""
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
LTS = HERE.parent / "ubuntu26_lts_full_rerun_20261114"
sys.path.insert(0, str(LTS))
from remote_job import SSH, OPTIONS, HOST  # noqa

GUEST = "/home/kicba/ubuntu26_extended_20261116_triplecross_build"
TARBALL = HERE / "triplecross_patched.tar.gz"
TARBALL_SHA = "320b09a925183725c379fccd56dde36037f0f899cdff553e972932ce2cfabb1f"


def execute(args, timeout=60, checked=True, data=None):
    import shlex
    r = subprocess.run([SSH, "-n" if data is None else "-T", *OPTIONS, HOST, shlex.join(args)],
                       input=data, capture_output=True, timeout=timeout)
    if checked and r.returncode:
        raise RuntimeError(shlex.join(args) + " -> " + r.stderr.decode(errors="replace"))
    return r


def identity():
    assert execute(["hostname"]).stdout.decode().strip() == "kicba-ubuntu26"
    assert execute(["uname", "-r"]).stdout.decode().strip() == "7.0.0-43-generic"
    for family in ([], ["-6"]):
        out = execute(["ip", *family, "-j", "route", "show", "default"]).stdout.decode().strip()
        assert out in ("", "[]"), "default route: " + out
    return execute(["cat", "/proc/sys/kernel/random/boot_id"]).stdout.decode().strip()


def tool_versions():
    tools = {}
    for name in ("clang", "llvm-strip", "bpftool", "make", "gcc", "ld"):
        r = execute([name, "--version"], checked=False)
        tools[name] = {"returncode": r.returncode,
                       "stdout": r.stdout.decode(errors="replace").splitlines()[:3],
                       "stderr": r.stderr.decode(errors="replace").splitlines()[:3]}
    return tools


def stage():
    assert sha256(TARBALL.read_bytes()).hexdigest() == TARBALL_SHA
    execute(["mkdir", "-p", GUEST])
    execute(["sudo", "-n", "rm", "-rf", GUEST + "/source"])
    execute(["mkdir", "-p", GUEST + "/source"])
    execute(["tee", GUEST + "/triplecross.tar.gz"], data=TARBALL.read_bytes(), timeout=120)
    assert execute(["sha256sum", GUEST + "/triplecross.tar.gz"]).stdout.decode().split()[0] == TARBALL_SHA
    # Extract on guest (keeps symlinks intact unlike our Windows extraction).
    import shlex
    r = execute(["tar", "-xzf", GUEST + "/triplecross.tar.gz", "-C", GUEST + "/source",
                 "--strip-components=1"], timeout=180, checked=False)
    if r.returncode:
        return {"extracted": False, "stderr": r.stderr.decode(errors="replace")}
    return {"extracted": True}


def attempt_build():
    import shlex
    boot = identity()
    out_dir = HERE / ("build_result_" + boot)
    out_dir.mkdir(exist_ok=True)
    tools = tool_versions()
    (out_dir / "tool_versions.json").write_text(json.dumps(tools, indent=2))
    stage_result = stage()
    (out_dir / "stage_result.json").write_text(json.dumps(stage_result, indent=2))
    if not stage_result.get("extracted"):
        return {"stage_failed": True, "out_dir": str(out_dir)}
    unit = "kicba-triplecross-build-" + boot[:8]
    log = GUEST + "/" + unit
    pre = execute(["systemctl", "show", unit, "--property=LoadState,ActiveState,ExecMainStatus"], checked=False).stdout.decode()
    if "LoadState=not-found" not in pre:
        raise RuntimeError("existing unit: " + pre)
    execute(["sudo", "-n", "systemd-run", "--unit=" + unit,
             "--working-directory=" + GUEST + "/source/src",
             "--property=StandardOutput=append:" + log + ".stdout",
             "--property=StandardError=append:" + log + ".stderr",
             "--property=RuntimeMaxSec=1200",
             "env", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
             "make", "all"])
    deadline = time.monotonic() + 1250
    while time.monotonic() < deadline:
        st = execute(["systemctl", "show", unit,
                      "--property=ActiveState,ExecMainStatus,Result"], checked=False).stdout.decode()
        if "ActiveState=inactive" in st or "ActiveState=failed" in st:
            rc = 0
            for line in st.splitlines():
                if line.startswith("ExecMainStatus="):
                    rc = int(line.split("=", 1)[1])
            (out_dir / "unit_final.txt").write_text(st)
            # Pull logs
            for ext in ("stdout", "stderr"):
                tail = execute(["sudo", "-n", "tar", "-C", GUEST, "-cf", "-", unit + "." + ext], timeout=60)
                if tail.returncode == 0:
                    with tarfile.open(fileobj=BytesIO(tail.stdout)) as a:
                        for m in a.getmembers():
                            if not m.isfile():
                                continue
                            target = (out_dir / m.name).resolve()
                            if not target.is_relative_to(out_dir):
                                continue
                            a.extract(m, out_dir, filter="data")
            # Pull built outputs (if any)
            listing = execute(["ls", "-la", GUEST + "/source/src/bin"], checked=False).stdout.decode()
            (out_dir / "bin_listing.txt").write_text(listing)
            # If pass, tar and pull built artifacts for hashing
            if rc == 0:
                tar_r = execute(["sudo", "-n", "tar", "-C", GUEST + "/source/src",
                                 "-czf", "-", "bin", "ebpf/.output", "user", "helpers"],
                                timeout=120, checked=False)
                if tar_r.returncode == 0:
                    (out_dir / "artifacts.tar.gz").write_bytes(tar_r.stdout)
                    # Compute SHAs of key outputs
                    hashes = {}
                    with tarfile.open(fileobj=BytesIO(tar_r.stdout)) as a:
                        for m in a.getmembers():
                            if m.isfile() and (m.name.endswith(("kit", "tckit", ".o", ".so", ".bpf.o"))):
                                f = a.extractfile(m)
                                if f:
                                    hashes[m.name] = sha256(f.read()).hexdigest()
                    (out_dir / "artifact_hashes.json").write_text(json.dumps(hashes, indent=2))
            summary = {"boot": boot, "returncode": rc, "unit_final": st.strip(),
                       "status": "pass" if rc == 0 else "fail",
                       "out_dir": str(out_dir)}
            (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
            print(json.dumps(summary, indent=2), flush=True)
            return summary
        time.sleep(5)
    raise TimeoutError(unit)


if __name__ == "__main__":
    attempt_build()
