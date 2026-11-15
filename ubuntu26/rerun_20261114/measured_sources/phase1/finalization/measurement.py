"""Wrap the retained packed collector with additional quality/recovery checks."""
from __future__ import annotations

from pathlib import Path
import time

from kicba.recovery_validation import finalize_record


def read_program_counters(bpf) -> dict:
    programs = {}
    for name in ("packed_enter", "packed_return"):
        # load_func returns the already loaded function when it is attached.
        function = bpf.load_func(name, bpf.KPROBE)
        fields = {}
        for line in Path(f"/proc/self/fdinfo/{function.fd}").read_text().splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                label = "id" if key.strip() == "prog_id" else key.strip()
                if key.strip() in ("prog_id", "prog_tag", "recursion_misses"):
                    if label in fields:
                        raise ValueError("duplicate program counter field")
                    fields[label] = value.strip()
        if not all(key in fields for key in ("id", "prog_tag", "recursion_misses")):
            raise ValueError("required program identity/counter unavailable")
        for key in ("id", "recursion_misses"):
            if not fields[key].isascii() or not fields[key].isdigit():
                raise ValueError("invalid program counter")
            fields[key] = int(fields[key])
        programs[name] = fields
    return programs


def compare_program_counters(before, after) -> dict:
    result = {"available": False, "valid": False, "reasons": [], "per_program": {},
              "scope": "program recursion_misses plus the base return-profile gate",
              "not_covered": "all nmissed sources of the perf-attached entry kprobe"}
    try:
        for name in ("packed_enter", "packed_return"):
            first, last = before[name], after[name]
            for item in (first, last):
                if (type(item["id"]) is not int or item["id"] <= 0
                        or not isinstance(item["prog_tag"], str) or not item["prog_tag"]
                        or type(item["recursion_misses"]) is not int or item["recursion_misses"] < 0):
                    raise ValueError("malformed program identity/counter")
            if (first["id"], first["prog_tag"]) != (last["id"], last["prog_tag"]):
                result["reasons"].append("program_identity_changed:" + name)
            delta = last["recursion_misses"] - first["recursion_misses"]
            result["per_program"][name] = {"program_id_before": first["id"],
                                            "program_id_after": last["id"],
                                            "prog_tag_before": first["prog_tag"],
                                            "prog_tag_after": last["prog_tag"],
                                            "recursion_misses_before": first["recursion_misses"],
                                            "recursion_misses_after": last["recursion_misses"],
                                            "recursion_misses_delta": delta}
            if delta < 0:
                result["reasons"].append("counter_reset:" + name)
            elif delta:
                result["reasons"].append("program_recursion_missed:" + name)
        result["available"] = True
        result["valid"] = not result["reasons"]
    except (KeyError, TypeError, ValueError) as error:
        result["reasons"].append(str(error))
    return result


class CheckedMeasurement:
    def __init__(self, base):
        if base.implementation != "packed":
            raise ValueError("completion wrapper requires the packed collector")
        self.base = base

    def collect_started(self, processes):
        start = time.monotonic_ns()
        try:
            first = read_program_counters(self.base.bpf)
        except (OSError, ValueError) as error:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate()
            return [{"verdict": "invalid", "measurement_valid": False, "alarm": None,
                     "recovery_verified": False, "recovery_status": "not_assessed",
                     "error": str(error)} for _ in processes]
        rows = self.base.collect_started(processes)
        try:
            quality = compare_program_counters(first, read_program_counters(self.base.bpf))
        except (OSError, ValueError) as error:
            quality = {"available": False, "valid": False, "reasons": [str(error)]}
        results = [finalize_record(row, quality) for row in rows]
        elapsed = time.monotonic_ns() - start
        for row in results:
            row["group_wall_with_all_quality_and_recovery_ns"] = elapsed
            row["completion_version"] = "2026-11-01"
        return results

    def scan(self, directory, buffer=65536, dump=None):
        start = time.monotonic_ns()
        try:
            first = read_program_counters(self.base.bpf)
        except (OSError, ValueError) as error:
            return {"verdict": "invalid", "measurement_valid": False, "alarm": None,
                    "recovery_verified": False, "recovery_status": "not_assessed",
                    "error": "program counter unavailable before scan: " + str(error)}
        record = self.base.scan(directory, buffer, dump)
        try:
            last = read_program_counters(self.base.bpf)
            quality = compare_program_counters(first, last)
        except (OSError, ValueError) as error:
            quality = {"available": False, "valid": False, "reasons": [str(error)]}
        result = finalize_record(record, quality)
        result["wall_with_all_quality_and_recovery_ns"] = time.monotonic_ns() - start
        result["completion_version"] = "2026-11-01"
        return result
