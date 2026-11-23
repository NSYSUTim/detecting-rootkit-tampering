"""Compare one completed getdents64/readdir64 observation using the existing IBLT."""

from collections import Counter
import re

from .reconciliation import IBLT, MultisetFingerprint, token_for_entry
from .recovery_validation import validate_recovery


CALL = re.compile(r"getdents64\((\d+), \[(.*)\], (\d+)\)\s+= (\d+)")
ENTRY = re.compile(
    r'\{d_ino=(\d+), d_off=(-?\d+), d_reclen=(\d+), d_type=(DT_[A-Z0-9]+), '
    r'd_name="((?:\\x[0-9a-f]{2})+)"\}'
)
TYPES = dict(DT_UNKNOWN=0, DT_FIFO=1, DT_CHR=2, DT_DIR=4, DT_BLK=6,
             DT_REG=8, DT_LNK=10, DT_SOCK=12, DT_WHT=14)


def parse_syscall_trace(text):
    """Reject truncated traces, mixed directory streams, errors, and incomplete scans."""
    calls = []
    for line in text.splitlines():
        if line == "+++ exited with 0 +++":
            continue
        match = CALL.fullmatch(line)
        if match is None:
            raise ValueError(f"unsupported or incomplete getdents64 trace: {line[:160]}")
        fd, records, buffer_size, byte_count = match.groups()
        entries = list(ENTRY.finditer(records))
        if ", ".join(entry.group() for entry in entries) != records:
            raise ValueError("incomplete strace directory record decoding")
        rows, covered = [], 0
        for entry in entries:
            inode, _offset, length, kind, name = entry.groups()
            name = bytes.fromhex(name.replace(r"\x", ""))
            length = int(length)
            if not 0 < len(name) <= 255 or b"\0" in name or b"/" in name:
                raise ValueError("invalid directory-entry name")
            if length < 20 + len(name) or length > int(buffer_size) or length % 8:
                raise ValueError("invalid linux_dirent64 record length")
            if kind not in TYPES:
                raise ValueError(f"unknown directory-entry type: {kind}")
            rows.append((name, int(inode), TYPES[kind]))
            covered += length
        if covered != int(byte_count) or covered > int(buffer_size):
            raise ValueError("decoded records do not cover the syscall return")
        calls.append(dict(fd=int(fd), returned_bytes=int(byte_count), rows=rows))
    if not calls or len({call["fd"] for call in calls}) != 1:
        raise ValueError("expected one traced directory stream")
    ended = False
    for call in calls:
        if ended and call["returned_bytes"]:
            raise ValueError("positive syscall after terminal EOF")
        ended |= call["returned_bytes"] == 0
    if not ended:
        raise ValueError("getdents64 did not reach EOF")
    return [row for call in calls for row in call["rows"]], len(calls)


def parse_application_output(text):
    lines = text.splitlines()
    if len(lines) < 2 or re.fullmatch(r"PID \d+", lines[0]) is None:
        raise ValueError("missing controlled application's PID")
    if lines[-1] != "END eof":
        raise ValueError("readdir64 did not reach EOF")
    entries = []
    for line in lines[1:-1]:
        match = re.fullmatch(r"ENTRY (\d+) (\d+) ([0-9a-f]+)", line)
        if match is None:
            raise ValueError("unrecognized application record")
        inode, kind, name_hex = match.groups()
        name = bytes.fromhex(name_hex)
        if not 0 < len(name) <= 255 or b"\0" in name or b"/" in name:
            raise ValueError("invalid application directory-entry name")
        if not 0 <= int(inode) < 2**64 or not 0 <= int(kind) <= 255:
            raise ValueError("out-of-range application directory-entry identity")
        entries.append((name, int(inode), int(kind)))
    return entries, int(lines[0].split()[1])


def compare_entries(syscall_entries, application_entries, seeds, cells=256):
    """Use the retained fingerprints, decoder, and recovery validation unchanged."""
    s_tokens = [token_for_entry(name, inode, kind, *seeds)
                for name, inode, kind in syscall_entries]
    l_tokens = [token_for_entry(name, inode, kind, *seeds)
                for name, inode, kind in application_entries]
    s_fp = MultisetFingerprint.from_tokens(s_tokens).as_tuple()
    l_fp = MultisetFingerprint.from_tokens(l_tokens).as_tuple()
    different = s_fp != l_fp
    removed = Counter(s_tokens) - Counter(l_tokens)
    added = Counter(l_tokens) - Counter(s_tokens)
    if different != bool(removed or added):
        raise ValueError("fingerprints disagree with the captured entry differences")
    decoded = IBLT.from_tokens(s_tokens, cells, *seeds).subtract(
        IBLT.from_tokens(l_tokens, cells, *seeds)
    ).decode()
    up = [[item.key_hash, item.inode, item.d_type] for item in decoded.upstream_only]
    down = [[item.key_hash, item.inode, item.d_type] for item in decoded.downstream_only]
    validation = validate_recovery(s_fp, l_fp, up, down, decoded.success, decoded.residual_cells)
    exact = (decoded.success and Counter(decoded.upstream_only) == removed
             and Counter(decoded.downstream_only) == added)

    def names_for(items, entries, tokens):
        names = {}
        for entry, token in zip(entries, tokens):
            names.setdefault(token, []).append(entry[0].hex())
        return [dict(identity=[item.key_hash, item.inode, item.d_type],
                     observed_name_hex=names.get(item, [])) for item in items]

    return dict(
        boundary="S-L", measurement_valid=True, verdict="different" if different else "equal",
        alarm=different, seeds=list(seeds), cells=cells,
        syscall_fingerprint=list(s_fp), application_fingerprint=list(l_fp),
        decode_success=decoded.success, residual_cells=decoded.residual_cells,
        recovery_verified=different and exact and validation["verified"],
        recovery_validation=validation, decoded_matches_observed_difference=exact,
        upstream_only=up, downstream_only=down,
        recovered_syscall_only=names_for(decoded.upstream_only, syscall_entries, s_tokens),
        recovered_application_only=names_for(decoded.downstream_only, application_entries, l_tokens),
    )
