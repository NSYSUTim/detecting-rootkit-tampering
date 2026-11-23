#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

if [[ $# -ne 2 ]]; then
    printf '%s\n' 'Usage: bash demo/scan.sh DIRECTORY DECLOAKER' >&2
    exit 2
fi

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
directory="$(realpath -e -- "$1")"
decloaker="$(realpath -e -- "$2")"
temp_root="$(realpath -e -- "${TMPDIR:-/tmp}")"
[[ -d "$directory" && "$directory" != / && -x "$decloaker" ]] || exit 2
case "$temp_root/" in "$directory/"*) printf '%s\n' 'Set TMPDIR outside DIRECTORY.' >&2; exit 2 ;; esac
mount="$(findmnt -n -o TARGET,FSTYPE,FSROOT -T "$directory")"
[[ "$mount" =~ ^/[[:space:]]+ext4[[:space:]]+/$ ]] || {
    printf '%s\n' 'Use a directory on the Linux root ext4 filesystem.' >&2
    exit 2
}
device="$(findmnt -n -e -o SOURCE -T "$directory")"
[[ -b "$device" ]] || exit 2
run="$(mktemp -d -- "$temp_root/kicba-demo.XXXXXX")"
status=0

printf '%s\n' '【當場】目錄列舉'
ls -1ai --quoting-style=escape -- "$directory" | tee "$run/listing.txt"
printf '\n%s\n' '【當場】K↔S'
gcc -O2 -Wall -Wextra "$root/phase1/enum_probe.c" -o "$run/enum_probe"
sudo python3 -B "$root/scan_directory.py" "$directory" --probe "$run/enum_probe" \
    > "$run/k-s.json" 2> "$run/k-s.stderr" || status=2
python3 -B "$root/demo/replay.py" ks "$run" || status=2

printf '\n%s\n' '【當場】S↔L'
python3 -B "$root/scan_library.py" "$directory" --output "$run/s-l" --text || status=2

printf '\n%s\n' '【當場】Decloaker'
disk_exit=0
sudo "$decloaker" --format=plain --log-level=info disk ls --dev="$device" --compare "$directory" \
    > "$run/decloaker.txt" 2> "$run/decloaker.stderr" || disk_exit=$?
printf '%s\n' "$disk_exit" > "$run/decloaker.exit"
python3 -B "$root/demo/replay.py" disk "$run" || status=2

printf '\n%s\n' '【預跑】Trace of the Times'
python3 -B "$root/demo/replay.py" timing || status=2
printf '\n資料：%s\n' "$run"
exit "$status"
