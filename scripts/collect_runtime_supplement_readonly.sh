#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
audit_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
device_dir="$audit_dir/device"
log_dir="$audit_dir/logs"
manifest_dir="$audit_dir/manifests"
mkdir -p "$device_dir" "$log_dir" "$manifest_dir"

adb_bin=${ADB_BIN:-adb}
started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
session_log="$log_dir/runtime-supplement-collection.log"

run_adb() {
    local output_name=$1
    local remote_command=$2
    local output_path="$device_dir/$output_name"
    printf '[%s] adb shell su -c %q\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$remote_command" >> "$session_log"
    "$adb_bin" shell "su -c '$remote_command'" > "$output_path"
}

: > "$session_log"
printf 'collection_started_utc=%s\n' "$started_utc" >> "$session_log"
"$adb_bin" shell su -c id >> "$session_log"

run_adb init-emservice.rc 'cat /vendor/etc/init/emservice.rc 2>&1'
run_adb engmode-service-state.txt 'for s in vendor.samsung.hardware.security.engmode-service emservice; do printf "%s=" "$s"; getprop "init.svc.$s"; done; ps -AZ | grep -i -E "engmode|emservice" || true'
run_adb engmode-process-details.txt 'for p in $(pidof vendor.samsung.hardware.security.engmode-service emservice 2>/dev/null); do echo "### pid=$p"; tr "\\0" " " < /proc/$p/cmdline; echo; cat /proc/$p/attr/current 2>/dev/null || true; ls -lZ /proc/$p/exe /proc/$p/cwd /proc/$p/root 2>/dev/null || true; done'
run_adb engmode-lsof.txt 'lsof 2>/dev/null | grep -i -E "(^COMMAND|engmode|emservice|libQSEEComAPI|libsecril-client|librtts|binderfs/(binder|vndbinder))" || true'
run_adb engmode-maps.txt 'for p in $(pidof vendor.samsung.hardware.security.engmode-service emservice 2>/dev/null); do echo "### pid=$p"; cat /proc/$p/maps 2>&1 || true; done'
run_adb engmode-fds.txt 'for p in $(pidof vendor.samsung.hardware.security.engmode-service emservice 2>/dev/null); do echo "### pid=$p"; ls -laZ /proc/$p/fd 2>&1 || true; done'
run_adb binder-services-supplement.txt 'service check vendor.samsung.hardware.security.engmode.ISehEngmode/default; service check EngineeringModeService; service check SatsService; dumpsys -l | grep -i -E "engmode|sats" || true'
run_adb satsservice-dump.txt 'dumpsys SatsService 2>&1 || true'

{
    printf 'sha256\tsize\tcollected_utc\tpath\n'
    for name in \
        init-emservice.rc \
        engmode-service-state.txt \
        engmode-process-details.txt \
        engmode-lsof.txt \
        engmode-maps.txt \
        engmode-fds.txt \
        binder-services-supplement.txt \
        satsservice-dump.txt; do
        path="$device_dir/$name"
        hash=$(sha256sum "$path" | awk '{print $1}')
        size=$(stat -c %s "$path")
        printf '%s\t%s\t%s\t%s\n' "$hash" "$size" "$started_utc" "${path#$audit_dir/}"
    done
} > "$manifest_dir/runtime-supplement-files.tsv"

printf 'collection_finished_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$session_log"
