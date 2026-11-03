#!/usr/bin/env bash
set -euo pipefail

# Level 0 read-only gap closure.
# Safety: query only. No token install/remove, no sendFuseCmd, no makeTokenReq,
# no commandForESS, no ESS mutation, no partition writes, no reboot,
# no remount rw, no setenforce. The only mount touched is efivarfs and it is
# unmounted again if this script mounted it.

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
audit_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
device_dir="$audit_dir/device"
log_dir="$audit_dir/logs"
manifest_dir="$audit_dir/manifests"
mkdir -p "$device_dir" "$log_dir" "$manifest_dir"

adb_bin=${ADB_BIN:-adb}
started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
session_log="$log_dir/level0-collection.log"
ENGMODE_SERVICE='vendor.samsung.hardware.security.engmode.ISehEngmode/default'

: > "$session_log"
printf 'collection_started_utc=%s\n' "$started_utc" >> "$session_log"
printf '[%s] adb devices -l\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$session_log"
"$adb_bin" devices -l | tee "$device_dir/level0-adb-devices.txt" >> "$session_log"

# identity + selinux, read-only
{
    printf '$ adb shell su -c id; getenforce\n'
    "$adb_bin" shell "su -c 'id; id -Z 2>/dev/null || true'" | tr -d '\r'
    printf 'getenforce_shell='
    "$adb_bin" shell getenforce 2>/dev/null | tr -d '\r'
    printf '\n'
    printf 'getenforce_root='
    "$adb_bin" shell "su -c 'getenforce'" | tr -d '\r'
    printf '\n'
} > "$device_dir/level0-identity.txt"

# 1. oemlock inventory fix. Old collector grepped oem_lock only and missed
# the bare oemlock endpoint, so backend stayed Unknown. No su needed here
# on purpose, keeps the caller SELinux context as shell.
{
    printf 'SERVICE_LIST\n'
    "$adb_bin" shell service list 2>&1 | grep -Ei 'oemlock|oem_lock|persistent_data_block|vaultkeeper|kmx|trustchain' || true
    printf '\nLSHAL\n'
    "$adb_bin" shell lshal 2>/dev/null | grep -Ei 'oemlock|oem_lock|persistent_data_block|vaultkeeper|engmode|kmx|trustchain' || true
    printf '\nVINTF_MAIN\n'
    "$adb_bin" shell cat /vendor/etc/vintf/manifest.xml 2>/dev/null | grep -Ei -B2 -A5 'oemlock|oem_lock|vaultkeeper|engmode|kmx' || true
    printf '\nVINTF_FRAGMENTS\n'
    "$adb_bin" shell ls /vendor/etc/vintf/manifest/ 2>/dev/null || true
    "$adb_bin" shell grep -ril -E 'oemlock|vaultkeeper' /vendor/etc/vintf/ 2>/dev/null || true
} > "$device_dir/level0-oemlock-inventory.txt" 2>> "$session_log"

# 2. dumpsys state, read-only. Each line must not abort the script.
{
    printf '### dumpsys oem_lock\n'
    "$adb_bin" shell dumpsys oem_lock 2>&1 || true
    printf '\n### dumpsys persistent_data_block\n'
    "$adb_bin" shell dumpsys persistent_data_block 2>&1 || true
    printf '\n### dumpsys SatsService\n'
    "$adb_bin" shell dumpsys SatsService 2>&1 || true
    printf '\n### dumpsys activity service SatsService\n'
    "$adb_bin" shell dumpsys activity service SatsService 2>&1 || true
    printf '\n### props\n'
    for p in sys.oem_unlock_allowed ro.oem_unlock_supported ro.frp.pst ro.boot.flash.locked ro.boot.other.locked ro.boot.vbmeta.device_state ro.boot.verifiedbootstate; do
        printf '%s=' "$p"
        "$adb_bin" shell getprop "$p" 2>/dev/null | tr -d '\r'
        printf '\n'
    done
} > "$device_dir/level0-dumpsys-oemlock.txt" 2>> "$session_log"

# 3. efivars, read-only. Mounts efivarfs only if missing, unmounts only
# what it mounted. Leaves pre-mounted state alone.
EFIVARS_MOUNTED_BY_SCRIPT=0
{
    printf '$ ls /sys/firmware/efi/efivars (before)\n'
    "$adb_bin" shell "su -c 'ls -la /sys/firmware/efi/efivars 2>&1; echo ---MOUNTS---; grep -i efi /proc/mounts 2>/dev/null || echo no_efi_mounts'" | tr -d '\r' || true
} > "$device_dir/level0-efivars.txt" 2>> "$session_log"

if ! "$adb_bin" shell "su -c 'grep -q efivarfs /proc/mounts'" 2>/dev/null; then
    printf '[%s] efivarfs not mounted, mounting temporarily\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$session_log"
    if "$adb_bin" shell "su -c 'mkdir -p /sys/firmware/efi/efivars && mount -t efivarfs none /sys/firmware/efi/efivars'" >> "$session_log" 2>&1; then
        EFIVARS_MOUNTED_BY_SCRIPT=1
    else
        printf 'mount_failed\n' >> "$device_dir/level0-efivars.txt"
    fi
fi

{
    printf '\n$ ls /sys/firmware/efi/efivars (after mount attempt)\n'
    "$adb_bin" shell "su -c 'ls -la /sys/firmware/efi/efivars 2>&1'" | tr -d '\r' || true
    printf '\n$ efivar count\n'
    "$adb_bin" shell "su -c 'ls /sys/firmware/efi/efivars 2>/dev/null | wc -l'" | tr -d '\r' || true
} >> "$device_dir/level0-efivars.txt" 2>> "$session_log"

if [ "$EFIVARS_MOUNTED_BY_SCRIPT" = 1 ]; then
    "$adb_bin" shell "su -c 'umount /sys/firmware/efi/efivars'" >> "$session_log" 2>&1 || true
    printf '[%s] efivarfs unmounted again\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$session_log"
fi

# 4. logcat snapshot around engmode, read-only, bounded.
{
    printf '$ logcat -d filtered\n'
    "$adb_bin" shell logcat -d -b main,system,crash 2>/dev/null | grep -Ei 'engmode|emservice|oemlock|oem_lock|vaultkeeper|kmx|avb|vbmeta' | head -n 300 || true
} > "$device_dir/level0-logcat-engmode.txt" 2>> "$session_log"

# 5. strace on emservice during one query-only tx 22. Skips cleanly if
# no strace or no pid. The Binder call below is the same shape as the
# existing read-only probe: length 32 + 8 zero words.
STRACE_BIN=$("$adb_bin" shell "su -c 'command -v strace'" 2>/dev/null | tr -d '\r' || true)
EM_PID=$("$adb_bin" shell pidof vendor.samsung.hardware.security.engmode-service 2>/dev/null | tr -d '\r' || true)
if [ -z "$EM_PID" ]; then
    EM_PID=$("$adb_bin" shell pidof emservice 2>/dev/null | tr -d '\r' || true)
fi
printf 'strace_bin=%s\nem_pid=%s\n' "$STRACE_BIN" "$EM_PID" > "$device_dir/level0-strace-info.txt"

if [ -n "$STRACE_BIN" ] && [ -n "$EM_PID" ]; then
    printf '[%s] starting strace on pid %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$EM_PID" >> "$session_log"
    "$adb_bin" shell "su -c 'rm -f /data/local/tmp/level0-strace.log'" >> "$session_log" 2>&1 || true
    "$adb_bin" shell "su -c 'nohup strace -f -tt -s 256 -p $EM_PID -o /data/local/tmp/level0-strace.log 2>&1 & echo started'" >> "$session_log" 2>&1 || true
    sleep 1
    "$adb_bin" shell service call "$ENGMODE_SERVICE" 22 i32 32 i32 0 i32 0 i32 0 i32 0 i32 0 i32 0 i32 0 i32 0 >> "$session_log" 2>&1 || true
    sleep 1
    "$adb_bin" shell "su -c 'pkill -f level0-strace.log; pkill -x strace; sleep 0.5'" >> "$session_log" 2>&1 || true
    "$adb_bin" exec-out "su -c 'cat /data/local/tmp/level0-strace.log 2>/dev/null'" > "$device_dir/level0-strace.log" 2>> "$session_log" || true
    "$adb_bin" shell "su -c 'rm -f /data/local/tmp/level0-strace.log'" >> "$session_log" 2>&1 || true
    printf '[%s] strace done, bytes=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(stat -c %s "$device_dir/level0-strace.log" 2>/dev/null || echo 0)" >> "$session_log"
else
    printf 'skipped: need both strace binary and emservice pid on device\n' > "$device_dir/level0-strace.log"
fi

# manifest
{
    printf 'sha256\tsize\tcollected_utc\tpath\n'
    for name in \
        level0-adb-devices.txt \
        level0-identity.txt \
        level0-oemlock-inventory.txt \
        level0-dumpsys-oemlock.txt \
        level0-efivars.txt \
        level0-logcat-engmode.txt \
        level0-strace-info.txt \
        level0-strace.log; do
        path="$device_dir/$name"
        [ -f "$path" ] || continue
        hash=$(sha256sum "$path" | awk '{print $1}')
        size=$(stat -c %s "$path")
        printf '%s\t%s\t%s\t%s\n' "$hash" "$size" "$started_utc" "${path#$audit_dir/}"
    done
} > "$manifest_dir/level0-files.tsv"

printf 'collection_finished_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$session_log"
cat "$manifest_dir/level0-files.tsv"
