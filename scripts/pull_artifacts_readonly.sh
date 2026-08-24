#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
audit_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
partition_dir="$audit_dir/partitions"
binary_dir="$audit_dir/binaries"
framework_dir="$audit_dir/framework"
log_dir="$audit_dir/logs"
manifest_dir="$audit_dir/manifests"
mkdir -p "$partition_dir" "$binary_dir" "$framework_dir" "$log_dir" "$manifest_dir"

adb_bin=${ADB_BIN:-adb}
started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
session_log="$log_dir/artifact-collection.log"
manifest="$manifest_dir/device-artifacts.tsv"
: > "$session_log"
printf 'kind\torigin\tdestination\tsize\tsha256\tcollected_utc\tcommand\n' > "$manifest"

record_local() {
    local kind=$1
    local origin=$2
    local destination=$3
    local command_text=$4
    local size hash relative
    size=$(stat -c %s "$destination")
    hash=$(sha256sum "$destination" | awk '{print $1}')
    relative=${destination#$audit_dir/}
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$kind" "$origin" "$relative" "$size" "$hash" "$started_utc" "$command_text" >> "$manifest"
}

pull_partition() {
    local name=$1
    local destination="$partition_dir/$name.img"
    local source="/dev/block/by-name/$name"
    local command_text="adb exec-out su -c 'dd if=$source bs=1048576 status=none'"
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$command_text" >> "$session_log"
    "$adb_bin" exec-out "su -c 'dd if=$source bs=1048576 status=none'" > "$destination"
    record_local partition "$source" "$destination" "$command_text"
}

pull_file() {
    local source=$1
    local destination=$2
    local kind=$3
    local command_text="adb exec-out su -c 'dd if=$source bs=1048576 status=none'"
    mkdir -p "$(dirname -- "$destination")"
    printf '[%s] %s -> %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$command_text" "$destination" >> "$session_log"
    "$adb_bin" exec-out "su -c 'dd if=$source bs=1048576 status=none'" > "$destination"
    record_local "$kind" "$source" "$destination" "$command_text"
}

for part in abl devinfo em imagefv uefisecapp vbmeta vbmeta_system; do
    pull_partition "$part"
done

pull_file /vendor/bin/vendor.samsung.hardware.security.engmode-service "$binary_dir/vendor.samsung.hardware.security.engmode-service" binary
pull_file /vendor/bin/emservice "$binary_dir/emservice" binary
pull_file /vendor/lib64/libengmode_client.so "$binary_dir/libengmode_client.so" library
pull_file /vendor/lib64/libengmode_server.so "$binary_dir/libengmode_server.so" library
pull_file /vendor/lib64/libengmode_tlc.so "$binary_dir/libengmode_tlc.so" library
pull_file /vendor/lib64/libengmode2lite.so "$binary_dir/libengmode2lite.so" library
pull_file /vendor/lib64/libengmode15.so "$binary_dir/libengmode15.so" library
pull_file /vendor/lib64/libsecril-client.so "$binary_dir/libsecril-client.so" library
pull_file /system/lib64/lib.engmode.samsung.so "$binary_dir/lib.engmode.samsung.so" library
pull_file /system/lib64/lib.engmodejni.samsung.so "$binary_dir/lib.engmodejni.samsung.so" library
pull_file /system/lib64/libfrpunlock.so "$binary_dir/libfrpunlock.so" library
pull_file /system/lib64/vendor.samsung.hardware.security.engmode-V1-ndk.so "$binary_dir/engmode-V1-ndk-system.so" library
pull_file /vendor/lib64/vendor.samsung.hardware.security.engmode-V1-ndk.so "$binary_dir/engmode-V1-ndk-vendor.so" library
pull_file /vendor/etc/vintf/manifest/vendor.samsung.hardware.security.engmode-manifest.xml "$framework_dir/vendor.samsung.hardware.security.engmode-manifest.xml" configuration
pull_file /vendor/etc/init/vendor.samsung.hardware.security.engmode-service.rc "$framework_dir/vendor.samsung.hardware.security.engmode-service.rc" configuration
pull_file /system/framework/framework.jar "$framework_dir/framework.jar" framework
pull_file /system/framework/services.jar "$framework_dir/services.jar" framework
pull_file /system/app/FactoryAirCommandManager/FactoryAirCommandManager.apk "$framework_dir/FactoryAirCommandManager.apk" apk
pull_file /system/app/Rampart/Rampart.apk "$framework_dir/Rampart.apk" apk
pull_file /system/app/HMT/HMT.apk "$framework_dir/HMT.apk" apk
pull_file /system/priv-app/serviceModeApp_FB/serviceModeApp_FB.apk "$framework_dir/serviceModeApp_FB.apk" apk
pull_file /system/priv-app/SecSettings/SecSettings.apk "$framework_dir/SecSettings.apk" apk
pull_file /system/priv-app/KmxService/KmxService.apk "$framework_dir/KmxService-stock.apk" apk

pull_package() {
    local package=$1
    local destination=$2
    local command_text="adb shell dumpsys package $package"
    printf '[%s] %s -> %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$command_text" "$destination" >> "$session_log"
    "$adb_bin" shell dumpsys package "$package" > "$destination"
    record_local package-dump "$package" "$destination" "$command_text"
}

pull_package com.android.settings "$audit_dir/device/package-settings.txt"
pull_package com.samsung.android.kmxservice "$audit_dir/device/package-kmxservice.txt"

kmx_source=$(
    "$adb_bin" shell pm path com.samsung.android.kmxservice |
        python3 -c 'import sys
for line in sys.stdin:
    if line.startswith("package:"):
        print(line.removeprefix("package:").rstrip("\r\n"))
        break'
)
if [[ -n "$kmx_source" ]]; then
    pull_file "$kmx_source" "$framework_dir/KmxService.apk" apk
fi

action=com.samsung.android.kmxservice.trustchain.CHANGE_OEM_UNLOCK_ALLOWED
action_dump="$audit_dir/device/oem-unlock-action-components.txt"
action_command="adb shell cmd package query-{activities,receivers,services} -a $action"
printf '[%s] %s -> %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$action_command" "$action_dump" >> "$session_log"
{
    "$adb_bin" shell cmd package query-activities -a "$action"
    "$adb_bin" shell cmd package query-receivers -a "$action"
    "$adb_bin" shell cmd package query-services -a "$action"
} > "$action_dump"
record_local package-query "$action" "$action_dump" "$action_command"

state_file="$audit_dir/device/oem-lock-state.txt"
state_command="adb shell 'getenforce; getprop ro.oem_unlock_supported; getprop sys.oem_unlock_allowed; getprop ro.boot.flash.locked; getprop ro.boot.vbmeta.device_state'"
printf '[%s] %s -> %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$state_command" "$state_file" >> "$session_log"
{
    printf 'selinux=%s\n' "$("$adb_bin" shell getenforce | tr -d '\r')"
    printf 'ro.oem_unlock_supported=%s\n' "$("$adb_bin" shell getprop ro.oem_unlock_supported | tr -d '\r')"
    printf 'sys.oem_unlock_allowed=%s\n' "$("$adb_bin" shell getprop sys.oem_unlock_allowed | tr -d '\r')"
    printf 'ro.boot.flash.locked=%s\n' "$("$adb_bin" shell getprop ro.boot.flash.locked | tr -d '\r')"
    printf 'ro.boot.vbmeta.device_state=%s\n' "$("$adb_bin" shell getprop ro.boot.vbmeta.device_state | tr -d '\r')"
} > "$state_file"
record_local runtime-state oem-lock-properties "$state_file" "$state_command"

services_file="$audit_dir/device/oem-lock-services.txt"
services_command="adb shell 'service list; lshal; /vendor/etc/vintf/manifest.xml filters for oemlock/vaultkeeper/kmx/trust'"
printf '[%s] %s -> %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$services_command" "$services_file" >> "$session_log"
{
    printf 'SERVICE_LIST\n'
    "$adb_bin" shell service list | grep -Ei 'vaultkeeper|oem_lock|persistent_data_block|trust|blockchain|lock_settings|lockscreen_overlay|knox_nwFilterMgr_policy|secureclock|updatelock|trustedui' | tr -d '\r' || true
    printf 'LSHAL\n'
    "$adb_bin" shell lshal 2>/dev/null | grep -Ei 'trustedui|engmode|vaultkeeper|kmx' | tr -d '\r' || true
    printf 'VINTF\n'
    "$adb_bin" shell cat /vendor/etc/vintf/manifest.xml 2>/dev/null | grep -Ei -B2 -A5 'vaultkeeper|engmode|kmx' | tr -d '\r' || true
} > "$services_file"
record_local runtime-inventory oem-lock-services "$services_file" "$services_command"

printf 'collection_finished_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$session_log"
