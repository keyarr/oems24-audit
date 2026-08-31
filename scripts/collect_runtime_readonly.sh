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
session_log="$log_dir/runtime-collection.log"

run_adb() {
    local output_name=$1
    local remote_command=$2
    local output_path="$device_dir/$output_name"
    printf '[%s] adb shell su -c %q\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$remote_command" >> "$session_log"
    "$adb_bin" shell "su -c '$remote_command'" > "$output_path"
}

: > "$session_log"
printf 'collection_started_utc=%s\n' "$started_utc" >> "$session_log"
printf '[%s] adb devices -l\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$session_log"
"$adb_bin" devices -l > "$device_dir/adb-devices.txt"

run_adb root-identity.txt 'id; id -Z 2>/dev/null || true; date -u; cat /proc/uptime'
run_adb properties-all.txt 'getprop'
run_adb properties-targeted.txt 'for p in ro.product.model ro.product.device ro.build.fingerprint ro.build.display.id ro.build.version.release ro.build.version.security_patch ro.boot.flash.locked ro.boot.other.locked ro.boot.vbmeta.device_state ro.boot.verifiedbootstate ro.boot.veritymode ro.boot.warranty_bit ro.boot.kg knox.kg.state ro.oem_unlock_supported sys.oem_unlock_allowed ro.frp.pst ro.boot.em.status ro.boot.em.model ro.boot.em.did; do printf "%s=" "$p"; getprop "$p"; done'
run_adb proc-cmdline.txt 'cat /proc/cmdline'
run_adb proc-bootconfig.txt 'cat /proc/bootconfig'
run_adb partitions-by-name.txt 'ls -laZ /dev/block/by-name'
run_adb block-sizes.txt 'for p in abl devinfo em imagefv uefisecapp persistent steady secdata vbmeta vbmeta_system uefi; do n=/dev/block/by-name/$p; printf "%s\t%s\t" "$p" "$(readlink -f "$n")"; blockdev --getsize64 "$n" 2>/dev/null || stat -c %s "$n"; done'
run_adb partition-hashes-device.txt 'for p in abl devinfo em imagefv uefisecapp persistent steady secdata vbmeta vbmeta_system uefi; do n=/dev/block/by-name/$p; printf "%s\t%s\t" "$p" "$(readlink -f "$n")"; sha256sum "$n"; done'
run_adb mounts.txt 'mount'
run_adb proc-mounts.txt 'cat /proc/mounts'
run_adb services.txt 'service list'
run_adb engmode-services.txt 'printf "public="; service check vendor.samsung.hardware.security.engmode.ISehEngmode/default; printf "internal="; service check EngineeringModeService; printf "sats="; service check SatsService'
run_adb processes.txt 'ps -AZ -o LABEL,USER,PID,PPID,VSZ,RSS,WCHAN,ADDR,S,NAME'
run_adb engmode-processes.txt 'ps -AZ | grep -i -E "engmode|emservice" || true'
run_adb unix-sockets.txt 'cat /proc/net/unix'
run_adb vintf-engmode-manifest.xml 'cat /vendor/etc/vintf/manifest/vendor.samsung.hardware.security.engmode-manifest.xml'
run_adb init-engmode-service.rc 'cat /vendor/etc/init/vendor.samsung.hardware.security.engmode-service.rc'
run_adb init-emservice-files.txt 'find /system/etc/init /system_ext/etc/init /vendor/etc/init /odm/etc/init -type f -maxdepth 2 2>/dev/null | xargs grep -l -i "emservice\|EngineeringModeService" 2>/dev/null || true'
run_adb selinux-state.txt 'getenforce; ls -lZ /vendor/bin/vendor.samsung.hardware.security.engmode-service /vendor/bin/emservice /system/lib64/lib.engmode.samsung.so /system/lib64/lib.engmodejni.samsung.so /vendor/lib64/libengmode_client.so /vendor/lib64/libengmode_server.so /vendor/lib64/libengmode_tlc.so'
run_adb relevant-files.txt 'find /system /system_ext /product /vendor /odm -xdev -type f \( -name "*engmode*" -o -name "framework.jar" -o -name "services.jar" -o -name "libfrpunlock.so" -o -name "FactoryAirCommandManager.apk" -o -name "Rampart.apk" -o -name "HMT.apk" -o -name "serviceModeApp_FB.apk" \) 2>/dev/null | sort'
run_adb package-paths.txt 'for p in com.samsung.android.aircommandmanager com.samsung.android.rampart com.samsung.android.hmt com.sec.android.app.servicemodeapp; do echo "### $p"; pm path "$p"; done'
run_adb package-aircommand.txt 'dumpsys package com.samsung.android.aircommandmanager'
run_adb package-rampart.txt 'dumpsys package com.samsung.android.rampart'
run_adb package-hmt.txt 'dumpsys package com.samsung.android.hmt'
run_adb package-servicemode.txt 'dumpsys package com.sec.android.app.servicemodeapp'
run_adb framework-classpath.txt 'printf "BOOTCLASSPATH=%s\nSYSTEMSERVERCLASSPATH=%s\nSTANDALONE_SYSTEMSERVER_JARS=%s\n" "$BOOTCLASSPATH" "$SYSTEMSERVERCLASSPATH" "$STANDALONE_SYSTEMSERVER_JARS"'

{
    printf 'sha256\tsize\tcollected_utc\tpath\n'
    find "$device_dir" -maxdepth 1 -type f -print0 | sort -z | while IFS= read -r -d '' path; do
        hash=$(sha256sum "$path" | awk '{print $1}')
        size=$(stat -c %s "$path")
        printf '%s\t%s\t%s\t%s\n' "$hash" "$size" "$started_utc" "${path#$audit_dir/}"
    done
} > "$manifest_dir/runtime-files.tsv"

printf 'collection_finished_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$session_log"

