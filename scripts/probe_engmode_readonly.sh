#!/usr/bin/env bash
set -euo pipefail

# Read-only Binder probes for the stable AIDL Engineering Mode HAL.
# Deliberately excluded: installToken, removeToken, sendFuseCmd,
# makeTokenReq, commandForESS, and every ESS mutation.

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
OUT="$ROOT_DIR/audit/device/engmode-binder-readonly-probes.txt"
SERVICE='vendor.samsung.hardware.security.engmode.ISehEngmode/default'

{
    date -u '+collected_utc=%Y-%m-%dT%H:%M:%SZ'
    printf 'device='; adb get-serialno
    printf 'service=%s\n' "$SERVICE"
    printf 'safety=transactions 3, 5, 7, and 22 are query-only; no token/fuse/ESS mutation invoked\n'

    printf '\n$ adb shell service check %s\n' "$SERVICE"
    adb shell service check "$SERVICE"

    printf '\n$ adb shell service call %s 3\n' "$SERVICE"
    adb shell service call "$SERVICE" 3

    printf '\n$ adb shell service call %s 5\n' "$SERVICE"
    adb shell service call "$SERVICE" 5

    printf '\n$ adb shell service call %s 7\n' "$SERVICE"
    adb shell service call "$SERVICE" 7

    printf '\n$ adb shell service call %s 22 i32 32 i32 0 i32 0 i32 0 i32 0 i32 0 i32 0 i32 0 i32 0\n' "$SERVICE"
    adb shell service call "$SERVICE" 22 \
        i32 32 \
        i32 0 i32 0 i32 0 i32 0 \
        i32 0 i32 0 i32 0 i32 0
} > "$OUT"

sha256sum "$OUT"
