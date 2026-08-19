#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
audit_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
root_dir=$(CDPATH= cd -- "$audit_dir/.." && pwd)
dex="$audit_dir/decompiled/services/classes.dex"
jar="$audit_dir/framework/services.jar"
out="$audit_dir/decompiled/services-systemserver-satsservice.txt"
dexdump_bin=${DEXDUMP_BIN:-/home/erick/Android/Sdk/build-tools/36.0.0/dexdump}

{
    printf 'SOURCE audit/framework/services.jar\n'
    printf 'JAR_SHA256 %s\n' "$(sha256sum "$jar" | awk '{print $1}')"
    printf 'DEX audit/decompiled/services/classes.dex\n'
    printf 'DEX_SIZE %s\n' "$(stat -c %s "$dex")"
    printf 'DEX_SHA256 %s\n' "$(sha256sum "$dex" | awk '{print $1}')"
    printf 'COMMAND %s -d -n -j %s | rg -C 30 SatsService\n\n' "$dexdump_bin" "$dex"
    "$dexdump_bin" -d -n -j "$dex" 2>/dev/null \
        | rg -C 30 'SatsService|Lcom/android/server/SatsService;'
} > "$out"

printf '%s\t%s\t%s\n' \
    "${out#$root_dir/}" \
    "$(stat -c %s "$out")" \
    "$(sha256sum "$out" | awk '{print $1}')"
