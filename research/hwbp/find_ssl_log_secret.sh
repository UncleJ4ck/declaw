#!/bin/bash
# Locate ssl_log_secret's file offset in a BoringSSL .so via the CLIENT_RANDOM
# rodata label: every xref to it is a caller that loads it into x1 and `bl`s
# ssl_log_secret a few instructions later; take the first call target after each
# xref, the one that shows from the most sites is ssl_log_secret.
#
# SCOPE: arm64 only. It relies on the adrp/add string-load pattern, so it does NOT
# work on 32-bit ARM (PC-relative literal pools) or other arches. For multi-arch
# locating use BoringSecretHunter (fkie-cad), the Ghidra tool this reimplements the
# idea of: https://github.com/monkeywave/BoringSecretHunter . declaw uses this
# lightweight r2 port for the arm64 fast path and defers to BoringSecretHunter /
# Ghidra for 32-bit and bundled libs.
#
# Usage: find_ssl_log_secret.sh <libssl.so>   (arm64 only)
set -uo pipefail
LIB="${1:?usage: find_ssl_log_secret.sh <libssl.so>}"
command -v r2 >/dev/null || { echo "need radare2"; exit 1; }
command -v jq >/dev/null || { echo "need jq"; exit 1; }

STR=$(r2 -q -c 'izzq~CLIENT_RANDOM' "$LIB" 2>/dev/null | awk '{print $1}' | head -1)
[ -z "${STR:-}" ] && { echo "no CLIENT_RANDOM string (not a keylog-capable BoringSSL?)"; exit 2; }

# xref sites that load the string (field 2 of axt)
XREFS=$(r2 -q -c "aaa 2>/dev/null; axt @ $STR" "$LIB" 2>/dev/null \
        | sed 's/\x1b\[[0-9;]*m//g' | awk '{print $2}' | grep '^0x')
[ -z "$XREFS" ] && { echo "no xref to CLIENT_RANDOM (unanalyzable?)"; exit 3; }

for X in $XREFS; do
  r2 -q -c "aaa 2>/dev/null; s $X; pdj 12" "$LIB" 2>/dev/null \
    | jq -r '.[] | select(.type=="call") | .jump' 2>/dev/null | head -1
done | grep -E '^[0-9]+$' | sort | uniq -c | sort -rn | \
while read -r cnt addr; do
  printf "0x%x  (ssl_log_secret, from %s CLIENT_RANDOM call site(s))\n" "$addr" "$cnt"
done
