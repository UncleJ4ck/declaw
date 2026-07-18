#!/bin/bash
# HWBP monitor vs REAL BoringSSL handshake. The no-injection monitor must extract
# the same secrets BoringSSL emits via its own keylog callback (ground truth).
# Uses the real declaw resolution mode: lib substring + file offset (not @abs).
set -uo pipefail
cd /tmp/mitm
MON=/tmp/v32/hwbp_keylog-arm64
LIBSSL=$(find /tmp/v32/boringssl/build -name 'libssl.so' | head -1)
LIBCRYPTO=$(find /tmp/v32/boringssl/build -name 'libcrypto.so' | head -1)
LIBDIR=$(dirname "$LIBSSL")
INC=/tmp/v32/boringssl/include

[ -f cert.pem ] || openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1

echo "=== ssl_log_secret -> file offset ==="
VADDR=$(nm "$LIBSSL" | awk '$3 ~ /ssl_log_secretE?$/ {print $1; exit}')
[ -z "$VADDR" ] && VADDR=$(nm "$LIBSSL" | grep -iE 'ssl_log_secret' | awk '{print $1; exit}')
FOFF=$(python3 - "$LIBSSL" "$VADDR" <<'PY'
import sys, subprocess
lib, vaddr = sys.argv[1], int(sys.argv[2], 16)
out = subprocess.check_output(['readelf', '-lW', lib]).decode()
for line in out.splitlines():
    p = line.split()
    if len(p) >= 6 and p[0] == 'LOAD':
        o, va, msz = int(p[1], 16), int(p[2], 16), int(p[5], 16)
        if va <= vaddr < va + msz:
            print(hex(vaddr - va + o)[2:]); break
PY
)
echo "ssl_log_secret vaddr=0x$VADDR file_offset=0x$FOFF"

echo "=== build loop client ==="
cc -O0 -o tls_keylog_loop tls_keylog_loop.c -I"$INC" -L"$LIBDIR" -lssl -lcrypto || { echo BUILD_FAIL; exit 1; }

echo "=== loop client -> real TLS1.3 endpoint 1.1.1.1:443 (always up) ==="
rm -f client_keys.log hwbp_keys.log
LD_LIBRARY_PATH="$LIBDIR" ./tls_keylog_loop 443 /tmp/mitm/client_keys.log 1.1.1.1 2>/dev/null & CLI=$!
sleep 3
kill -0 "$CLI" 2>/dev/null || { echo CLIENT_DIED; exit 1; }
echo "  client handshakes so far (callback lines): $(wc -l < client_keys.log)"

echo "=== arm HWBP monitor on libssl.so@$FOFF (lib-substr mode, arm64 defaults) ==="
sudo sysctl -w kernel.perf_event_paranoid=-1 kernel.yama.ptrace_scope=0 >/dev/null 2>&1
sudo "$MON" "$CLI" libssl.so "$FOFF" 12 /tmp/mitm/hwbp_keys.log 2>&1 | grep -E 'RESULT|bp\[' | sed 's/^/  /'
kill "$CLI" 2>/dev/null; pkill -f 's_server -accept 4444' 2>/dev/null || true

echo "=== compare (ground truth = BoringSSL's own keylog callback) ==="
echo "  client_keys(callback): $(wc -l < client_keys.log) lines   hwbp_keys: $(wc -l < hwbp_keys.log) lines"
# HWBP full lines that also appear in the callback log (label + client_random + secret)
FULL=$(grep -Fxf client_keys.log hwbp_keys.log | wc -l)
# register-only match (label + secret), robust to any s3/client_random offset diff
awk '{print $1, $3}' client_keys.log | sort -u > _cbk_ls.txt
awk '{print $1, $3}' hwbp_keys.log   | sort -u > _hwbp_ls.txt
LS=$(comm -12 _cbk_ls.txt _hwbp_ls.txt | wc -l)
HWBP_LS=$(wc -l < _hwbp_ls.txt)
echo "  HWBP full-line matches in callback log: $FULL"
echo "  HWBP (label+secret) pairs also in callback: $LS / $HWBP_LS"
echo "  sample HWBP line: $(head -1 hwbp_keys.log)"
if [ "$HWBP_LS" -gt 0 ] && [ "$LS" -eq "$HWBP_LS" ]; then
  echo "HWBP_REAL_OK: every HWBP-extracted secret matches BoringSSL's own keylog (real keys, zero injection)"
  [ "$FULL" -eq "$(wc -l < hwbp_keys.log)" ] && echo "  (client_random also matches -> s3/cr offsets 0x30/0x30 correct for this build)" || echo "  (client_random differs -> s3/cr offset is per-build; label+secret via registers are exact)"
else
  echo "HWBP_REAL_FAILED: HWBP secrets do not all match the callback"
fi