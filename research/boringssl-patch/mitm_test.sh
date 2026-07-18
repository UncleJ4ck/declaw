#!/bin/bash
# Validates declaw's static ssl_verify_peer_cert patch end-to-end against a real
# from-source BoringSSL, with a built-in negative control:
#   unpatched libssl.so  -> client REJECTS a self-signed cert (verification works)
#   patched   libssl.so  -> client ACCEPTS it (declaw MITM bypass)
set -uo pipefail
BSSL=/tmp/v32/boringssl
BUILD=$BSSL/build
INC=$BSSL/include
cd /tmp/mitm

LIBSSL=$(find "$BUILD" -name 'libssl.so' | head -1)
LIBCRYPTO=$(find "$BUILD" -name 'libcrypto.so' | head -1)
echo "libssl=$LIBSSL"
echo "libcrypto=$LIBCRYPTO"
[ -z "$LIBSSL" ] || [ -z "$LIBCRYPTO" ] && { echo NO_LIBS; exit 1; }

echo "=== [1] self-signed server cert ==="
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1
echo "cert bytes: $(stat -c%s cert.pem)"

echo "=== [2] locate ssl_verify_peer_cert -> file offset ==="
# BoringSSL is C++ -> the symbol is mangled: bssl::ssl_verify_peer_cert(SSL_HANDSHAKE*)
VADDR=$(nm "$LIBSSL" 2>/dev/null | awk '$3 ~ /^_ZN4bssl20ssl_verify_peer_certE/{print $1; exit}')
[ -z "$VADDR" ] && { echo NO_SYMBOL; exit 1; }
FOFF=$(python3 - "$LIBSSL" "$VADDR" <<'PY'
import sys, subprocess
lib, vaddr = sys.argv[1], int(sys.argv[2], 16)
out = subprocess.check_output(['readelf', '-lW', lib]).decode()
for line in out.splitlines():
    p = line.split()
    if len(p) >= 6 and p[0] == 'LOAD':
        o, va, msz = int(p[1], 16), int(p[2], 16), int(p[5], 16)
        if va <= vaddr < va + msz:
            print(hex(vaddr - va + o)); break
PY
)
echo "ssl_verify_peer_cert vaddr=0x$VADDR file_offset=$FOFF"
[ -z "$FOFF" ] && { echo NO_OFFSET; exit 1; }

echo "=== [3] build client against BoringSSL ==="
LIBDIR=$(dirname "$LIBSSL")
cc -O0 -o tls_verify_client tls_verify_client.c -I"$INC" -L"$LIBDIR" -lssl -lcrypto || { echo BUILD_FAIL; exit 1; }

echo "=== [4] make unpatched + patched libssl copies ==="
rm -rf unpatched patched; mkdir unpatched patched
cp "$LIBSSL" "$LIBCRYPTO" unpatched/
cp "$LIBSSL" "$LIBCRYPTO" patched/
# patch the copy with DECLAW's real machinery
python3 - "$FOFF" <<'PY'
import sys
sys.path.insert(0, '/tmp/v32')
from boringssl_patch import patch_ssl_verify_peer_cert, verify_patch, STUB_ASM
off = int(sys.argv[1], 0)
patch_ssl_verify_peer_cert('patched/libssl.so', off)
print("declaw patch applied @", hex(off), "verify_patch=", verify_patch('patched/libssl.so', off), "(", STUB_ASM, ")")
PY
echo "patched bytes @ $FOFF: $(python3 -c "print(open('patched/libssl.so','rb').read()[$FOFF:$FOFF+8].hex())")"
echo "  (expect 000080 52 c003 5fd6 = mov w0,#0 ; ret)"

echo "=== [5] start server (openssl s_server, self-signed) ==="
pkill -f 's_server -accept 4443' 2>/dev/null || true
( openssl s_server -accept 4443 -cert cert.pem -key key.pem -quiet -naccept 4 >/dev/null 2>&1 & )
sleep 1

PASS=0; FAIL=0
echo "=== [6] BASELINE: unpatched must REJECT ==="
OUT=$(LD_LIBRARY_PATH=unpatched ./tls_verify_client 4443 2>&1); echo "  $OUT"
if echo "$OUT" | grep -q HANDSHAKE_FAIL; then echo "  PASS baseline rejects self-signed cert"; PASS=$((PASS+1))
else echo "  FAIL baseline should have rejected"; FAIL=$((FAIL+1)); fi

echo "=== [7] PATCHED: declaw patch must ACCEPT (MITM bypass) ==="
OUT=$(LD_LIBRARY_PATH=patched ./tls_verify_client 4443 2>&1); echo "  $OUT"
if echo "$OUT" | grep -q HANDSHAKE_OK; then echo "  PASS declaw patch accepts bad cert -> MITM bypass proven"; PASS=$((PASS+1))
else echo "  FAIL patch did not bypass verification"; FAIL=$((FAIL+1)); fi

pkill -f 's_server -accept 4443' 2>/dev/null || true
echo "=== summary: PASS=$PASS FAIL=$FAIL ==="
[ "$FAIL" -eq 0 ] && echo "MITM_TEST_OK" || echo "MITM_TEST_FAILED"
