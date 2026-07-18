#!/usr/bin/env bash
# Host-side proof of the mempatch PRIMITIVE (portable, no Android/arm64 needed): a process
# writes the ssl_verify_ok stub into ANOTHER process's read-only executable page via
# /proc/pid/mem, and the backing file on disk stays byte-identical. This validates the
# mechanism hwbp_mempatch.c uses; the arm64 binary is the same logic recompiled, and the
# SELinux-on-a-real-device leg is the only part this cannot cover.
#
# Run: bash research/hwbp/mempatch_selftest.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'kill "${CPID:-0}" 2>/dev/null; rm -rf "$TMP"' EXIT
fail=0
STUB=00008052c0035fd6   # mov w0,#0 ; ret (LE)

# native build of the real tool
gcc -O2 -Wall -o "$TMP/mempatch" "$HERE/hwbp_mempatch.c" || { echo "FAIL build tool"; exit 1; }

# a child that maps a file r-x (MAP_PRIVATE) and holds it, opting any same-user tracer in
cat > "$TMP/child.c" <<'C'
#include <sys/mman.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
int main(int argc, char **argv) {
    prctl(PR_SET_PTRACER, (unsigned long)-1, 0, 0, 0);
    int fd = open(argv[1], O_RDONLY);
    void *p = mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    printf("%d %p\n", getpid(), p); fflush(stdout);
    for (;;) sleep(1);
}
C
gcc -O2 -o "$TMP/child" "$TMP/child.c" || { echo "FAIL build child"; exit 1; }

head -c 4096 /dev/zero | tr '\0' '\252' > "$TMP/libssltest.so"   # 4096 x 0xAA
before=$(head -c8 "$TMP/libssltest.so" | xxd -p)

"$TMP/child" "$TMP/libssltest.so" & CPID=$!
sleep 0.5

if "$TMP/mempatch" "$CPID" libssltest 0x0 | grep -q " OK"; then
    echo "PASS tool reports a verified /proc/pid/mem write to the r-x page"
else
    echo "FAIL mempatch did not verify"; fail=1
fi

after=$(head -c8 "$TMP/libssltest.so" | xxd -p)
[ "$before" = "$after" ] && echo "PASS backing file unchanged on disk (zero footprint)" \
    || { echo "FAIL file changed: $before -> $after"; fail=1; }

live=$(python3 - "$CPID" <<'PY'
import sys
pid = sys.argv[1]
base = None
for l in open(f"/proc/{pid}/maps"):
    if "libssltest" in l and "r-x" in l:
        base = int(l.split("-")[0], 16); break
with open(f"/proc/{pid}/mem", "rb", 0) as f:
    f.seek(base); print(f.read(8).hex())
PY
)
[ "$live" = "$STUB" ] && echo "PASS live memory now holds the stub ($live)" \
    || { echo "FAIL live memory not patched: $live"; fail=1; }

echo "mempatch_selftest: $([ $fail = 0 ] && echo PASS || echo FAIL)"
exit $fail
