#!/bin/bash
# HWBP monitor self-test. Runs on any arm64 Linux (CONFIG_COMPAT=y for the 32-bit
# cases) with root + the armhf cross-compiler. Ground-truth sentinel controls plus
# negative controls: a signal the tool cannot turn off on demand is noise.
#   arm64 single      -> sentinel present (default 8-byte s3 path)
#   arm64 worker      -> sentinel present (proves per-task arming + rescan)
#   wrong offset      -> 0 hits          (bp only fires on executed code)
#   32-bit PTR32=1    -> sentinel present (4-byte s3 read)
#   32-bit no PTR32   -> sentinel ABSENT  (8-byte read hits the 0xEE guard -> bogus)
set -uo pipefail
cd /tmp/v32
MON=./hwbp_keylog-arm64
LBL="SENTINEL_CLIENT_HANDSHAKE_TRAFFIC_SECRET"
CR="a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
SEC="c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
EXPECT="$LBL $CR $SEC"
PASS=0; FAIL=0

sym(){ readelf -sW "$1" | awk -v n="$2" '$8==n{print $2; exit}'; }
mask(){ printf '%x' $(( 0x$1 & ~1 )); }   # clear Thumb bit

echo "=== build ==="
gcc -O0 -static -no-pie -pthread -o tls64ctl tls64ctl.c || { echo BUILD64_FAIL; exit 1; }
arm-linux-gnueabihf-gcc -marm -O0 -static -no-pie -o tls32ctl tls32ctl.c || { echo BUILD32_FAIL; exit 1; }
file tls64ctl | cut -d, -f1-2; file tls32ctl | cut -d, -f1-2
sudo sysctl -w kernel.perf_event_paranoid=-1 kernel.yama.ptrace_scope=0 >/dev/null 2>&1

# runtest name bin ctlargs symname env secs expect(present|absent|zerohits)
runtest(){
  local name="$1" bin="$2" ctlargs="$3" symname="$4" env="$5" secs="$6" expect="$7"
  rm -f keys.log mon.out
  ./"$bin" $ctlargs 2>/dev/null & local CTL=$!
  sleep 1
  if ! kill -0 "$CTL" 2>/dev/null; then echo "FAIL $name: control died"; FAIL=$((FAIL+1)); return; fi
  local S; S=$(mask "$(sym "$bin" "$symname")")
  sudo env $env "$MON" "$CTL" @abs "$S" "$secs" keys.log > mon.out 2>&1
  kill "$CTL" 2>/dev/null; wait "$CTL" 2>/dev/null
  local hits; hits=$(grep -oE 'hits=[0-9]+' mon.out | head -1 | cut -d= -f2)
  local got="?"
  case "$expect" in
    present|absent) if grep -qxF "$EXPECT" keys.log 2>/dev/null; then got=present; else got=absent; fi;;
    zerohits) if [ "${hits:-x}" = "0" ]; then got=zerohits; else got="hits=${hits:-none}"; fi;;
  esac
  if [ "$got" = "$expect" ]; then echo "PASS $name  ($got, $(grep -oE 'hits=[0-9]+ .*nss_lines=[0-9]+' mon.out | head -1))"; PASS=$((PASS+1))
  else echo "FAIL $name: want $expect got $got"; grep RESULT mon.out | sed 's/^/    /'; FAIL=$((FAIL+1)); fi
}

echo "=== matrix ==="
runtest "arm64-single"     tls64ctl ""       ssl_log_secret ""                                             6 present
runtest "arm64-worker"     tls64ctl thread   ssl_log_secret ""                                             6 present
runtest "arm64-tagged-ptr" tls64ctl tag      ssl_log_secret ""                                             6 present
runtest "arm64-late-rescan" tls64ctl latethread ssl_log_secret ""                                          10 present
runtest "wrong-offset-neg" tls64ctl ""       never          ""                                             5 zerohits
runtest "32bit-ptr32"      tls32ctl ""       ssl_log_secret "DECLAW_PTR32=1 DECLAW_S3_OFF=0x18 DECLAW_CR_OFF=0x30" 6 present
runtest "32bit-noptr32-neg" tls32ctl ""      ssl_log_secret "DECLAW_S3_OFF=0x18 DECLAW_CR_OFF=0x30"        6 absent

echo "=== multi-bp (two libs in one run) ==="
rm -f keys.log mon.out
./tls64ctl multi 2>/dev/null & CTLM=$!
sleep 1
if kill -0 "$CTLM" 2>/dev/null; then
  S1=$(mask "$(sym tls64ctl ssl_log_secret)")
  V2=$(mask "$(sym tls64ctl ssl_log_secret_b)")
  BASE=$(grep -m1 tls64ctl /proc/"$CTLM"/maps | cut -d- -f1)
  OFF2=$(printf '%x' $(( 0x$V2 - 0x$BASE )))
  echo "  s1=$S1 s2=$V2 base=$BASE off2=$OFF2"
  sudo "$MON" "$CTLM" @abs "$S1" 6 keys.log "tls64ctl@$OFF2" > mon.out 2>&1
  kill "$CTLM" 2>/dev/null; wait "$CTLM" 2>/dev/null
  L1="$LBL $CR $SEC"
  CR2="101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
  SEC2="303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
  L2="SENTINEL_SERVER_HANDSHAKE_TRAFFIC_SECRET $CR2 $SEC2"
  if grep -qxF "$L1" keys.log && grep -qxF "$L2" keys.log; then
    echo "PASS multi-bp  (both sentinel lines, $(grep -oE 'bps=[0-9]+ .*nss_lines=[0-9]+' mon.out | head -1))"; PASS=$((PASS+1))
  else
    echo "FAIL multi-bp: L1=$(grep -qxF "$L1" keys.log && echo y || echo n) L2=$(grep -qxF "$L2" keys.log && echo y || echo n)"
    grep RESULT mon.out | sed 's/^/    /'; FAIL=$((FAIL+1))
  fi
else echo "FAIL multi-bp: control died"; FAIL=$((FAIL+1)); fi

echo "=== summary ==="
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && echo "MON_SELFTEST_OK" || echo "MON_SELFTEST_FAILED"
