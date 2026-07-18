# No-injection TLS key extraction via hardware breakpoints

Research prototype: pull TLS session secrets out of a running app **without
injecting anything into it**: no Frida, no gadget, no `ptrace`-attach, no inline
hook, no code patch. A separate process sets a CPU **hardware execute-breakpoint**
on BoringSSL's `ssl_log_secret` in the target and reads the secret out of the
target's memory when it fires.

Why this exists: VM-based anti-tamper (PairIP, an anti-tamper packer) crashes the
process on the first *inline* Frida hook of the TLS libraries, and also detects a
Frida agent at spawn. Every injection-based key logger dies. A hardware breakpoint
is programmed in the CPU debug registers by the kernel, so there is no code change and
nothing loaded inside the target, so PairIP's code-integrity check, its
`ptrace`-based anti-debug, and the Frida spawn-detector all see nothing.

## Requires root (important)

This technique **does not work on a stock non-rooted device**, and that is a hard
Android boundary, not a fixable detail:

- `perf_event_open(PERF_TYPE_BREAKPOINT, …, pid)` against another process, and
  `/proc/<pid>/mem` of another process, both require `ptrace_may_access()` to pass:
  same-uid or `CAP_SYS_PTRACE`. Apps run as separate uids → needs root.
- Stock Android ships `kernel.perf_event_paranoid=3` and **SELinux Enforcing**,
  which block cross-process perf/ptrace even for `su` in most domains. This rig has
  `perf_event_paranoid=-1` and SELinux `Disabled` because it is a rooted emulator.
- You cannot program arm64 debug registers from EL0 at all; it always goes through
  the kernel (perf or ptrace), which is privileged/paranoid-gated.

So in declaw terms this is a **rooted / emulator-tier** capability (the strongest
capture when you have root and the app defeats every injection method). declaw's
**non-rooted** path against anti-tamper stays static `.so` repackaging.

## How it works

1. Find `ssl_log_secret` in the target's BoringSSL. It is stripped/internal, so
   locate it structurally: the `CLIENT_RANDOM` rodata string → its xref site → the
   following `bl ssl_log_secret`. Version-independent, no fixed offset. In the
   redroid system libssl (`/system/lib64/libssl.so`, Android 11) it is at file
   offset `0x3038c`.
2. For every thread in `/proc/<pid>/task`, `perf_event_open` a `HW_BREAKPOINT_X`
   at `base + offset` with `PERF_SAMPLE_REGS_USER` masking `x0..x3`, and mmap the
   sample ring. HW breakpoints are **per-task** (debug registers swap per thread at
   context switch), so arming only the main pid catches nothing, since apps run TLS on
   worker threads. Rescan for new threads.
3. On each hit the ring yields `x0=SSL*, x1=label, x2=secret ptr, x3=len`. Read the
   label and secret from the target via `/proc/<pid>/mem`.
4. `client_random` (for the NSS line) = `*(u8*)( *(u64*)(ssl+0x30) + 0x30 )`, 32
   bytes, RE'd from `ssl_log_secret`'s own keylog formatter, so it is the exact
   source BoringSSL would emit. Write standard NSS Key Log lines.

**Android pointer tagging gotcha:** heap pointers come back tagged in the top byte
(`0xb4…`, TBI/Scudo). The CPU ignores the tag on access, but `/proc/pid/mem` needs
the untagged VA: `addr & 0x00ffffffffffffff`. Until masked, the label reads (rodata,
untagged) but every heap read (secret, client_random) fails.

## Files

| file | what |
|---|---|
| `hwbp_keylog.c` | the extractor: multi-thread HWBP monitor → NSS keylog |
| `xhwbp.c` | proves cross-process HWBP + register capture on this kernel |
| `pe_test.c` | proves self-process HWBP (the original feasibility probe) |
| `busy.c` | discriminator: HWBP fires on a pre-existing external process |
| `tls_selftest.c` | controlled BoringSSL handshake target (needs a bionic toolchain to build; unused on this rig) |
| `tls32ctl.c` | controlled AArch32 target with sentinel r0..r3; proves the PTR32 path (see 32-bit section) |
| `tls64ctl.c` | controlled arm64 target (single + worker-thread modes) with a `never()` decoy |
| `mon_selftest.sh` | monitor self-test: ground-truth + negative controls (run on an arm64 Linux, root) |
| `kl_cronet.sh` / `kl_gms.sh` / `kl_netstack.sh` | device drivers for real targets |

Build (arm64): `aarch64-linux-gnu-gcc -O0 -static -o hwbp_keylog hwbp_keylog.c`
Run in redroid (root): `adb -s localhost:5555 shell '/data/local/tmp/hwbp_keylog <pid> /system/lib64/libssl.so 3038c 45'`

## Status

Proven on the rig against a **live, unmodified, uninjected cronet app**: the monitor
extracts real TLS 1.3 secrets with correct BoringSSL labels
(`CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_…`, `CLIENT_TRAFFIC_SECRET_0`, …) and
full NSS keylog lines including `client_random`, all read out of the app's memory with
zero injection.

Not yet done: application to the PairIP-hardened app specifically (it bundles its own BoringSSL, so
re-RE `ssl_log_secret` in *its* lib via the same `CLIENT_RANDOM`-xref method; plus
login-gated traffic).

## 32-bit (armv7) targets

The arm64 monitor also handles a 32-bit target, where
friTap's 32-bit agent faults. The breakpoint and register capture are unchanged
(`x0..x3` alias `r0..r3`), so only the `SSL->s3` pointer read differs: 4 bytes,
and the field offset moves. Set `DECLAW_PTR32=1` plus the 32-bit offsets.

Known offsets for the Android 11 system BoringSSL (`/system/lib/libssl.so`,
Thumb): `ssl_log_secret @ 0x1f13c`, `s3 = *(ssl+0x18)`, `client_random = s3+0x30`.
declaw sets `DECLAW_PTR32=1 DECLAW_S3_OFF=0x18 DECLAW_CR_OFF=0x30` automatically
when the target maps `/system/lib/` (a 32-bit process).

Manual run against a 32-bit app:
```
DECLAW_PTR32=1 DECLAW_S3_OFF=0x18 DECLAW_CR_OFF=0x30 \
  hwbp_keylog <pid> /system/lib/libssl.so 1f13c 45 keys.log
```

The r2 finder is arm64-only (ARM uses PC-relative literal pools, not adrp/add), so
the 32-bit `ssl_log_secret` offset comes from BoringSecretHunter or Ghidra, not from
`find_ssl_log_secret.sh`.

**Status: the PTR32 mechanism is proven end-to-end (2026-07-06).** `tls32ctl.c` is a
controlled AArch32 target: it calls the real `ssl_log_secret(SSL*, label, secret, len)`
ABI with distinct sentinel bytes in r0..r3 (r0 → fake SSL whose `*(ssl+0x18)` s3 pointer
chains to a known `client_random`, r1 → label, r2 → secret, r3 → len). Built with
`arm-linux-gnueabihf-gcc -marm -O0 -static -no-pie` and run on an arm64 Linux with
`CONFIG_COMPAT=y`, the arm64 monitor armed with `DECLAW_PTR32=1 DECLAW_S3_OFF=0x18`
recovered the complete NSS line matching **all** sentinels (label + client_random +
secret). That confirms the two things a 32-bit target changes: `PERF_SAMPLE_REGS_USER`
x0..x3 alias r0..r3 on a compat task, and the 4-byte s3 pointer read is correct.

Still not proven (rig-blocked): a live Android-app decrypt, the `0x1f13c` offset in a
real libssl, and declaw CLI auto-routing against a real 32-bit app.

**declaw CLI route for 32-bit / bundled BoringSSL.** `declaw --hwbp-capture` resolves
each mapped lib's `ssl_log_secret` offset via the sha256 cache then the r2 finder, but
the finder is arm64-only, so on a 32-bit or bundled-BoringSSL lib it returns nothing and
(previously) the breakpoint was silently dropped, yielding 0 keys with no reason. It now
logs an actionable error and takes an offset override: get the offset from
BoringSecretHunter/Ghidra and pass `DECLAW_HWBP_OFFSETS=libssl.so@1f13c` (comma-separate
per lib, e.g. `...,libttboringssl.so@49d214` for a vendored BoringSSL). declaw still auto-sets
`DECLAW_PTR32` for the 32-bit case. This is unit-tested (`tests/test_analyze.py`
`test_offset_override`); end-to-end against a live 32-bit app stays unproven pending a
working arm64 Android env.

Reproduce (on any arm64 Linux with the armhf cross-compiler and root):
```
arm-linux-gnueabihf-gcc -marm -O0 -static -no-pie -o tls32ctl tls32ctl.c
./tls32ctl &                       # note pid; prints &ssl_log_secret
SYM=$(readelf -sW tls32ctl | awk '$8=="ssl_log_secret"{print $2;exit}')
sudo sysctl -w kernel.perf_event_paranoid=-1 kernel.yama.ptrace_scope=0
sudo DECLAW_PTR32=1 DECLAW_S3_OFF=0x18 DECLAW_CR_OFF=0x30 \
  ./hwbp_keylog-arm64 <pid> @abs $SYM 12 keys.log
# keys.log line == label + client_random(a0..bf) + secret(c0..df)
```

## Monitor self-test

`mon_selftest.sh` exercises the monitor against controlled targets with known
sentinel bytes, including negative controls (a signal you cannot turn off is noise).
On an arm64 Linux with root + the armhf cross-compiler it runs 5 cases, all green:

| case | expect | proves |
|---|---|---|
| arm64 single | sentinel present | default 8-byte s3 path (control, not just a live cronet app) |
| arm64 worker-thread | sentinel present | per-task arming + rescan (call is on a worker tid, not main) |
| arm64 tagged pointers | sentinel present | UNTAG mask on r0/r1/r2 + in-memory s3 (TBI/Scudo top-byte) |
| arm64 late thread | sentinel present | periodic rescan catches a worker spawned mid-capture |
| multi-bp (two entry points) | both sentinel lines | two breakpoints armed in one process both fire (system libssl + cronet + bundled in one run) |
| wrong offset (`never()`) | 0 hits | breakpoint fires only on executed code, no fabrication |
| 32-bit `DECLAW_PTR32=1` | sentinel present | 4-byte s3 read correct |
| 32-bit without `DECLAW_PTR32` | sentinel **absent** | 27 hits but 0 keys: the 8-byte read hits a `0xEE` guard, so PTR32 is load-bearing |

## Real BoringSSL validation (ground truth)

`mon_selftest.sh` uses sentinel bytes to prove the capture mechanism. `hwbp_real_test.sh`
goes further: `tls_keylog_loop.c` runs real TLS 1.3 handshakes (to 1.1.1.1:443) against a
from-source BoringSSL and logs BoringSSL's OWN keys via `SSL_CTX_set_keylog_callback`. The
monitor, armed on that process with zero injection (real declaw mode: lib-substring +
file offset, not `@abs`), then extracts keys independently. Result (2026-07-06): every
HWBP-extracted line matched BoringSSL's own keylog byte-for-byte, label + client_random +
secret (e.g. `CLIENT_HANDSHAKE_TRAFFIC_SECRET a12445…`), 3/3, no false keys. So the
no-injection extraction reads the real secrets, validated against BoringSSL's own output
rather than an assertion, and reproducibly, without the redroid rig.

## Prior art / why this is different

Every published Android TLS key extractor injects or `ptrace`-attaches, and both are
detectable by VM/anti-tamper protection (PairIP):

- [friTap](https://github.com/fkie-cad/friTap): Frida inject + BoringSSL hook. Frida's
  spawn-detector and code-integrity checks catch it; it dies on PairIP.
- [DroidKex](https://dfrws.org/presentation/droidkex-fast-extraction-of-ephemeral-tls-keys-from-the-memory-of-android-apps/),
  TLSkex, TeLeScope (academic): `ptrace`-attach + pointer-path memory reconstruction.
- [tlsdump](https://github.com/blechschmidt/tlsdump): `ptrace` syscall-hooking, pause
  the target, read memory. Closest OSS design to this monitor, but it attaches.

`ptrace`-attach sets `TracerPid` in `/proc/<pid>/status` and consumes the single tracer
slot, so PairIP's anti-ptrace / `TracerPid` checks see it. This monitor instead programs
the CPU debug register via `perf_event_open(PERF_TYPE_BREAKPOINT)` from a separate process
and reads `/proc/<pid>/mem`: **no injected code, no `TracerPid`, no tracer-slot use, and no
userspace-visible debug-register state** (EL0 can't read the debug regs). A perf-programmed
HW breakpoint is also invisible to the usual `PTRACE_POKEUSER`-debugreg anti-debug hooks.
Breaking at `ssl_log_secret`'s entry also beats in-memory key obfuscation (the value is
live in a register at the call), which the memory-scrapers above cannot handle.

A bounded search (~7 targeted queries, 2026-07) found no tool doing perf-HWBP TLS
extraction on Android. The novelty is the **application/packaging** (perf HW breakpoints are
old), it **requires root** (perf_event_paranoid + `ptrace_may_access` for cross-process), and
"no prior art" means none found, not proof of global absence. Demonstrated live against
The PairIP-hardened app this session: the external breakpoint armed and the app kept running, its anti-frida
never fired, where a friTap inject had killed it in ~15s.
