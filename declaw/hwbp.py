"""declaw.hwbp — root-tier, zero-injection TLS key capture via hardware breakpoints.

A separate root process sets an arm64 hardware execute-breakpoint on BoringSSL's
``ssl_log_secret`` in the target and reads the secret + client_random out of
``/proc/pid/mem``. Nothing is injected into the app: no frida, no gadget, no
ptrace-attach, no code patch. So anti-tamper (PairIP) frida-detection, ptrace
anti-debug, and code-integrity checks are all blind to it. This is the capture
mode for apps that defeat every injection method.

Hard requirements, stated loud because they are not negotiable:
  * root  - cross-process ``perf_event_open`` and ``/proc/pid/mem`` need
            CAP_SYS_PTRACE; stock non-rooted Android cannot do this.
  * arm64 - the breakpoint programs the arm64 CPU debug registers.
  * a permissive kernel - ``perf_event_paranoid`` low enough and (on real
            devices) SELinux not blocking cross-process perf. Rooted emulators
            (redroid) and rooted devices with a permissive policy qualify.

Proven on live, unmodified apps (see research/hwbp/). Extraction is passive:
you must DRIVE the app during the window to make it handshake.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess as sp
import time
from pathlib import Path
from typing import Optional

from declaw.config import UTILS_DIR, log, safe_pkg

# A mapped library path from /proc/<pid>/maps is attacker-influenceable: an app can
# dlopen a .so from any path it controls, so a malicious target could map a
# BoringSSL-named lib at e.g. /data/data/evil/files/libssl;id.so. Those paths get
# spliced into root shell commands (the cat pull and the monitor sh -c), so anything
# outside this set (no space, ; | $ ` ( ) & < > quotes) is rejected before it reaches
# a shell. Legit Android .so paths only use these characters (/data/app/~~a==/b==/lib..).
_SAFE_LIB_PATH = re.compile(r"^[\w./~=@:+-]+$")

MONITOR_BIN = UTILS_DIR / "hwbp_keylog-arm64"
MEMPATCH_BIN = UTILS_DIR / "hwbp_mempatch-arm64"
DEVICE_MEMPATCH = "/data/local/tmp/declaw_mempatch"
RAWCAP_BIN = UTILS_DIR / "rawcap-arm64"
FINDER = UTILS_DIR / "find_ssl_log_secret.sh"
OFFSET_CACHE = UTILS_DIR / "hwbp_offsets.json"
DEVICE_MON = "/data/local/tmp/declaw_hwbp"
DEVICE_KEYS = "/data/local/tmp/declaw_hwbp_keys.log"
DEVICE_RAWCAP = "/data/local/tmp/declaw_rawcap"
DEVICE_PCAP = "/data/local/tmp/declaw_hwbp.pcap"

# Library basenames that carry a BoringSSL an app's real traffic tends to use,
# most-preferred first. Bundled BoringSSL is where hard apps (cronet, custom net
# stacks) route; system libssl is the OkHttp/Conscrypt fallback.
_TLS_LIB_PREFERENCE = (
    "libttboringssl.so", "libcronet", "libboringssl", "boringssl",
    "libssl.so",
)


def _adb(serial: Optional[str], *args: str, timeout: int = 60) -> sp.CompletedProcess:
    base = ["adb"] + (["-s", serial] if serial else [])
    return sp.run(base + list(args), capture_output=True, text=True, timeout=timeout)


def _sh(serial: Optional[str], cmd: str, timeout: int = 60) -> str:
    return _adb(serial, "shell", cmd, timeout=timeout).stdout


def _root_prefix(serial: Optional[str]) -> Optional[str]:
    """Return the shell prefix that yields uid 0 ('' if already root, 'su 0 ' if
    su gives root), or None if root is unavailable."""
    if "uid=0" in _sh(serial, "id"):
        return ""
    if "uid=0" in _sh(serial, "su 0 id"):
        return "su 0 "
    return None


def _device_abi(serial: Optional[str]) -> str:
    return _sh(serial, "getprop ro.product.cpu.abi").strip()


def _pid_of(serial: Optional[str], pkg: str) -> str:
    out = _sh(serial, f"pidof {pkg}").strip()
    return out.split(" ")[0] if out else ""


def _launch(serial: Optional[str], pkg: str) -> None:
    """Start the app's launcher activity. `am start -n <activity>` is more reliable
    than monkey under TCG; fall back to monkey if the activity does not resolve."""
    out = _sh(serial, f"cmd package resolve-activity --brief {pkg}").strip().splitlines()
    act = out[-1].strip() if out else ""
    if "/" in act and " " not in act:
        _sh(serial, f"am start -n {act}")
    else:
        _sh(serial, f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1")


def _launch_wait(serial: Optional[str], pkg: str, *, tries: int = 3, per_try_s: int = 12) -> str:
    """Launch and wait for a pid, retrying the launch itself (cold start flakes
    under TCG). Returns the pid or ''."""
    for attempt in range(tries):
        _launch(serial, pkg)
        for _ in range(per_try_s * 5):        # poll every 0.2s
            pid = _pid_of(serial, pkg)
            if pid:
                return pid
            time.sleep(0.2)
        log.warning("hwbp: %s did not start (attempt %d/%d), retrying launch", pkg, attempt + 1, tries)
    return ""


def _ensure_running(serial: Optional[str], pkg: str) -> str:
    return _pid_of(serial, pkg) or _launch_wait(serial, pkg)


def _tls_libs(serial: Optional[str], pid: str, rp: str) -> list[str]:
    """Distinct BoringSSL-bearing lib paths mapped in the target, preference-ordered."""
    maps = _sh(serial, f"{rp}cat /proc/{pid}/maps")
    seen: dict[str, None] = {}
    for line in maps.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        path = parts[5]
        low = path.lower()
        if low.endswith(".so") and any(k in low for k in ("ssl", "cronet", "boringssl")):
            if not _SAFE_LIB_PATH.match(path):
                log.warning("hwbp: ignoring mapped lib with an unsafe path "
                            "(shell-metacharacter injection guard): %r", path)
                continue
            seen.setdefault(path, None)
    def rank(p: str) -> int:
        low = p.lower()
        for i, k in enumerate(_TLS_LIB_PREFERENCE):
            if k in low:
                return i
        return len(_TLS_LIB_PREFERENCE)
    return sorted(seen, key=rank)


def _apk_native_maps(serial: Optional[str], pid: str, rp: str) -> bool:
    """True if the target executes native code straight from an uncompressed APK
    (android:extractNativeLibs=false), so /proc/pid/maps shows an r-xp .apk mapping
    instead of a .so path. Its bundled BoringSSL is then invisible to a .so-name scan."""
    maps = _sh(serial, f"{rp}cat /proc/{pid}/maps")
    for line in maps.splitlines():
        parts = line.split()
        if len(parts) >= 6 and "x" in parts[1] and parts[5].endswith(".apk"):
            return True
    return False


def _is_32bit_proc(serial: Optional[str], pid: str, rp: str) -> bool:
    """Process bitness from the target's own maps, not a single lib path. A 64-bit
    process maps the 64-bit linker / lib64; only a genuinely 32-bit process maps the
    32-bit linker. Deciding from one lib path can false-positive on a 64-bit app that
    drops a lib under a ``/lib/`` data path, which would force a 4-byte pointer read
    and yield garbage client_random."""
    maps = _sh(serial, f"{rp}cat /proc/{pid}/maps")
    if "/linker64" in maps or "/lib64/" in maps or "/bin/app_process64" in maps:
        return False
    if "/system/bin/linker" in maps or "/bin/app_process32" in maps:
        return True
    return False  # default to 64-bit (the modern case) when maps are inconclusive


def _load_cache() -> dict:
    try:
        return json.loads(OFFSET_CACHE.read_text())
    except Exception:
        return {}


def _offset_override(lib_path: str, spec: str) -> Optional[str]:
    """Resolve ssl_log_secret's offset for lib_path from a manual spec string.

    Spec is comma-separated ``lib-substring@hexoffset`` items, e.g.
    ``libssl.so@1f13c,libttboringssl.so@49d214``. The first item whose substring
    is in lib_path wins. This is the escape hatch for libs the arm64-only r2
    finder can't locate (32-bit/ARM literal pools, a vendored bundled BoringSSL):
    get the offset from BoringSecretHunter/Ghidra and pass it here. Returns the
    hex offset (``0x``-prefixed) or None.
    """
    for item in spec.split(","):
        item = item.strip()
        if "@" not in item:
            continue
        sub, off = item.rsplit("@", 1)
        sub, off = sub.strip(), off.strip()
        if sub and off and sub in lib_path:
            return off if off.startswith("0x") else "0x" + off
    return None


def _resolve_offset(serial: Optional[str], lib_path: str, rp: str, out_dir: Path) -> Optional[str]:
    """Offset of ssl_log_secret in lib_path. Manual DECLAW_HWBP_OFFSETS override
    first, then sha256 cache, then the arm64-only r2 finder; None if none work."""
    spec = os.environ.get("DECLAW_HWBP_OFFSETS", "").strip()
    if spec:
        ov = _offset_override(lib_path, spec)
        if ov:
            log.info("hwbp: %s offset %s (DECLAW_HWBP_OFFSETS override)",
                     Path(lib_path).name, ov)
            return ov
    local = out_dir / ("_" + lib_path.replace("/", "_"))
    # exec-out preserves the binary stream (adb shell would mangle CRLF).
    with open(local, "wb") as fh:
        sp.run(["adb"] + (["-s", serial] if serial else []) +
               ["exec-out", f"{rp}cat {shlex.quote(lib_path)}"], stdout=fh, timeout=300)
    if local.stat().st_size == 0:
        log.warning("hwbp: could not pull %s (0 bytes)", lib_path)
        return None
    import hashlib
    digest = hashlib.sha256(local.read_bytes()).hexdigest()
    cache = _load_cache()
    if digest in cache:
        log.info("hwbp: %s offset %s (cached)", Path(lib_path).name, cache[digest])
        return cache[digest]
    # unknown lib: run the generic finder (needs r2 + jq on host)
    if not FINDER.exists():
        log.warning("hwbp: finder missing and %s not cached", Path(lib_path).name)
        return None
    try:
        out = sp.run(["bash", str(FINDER), str(local)], capture_output=True, text=True, timeout=300)
    except Exception as exc:
        log.warning("hwbp: finder failed (%s). Is radare2+jq installed?", exc)
        return None
    off = ""
    for line in out.stdout.splitlines():
        line = line.strip()
        if line.startswith("0x"):
            off = line.split()[0]
            break
    if not off:
        log.warning(
            "hwbp: could not locate ssl_log_secret in %s. The r2 finder is "
            "arm64-only (ARM/32-bit use PC-relative literal pools). Get the "
            "offset from BoringSecretHunter or Ghidra and supply it: "
            "DECLAW_HWBP_OFFSETS=%s@<hexoff> (repeat comma-separated per lib).",
            Path(lib_path).name, Path(lib_path).name)
        return None
    cache[digest] = off
    try:
        OFFSET_CACHE.write_text(json.dumps(cache, indent=2) + "\n")
    except Exception:
        pass
    log.info("hwbp: %s offset %s (found via CLIENT_RANDOM xref)", Path(lib_path).name, off)
    return off


def run_hwbp_capture(package: str, serial: Optional[str], out_dir: Path, *,
                     seconds: int = 60, refresh: bool = False) -> int:
    pkg = safe_pkg(package.removeprefix("package:").strip())
    out_dir.mkdir(parents=True, exist_ok=True)

    rp = _root_prefix(serial)
    if rp is None:
        log.error("hwbp-capture needs ROOT (cross-process perf_event_open + "
                  "/proc/pid/mem). This device is not rooted. Use the repackage "
                  "path (declaw <pkg>) for non-rooted devices.")
        return 5
    # perf_event_open on another task needs a permissive gate; reboots reset it.
    _sh(serial, f"{rp}sh -c 'echo -1 > /proc/sys/kernel/perf_event_paranoid' 2>/dev/null")
    abi = _device_abi(serial)
    if "arm64" not in abi:
        log.error("hwbp-capture is arm64-only; device arch is %s.", abi or "unknown")
        return 5
    if not MONITOR_BIN.exists():
        log.error("hwbp: prebuilt monitor missing at %s "
                  "(build: aarch64-linux-gnu-gcc -O2 -static -o %s research/hwbp/hwbp_keylog.c)",
                  MONITOR_BIN, MONITOR_BIN)
        return 5

    iface = os.environ.get("DECLAW_HWBP_IFACE", "eth0").strip()
    pcap_on = RAWCAP_BIN.exists() and os.environ.get("DECLAW_HWBP_PCAP", "1") != "0"
    # opt-in: force-stop + relaunch to catch startup handshakes (full-flow decrypt).
    # Off by default because a flaky device may fail to cold-start after force-stop;
    # the safe default captures the running instance and relies on driving.
    relaunch = os.environ.get("DECLAW_HWBP_RELAUNCH", "0") != "0"
    MAX_BPS = 6

    # push binaries once
    _adb(serial, "push", str(MONITOR_BIN), DEVICE_MON)
    _sh(serial, f"{rp}chmod 755 {DEVICE_MON}")
    if pcap_on:
        _adb(serial, "push", str(RAWCAP_BIN), DEVICE_RAWCAP)
        _sh(serial, f"{rp}chmod 755 {DEVICE_RAWCAP}")
    elif not RAWCAP_BIN.exists():
        log.info("hwbp: rawcap not built (utils/rawcap-arm64); keys only, no pcap.")

    _rawcap_started = [False]

    def _start_rawcap(headroom: int = 180):
        # Backstop only: the finally below ends capture on every exit path. headroom must
        # outlast everything before the monitor arms (BP resolution across up to MAX_BPS libs,
        # each an adb pull + r2 finder on a cold cache; plus the relaunch cold start), so a
        # slow first run does not self-terminate the sniffer mid-window.
        if pcap_on:
            _sh(serial, f"{rp}sh -c 'nohup {DEVICE_RAWCAP} {iface} {seconds + headroom} "
                        f"{DEVICE_PCAP} >/dev/null 2>&1 &'")
            _rawcap_started[0] = True

    def _stop_rawcap():
        # Latched, so calling it from the finally AND from the pre-pull flush site each does
        # the cleanup at most once. Without a guaranteed stop an orphaned sniffer keeps writing
        # DEVICE_PCAP and a rerun starts a second writer on the same file -> corrupt pcap.
        if _rawcap_started[0]:
            _sh(serial, f"{rp}pkill -f {DEVICE_RAWCAP} 2>/dev/null; sleep 1")
            time.sleep(1)
            _rawcap_started[0] = False

    # Cold-start: force-stop, begin the capture BEFORE launch, then arm the instant
    # the pid appears, so a flow's handshake AND its later application data both land
    # in the window (that is what makes the app-data decrypt, not just the handshake).
    # Everything past _start_rawcap is wrapped so any raise (r2 finder / monitor / pull
    # timeout) still stops the sniffer via the finally, never orphaning it.
    try:
        if relaunch:
            log.info("hwbp: cold-start relaunch of %s to catch startup handshakes.", pkg)
            _sh(serial, f"am force-stop {pkg}")
            time.sleep(1)
            _start_rawcap(headroom=36 + 180)  # +36 for _launch_wait worst case (3 * 12s)
            pid = _launch_wait(serial, pkg)   # retries the launch; cold start flakes under TCG
            if not pid:
                log.error("hwbp: %s did not start after retries", pkg)
                return 3
        else:
            pid = _ensure_running(serial, pkg)
            if not pid:
                log.error("hwbp: could not get a pid for %s", pkg)
                return 3
            _start_rawcap()

        # Resolve a breakpoint for EVERY BoringSSL lib mapped in the target, so one run
        # catches system libssl AND cronet AND any bundled BoringSSL at once.
        libs = _tls_libs(serial, pid, rp)
        if not libs:
            if _apk_native_maps(serial, pid, rp):
                log.error("hwbp: %s runs native code straight from the APK "
                          "(extractNativeLibs=false), so its bundled BoringSSL shows as base.apk, "
                          "not a .so, and cannot be located by lib name. Extract the .so and pass "
                          "its offset via DECLAW_HWBP_OFFSETS, or use the repackage path.", pkg)
            else:
                log.error("hwbp: no BoringSSL/ssl lib mapped in %s (pid %s) yet. Drive the app "
                          "so it opens a TLS connection, then retry.", pkg, pid)
            return 3
        force = os.environ.get("DECLAW_HWBP_LIB", "").strip()
        if force:
            libs = [x for x in libs if force in x] or libs
        bps = []
        for lib in libs[:MAX_BPS]:
            off = _resolve_offset(serial, lib, rp, out_dir)
            if off:
                bps.append((lib, off[2:] if off.startswith("0x") else off))
        if not bps:
            log.error("hwbp: could not resolve ssl_log_secret in any mapped lib (%s). "
                      "For ARM/32-bit or bundled BoringSSL the arm64 finder fails; pass "
                      "offsets from BoringSecretHunter/Ghidra via "
                      "DECLAW_HWBP_OFFSETS=lib@hexoff[,lib2@hexoff2].",
                      ", ".join(Path(x).name for x in libs[:MAX_BPS]))
            return 3

        # A process is one bitness. A 32-bit target maps /system/lib/ (not lib64); its
        # SSL->s3 pointer is 4 bytes and lives at a different offset (0x18 vs 0x30).
        env32 = ""
        if _is_32bit_proc(serial, pid, rp):
            env32 = os.environ.get("DECLAW_ENV32", "DECLAW_PTR32=1 DECLAW_S3_OFF=0x18 DECLAW_CR_OFF=0x30 ")
            # env32 is spliced raw into the root sh -c below so the shell applies the
            # assignments; keep it to KEY=value tokens so it cannot smuggle a command.
            if not re.fullmatch(r"[\w=. +-]*", env32):
                log.error("hwbp: refusing unsafe DECLAW_ENV32 (only KEY=value tokens allowed): %r", env32)
                return 3
            log.info("hwbp: 32-bit target -> reading 4-byte s3 pointer at 0x18.")

        log.info("hwbp: arming ssl_log_secret in %s (pid %s) for %ds%s. DRIVE THE APP NOW.",
                 ", ".join(Path(x).name for x, _ in bps), pid, seconds,
                 f", capturing {iface}" if pcap_on else "")
        # clear any keylog from a prior run so a launch failure cannot pull stale keys and
        # report them as fresh success.
        _sh(serial, f"{rp}rm -f {DEVICE_KEYS}")
        # env-assignments must reach the MONITOR, not su: `su 0 VAR=x prog` makes su try to
        # exec a binary literally named `VAR=x`, so the monitor never launches (the 32-bit
        # path died here). Route through `sh -c` so the shell applies the assignments and
        # execs the monitor, whether root is via su or adb root. Each monitor arg is
        # shlex-quoted so a lib path from /proc/maps cannot inject into that inner shell;
        # env32 stays raw (validated above) because the shell must interpret the assignments.
        mon_argv = [DEVICE_MON, str(pid), bps[0][0], bps[0][1], str(seconds), DEVICE_KEYS]
        mon_argv += [f"{lib}@{o}" for lib, o in bps[1:]]
        inner = (env32 + " ".join(shlex.quote(a) for a in mon_argv)).strip()
        cmd = f"{rp}sh -c {shlex.quote(inner)}"
        proc = _adb(serial, "shell", cmd, timeout=seconds + 60)
        mon_out = (proc.stdout or "").strip()
        log.info("hwbp monitor: %s", mon_out.splitlines()[-1] if mon_out else "(no output)")
        if proc.returncode != 0:
            log.warning("hwbp: monitor exited nonzero (%s); stderr: %s",
                        proc.returncode, (proc.stderr or "").strip()[:200])

        # pull the NSS keylog
        keys_out = out_dir / f"{pkg}-hwbp-keys.log"
        with open(keys_out, "wb") as fh:
            sp.run(["adb"] + (["-s", serial] if serial else []) +
                   ["exec-out", f"{rp}cat {DEVICE_KEYS}"], stdout=fh, timeout=60)
        n = sum(1 for _ in keys_out.open()) if keys_out.exists() else 0

        # pull the pcap. Stop rawcap first so the file is closed/flushed, then use
        # `adb pull` (reliable for binary; exec-out cat raced the still-open file).
        pcap_out = out_dir / f"{pkg}-hwbp.pcap"
        if pcap_on:
            _stop_rawcap()
            sp.run(["adb"] + (["-s", serial] if serial else []) +
                   ["pull", DEVICE_PCAP, str(pcap_out)], capture_output=True, timeout=120)

        if n == 0:
            log.warning("hwbp: 0 keys. The app made no fresh TLS handshake through %s "
                        "during the window. Drive it harder (scroll/navigate to load new "
                        "hosts), or it may route TLS through a different lib.",
                        ", ".join(Path(lb).name for lb, _ in bps))
            return 1
        if pcap_on and pcap_out.exists() and pcap_out.stat().st_size > 24:
            log.info("hwbp: %d NSS keys -> %s ; pcap -> %s. Decrypt: "
                     "tshark -r %s -o tls.keylog_file:%s", n, keys_out, pcap_out, pcap_out, keys_out)
        else:
            log.info("hwbp: %d NSS keylog lines -> %s. Decrypt a captured pcap with "
                     "`tshark -o tls.keylog_file:%s`.", n, keys_out, keys_out)
        return 0
    finally:
        _stop_rawcap()


def verify_offset_decision(live, decoy, off):
    """Pure guard decision for --mode mempatch, split out so it is unit-testable without a
    device. `off=None` means auto-locate. Returns (offset, error, warning): refuses the
    ssl_reverify_peer_cert decoy, resolves auto to the live offset, warns on a live mismatch."""
    if off is None:
        if live is None:
            return None, "no ssl_verify_peer_cert candidate; pass --offset explicitly", None
        return live, None, None
    if decoy is not None and off == decoy:
        hint = f" Use the live one @0x{live:x}." if live is not None else ""
        return None, f"0x{off:x} is the ssl_reverify_peer_cert DECOY; patching it is a no-op.{hint}", None
    if live is not None and off != live:
        return off, None, f"offset 0x{off:x} is not the detected live ssl_verify_peer_cert @0x{live:x}"
    return off, None, None


def _resolve_verify(serial: Optional[str], rp: str, pid: str, lib_substr: str, off):
    """Best-effort: pull the app's ACTUAL loaded lib, locate the live ssl_verify_peer_cert,
    resolve `off` if it is None (LIB@auto / bare LIB), and refuse the ssl_reverify_peer_cert
    decoy (patching it is a silent no-op). Returns (offset:int, None) to proceed or
    (None, errmsg) to abort. If the lib cannot be pulled/scanned, an explicit offset is
    passed through unguarded (never block a valid ground-truth offset)."""
    import os
    import tempfile
    from declaw.find_verify import find_in_bytes
    maps = (_sh(serial, f"{rp}cat /proc/{pid}/maps") or "")
    path = ""
    for ln in maps.splitlines():
        p = ln.split()
        if len(p) >= 6 and len(p[1]) >= 3 and p[1][2] == "x" and lib_substr in p[5]:
            path = p[5]
            break
    if not path:
        if off is None:
            return None, (f"could not find {lib_substr} in {pid}'s maps to auto-locate the "
                          f"offset; pass --offset {lib_substr}@0xNNN "
                          f"(python -m declaw.find_verify <lib.so>)")
        return off, None
    local = tempfile.NamedTemporaryFile(suffix=".so", delete=False).name
    try:
        _adb(serial, "pull", path, local)
        r = find_in_bytes(open(local, "rb").read())
    except Exception:
        r = None
    finally:
        try:
            os.unlink(local)
        except OSError:
            pass
    if r is None:
        if off is None:
            return None, f"could not read {path} to auto-locate ssl_verify_peer_cert; pass --offset"
        return off, None
    off2, err, warn = verify_offset_decision(r["live"], r["reverify"], off)
    if err:
        return None, err
    if off is None:
        log.info("mempatch: auto-located live ssl_verify_peer_cert @0x%x in %s", r["live"], lib_substr)
    if warn:
        log.warning("mempatch: %s; proceeding as given.", warn)
    return off2, None


def _verify_execution(serial, rp, pid, pkg, lib_substr, off, orig, secs=15):
    """After a mempatch, confirm the patched ssl_verify_peer_cert actually EXECUTES on a
    real handshake, non-destructively (a HW execute breakpoint via hwbp_keylog, which does
    NOT stop or crash the app). If it never fires within `secs`, revert to the original
    bytes. Traffic is driven by you or the app's own background calls: this watches, it does
    not tap arbitrary UI (auto-tapping a real app is unsafe). A safe foreground nudge is sent."""
    if not MONITOR_BIN.exists():
        log.warning("verify: hwbp watcher missing at %s; patch left in place, unverified.", MONITOR_BIN)
        return
    _adb(serial, "push", str(MONITOR_BIN), DEVICE_MON)
    _sh(serial, f"{rp}chmod 755 {DEVICE_MON}")
    # best-effort, pid-safe nudge: resume the app to the foreground (no force-stop). If it
    # was dead and this restarts it, re-patch the new pid so the watch stays valid.
    act = (_sh(serial, f"cmd package resolve-activity --brief {pkg} 2>/dev/null | tail -1") or "").strip()
    if "/" in act:
        _sh(serial, f"am start -n {shlex.quote(act)} >/dev/null 2>&1")
        newpid = (_sh(serial, f"pidof {shlex.quote(pkg)}") or "").strip().split()
        if newpid and newpid[0] != str(pid):
            pid = newpid[0]
            log.info("verify: app came up as pid %s; re-patching it.", pid)
            _sh(serial, f"{rp}{DEVICE_MEMPATCH} {pid} {shlex.quote(lib_substr)} {off:x}")
    log.info("verify: watching the patched ssl_verify_peer_cert for %ds. Drive the app so it "
             "makes an HTTPS request (open a screen that loads network data)...", secs)
    inner = f"{DEVICE_MON} {pid} {shlex.quote(lib_substr)} {off:x} {secs}"
    vp = _adb(serial, "shell", f"{rp}sh -c {shlex.quote(inner)}", timeout=secs + 30)
    if "HIT" in (vp.stdout or ""):
        log.info("verify: CONFIRMED. ssl_verify_peer_cert ran under the patch, so the "
                 "handshake now accepts any cert. Bypass is live.")
        return
    log.warning("verify: NOT confirmed in %ds (no handshake reached the function).", secs)
    if orig:
        _sh(serial, f"{rp}{DEVICE_MEMPATCH} {pid} {shlex.quote(lib_substr)} {off:x} {orig}")
        log.info("verify: reverted to original bytes (%s). Drive the app first, then re-run "
                 "--mode mempatch --verify.", orig)
    else:
        log.warning("verify: could not read original bytes to revert; patch left in place.")


def run_mempatch(package: str, serial: Optional[str], spec: str, *, refresh: bool = False,
                 verify: bool = False) -> int:
    """Zero-footprint pinning bypass: write the return-ssl_verify_ok stub into the RUNNING
    app's loaded BoringSSL via /proc/pid/mem. No file change (native integrity / PairIP
    passes), no frida, no ptrace-attach. Active counterpart to --hwbp-capture, reusing the
    same root + offset-ground-truth model. spec is LIB@OFFSET (same as --patch-boringssl)."""
    from declaw.boringssl_patch import parse_spec
    pkg = safe_pkg(package.removeprefix("package:").strip())
    rp = _root_prefix(serial)
    if rp is None:
        log.error("mempatch needs ROOT (/proc/pid/mem write). This device is not rooted. Use "
                  "the repackage path (declaw <pkg>) for non-rooted devices.")
        return 5
    abi = _device_abi(serial)
    if "arm64" not in abi:
        log.error("mempatch is arm64-only (the stub is AArch64); device arch is %s.", abi or "unknown")
        return 5
    if not MEMPATCH_BIN.exists():
        log.error("mempatch: prebuilt tool missing at %s (build: aarch64-linux-gnu-gcc -O2 "
                  "-static -o %s research/hwbp/hwbp_mempatch.c)", MEMPATCH_BIN, MEMPATCH_BIN)
        return 5
    try:
        lib_substr, off = parse_spec(spec)
    except ValueError as e:
        log.error("mempatch: %s", e)
        return 2
    pid = _ensure_running(serial, pkg)
    if not pid:
        log.error("mempatch: could not get a pid for %s", pkg)
        return 3
    off, gerr = _resolve_verify(serial, rp, pid, lib_substr, off)
    if gerr:
        log.error("mempatch: %s", gerr)
        return 2
    _adb(serial, "push", str(MEMPATCH_BIN), DEVICE_MEMPATCH)
    _sh(serial, f"{rp}chmod 755 {DEVICE_MEMPATCH}")
    inner = f"{DEVICE_MEMPATCH} {pid} {shlex.quote(lib_substr)} {off:x}"
    proc = _adb(serial, "shell", f"{rp}sh -c {shlex.quote(inner)}", timeout=60)
    out = (proc.stdout or "").strip()
    log.info("mempatch: %s", out.splitlines()[-1] if out else "(no output)")
    if proc.returncode != 0 or "OK" not in out:
        log.error("mempatch did NOT apply (rc=%s). On a real device SELinux can deny a "
                  "/proc/pid/mem WRITE even as root (read works for --hwbp-capture); a "
                  "permissive context is then needed. stderr: %s",
                  proc.returncode, (proc.stderr or "").strip()[:200])
        return 1
    log.info("mempatch: ssl_verify_peer_cert patched IN MEMORY of %s (pid %s); NO file "
             "changed. Point the app at your MITM via transparent redirect (iptables -> "
             "Burp); its TLS now accepts any cert. Re-run after each app restart, the patch "
             "lives only in the running process.", pkg, pid)
    if verify:
        import re
        m = re.search(r"before=([0-9a-fA-F]+)", out)
        _verify_execution(serial, rp, pid, pkg, lib_substr, off,
                          m.group(1).lower() if m else "")
    return 0
