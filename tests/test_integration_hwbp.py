"""Integration smoke for the --hwbp-capture device plumbing. Exercises the real
adb/root/offset path deterministically (no flaky full-capture assertion). SKIPS
cleanly when no rooted arm64 device is reachable, so CI without a rig stays green.

Run: uv run python tests/test_integration_hwbp.py
Env: DECLAW_TEST_SERIAL (default localhost:5555), DECLAW_TEST_PKG (default a running app).
"""
import os
import subprocess as sp
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

SER = os.environ.get("DECLAW_TEST_SERIAL", "localhost:5555")
FAILS = 0


def check(cond, msg):
    global FAILS
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS += 1


def _adb(*a, timeout=30):
    return sp.run(["adb", "-s", SER, *a], capture_output=True, text=True, timeout=timeout)


def main():
    st = _adb("get-state")
    if "device" not in st.stdout:
        print(f"SKIP: no device at {SER} ({st.stdout.strip() or st.stderr.strip()})")
        return
    from declaw.hwbp import _root_prefix, _device_abi, _tls_libs, _resolve_offset, MONITOR_BIN, _launch_wait, _pid_of

    rp = _root_prefix(SER)
    if rp is None:
        print("SKIP: device is not rooted"); return
    if "arm64" not in _device_abi(SER):
        print("SKIP: device is not arm64"); return
    check(MONITOR_BIN.exists(), "prebuilt monitor present in utils/")

    # a running app that uses system libssl; launch a cronet app if present, else any given pkg
    pkg = os.environ.get("DECLAW_TEST_PKG", "com.example.cronetapp")
    if "package:" not in _adb("shell", "pm", "path", pkg).stdout:
        print(f"SKIP: test pkg {pkg} not installed"); return
    pid = _pid_of(SER, pkg) or _launch_wait(SER, pkg)
    if not pid:
        print(f"SKIP: could not start {pkg}"); return
    check(pid.isdigit(), f"got a pid for {pkg} ({pid})")

    libs = _tls_libs(SER, pid, rp)
    check(any("libssl.so" in l for l in libs), f"a BoringSSL lib is mapped ({[Path(l).name for l in libs][:3]})")

    with tempfile.TemporaryDirectory() as td:
        sysssl = next((l for l in libs if l == "/system/lib64/libssl.so"), None)
        if sysssl:
            off = _resolve_offset(SER, sysssl, rp, Path(td))
            check(off == "0x3038c", f"system libssl ssl_log_secret resolves to 0x3038c (got {off})")

        # arm the monitor for 3s; it must arm >0 threads with no perf error
        _adb("push", str(MONITOR_BIN), "/data/local/tmp/declaw_hwbp_it")
        _adb("shell", f"{rp}chmod 755 /data/local/tmp/declaw_hwbp_it")
        out = _adb("shell",
                   f"{rp}/data/local/tmp/declaw_hwbp_it {pid} /system/lib64/libssl.so 3038c 3 /data/local/tmp/it_keys.log",
                   timeout=40).stdout
        check("armed_events=" in out and "threads=" in out, "monitor armed the target with no perf error")
        # perf must not have failed on every thread
        res = [l for l in out.splitlines() if l.startswith("RESULT:")]
        check(bool(res) and "events=0" not in res[-1], f"monitor RESULT sane: {res[-1] if res else '(none)'}")

    print()
    if FAILS:
        print(f"{FAILS} FAILURES"); sys.exit(1)
    print("integration smoke passed")


if __name__ == "__main__":
    main()
