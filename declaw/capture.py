"""declaw.capture — Passive TLS key extraction via friTap + frida-server.

For pinned apps (cronet, apps with hard certificate pinning) the CA+NSC
patch and the gadget hooks cannot win: the app checks for a specific key, so a
local CA is rejected and the handshake aborts. This mode never sits in the
middle. friTap hooks the app's own BoringSSL inside the process and logs the TLS
session keys, so the real (pinned) traffic decrypts after the fact with no MITM,
no cert, and nothing for the pin to detect.

Requirements: root (an emulator or a rooted device, for frida-server) and the
`fritap` CLI on PATH (`pipx install friTap` or `uv tool install friTap`).
frida-server is downloaded automatically and matched to friTap's own frida
version.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import lzma
import os
import re
import shutil
import signal
import subprocess as sp
import sys
import time

from adbutils import AdbClient

from declaw.config import ADB_HOST, ADB_PORT, FRIDA_ABI_MAP, FRIDA_RELEASES_TAG_URL, UTILS_DIR, log
from declaw.device import resolve_device
from declaw.shell import _gh_latest, _run, _stream_download

# Bundled anti-PairIP frida script, loaded via `fritap -c` when an anti-tamper
# app (PairIP, an anti-tamper packer) is detected. Best-known GENERIC native bypass
# (strstr/maps caller-hide, ptrace/kill block, SIGSEGV auto-patch of the
# dl_iterate_phdr fault). Not guaranteed on hardened apps; raises the odds.
ANTI_PAIRIP_JS = Path(__file__).resolve().parent / "anti_pairip.js"


# declaw-managed friTap venv. Created on first capture so declaw is
# self-contained: no manual `pipx install friTap`. Lives under utils/ (gitignored)
# and is reused on later runs. friTap is bundled, not reimplemented, because its
# value is the maintained cronet/BoringSSL byte-pattern database that would rot
# if forked into declaw.
FRITAP_VENV = UTILS_DIR / "fritap-venv"

# What to `pip install` for friTap. Defaults to PyPI main. Point it at a fork to
# develop friTap yourself, e.g. DECLAW_FRITAP_SPEC="git+https://github.com/you/friTap"
# (a `--refresh` run reinstalls the spec into the existing venv).
DEFAULT_FRITAP_SPEC = "friTap"

# On-device name for the pushed frida-server. Deliberately NOT "frida-server":
# anti-frida packers (PairIP) scan process names + files for
# "frida" and kill the app. Paired with _harden_frida_server (below), which
# strips the frida symbols/strings/thread-names from the binary itself.
FS_DEVICE_NAME = os.environ.get("DECLAW_FRIDA_SERVER_NAME", "dsvc")
FS_DEVICE_PATH = f"/data/local/tmp/{FS_DEVICE_NAME}"

# Anti-detection patch applied to the frida-server binary so PairIP-style anti-
# frida checks (strstr "frida"/"FridaScriptEngine"/"GumScript", symbol scans,
# gum-* thread names) do not fire. Ported from zer0def/undetected-frida's
# anti-anti-frida.py (lief symbol/string rename + sed thread-name rename). Runs
# in the friTap venv (which carries lief). Best-effort: on any failure declaw
# falls back to the stock server so capture still works on non-hardened apps.
_HARDEN_PY = r'''
import lief, sys, random, string, subprocess
f = sys.argv[1]
b = lief.parse(f)
if not b:
    sys.exit("lief parse failed")
rn = "".join(random.sample(string.ascii_letters, 5))
for s in b.symbols:
    try:
        if s.name == "frida_agent_main":
            s.name = "main"
        elif "frida" in s.name:
            s.name = s.name.replace("frida", rn)
        elif "FRIDA" in s.name:
            s.name = s.name.replace("FRIDA", rn)
    except Exception:
        pass
for sec in b.sections:
    if sec.name == ".rodata":
        for ps in ["FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript"]:
            for addr in sec.search_all(ps):
                b.patch_address(sec.file_offset + addr, [ord(c) for c in ps[::-1]])
b.write(f)
for t in ["gum-js-loop", "gmain", "gdbus"]:
    r = "".join(random.sample(string.ascii_letters, len(t)))
    subprocess.run(["sed", "-i", "s/" + t + "/" + r + "/g", f], check=False)
print("hardened")
'''


def _harden_frida_server(fs: Path, venv_python: Path, *, refresh: bool = False) -> Path:
    """Return an anti-detection copy of the frida-server binary, cached next to it
    as '<name>-undetected'. Re-patches automatically when the stock binary is newer
    (i.e. a new frida version was fetched) or on --refresh. Falls back to the stock
    binary if lief/patching is unavailable, so capture never breaks."""
    out = fs.with_name(fs.name + "-undetected")
    if out.exists() and not refresh and out.stat().st_mtime >= fs.stat().st_mtime:
        log.debug("Using cached anti-detection frida-server %s", out.name)
        return out
    try:
        # lief lives in the friTap venv; ensure it, then run the embedded patcher.
        if shutil.which("uv"):
            _run(["uv", "pip", "install", "--python", str(venv_python), "lief"], check=False)
        else:
            _run([str(venv_python), "-m", "pip", "install", "-q", "lief"], check=False)
        shutil.copy2(fs, out)
        script = UTILS_DIR / "_harden_fs.py"
        script.write_text(_HARDEN_PY, encoding="utf-8")
        r = sp.run([str(venv_python), str(script), str(out)],
                   capture_output=True, text=True, timeout=180)
        if r.returncode != 0 or "hardened" not in r.stdout:
            raise RuntimeError((r.stderr or r.stdout).strip()[:200])
        out.chmod(0o755)
        log.info("Anti-detection frida-server ready (%s), defeats PairIP-style "
                 "anti-frida checks.", out.name)
        return out
    except Exception as exc:
        log.warning("Could not harden frida-server (%s); using the stock binary. "
                    "PairIP/anti-frida apps may kill the process.", exc)
        return fs


def _ensure_fritap(refresh: bool = False) -> tuple[str, str]:
    """Return (fritap_path, frida_version), provisioning the managed venv on
    first use. frida-server must match this exact frida version or frida refuses
    to attach, so the version is read from the same venv that runs fritap."""
    spec = os.environ.get("DECLAW_FRITAP_SPEC", DEFAULT_FRITAP_SPEC).strip() or DEFAULT_FRITAP_SPEC
    py = FRITAP_VENV / "bin" / "python"
    fritap = FRITAP_VENV / "bin" / "fritap"
    fresh = not py.exists()
    if fresh or refresh or not fritap.exists():
        log.info("Provisioning friTap (%s) in %s", spec, FRITAP_VENV)
        try:
            if shutil.which("uv"):
                if fresh:
                    _run(["uv", "venv", str(FRITAP_VENV)], check=True)
                _run(["uv", "pip", "install", "--python", str(py),
                      *(["--upgrade"] if refresh else []), spec], check=True)
            else:
                if fresh:
                    _run([sys.executable, "-m", "venv", str(FRITAP_VENV)], check=True)
                _run([str(py), "-m", "pip", "install", "-q",
                      *(["--upgrade"] if refresh else []), spec], check=True)
        except Exception as exc:
            log.error("Failed to provision friTap from %r (%s). Install uv, or set "
                      "DECLAW_FRITAP_SPEC to a valid pip target.", spec, exc)
            sys.exit(2)
    if not fritap.exists():
        log.error("friTap provisioning did not produce %s.", fritap)
        sys.exit(2)
    try:
        out = sp.run([str(py), "-c", "import frida;print(frida.__version__)"],
                     capture_output=True, text=True, timeout=30)
        version = out.stdout.strip()
    except Exception:
        version = ""
    if not version:
        log.error("Could not read friTap's frida version from %s.", py)
        sys.exit(2)
    return str(fritap), version


def fetch_frida_server(abi: str, version: str, *, refresh: bool = False) -> Path:
    """Download + cache the frida-server binary for this ABI and exact version.

    Mirrors fetch_frida_gadget but for the server executable (no 16 KB ELF
    re-alignment: frida-server runs as a normal binary, not a mapped library)."""
    if abi not in FRIDA_ABI_MAP:
        raise ValueError(f"Unsupported ABI for frida-server: {abi}")
    suffix = FRIDA_ABI_MAP[abi]  # e.g. android-x86_64 / android-arm64
    out = UTILS_DIR / f"frida-server-{version}-{suffix}"
    if out.exists() and not refresh:
        log.debug("Using cached %s", out.name)
        return out
    info = _gh_latest(FRIDA_RELEASES_TAG_URL.format(tag=version))
    tag = info.get("tag_name", version).lstrip("v")
    pattern = re.compile(rf"frida-server-.*{re.escape(suffix)}\.xz$")
    asset = next((a for a in info.get("assets", []) if pattern.search(a["name"])), None)
    if asset is None:
        raise RuntimeError(f"No frida-server asset for {abi} in frida release {tag}")
    xz = UTILS_DIR / asset["name"]
    if not xz.exists() or refresh:
        _stream_download(asset["browser_download_url"], xz)
    log.info("Decompressing %s", xz.name)
    with lzma.open(xz, "rb") as src, open(out, "wb") as dst:
        shutil.copyfileobj(src, dst)
    out.chmod(0o755)
    return out


def _adb(serial: str, *args: str, check: bool = False):
    return _run(["adb", "-s", serial, *args], check=check)


def _start_frida_server(serial: str, local_fs: Path) -> None:
    """Push frida-server and start it detached as root, via the adb CLI.

    The adb CLI is used (not adbutils device.shell) on purpose: adbutils runs
    the command in an exec session that tears down the backgrounded process, so
    `nohup ... &` does not survive and frida falls back to jailed mode ("need
    Gadget to attach on jailed Android"). The adb CLI detaches it correctly."""
    _adb(serial, "root")
    time.sleep(4)
    _adb(serial, "wait-for-device")
    _adb(serial, "shell", "setenforce", "0")          # emulator/userdebug: relax SELinux
    _adb(serial, "push", str(local_fs), FS_DEVICE_PATH)
    _adb(serial, "shell", f"su 0 chmod 755 {FS_DEVICE_PATH}")
    _adb(serial, "shell", f"su 0 pkill -f {FS_DEVICE_NAME}")
    _adb(serial, "shell", f"su 0 sh -c 'nohup {FS_DEVICE_PATH} >/dev/null 2>&1 &'")
    time.sleep(4)


def _frida_server_ready(fritap_path: str, serial: str) -> bool:
    """True once frida-server answers on the device (frida-ps lists processes)."""
    fps = Path(fritap_path).with_name("frida-ps")
    for _ in range(4):
        try:
            out = sp.run([str(fps), "-D", serial], capture_output=True, text=True, timeout=20)
            if out.returncode == 0 and len(out.stdout.strip().splitlines()) > 1:
                return True
        except Exception:
            pass
        time.sleep(3)
    return False


def run_capture(package: str, serial: Optional[str], out_dir: Path, *,
                seconds: int = 90, refresh: bool = False,
                anti_pairip: Optional[bool] = None) -> int:
    fritap, version = _ensure_fritap(refresh=refresh)
    client = AdbClient(host=ADB_HOST, port=ADB_PORT)
    device = resolve_device(client, serial)
    serial = device.serial
    abi = device.shell("getprop ro.product.cpu.abi").strip()
    if abi not in FRIDA_ABI_MAP:
        log.error("Device ABI %r unsupported (need one of %s).", abi, ", ".join(FRIDA_ABI_MAP))
        return 2
    log.info("Capture mode: %s on %s (%s), friTap frida %s", package, serial, abi, version)

    # None = standalone --mode capture (no prior analysis): detect here, early, not right
    # before the spawn. --auto passes an explicit bool and skips this.
    if anti_pairip is None:
        import tempfile
        from declaw.analyze import analyze_apks
        from declaw.device import pull_package
        with tempfile.TemporaryDirectory(prefix="declaw-cap-") as td:
            profile = analyze_apks(pull_package(device, package, Path(td)))
        anti_pairip = bool(profile.anti_tamper)
        if anti_pairip:
            log.info("Detected anti-tamper (%s); enabling anti-PairIP bypass.",
                     ", ".join(sorted(profile.anti_tamper)))

    fs = fetch_frida_server(abi, version, refresh=refresh)
    # Anti-detection hardening is OPT-IN (DECLAW_STEALTH_FRIDA=1): the anti-anti-
    # frida patch hides frida-server from PairIP-style scans, but the same patch
    # can corrupt the injected frida-agent on some frida versions and crash the
    # target. Default off so normal capture uses the stock (working) server; turn
    # it on only for apps that kill the process on frida-server detection.
    if os.environ.get("DECLAW_STEALTH_FRIDA", "").strip() not in ("", "0", "false", "False"):
        fs = _harden_frida_server(fs, FRITAP_VENV / "bin" / "python", refresh=refresh)
    _start_frida_server(serial, fs)
    if not _frida_server_ready(fritap, serial):
        log.error("frida-server is not responding on %s. friTap needs root "
                  "(an emulator or a rooted device). On a non-rooted device, use "
                  "the patch mode (default) instead of --capture.", serial)
        return 3

    # DECLAW_ANTI_PAIRIP forces the bypass on even when no packer lib was detected.
    anti_pairip = bool(anti_pairip) or os.environ.get("DECLAW_ANTI_PAIRIP", "").strip() not in ("", "0", "false", "False")

    out_dir.mkdir(parents=True, exist_ok=True)
    keys = out_dir / "keys.log"
    pcap = out_dir / "traffic.pcap"
    # clear a prior run's keylog: friTap's handler only truncates on its FIRST key event,
    # so a run that captures nothing would otherwise count stale keys as fresh success
    # (mirrors run_hwbp_capture's guard).
    keys.unlink(missing_ok=True)
    # SPAWN (-s), never attach: friTap must hook before the app creates any TLS
    # context, or the keylog callback never fires for already-open sessions.
    cmd = [fritap, "-m", serial, "-s", "-k", str(keys), "-p", str(pcap), package, "-v"]
    if anti_pairip and ANTI_PAIRIP_JS.exists():
        # -c runs our script at spawn (before PairIP arms); --pairip-safe blinks
        # friTap's own hooks so they are not caught mid-install.
        cmd[6:6] = ["-c", str(ANTI_PAIRIP_JS), "--pairip-safe"]
        log.info("anti-PairIP: loading %s + --pairip-safe (best-known generic "
                 "bypass; hardened apps may still resist).", ANTI_PAIRIP_JS.name)
    log.info("friTap spawning %s. Drive the app now (log in, scroll) to generate "
             "traffic; capturing for %ds.", package, seconds)
    log.debug("$ %s", " ".join(cmd))
    proc = sp.Popen(cmd)
    died_early = False
    try:
        for _ in range(max(1, seconds) * 5):      # poll every 0.2s
            if proc.poll() is not None:           # friTap exited on its own
                died_early = True
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        log.info("Interrupted; stopping capture.")
    if not died_early:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except sp.TimeoutExpired:
            proc.kill()
    rc = proc.returncode
    _adb(serial, "shell", f"su 0 pkill -f {FS_DEVICE_NAME}")

    secrets = sum(1 for _ in keys.open()) if keys.exists() else 0
    size = pcap.stat().st_size if pcap.exists() else 0

    if died_early and secrets == 0:
        # friTap exited before we SIGINT'd it AND logged nothing: a tool-invocation
        # failure (missing/incompatible friTap, package not installed, wrong -m serial),
        # NOT "the app made no TLS calls". Report the real cause.
        log.error("friTap exited on its own (code %s) before the capture window with no keys. "
                  "This is a friTap invocation failure, not 'no traffic'. Re-run with -v and "
                  "read the friTap output above (is friTap installed and the package installed "
                  "on %s?).", rc, serial)
        return 5
    if died_early:
        # exited early but DID log secrets: the app almost certainly self-killed after a
        # handshake (anti-tamper integrity check), so keep what we already captured.
        log.warning("friTap exited early (code %s) but captured %d secret(s) first; the app "
                    "likely self-killed after handshaking. Keeping the capture.", rc, secrets)
    log.info("Captured %d TLS secrets -> %s", secrets, keys)
    log.info("Wrote %d bytes of pcap -> %s", size, pcap)
    if secrets == 0:
        log.warning("No keys captured. The app may not have made TLS calls in the "
                    "window, or needs root. Increase --capture-seconds and interact "
                    "with the app during the capture.")
    tshark = shutil.which("tshark")
    if tshark:
        log.info("Decode the decrypted HTTP/2 with:\n"
                 "  tshark -r %s -d tcp.port==443,http2 "
                 "-Y http2.headers.authority -T fields -e http2.headers.authority", pcap)
    else:
        log.info("Install wireshark/tshark to decode, or open %s in Wireshark "
                 "(it embeds the keys).", pcap)
    return 0 if secrets else 5
