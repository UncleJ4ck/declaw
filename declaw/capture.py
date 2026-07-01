"""declaw.capture — Passive TLS key extraction via friTap + frida-server.

For pinned apps (Reddit/cronet, apps with hard certificate pinning) the CA+NSC
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
    _adb(serial, "push", str(local_fs), "/data/local/tmp/frida-server")
    _adb(serial, "shell", "su 0 chmod 755 /data/local/tmp/frida-server")
    _adb(serial, "shell", "su 0 pkill frida-server")
    _adb(serial, "shell", "su 0 sh -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'")
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
                seconds: int = 90, refresh: bool = False) -> int:
    fritap, version = _ensure_fritap(refresh=refresh)
    client = AdbClient(host=ADB_HOST, port=ADB_PORT)
    device = resolve_device(client, serial)
    serial = device.serial
    abi = device.shell("getprop ro.product.cpu.abi").strip()
    if abi not in FRIDA_ABI_MAP:
        log.error("Device ABI %r unsupported (need one of %s).", abi, ", ".join(FRIDA_ABI_MAP))
        return 2
    log.info("Capture mode: %s on %s (%s), friTap frida %s", package, serial, abi, version)

    fs = fetch_frida_server(abi, version, refresh=refresh)
    _start_frida_server(serial, fs)
    if not _frida_server_ready(fritap, serial):
        log.error("frida-server is not responding on %s. friTap needs root "
                  "(an emulator or a rooted device). On a non-rooted device, use "
                  "the patch mode (default) instead of --capture.", serial)
        return 3

    out_dir.mkdir(parents=True, exist_ok=True)
    keys = out_dir / "keys.log"
    pcap = out_dir / "traffic.pcap"
    # SPAWN (-s), never attach: friTap must hook before the app creates any TLS
    # context, or the keylog callback never fires for already-open sessions.
    cmd = [fritap, "-m", serial, "-s", "-k", str(keys), "-p", str(pcap), package, "-v"]
    log.info("friTap spawning %s. Drive the app now (log in, scroll) to generate "
             "traffic; capturing for %ds.", package, seconds)
    log.debug("$ %s", " ".join(cmd))
    proc = sp.Popen(cmd)
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        log.info("Interrupted; stopping capture.")
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=15)
    except sp.TimeoutExpired:
        proc.kill()
    _adb(serial, "shell", "su 0 pkill frida-server")

    secrets = sum(1 for _ in keys.open()) if keys.exists() else 0
    size = pcap.stat().st_size if pcap.exists() else 0
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
