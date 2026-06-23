"""declaw.device — Proxy parsing/detection and adb device helpers."""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import re
import subprocess as sp
import sys
import zipfile


try:
    from adbutils import AdbClient, AdbDevice
except ImportError as exc:  # pragma: no cover
    print(
        f"[fatal] adbutils import failed ({exc}). "
        "Run with `uv run declaw.py ...` or install deps from requirements.txt.",
        file=sys.stderr,
    )
    sys.exit(1)

from declaw.config import ADB_HOST, ADB_PORT, DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT, log


def parse_proxy(spec: str) -> tuple[str, int]:
    """Parse HOST:PORT. Accepts 'host:port' or 'host port'."""
    text = spec.strip()
    if not text:
        return DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT
    sep = ":" if ":" in text else (" " if " " in text else None)
    if sep is None:
        log.error("--proxy expects HOST:PORT, got %r", spec)
        sys.exit(2)
    host, _, port_s = text.partition(sep)
    host = host.strip()
    try:
        port = int(port_s.strip())
    except ValueError:
        log.error("--proxy port is not an integer: %r", port_s)
        sys.exit(2)
    if not host or not (1 <= port <= 65535):
        log.error("--proxy host/port invalid: %r", spec)
        sys.exit(2)
    return host, port


def auto_detect_proxy_host(serial: Optional[str], default_port: int = DEFAULT_PROXY_PORT) -> Optional[tuple[str, int]]:
    """Pick the best host alias the connected device can use to reach the
    laptop's proxy listener. Emulators get the QEMU alias 10.0.2.2. Physical
    phones get whichever host LAN IP shares a subnet with the phone's Wi-Fi
    IP. Returns None when no device is reachable or the heuristic cannot
    decide; caller falls back to DEFAULT_PROXY_HOST."""
    try:
        client = AdbClient(host=ADB_HOST, port=ADB_PORT)
        devices = client.device_list()
    except Exception as exc:
        log.debug("auto-proxy: adb unreachable (%s)", exc)
        return None
    if not devices:
        log.debug("auto-proxy: no adb devices")
        return None
    if serial:
        devices = [d for d in devices if d.serial == serial]
        if not devices:
            return None
    if len(devices) > 1:
        log.debug("auto-proxy: multiple devices, pass -s SERIAL")
        return None
    d = devices[0]
    # Emulator alias for the host loopback.
    try:
        is_emu = d.serial.startswith("emulator-") or d.shell("getprop ro.kernel.qemu").strip() == "1"
    except Exception:
        is_emu = d.serial.startswith("emulator-")
    if is_emu:
        log.info("auto-proxy: %s looks like an emulator, using 10.0.2.2:%d", d.serial, default_port)
        return ("10.0.2.2", default_port)
    # Physical device: pick the laptop's LAN IP on the same /24 as the phone.
    try:
        phone_ifaces = d.shell("ip -4 -o addr show 2>/dev/null").splitlines()
    except Exception:
        phone_ifaces = []
    phone_ips = []
    for line in phone_ifaces:
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if m and not m.group(1).startswith("127."):
            phone_ips.append(m.group(1))
    if not phone_ips:
        return None
    # Walk local interfaces, find one on the same /24 as any phone IP.
    try:
        host_out = sp.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, check=True).stdout
    except Exception:
        return None
    for line in host_out.splitlines():
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        host_ip = m.group(1)
        if host_ip.startswith("127."):
            continue
        host_prefix = ".".join(host_ip.split(".")[:3])
        for pip in phone_ips:
            if pip.startswith(host_prefix + "."):
                log.info("auto-proxy: phone %s on %s/24, using host %s:%d",
                         d.serial, host_prefix + ".0", host_ip, default_port)
                return (host_ip, default_port)
    # A real phone is connected but no host interface shares its subnet. The
    # caller will bake the loopback default, which the phone cannot reach, so
    # warn loudly rather than fail silently. Pass --proxy HOST:PORT explicitly.
    log.warning("auto-proxy: phone %s reachable (IPs %s) but no host interface "
                "shares its /24; bundle will use the loopback default, which the "
                "phone CANNOT reach. Pass --proxy <host-ip>:%d explicitly.",
                d.serial, phone_ips, default_port)
    return None


# --------------------------------------------------------------------------- #
#  Device / APK I/O                                                           #
# --------------------------------------------------------------------------- #

def resolve_device(client: AdbClient, serial: Optional[str]) -> AdbDevice:
    devices = client.device_list()
    if not devices:
        log.error("No ADB devices attached. `adb devices` should list at least one.")
        sys.exit(2)
    if serial:
        for d in devices:
            if d.serial == serial:
                return d
        log.error("Serial %r not found. Seen: %s", serial,
                  ", ".join(d.serial for d in devices))
        sys.exit(2)
    if len(devices) > 1:
        log.error("Multiple devices attached, pass -s <serial>: %s",
                  ", ".join(d.serial for d in devices))
        sys.exit(2)
    return devices[0]


def pull_package(device: AdbDevice, package: str, dest: Path) -> list[Path]:
    log.info("Resolving %s on %s", package, device.serial)
    paths = device.shell(f"pm path {package}").strip()
    if not paths or "package:" not in paths:
        log.error("Package %s is not installed on %s.", package, device.serial)
        sys.exit(3)

    dest.mkdir(parents=True, exist_ok=True)
    for stale in dest.glob("*.apk"):
        stale.unlink()

    out: list[Path] = []
    for line in paths.splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        remote = line[len("package:"):]
        local = dest / Path(remote).name
        log.info("  pull %s", remote)
        device.sync.pull(remote, local)
        out.append(local)
    log.info("Pulled %d APK(s)", len(out))
    return out


def identify_base_apk(apks: list[Path]) -> Path:
    """Pick the APK that actually carries classes.dex."""
    carriers: list[Path] = []
    for apk in apks:
        try:
            with zipfile.ZipFile(apk) as zf:
                names = zf.namelist()
        except zipfile.BadZipFile:
            continue
        if any(re.fullmatch(r"classes\d*\.dex", n) for n in names):
            carriers.append(apk)
    if len(carriers) == 1:
        return carriers[0]
    if carriers:
        for c in carriers:
            if c.stem == "base":
                return c
        return max(carriers, key=lambda p: p.stat().st_size)
    for apk in apks:
        if apk.stem == "base":
            return apk
    return max(apks, key=lambda p: p.stat().st_size)
