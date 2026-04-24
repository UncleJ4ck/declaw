#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "adbutils>=2.0",
#   "defusedxml>=0.7",
#   "requests>=2.30",
# ]
# ///
"""declaw: patch an Android APK so it stops caring about SSL pinning.

Pulls the app off the device (base + every split), decodes it, drops in
a network security config that trusts user CAs, patches the manifest,
optionally injects a Frida gadget wired up to run a universal unpinning
script at launch, repacks, resigns, and installs it back.

The gadget and the script live inside the APK. Nothing attaches at
runtime, no Frida client needed. If you only need NSC (system
TrustManager apps), pass --minimal and you skip the gadget entirely.

Quick usage:

    declaw com.example.app                  # one device attached
    declaw -s emulator-5554 com.example.app  # multiple devices
    declaw ./app.apk                         # patch a local APK, no install
    declaw --minimal com.example.app         # NSC only, no gadget
    declaw -c ~/.mitmproxy/ca.pem com.example.app

Env overrides (useful for air-gapped pentests):
    DECLAW_BYPASS_URLS   ; separated list of script URLs to fetch
    DECLAW_CERT_PEM      path to a PEM; baked into CERT_PEM in the bundle
"""

from __future__ import annotations

import argparse
import json
import logging
import lzma
import os
import re
import shutil
import subprocess as sp
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from xml.etree import ElementTree as _stdlib_ET  # for register_namespace only
from defusedxml import ElementTree as ET

try:
    from adbutils import AdbClient, AdbDevice
except ImportError as exc:  # pragma: no cover
    print(
        f"[fatal] adbutils import failed ({exc}). "
        "Run with `uv run declaw.py ...` or install deps from requirements.txt.",
        file=sys.stderr,
    )
    sys.exit(1)


# --------------------------------------------------------------------------- #
#  Constants                                                                  #
# --------------------------------------------------------------------------- #

ADB_HOST = os.environ.get("ADB_HOST", "127.0.0.1")
ADB_PORT = int(os.environ.get("ADB_PORT", "5037"))

APKTOOL_URL = "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest"
UBER_APK_SIGNER_URL = "https://api.github.com/repos/patrickfav/uber-apk-signer/releases/latest"
FRIDA_RELEASES_URL = "https://api.github.com/repos/frida/frida/releases/latest"

DEFAULT_BYPASS_URLS = [
    "https://raw.githubusercontent.com/httptoolkit/frida-interception-and-unpinning/main/android/android-certificate-unpinning.js",
    "https://raw.githubusercontent.com/httptoolkit/frida-interception-and-unpinning/main/android/android-certificate-unpinning-fallback.js",
    "https://raw.githubusercontent.com/httptoolkit/frida-interception-and-unpinning/main/android/android-disable-flutter-certificate-pinning.js",
    "https://raw.githubusercontent.com/httptoolkit/frida-interception-and-unpinning/main/android/android-disable-root-detection.js",
    "https://raw.githubusercontent.com/httptoolkit/frida-interception-and-unpinning/main/native-tls-hook.js",
]

ROOT_DIR = Path(__file__).resolve().parent
UTILS_DIR = ROOT_DIR / "utils"
PACKAGES_DIR = ROOT_DIR / "packages"
PATCHED_DIR = ROOT_DIR / "patched"
for _d in (UTILS_DIR, PACKAGES_DIR, PATCHED_DIR):
    _d.mkdir(exist_ok=True)

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_stdlib_ET.register_namespace("android", ANDROID_NS)
QN_NSC = f"{{{ANDROID_NS}}}networkSecurityConfig"
QN_DEBUG = f"{{{ANDROID_NS}}}debuggable"
QN_CLEAR = f"{{{ANDROID_NS}}}usesCleartextTraffic"
QN_EXTRACT = f"{{{ANDROID_NS}}}extractNativeLibs"
QN_NAME = f"{{{ANDROID_NS}}}name"

FRIDA_ABI_MAP = {
    "arm64-v8a": "android-arm64",
    "armeabi-v7a": "android-arm",
    "armeabi": "android-arm",
    "x86": "android-x86",
    "x86_64": "android-x86_64",
}

NETWORK_SECURITY_CONFIG_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""

# Dummy CA (ISRG Root X1). Parses cleanly so the httptoolkit hooks that do
# CertificateFactory.generateCertificate(CERT_PEM) never throw; safe to inject
# into any trust store since the device already trusts LE anyway. Overridden
# if the user passes --cert or sets DECLAW_CERT_PEM.
DEFAULT_CERT_PEM = """\
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
"""

GADGET_CONFIG_JSON = {
    "interaction": {
        "type": "script",
        "path": "./libfrida-gadget.script.so",
        "on_change": "reload",
    },
}


# --------------------------------------------------------------------------- #
#  Logging                                                                    #
# --------------------------------------------------------------------------- #

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-5s %(message)s",
)
log = logging.getLogger("declaw")


def _run(cmd: list, *, check: bool = True, capture: bool = False) -> sp.CompletedProcess:
    log.debug("$ %s", " ".join(map(str, cmd)))
    return sp.run(list(map(str, cmd)), check=check, text=True, capture_output=capture)


# --------------------------------------------------------------------------- #
#  Network / caching                                                          #
# --------------------------------------------------------------------------- #

def _gh_latest(api_url: str) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.get(api_url, timeout=30, headers=headers)
    r.raise_for_status()
    return r.json()


def _stream_download(url: str, dest: Path) -> None:
    log.info("Downloading %s", dest.name)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with requests.get(url, timeout=300, stream=True) as resp:
        resp.raise_for_status()
        with open(tmp, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=1 << 20):
                if chunk:
                    fh.write(chunk)
    tmp.rename(dest)


def _cached_jar(api_url: str, *, refresh: bool) -> Path:
    info = _gh_latest(api_url)
    asset = next((a for a in info.get("assets", []) if a["name"].endswith(".jar")), None)
    if asset is None:
        raise RuntimeError(f"No .jar asset found at {api_url}")
    dest = UTILS_DIR / asset["name"]
    if dest.exists() and not refresh:
        log.debug("Using cached %s", dest.name)
        return dest
    _stream_download(asset["browser_download_url"], dest)
    return dest


def fetch_frida_gadget(abi: str, *, refresh: bool) -> Path:
    if abi not in FRIDA_ABI_MAP:
        raise ValueError(f"Unsupported ABI for Frida gadget: {abi}")
    suffix = FRIDA_ABI_MAP[abi]
    info = _gh_latest(FRIDA_RELEASES_URL)
    tag = info.get("tag_name", "latest").lstrip("v")
    pattern = re.compile(rf"frida-gadget-.*{re.escape(suffix)}\.so\.xz$")
    asset = next((a for a in info.get("assets", []) if pattern.search(a["name"])), None)
    if asset is None:
        raise RuntimeError(f"No frida-gadget asset for {abi} in release {tag}")
    xz = UTILS_DIR / asset["name"]
    so = UTILS_DIR / f"libfrida-gadget-{tag}-{suffix}.so"
    if so.exists() and not refresh:
        log.debug("Using cached %s", so.name)
        return so
    if not xz.exists() or refresh:
        _stream_download(asset["browser_download_url"], xz)
    log.info("Decompressing %s", xz.name)
    with lzma.open(xz, "rb") as src, open(so, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return so


def fetch_bypass_script(cert_pem: str, *, refresh: bool) -> Path:
    """Assemble the universal bypass JS and return the cached path."""
    urls_env = os.environ.get("DECLAW_BYPASS_URLS", "").strip()
    urls = [u for u in urls_env.split(";") if u] if urls_env else list(DEFAULT_BYPASS_URLS)
    cached = UTILS_DIR / "universal-bypass.js"

    if cached.exists() and not refresh:
        log.debug("Using cached %s", cached.name)
        # Still rewrite the header (CERT_PEM may have changed between runs).
        return _write_bypass(cached, cert_pem, _read_cached_parts(cached))

    parts: list[tuple[str, str]] = []
    for url in urls:
        log.info("Fetching bypass fragment: %s", url.rsplit("/", 1)[-1])
        r = requests.get(url, timeout=60)
        r.raise_for_status()
        parts.append((url, r.text))
    return _write_bypass(cached, cert_pem, parts)


def _read_cached_parts(cached: Path) -> list[tuple[str, str]]:
    # Cache only stores the final concatenated file; returning empty parts
    # forces _write_bypass to just refresh the header while preserving body.
    body = cached.read_text(encoding="utf-8")
    # Strip any previous declaw header so re-writing is idempotent.
    marker = "// ---- declaw header end ----"
    idx = body.find(marker)
    if idx >= 0:
        body = body[idx + len(marker):].lstrip("\n")
    return [("(cached)", body)]


def _write_bypass(cached: Path, cert_pem: str, parts: list[tuple[str, str]]) -> Path:
    header = _bypass_header(cert_pem)
    with open(cached, "w", encoding="utf-8") as fh:
        fh.write(header)
        for url, body in parts:
            fh.write(f"\n// ==== {url} ====\n")
            fh.write(body)
            if not body.endswith("\n"):
                fh.write("\n")
    return cached


def _bypass_header(cert_pem: str) -> str:
    escaped_pem = cert_pem.strip()
    return (
        "// declaw universal SSL-unpinning bundle\n"
        "// Generated header. Downstream hooks read these globals.\n"
        f"const CERT_PEM = `\n{escaped_pem}\n`;\n"
        "const PROXY_HOST = '127.0.0.1';\n"
        "const PROXY_PORT = 8000;\n"
        "const DEBUG_MODE = false;\n"
        "const IGNORED_NON_HTTP_PORTS = [];\n"
        "const BLOCK_HTTP3 = true;\n"
        "const PROXY_SUPPORTS_SOCKS5 = false;\n"
        "// ---- declaw header end ----\n"
    )


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


# --------------------------------------------------------------------------- #
#  Inspection                                                                 #
# --------------------------------------------------------------------------- #

@dataclass
class ApkInspection:
    frameworks: set[str] = field(default_factory=set)
    abis: set[str] = field(default_factory=set)


def inspect_unpacked(unpacked: Path) -> ApkInspection:
    info = ApkInspection()
    lib_dir = unpacked / "lib"
    if lib_dir.is_dir():
        for arch_dir in lib_dir.iterdir():
            if not arch_dir.is_dir():
                continue
            info.abis.add(arch_dir.name)
            for so in arch_dir.glob("*.so"):
                n = so.name.lower()
                if "libflutter" in n:
                    info.frameworks.add("flutter")
                elif "libreactnativejni" in n or "libhermes" in n or "libjsc" in n:
                    info.frameworks.add("react-native")
                elif "libmonodroid" in n or "libmono-" in n or "libxamarin" in n:
                    info.frameworks.add("xamarin")
                elif "libil2cpp" in n or "libunity" in n:
                    info.frameworks.add("unity")
    assets = unpacked / "assets"
    if assets.is_dir():
        if (assets / "flutter_assets").is_dir():
            info.frameworks.add("flutter")
        if any(assets.rglob("index.android.bundle")):
            info.frameworks.add("react-native")
        if (assets / "www").is_dir() or (assets / "cordova.js").exists():
            info.frameworks.add("cordova")
    return info


# --------------------------------------------------------------------------- #
#  Manifest / NSC                                                             #
# --------------------------------------------------------------------------- #

def _fq_class(name: str, package: str) -> str:
    if name.startswith("."):
        return package + name
    if "." in name:
        return name
    return f"{package}.{name}"


@dataclass
class ManifestPatchResult:
    application_class: Optional[str]
    launcher_activity: Optional[str]


def patch_manifest(unpacked: Path) -> ManifestPatchResult:
    manifest_path = unpacked / "AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    package = root.get("package", "")

    application = root.find(".//application")
    if application is None:
        log.warning("Manifest has no <application>, skipping manifest patch.")
        return ManifestPatchResult(None, None)

    wanted = {
        QN_NSC: "@xml/network_security_config",
        QN_DEBUG: "true",
        QN_CLEAR: "true",
        QN_EXTRACT: "true",
    }
    changes: list[str] = []
    for attr, value in wanted.items():
        if application.get(attr) != value:
            application.set(attr, value)
            changes.append(attr.split("}")[1])

    app_fq = None
    app_class = application.get(QN_NAME)
    if app_class:
        app_fq = _fq_class(app_class, package)

    launcher_fq = None
    for activity in application.findall(".//activity") + application.findall(".//activity-alias"):
        for ifilter in activity.findall("intent-filter"):
            actions = {a.get(QN_NAME) for a in ifilter.findall("action")}
            categories = {c.get(QN_NAME) for c in ifilter.findall("category")}
            if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                name = activity.get(QN_NAME) or activity.get(f"{{{ANDROID_NS}}}targetActivity")
                if name:
                    launcher_fq = _fq_class(name, package)
                    break
        if launcher_fq:
            break

    if changes:
        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
        log.info("Manifest patched: %s", ", ".join(changes))
    else:
        log.info("Manifest already correctly configured.")
    return ManifestPatchResult(app_fq, launcher_fq)


def add_network_security_config(unpacked: Path) -> None:
    out = unpacked / "res" / "xml"
    out.mkdir(parents=True, exist_ok=True)
    (out / "network_security_config.xml").write_text(
        NETWORK_SECURITY_CONFIG_XML, encoding="utf-8"
    )
    log.info("Wrote res/xml/network_security_config.xml")


# --------------------------------------------------------------------------- #
#  Gadget injection                                                           #
# --------------------------------------------------------------------------- #

def _find_smali_for_class(unpacked: Path, fq_class: str) -> Optional[Path]:
    rel = fq_class.replace(".", "/") + ".smali"
    for smali_root in sorted(unpacked.glob("smali*")):
        candidate = smali_root / rel
        if candidate.is_file():
            return candidate
    return None


_CLINIT_RE = re.compile(
    r"(\.method\s+static\s+constructor\s+<clinit>\(\)V\b.*?)(\.end method)",
    re.DOTALL,
)
_LOAD_LIBRARY_SMALI = (
    "    const-string v0, \"frida-gadget\"\n"
    "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
)
_NEW_CLINIT = (
    "\n.method static constructor <clinit>()V\n"
    "    .locals 1\n"
    f"{_LOAD_LIBRARY_SMALI}"
    "    return-void\n"
    ".end method\n"
)


def _inject_load_library(smali_path: Path) -> bool:
    text = smali_path.read_text(encoding="utf-8")
    if "\"frida-gadget\"" in text:
        return False
    m = _CLINIT_RE.search(text)
    if m:
        head, tail = m.group(1), m.group(2)
        head2 = re.sub(
            r"(\.(?:locals|registers)\s+)(\d+)",
            lambda mm: f"{mm.group(1)}{max(int(mm.group(2)), 1)}",
            head,
            count=1,
        )
        if head2 == head and ".locals" not in head and ".registers" not in head:
            head2 = head.replace(
                ".method static constructor <clinit>()V",
                ".method static constructor <clinit>()V\n    .locals 1",
                1,
            )
        # Inject *before* the final `return-void` so the new code actually runs.
        last_ret = head2.rfind("return-void")
        if last_ret == -1:
            new_head = head2 + _LOAD_LIBRARY_SMALI
        else:
            line_start = head2.rfind("\n", 0, last_ret) + 1
            new_head = head2[:line_start] + _LOAD_LIBRARY_SMALI + head2[line_start:]
        new_text = text.replace(m.group(0), new_head + tail, 1)
    else:
        anchor = text.find("\n.method")
        new_text = (text[:anchor] + _NEW_CLINIT + text[anchor:]) if anchor >= 0 else text + _NEW_CLINIT
    smali_path.write_text(new_text, encoding="utf-8")
    return True


def inject_frida_gadget(
    unpacked: Path,
    inspection: ApkInspection,
    manifest: ManifestPatchResult,
    *,
    bypass_script: Path,
    refresh: bool,
) -> None:
    target_abis = sorted(inspection.abis) or ["arm64-v8a"]

    lib_root = unpacked / "lib"
    lib_root.mkdir(exist_ok=True)

    config_bytes = json.dumps(GADGET_CONFIG_JSON, indent=2).encode("utf-8")

    for abi in target_abis:
        if abi not in FRIDA_ABI_MAP:
            log.warning("Skipping unsupported ABI for gadget: %s", abi)
            continue
        gadget_so = fetch_frida_gadget(abi, refresh=refresh)
        abi_dir = lib_root / abi
        abi_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(gadget_so, abi_dir / "libfrida-gadget.so")
        (abi_dir / "libfrida-gadget.config.so").write_bytes(config_bytes)
        shutil.copy2(bypass_script, abi_dir / "libfrida-gadget.script.so")
        log.info("Gadget + unpin script placed in lib/%s/", abi)

    target_class = manifest.application_class or manifest.launcher_activity
    if not target_class:
        log.warning("No Application or launcher class found. "
                    "The gadget is in the APK but nothing loads it. "
                    "Add System.loadLibrary(\"frida-gadget\") yourself.")
        return
    smali_path = _find_smali_for_class(unpacked, target_class)
    if smali_path is None:
        log.warning("Smali file for %s not found; gadget loader NOT injected.",
                    target_class)
        return
    if _inject_load_library(smali_path):
        log.info("Injected loadLibrary(\"frida-gadget\") into %s", target_class)
    else:
        log.info("Gadget loader already present in %s", target_class)


# --------------------------------------------------------------------------- #
#  apktool / signer                                                           #
# --------------------------------------------------------------------------- #

def apktool_decode(apk: Path, out_dir: Path, jar: Path, *, with_sources: bool) -> None:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    cmd = ["java", "-jar", jar, "d", "-f", "-o", out_dir]
    if not with_sources:
        cmd.append("-s")
    cmd.append(apk)
    log.info("Unpacking %s (sources=%s)", apk.name, "yes" if with_sources else "no")
    _run(cmd)


def apktool_build(unpacked: Path, out_apk: Path, jar: Path) -> None:
    log.info("Repacking -> %s", out_apk.name)
    # Apktool 2.x understood --use-aapt2; 3.x uses aapt2 by default and removed
    # the flag. Leaving it off works for both.
    _run(["java", "-jar", jar, "b", "-f", unpacked, "-o", out_apk])


_SIGNED_SUFFIX_RE = re.compile(r"-aligned-(?:debugSigned|signed)\.apk$")


def sign_apk(apk: Path, signer_jar: Path) -> Path:
    log.info("Signing %s", apk.name)
    _run(["java", "-jar", signer_jar, "-a", apk, "--allowResign", "--overwrite"])
    if apk.exists():
        return apk
    for sib in apk.parent.iterdir():
        if _SIGNED_SUFFIX_RE.search(sib.name):
            sib.rename(apk)
            return apk
    raise RuntimeError(f"uber-apk-signer produced no output for {apk}")


# --------------------------------------------------------------------------- #
#  Install                                                                    #
# --------------------------------------------------------------------------- #

def install_apks(serial: str, apks: list[Path]) -> None:
    ordered = sorted(apks, key=lambda p: (0 if "base" in p.stem else 1, p.name))
    base_cmd = ["adb", "-s", serial, "install-multiple"]
    attempts = [
        base_cmd + ["-r", "-d", "-g", "-t"],
        base_cmd + ["-r", "-d"],
    ]
    for flags in attempts:
        try:
            _run(flags + list(map(str, ordered)))
            log.info("Installed %d APK(s) on %s", len(ordered), serial)
            return
        except sp.CalledProcessError as e:
            log.warning("install-multiple failed (%s), trying next flag set.", e.returncode)

    log.info("Falling back to pm install session …")
    total = sum(a.stat().st_size for a in ordered)
    session_out = _run(
        ["adb", "-s", serial, "shell", f"pm install-create -S {total}"],
        capture=True,
    ).stdout.strip()
    m = re.search(r"\[(\d+)\]", session_out)
    if not m:
        raise RuntimeError(f"Could not parse install-create output: {session_out!r}")
    sid = m.group(1)
    for idx, apk in enumerate(ordered):
        remote = f"/data/local/tmp/{apk.name}"
        _run(["adb", "-s", serial, "push", apk, remote])
        _run(["adb", "-s", serial, "shell", "pm", "install-write",
              "-S", str(apk.stat().st_size), sid, str(idx), remote])
        _run(["adb", "-s", serial, "shell", "rm", remote], check=False)
    _run(["adb", "-s", serial, "shell", "pm", "install-commit", sid])


# --------------------------------------------------------------------------- #
#  Orchestration                                                              #
# --------------------------------------------------------------------------- #

@dataclass
class Tools:
    apktool: Path
    signer: Path
    bypass_script: Path  # may be unused in --minimal mode


def prepare_tools(*, refresh: bool, minimal: bool, cert_pem: str) -> Tools:
    apktool = _cached_jar(APKTOOL_URL, refresh=refresh)
    signer = _cached_jar(UBER_APK_SIGNER_URL, refresh=refresh)
    bypass = UTILS_DIR / "universal-bypass.js"
    if not minimal:
        bypass = fetch_bypass_script(cert_pem, refresh=refresh)
    return Tools(apktool, signer, bypass)


def patch_base_apk(
    base_apk: Path,
    out_dir: Path,
    tools: Tools,
    *,
    minimal: bool,
    refresh: bool,
) -> Path:
    unpacked = out_dir / "base.unpacked"

    apktool_decode(base_apk, unpacked, tools.apktool, with_sources=not minimal)
    inspection = inspect_unpacked(unpacked)
    if inspection.frameworks:
        log.info("Frameworks detected: %s", ", ".join(sorted(inspection.frameworks)))
    if inspection.abis:
        log.info("ABIs detected: %s", ", ".join(sorted(inspection.abis)))

    manifest_info = patch_manifest(unpacked)
    add_network_security_config(unpacked)

    if not minimal:
        inject_frida_gadget(
            unpacked,
            inspection,
            manifest_info,
            bypass_script=tools.bypass_script,
            refresh=refresh,
        )

    repacked = out_dir / "base.repack.apk"
    apktool_build(unpacked, repacked, tools.apktool)
    sign_apk(repacked, tools.signer)

    final_base = out_dir / f"{base_apk.stem}_patched.apk"
    repacked.rename(final_base)
    shutil.rmtree(unpacked, ignore_errors=True)
    return final_base


def sign_splits(splits: list[Path], out_dir: Path, signer_jar: Path) -> list[Path]:
    if not splits:
        return []
    log.info("Re-signing %d split APK(s) in parallel", len(splits))
    tmps = []
    for s in splits:
        tmp = out_dir / f"{s.stem}.split.apk"
        shutil.copy2(s, tmp)
        tmps.append(tmp)

    errors: list[BaseException] = []
    with ThreadPoolExecutor(max_workers=min(4, len(tmps))) as pool:
        futures = {pool.submit(sign_apk, t, signer_jar): t for t in tmps}
        for fut in as_completed(futures):
            try:
                fut.result()
            except BaseException as exc:
                errors.append(exc)
    if errors:
        raise errors[0]

    finals = []
    for t in tmps:
        target = out_dir / f"{t.name.removesuffix('.split.apk')}_patched.apk"
        t.rename(target)
        finals.append(target)
    return finals


def save_copy(patched_dir: Path, dest_root: Path, label: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = dest_root.expanduser().resolve() / f"{label}_{ts}"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(patched_dir, dest)
    log.info("Saved patched APK(s) to %s", dest)
    return dest


def run_pipeline(
    *,
    target: str,
    serial: Optional[str],
    output: Optional[Path],
    minimal: bool,
    refresh: bool,
    cert_pem: str,
) -> int:
    target_path = Path(target)
    local_mode = target_path.exists()

    tools = prepare_tools(refresh=refresh, minimal=minimal, cert_pem=cert_pem)

    if local_mode:
        return _run_local_mode(target_path, tools, output=output,
                               minimal=minimal, refresh=refresh)
    return _run_adb_mode(target, serial, tools, output=output,
                         minimal=minimal, refresh=refresh)


def _collect_apks(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(path.glob("*.apk"))
    raise FileNotFoundError(path)


def _run_local_mode(
    target_path: Path,
    tools: Tools,
    *,
    output: Optional[Path],
    minimal: bool,
    refresh: bool,
) -> int:
    apks = _collect_apks(target_path)
    if not apks:
        log.error("No .apk files in %s", target_path)
        return 3

    label = target_path.stem if target_path.is_file() else target_path.name
    patched_out = PATCHED_DIR / f"{label}_patched"
    shutil.rmtree(patched_out, ignore_errors=True)
    patched_out.mkdir(parents=True)

    base_apk = identify_base_apk(apks)
    log.info("Local mode | base=%s, splits=%d", base_apk.name, len(apks) - 1)

    patch_base_apk(base_apk, patched_out, tools,
                   minimal=minimal, refresh=refresh)
    sign_splits([a for a in apks if a != base_apk], patched_out, tools.signer)

    target_root = (output or PATCHED_DIR).expanduser().resolve()
    if output is not None:
        save_copy(patched_out, target_root, label)
    log.info("Done. Patched APK(s) in %s", patched_out)
    return 0


def _run_adb_mode(
    package: str,
    serial: Optional[str],
    tools: Tools,
    *,
    output: Optional[Path],
    minimal: bool,
    refresh: bool,
) -> int:
    client = AdbClient(host=ADB_HOST, port=ADB_PORT)
    device = resolve_device(client, serial)

    pkg = package.removeprefix("package:").strip()

    original_out = PACKAGES_DIR / pkg
    patched_out = PATCHED_DIR / f"{pkg}_patched"
    shutil.rmtree(patched_out, ignore_errors=True)
    patched_out.mkdir(parents=True)

    apks = pull_package(device, pkg, original_out)
    base_apk = identify_base_apk(apks)
    log.info("ADB mode | device=%s, base=%s, splits=%d",
             device.serial, base_apk.name, len(apks) - 1)

    final_base = patch_base_apk(base_apk, patched_out, tools,
                                minimal=minimal, refresh=refresh)
    final_splits = sign_splits(
        [a for a in apks if a != base_apk], patched_out, tools.signer
    )

    if output is not None:
        save_copy(patched_out, output.expanduser().resolve(), pkg)

    try:
        device.uninstall(pkg)
        log.info("Uninstalled original %s", pkg)
    except Exception as e:
        log.warning("Uninstall failed (%s). Letting install-multiple -r handle it.", e)

    install_apks(device.serial, [final_base, *final_splits])
    log.info("Done. %s is patched and installed.", pkg)
    return 0


# --------------------------------------------------------------------------- #
#  CLI                                                                        #
# --------------------------------------------------------------------------- #

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="declaw",
        description=("Patch an Android APK to stop caring about SSL pinning, "
                     "then reinstall it."),
        epilog="TARGET is either a package name (adb mode) or a path to an "
               ".apk file / directory of split APKs (local mode). "
               "Local mode is selected automatically when TARGET is an "
               "existing filesystem path.",
    )
    p.add_argument("target", help="Package name on device, or path to APK / split-APK dir")
    p.add_argument("-s", "--serial",
                   help="ADB serial (optional if exactly one device is attached)")
    p.add_argument("-o", "--output",
                   help="Directory to copy patched APK(s) into (timestamped subdir)")
    p.add_argument("-c", "--cert",
                   help="Path to a PEM to embed as CERT_PEM (e.g. Burp / mitmproxy CA). "
                        "Overrides DECLAW_CERT_PEM env var.")
    p.add_argument("--minimal", action="store_true",
                   help="NSC only. Skip the Frida gadget, keep the APK small.")
    p.add_argument("--refresh", action="store_true",
                   help="Force re-download of apktool, signer, gadget, and bypass script.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Debug logging. Shows every subprocess and cache hit.")
    return p.parse_args(argv)


def load_cert_pem(args: argparse.Namespace) -> str:
    src = args.cert or os.environ.get("DECLAW_CERT_PEM")
    if src:
        path = Path(src).expanduser()
        if not path.exists():
            log.error("--cert path does not exist: %s", path)
            sys.exit(2)
        text = path.read_text(encoding="utf-8").strip()
        if "BEGIN CERTIFICATE" not in text:
            log.error("%s does not look like a PEM certificate.", path)
            sys.exit(2)
        log.info("Embedding user-provided CA from %s", path)
        return text
    return DEFAULT_CERT_PEM


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cert_pem = load_cert_pem(args)

    try:
        return run_pipeline(
            target=args.target,
            serial=args.serial,
            output=Path(args.output) if args.output else None,
            minimal=args.minimal,
            refresh=args.refresh,
            cert_pem=cert_pem,
        )
    except requests.RequestException as exc:
        log.error("Network error: %s", exc)
        return 4
    except sp.CalledProcessError as exc:
        log.error("External tool failed: %s", exc)
        return 6
    except KeyboardInterrupt:
        log.error("Interrupted.")
        return 130
    except Exception as exc:  # pragma: no cover
        log.exception("Unhandled error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
