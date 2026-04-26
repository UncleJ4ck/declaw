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
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from xml.etree import ElementTree as _stdlib_ET
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
BUNDLETOOL_URL = "https://api.github.com/repos/google/bundletool/releases/latest"

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

# Stealth name for the gadget. Defeats /proc/self/maps grep-for-frida-gadget.
GADGET_LIBNAME = os.environ.get("DECLAW_GADGET_LIBNAME", "app-support")

BUNDLE_EXTENSIONS = {".xapk", ".apks", ".apkm", ".apkmos"}
AAB_EXTENSION = ".aab"

REFLUTTER_CSV_URL = "https://raw.githubusercontent.com/Impact-I/reFlutter/main/enginehash.csv"
REFLUTTER_RELEASE_URL = "https://github.com/Impact-I/reFlutter/releases/download/android-v2-{hash}/libflutter_{arch}.so"
REFLUTTER_ABI_MAP = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
}
# Engines below 3.24.0 had a hardcoded Burp proxy baked in; we'd redirect
# traffic whether the user wanted it or not. Gate the static patch on this.
REFLUTTER_MIN_VERSION = (3, 24, 0)

SMALI_PIN_TARGETS = [
    ("okhttp3/CertificatePinner", "check"),
    ("com/datatheorem/android/trustkit/pinning/PinningTrustManager", "checkServerTrusted"),
    ("com/appmattus/certificatetransparency/internal/verifier/CertificateTransparencyTrustManager", "checkServerTrusted"),
]

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

# ISRG Root X1. Parses cleanly so CertificateFactory.generateCertificate
# inside the bundled hooks never throws when the user didn't pass --cert.
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

def _gadget_config_bytes() -> bytes:
    payload = {
        "interaction": {
            "type": "script",
            "path": f"./lib{GADGET_LIBNAME}.script.so",
            "on_change": "reload",
        },
    }
    return json.dumps(payload, indent=2).encode("utf-8")


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


def fetch_bundletool(*, refresh: bool) -> Path:
    """Return a cached bundletool jar (for .aab -> .apks conversion)."""
    info = _gh_latest(BUNDLETOOL_URL)
    asset = next((a for a in info.get("assets", []) if a["name"].endswith(".jar")), None)
    if asset is None:
        raise RuntimeError("No bundletool jar found in latest release")
    dest = UTILS_DIR / asset["name"]
    if dest.exists() and not refresh:
        log.debug("Using cached %s", dest.name)
        return dest
    _stream_download(asset["browser_download_url"], dest)
    return dest


def convert_aab(aab: Path, *, refresh: bool) -> Path:
    """Convert a Google .aab into a universal .apks set via bundletool.

    Returns the path to the generated .apks (a zip with a single
    universal.apk inside), ready to be fed through extract_bundle().
    bundletool signs with an auto-generated debug key; uber-apk-signer
    re-signs everything later so the key doesn't matter.
    """
    bundletool_jar = fetch_bundletool(refresh=refresh)
    out_dir = PACKAGES_DIR / f"{aab.stem}_aab"
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)
    apks_out = out_dir / f"{aab.stem}.apks"
    log.info("Converting %s to universal APKs via bundletool", aab.name)
    _run([
        "java", "-jar", bundletool_jar,
        "build-apks",
        f"--bundle={aab}",
        f"--output={apks_out}",
        "--mode=universal",
    ])
    return apks_out


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
    # Strip the previous declaw header so re-writing is idempotent.
    body = cached.read_text(encoding="utf-8")
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


def _load_library_smali() -> str:
    return (
        f"    const-string v0, \"{GADGET_LIBNAME}\"\n"
        "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
    )


def _new_clinit_smali() -> str:
    return (
        "\n.method static constructor <clinit>()V\n"
        "    .locals 1\n"
        f"{_load_library_smali()}"
        "    return-void\n"
        ".end method\n"
    )


def _inject_load_library(smali_path: Path) -> bool:
    text = smali_path.read_text(encoding="utf-8")
    if f'"{GADGET_LIBNAME}"' in text:
        return False
    load_snippet = _load_library_smali()
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
            new_head = head2 + load_snippet
        else:
            line_start = head2.rfind("\n", 0, last_ret) + 1
            new_head = head2[:line_start] + load_snippet + head2[line_start:]
        new_text = text.replace(m.group(0), new_head + tail, 1)
    else:
        new_clinit = _new_clinit_smali()
        anchor = text.find("\n.method")
        new_text = (text[:anchor] + new_clinit + text[anchor:]) if anchor >= 0 else text + new_clinit
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

    config_bytes = _gadget_config_bytes()
    gadget_file = f"lib{GADGET_LIBNAME}.so"
    config_file = f"lib{GADGET_LIBNAME}.config.so"
    script_file = f"lib{GADGET_LIBNAME}.script.so"

    for abi in target_abis:
        if abi not in FRIDA_ABI_MAP:
            log.warning("Skipping unsupported ABI for gadget: %s", abi)
            continue
        gadget_so = fetch_frida_gadget(abi, refresh=refresh)
        abi_dir = lib_root / abi
        abi_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(gadget_so, abi_dir / gadget_file)
        (abi_dir / config_file).write_bytes(config_bytes)
        shutil.copy2(bypass_script, abi_dir / script_file)
        log.info("Gadget + unpin script placed in lib/%s/ as %s", abi, gadget_file)

    target_class = manifest.application_class or manifest.launcher_activity
    loaded = False
    if target_class:
        smali_path = _find_smali_for_class(unpacked, target_class)
        if smali_path is not None:
            if _inject_load_library(smali_path):
                log.info("Injected loadLibrary(\"%s\") into %s", GADGET_LIBNAME, target_class)
            else:
                log.info("Gadget loader already present in %s", target_class)
            loaded = True

    if not loaded:
        # Only synthesize the wrapper when there is no original Application
        # class. Subclassing one whose smali we couldn't locate would crash
        # at launch with NoClassDefFoundError.
        if manifest.application_class is None:
            inject_application_wrapper(unpacked, None)
            loaded = True
        else:
            log.warning(
                "Could not locate smali for %s. Skipping Application wrapper; "
                "the gadget will load via the ContentProvider path only.",
                manifest.application_class,
            )

    # Belt-and-braces: a ContentProvider is constructed before
    # Application.onCreate(), so it loads the gadget even if the
    # Application path is skipped.
    inject_content_provider(unpacked)


# --------------------------------------------------------------------------- #
#  Bundle input (.xapk, .apks, .apkm)                                         #
# --------------------------------------------------------------------------- #

def extract_bundle(bundle_path: Path) -> Path:
    """Unpack a .xapk / .apks / .apkm into a flat dir of .apk files."""
    out_dir = PACKAGES_DIR / f"{bundle_path.stem}_bundle"
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)
    log.info("Extracting bundle %s", bundle_path.name)
    with zipfile.ZipFile(bundle_path) as zf:
        for name in zf.namelist():
            if name.lower().endswith(".apk"):
                zf.extract(name, out_dir)
    # Flatten: move any nested .apk to the top level.
    for apk in list(out_dir.rglob("*.apk")):
        if apk.parent != out_dir:
            target = out_dir / apk.name
            if target.exists():
                target.unlink()
            shutil.move(str(apk), str(target))
    # Drop empty subdirs.
    for sub in sorted(out_dir.iterdir(), reverse=True):
        if sub.is_dir():
            try:
                sub.rmdir()
            except OSError:
                pass
    found = sorted(out_dir.glob("*.apk"))
    if not found:
        raise RuntimeError(
            f"No .apk files inside bundle {bundle_path.name}. "
            "Is this a valid .xapk / .apks / .apkm container?"
        )
    log.info("Extracted %d APK(s) from bundle", len(found))
    return out_dir


# --------------------------------------------------------------------------- #
#  Smali-level pinning patches (apk-mitm style backup layer)                  #
# --------------------------------------------------------------------------- #

def apply_smali_pin_patches(unpacked: Path) -> int:
    """Stub well-known pinning classes' methods to `return-void`.

    Runs in addition to the runtime Frida hooks. If the target app kills
    Frida, the static patch still disables the most common Java-layer
    pinning. Count of patched methods is returned for logging.
    """
    patched = 0
    for class_path, method_name in SMALI_PIN_TARGETS:
        rel = class_path + ".smali"
        for smali_root in sorted(unpacked.glob("smali*")):
            target = smali_root / rel
            if not target.is_file():
                continue
            if _patch_void_method_to_noop(target, method_name):
                log.info("Smali-patched %s.%s", class_path, method_name)
                patched += 1
    if patched == 0:
        log.debug("No smali pin-patch targets found in this APK.")
    return patched


def _patch_void_method_to_noop(smali_path: Path, method_name: str) -> bool:
    """Replace the body of every `<method_name>(...)V` in the file with `return-void`."""
    text = smali_path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"(\.method\s+(?:\w+\s+)*{re.escape(method_name)}\([^)]*\)V[^\n]*\n)"
        r"(.*?)"
        r"(\.end method)",
        re.DOTALL,
    )
    new_text, n = pattern.subn(r"\1    .locals 0\n    return-void\n\3", text)
    if n > 0:
        smali_path.write_text(new_text, encoding="utf-8")
        return True
    return False


# --------------------------------------------------------------------------- #
#  Application-class wrapper (fallback when we cannot patch the original)     #
# --------------------------------------------------------------------------- #

_WRAPPER_CLASS = "com/declaw/DeclawApp"
_PROVIDER_CLASS = "com/declaw/DeclawPreload"


def inject_application_wrapper(unpacked: Path, orig_app_class: Optional[str]) -> None:
    """Create a subclass Application that loads the gadget in <clinit> and
    rewrite android:name to point at it. Used when there's no existing
    Application class to patch, or when its clinit couldn't be touched.
    """
    super_class = orig_app_class.replace(".", "/") if orig_app_class else "android/app/Application"
    rel = _WRAPPER_CLASS + ".smali"

    smali = (
        f".class public L{_WRAPPER_CLASS};\n"
        f".super L{super_class};\n"
        ".source \"DeclawApp.java\"\n\n"
        ".method public constructor <init>()V\n"
        "    .registers 1\n"
        f"    invoke-direct {{p0}}, L{super_class};-><init>()V\n"
        "    return-void\n"
        ".end method\n\n"
        ".method static constructor <clinit>()V\n"
        "    .locals 1\n"
        f"{_load_library_smali()}"
        "    return-void\n"
        ".end method\n"
    )

    smali_root = unpacked / "smali"
    smali_root.mkdir(exist_ok=True)
    out = smali_root / rel
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(smali, encoding="utf-8")

    manifest_path = unpacked / "AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    application = root.find(".//application")
    if application is not None:
        application.set(QN_NAME, _WRAPPER_CLASS.replace("/", "."))
        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
        log.info("Injected Application wrapper %s (super=%s)",
                 _WRAPPER_CLASS.replace("/", "."), super_class.replace("/", "."))


def inject_content_provider(unpacked: Path) -> None:
    """Register a stub ContentProvider that loads the gadget in <clinit>.

    ContentProviders are constructed before Application.onCreate(), so this
    pulls the gadget load earlier than Application-only injection and gives
    us a second shot if something bypasses the Application path.
    """
    manifest_path = unpacked / "AndroidManifest.xml"
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    application = root.find(".//application")
    if application is None:
        return

    # Authority must be unique across all installed apps, and must not start
    # with a dot (Android rejects that). apktool sometimes drops manifest@package
    # on modern builds, hence the empty-string fallback.
    pkg = (root.get("package") or "").strip()
    salt = uuid.uuid4().hex[:8]
    if pkg:
        authority = f"{pkg}.declaw.preload.{salt}"
    else:
        log.warning("Manifest@package is empty; using a self-contained "
                    "authority for the ContentProvider.")
        authority = f"declaw.preload.{salt}"

    # Don't inject twice.
    for prov in application.findall("provider"):
        if prov.get(QN_NAME) == _PROVIDER_CLASS.replace("/", "."):
            return

    # SubElement lives in stdlib ET (defusedxml only wraps parsing).
    provider = _stdlib_ET.SubElement(application, "provider")
    provider.set(QN_NAME, _PROVIDER_CLASS.replace("/", "."))
    provider.set(f"{{{ANDROID_NS}}}authorities", authority)
    provider.set(f"{{{ANDROID_NS}}}exported", "false")
    tree.write(manifest_path, encoding="utf-8", xml_declaration=True)

    smali = (
        f".class public L{_PROVIDER_CLASS};\n"
        ".super Landroid/content/ContentProvider;\n"
        ".source \"DeclawPreload.java\"\n\n"
        ".method public constructor <init>()V\n"
        "    .registers 1\n"
        "    invoke-direct {p0}, Landroid/content/ContentProvider;-><init>()V\n"
        "    return-void\n"
        ".end method\n\n"
        ".method static constructor <clinit>()V\n"
        "    .locals 1\n"
        f"{_load_library_smali()}"
        "    return-void\n"
        ".end method\n\n"
        ".method public onCreate()Z\n"
        "    .registers 2\n"
        "    const/4 v0, 0x1\n"
        "    return v0\n"
        ".end method\n\n"
        ".method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;\n"
        "    .registers 6\n"
        "    const/4 v0, 0x0\n"
        "    return-object v0\n"
        ".end method\n\n"
        ".method public getType(Landroid/net/Uri;)Ljava/lang/String;\n"
        "    .registers 2\n"
        "    const/4 v0, 0x0\n"
        "    return-object v0\n"
        ".end method\n\n"
        ".method public insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;\n"
        "    .registers 3\n"
        "    const/4 v0, 0x0\n"
        "    return-object v0\n"
        ".end method\n\n"
        ".method public delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I\n"
        "    .registers 4\n"
        "    const/4 v0, 0x0\n"
        "    return v0\n"
        ".end method\n\n"
        ".method public update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I\n"
        "    .registers 5\n"
        "    const/4 v0, 0x0\n"
        "    return v0\n"
        ".end method\n"
    )

    smali_root = unpacked / "smali"
    smali_root.mkdir(exist_ok=True)
    out = smali_root / (_PROVIDER_CLASS + ".smali")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(smali, encoding="utf-8")
    log.info("Injected ContentProvider %s for early gadget load",
             _PROVIDER_CLASS.replace("/", "."))


# --------------------------------------------------------------------------- #
#  Flutter static patch via reFlutter                                         #
# --------------------------------------------------------------------------- #

def _fetch_reflutter_engine_map(refresh: bool) -> dict[str, str]:
    """Return {snapshot_hash_hex: flutter_version}."""
    cache = UTILS_DIR / "reflutter-enginehash.csv"
    if not cache.exists() or refresh:
        _stream_download(REFLUTTER_CSV_URL, cache)
    mapping: dict[str, str] = {}
    for line in cache.read_text(encoding="utf-8").splitlines()[1:]:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 3:
            version, _commit, snap = parts[:3]
            if version and snap:
                mapping[snap.lower()] = version
    return mapping


def _flutter_version_tuple(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except ValueError:
        return (0, 0, 0)


def _find_flutter_snapshot_hash(libflutter: Path, known: dict[str, str]) -> Optional[str]:
    """Scan the libflutter.so bytes for any known snapshot hash."""
    data = libflutter.read_bytes()
    for h in known:
        if h.encode() in data:
            return h
    return None


def try_patch_flutter_static(
    unpacked: Path,
    inspection: ApkInspection,
    *,
    refresh: bool,
) -> bool:
    """Swap in reFlutter's pre-patched libflutter.so when the engine
    snapshot hash is known. Returns True if any ABI was patched."""
    if "flutter" not in inspection.frameworks:
        return False
    if os.environ.get("DECLAW_FLUTTER_STATIC", "1") == "0":
        log.info("Flutter static patch disabled by DECLAW_FLUTTER_STATIC=0.")
        return False
    try:
        known = _fetch_reflutter_engine_map(refresh=refresh)
    except requests.RequestException as exc:
        log.warning("reFlutter hash table fetch failed (%s). Falling back to Frida hooks.", exc)
        return False

    patched_any = False
    for abi in sorted(inspection.abis):
        if abi not in REFLUTTER_ABI_MAP:
            continue  # reFlutter publishes arm / arm64 only
        libflutter = unpacked / "lib" / abi / "libflutter.so"
        if not libflutter.exists():
            continue
        snap = _find_flutter_snapshot_hash(libflutter, known)
        if not snap:
            log.info("Flutter: unknown engine hash in lib/%s/, relying on Frida script.", abi)
            continue
        version = known[snap]
        if _flutter_version_tuple(version) < REFLUTTER_MIN_VERSION:
            log.info("Flutter %s (lib/%s/) has hardcoded proxy in reFlutter's patch, skipping.",
                     version, abi)
            continue
        arch = REFLUTTER_ABI_MAP[abi]
        cache = UTILS_DIR / f"reflutter-libflutter-{snap}-{arch}.so"
        if not cache.exists() or refresh:
            try:
                _stream_download(REFLUTTER_RELEASE_URL.format(hash=snap, arch=arch), cache)
            except requests.RequestException as exc:
                log.warning("reFlutter asset download failed for %s / %s (%s). Falling back.",
                            version, arch, exc)
                continue
        shutil.copy2(cache, libflutter)
        log.info("Flutter: replaced lib/%s/libflutter.so with reFlutter engine %s",
                 abi, version)
        patched_any = True
    return patched_any


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
            _run(flags + list(map(str, ordered)), capture=True)
            log.info("Installed %d APK(s) on %s", len(ordered), serial)
            return
        except sp.CalledProcessError as e:
            stderr = (e.stderr or "").strip()
            stdout = (e.stdout or "").strip()
            detail = stderr or stdout or f"exit {e.returncode}"
            log.warning("install-multiple failed: %s. Trying next strategy.", detail)

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
    bypass_script: Optional[Path]  # None in --minimal mode


def prepare_tools(*, refresh: bool, minimal: bool, cert_pem: str) -> Tools:
    apktool = _cached_jar(APKTOOL_URL, refresh=refresh)
    signer = _cached_jar(UBER_APK_SIGNER_URL, refresh=refresh)
    bypass = None if minimal else fetch_bypass_script(cert_pem, refresh=refresh)
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
        apply_smali_pin_patches(unpacked)
        # Static libflutter swap first; if it lands, the Frida hooks below
        # become a backstop instead of the only line of defence.
        try_patch_flutter_static(unpacked, inspection, refresh=refresh)
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


def _collect_apks(path: Path, *, refresh: bool = False) -> list[Path]:
    if path.is_file():
        suffix = path.suffix.lower()
        if suffix == AAB_EXTENSION:
            # .aab: convert to universal .apks with bundletool, then extract.
            apks = convert_aab(path, refresh=refresh)
            bundle_dir = extract_bundle(apks)
            return sorted(bundle_dir.glob("*.apk"))
        if suffix in BUNDLE_EXTENSIONS:
            bundle_dir = extract_bundle(path)
            return sorted(bundle_dir.glob("*.apk"))
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
    apks = _collect_apks(target_path, refresh=refresh)
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
