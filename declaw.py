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
import struct
import subprocess as sp
import zlib
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
BUNDLETOOL_URL = "https://api.github.com/repos/google/bundletool/releases/latest"

# Frida 17.x gadget script mode is BROKEN on Android. The gadget loads, parses
# the config, but never executes the JS script. Issue is tracked upstream:
#   https://github.com/frida/frida/issues/3526
#   https://github.com/frida/frida/issues/3645
# Symptom: console.log / Java.perform / setImmediate all silently no-op.
# Frida 16.7.19's Gum SIGSEGVs on Android 16+ the instant any hook executes
# (incompatible with the new ART/loader), so it is useless on current phones.
# Frida 17.x's Gum works there, but its gadget refuses to run a raw concatenated
# script (the language bridges were unbundled). The fix: ship the 17.x gadget and
# run the bundle through frida-compile (see _frida_compile), which inlines a shim
# providing the `Java` global + the moved Module APIs. That combination is the
# only one that works on EVERY Android. If node/frida-compile is unavailable we
# fall back to the 16.x gadget + raw bundle (fine for Android <= 15 only).
DEFAULT_FRIDA_VERSION = "17.15.2"
FALLBACK_FRIDA_VERSION = "16.7.19"  # used when frida-compile cannot run (no node)


def _frida_major(version: str) -> int:
    try:
        return int(version.lstrip("v").split(".")[0])
    except (ValueError, IndexError):
        return 0
FRIDA_RELEASES_TAG_URL = "https://api.github.com/repos/frida/frida/releases/tags/{tag}"
FRIDA_RELEASES_LATEST_URL = "https://api.github.com/repos/frida/frida/releases/latest"

# Bypass fragments grouped by category so the bundle is assembled per app
# from the frameworks actually detected, instead of always shipping every
# hook. (url, category). Categories:
#   "flutter-first" : Flutter BoringSSL bypass, must run before anything else
#   "core"          : Java/native TLS hooks that apply to almost any Android app
#   "flutter"       : extra Flutter hooks, only useful when libflutter is present
# The third field is the hook ENGINE:
#   "native" : pure Gum hooks (libc/BoringSSL/libflutter). GC-safe on every
#              Android, including 16+ under the 17.x gadget.
#   "java"   : instruments ART Java methods via frida-java-bridge. Crashes ART's
#              Concurrent Mark Compact GC on Android 16+ (frida-java-bridge#387),
#              so it is excluded unless explicitly requested or targeting old ART.
_NVISO = "https://raw.githubusercontent.com/NVISOsecurity/disable-flutter-tls-verification/main/disable-flutter-tls.js"
_HT = "https://raw.githubusercontent.com/httptoolkit/frida-interception-and-unpinning/main"
BYPASS_FRAGMENTS = [
    # NVISO Flutter TLS bypass FIRST. It pattern-locates ssl_verify_peer_cert
    # in libflutter's BoringSSL and patches it to return success, the only
    # reliable defeat of Flutter's own-trust-store TLS. Native, GC-safe.
    (_NVISO, "flutter-first", "native"),
    (f"{_HT}/android/android-certificate-unpinning.js", "core", "java"),
    (f"{_HT}/android/android-certificate-unpinning-fallback.js", "core", "java"),
    # NB: httptoolkit's android-disable-flutter-certificate-pinning.js is omitted
    # on purpose: NVISO + the static libflutter patch already cover Flutter, and
    # it throws "multiple matches for CertificateCallback" on current engines.
    (f"{_HT}/android/android-disable-root-detection.js", "core", "java"),
    # Hooks Conscrypt/BoringSSL native verify -> defeats system-trust + native
    # pinning without touching Java. Covers most OkHttp apps (OkHttp uses
    # Conscrypt). Native, GC-safe.
    (f"{_HT}/native-tls-hook.js", "core", "native"),
    # Rewrites connect() at the libc level so all TCP lands on PROXY_HOST:PORT.
    # Required for Flutter and any app that ignores the system proxy. Native.
    (f"{_HT}/native-connect-hook.js", "core", "native"),
]
# Every fragment URL, in canonical order. Used for the DECLAW_BYPASS_URLS-less
# "include everything" path and as the back-compat default.
DEFAULT_BYPASS_URLS = [u for u, _, _ in BYPASS_FRAGMENTS]


def select_bypass_urls(frameworks: set[str], *, native_only: bool = False) -> list[str]:
    """Pick bypass fragments for the frameworks detected in this app.

    Core fragments (Java/native TLS, connect redirect, root detection) always
    apply. Flutter fragments are added only when libflutter is present, so an
    OkHttp app does not carry the Flutter BoringSSL scanner and a Flutter app
    gets NVISO first. When frameworks is empty (detection found nothing) every
    fragment is included, which is the safe superset.

    native_only drops the "java" (ART-instrumenting) fragments, which crash the
    GC on Android 16+. Used with the Frida 17.x gadget so the bundle works on
    every Android; the dropped Java pinning is covered statically by the NSC
    patch (and natively by native-tls-hook for Conscrypt/OkHttp).
    """
    def keep(engine: str) -> bool:
        return engine == "native" or not native_only
    is_flutter = "flutter" in frameworks or not frameworks
    first = [u for u, c, e in BYPASS_FRAGMENTS if c == "flutter-first" and is_flutter and keep(e)]
    core = [u for u, c, e in BYPASS_FRAGMENTS if c == "core" and keep(e)]
    flutter = [u for u, c, e in BYPASS_FRAGMENTS if c == "flutter" and is_flutter and keep(e)]
    return first + core + flutter

DEFAULT_PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 8000

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
QN_APP_COMPONENT_FACTORY = f"{{{ANDROID_NS}}}appComponentFactory"

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
    # NOTE: do NOT set on_change="reload". On Android the gadget would then
    # try to inotify the script directory under /data/app/<pkg>/lib/<abi>/,
    # which SELinux denies for untrusted_app (avc: denied { watch } tclass=dir).
    # The denial happens before the script ever runs, so every hook is silently
    # skipped. We don't need hot-reload at runtime; the gadget reads the script
    # once at process start and that's all that matters here.
    payload = {
        "interaction": {
            "type": "script",
            "path": f"./lib{GADGET_LIBNAME}.script.so",
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


# Big apps (Western Union, banking apps with 10+ dex files) blow out the JVM
# default heap and apktool / signer get OOM-killed. Override via env.
_JVM_HEAP = os.environ.get("DECLAW_JVM_HEAP", "4g")


def _java(*args: str) -> list:
    """Build a `java -Xmx... -jar ... <args>` command line."""
    return ["java", f"-Xmx{_JVM_HEAP}", *args]


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


_JAR_CACHE_PATTERNS = {
    "iBotPeaches/Apktool": "apktool_*.jar",
    "patrickfav/uber-apk-signer": "uber-apk-signer-*.jar",
    "google/bundletool": "bundletool-*.jar",
}


def _existing_cached_jar(api_url: str) -> Optional[Path]:
    for repo, pattern in _JAR_CACHE_PATTERNS.items():
        if repo in api_url:
            matches = sorted(UTILS_DIR.glob(pattern))
            return matches[-1] if matches else None
    return None


def _cached_jar(api_url: str, *, refresh: bool) -> Path:
    # Fast path: cached file already present and user did not ask to refresh.
    # Avoids a GitHub API round-trip on every run (and lets declaw work offline).
    if not refresh:
        existing = _existing_cached_jar(api_url)
        if existing is not None:
            log.debug("Using cached %s", existing.name)
            return existing
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
    # Offline fast path: reuse a cached bundletool-*.jar without a GitHub round
    # trip (matters for air-gapped runs; see DECLAW_BYPASS_URLS docstring).
    if not refresh:
        cached = sorted(UTILS_DIR.glob("bundletool-*.jar"))
        if cached:
            log.debug("Using cached %s", cached[-1].name)
            return cached[-1]
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


def _bundletool_cmd(jar: Path, *args: str) -> list:
    return _java("-jar", str(jar), *args)


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
    _run(_bundletool_cmd(
        bundletool_jar,
        "build-apks",
        f"--bundle={aab}",
        f"--output={apks_out}",
        "--mode=universal",
    ))
    return apks_out


def fetch_frida_gadget(abi: str, *, refresh: bool, version: str = DEFAULT_FRIDA_VERSION) -> Path:
    if abi not in FRIDA_ABI_MAP:
        raise ValueError(f"Unsupported ABI for Frida gadget: {abi}")
    suffix = FRIDA_ABI_MAP[abi]
    # Fast path: cached gadget for THIS version + ABI. Matching on version too
    # because mixing a 16.x gadget with a 17.x cached one would reintroduce
    # the script-mode-broken bug; we have to be specific.
    pinned_so = UTILS_DIR / f"libfrida-gadget-{version}-{suffix}.so"
    if pinned_so.exists() and not refresh:
        log.debug("Using cached %s", pinned_so.name)
        return pinned_so
    # Fallback: any older cached version is better than failing on a flaky
    # network, but warn loudly so the user knows they may be hitting the
    # 17.x script-broken bug. Real bug surfaced during the docker-android
    # x86_64 test run: the pinned arm64 gadget was downloaded but the x86_64
    # ABI silently fell back to a stale 17.x cache and the gadget script
    # silently no-op'd in the emulator. Downloading the pinned version per
    # ABI is the only correct behaviour; if the network is down, fail loudly.
    if version.lower() == "latest":
        info = _gh_latest(FRIDA_RELEASES_LATEST_URL)
    else:
        info = _gh_latest(FRIDA_RELEASES_TAG_URL.format(tag=version))
    tag = info.get("tag_name", version).lstrip("v")
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


# Android 15+ on a 16 KB-page device (Pixel 8/9, current AOSP, many 2024+ phones)
# refuses to correctly map a .so whose LOAD segments are 4 KB-aligned. The Frida
# gadget ships 4 KB-aligned for every version (verified 16.7.19 and 17.x), so on
# such a device its segments land on the wrong pages and the first hook the
# script installs jumps through a corrupt trampoline -> SIGSEGV. Re-aligning the
# gadget's LOAD segments to 16 KB fixes it; 16 KB is a superset of 4 KB so the
# result still loads on every older 4 KB-page device. This is additive: it only
# touches the injected gadget, never the app's own libs (already 16 KB-aligned).
GADGET_PAGE_ALIGN = 0x4000  # 16 KB


def _align_native_lib_16k(src: Path, dst: Path) -> bool:
    """Copy src -> dst, re-aligning ELF64 LOAD segments to 16 KB when needed.

    Returns True if a re-align was applied, False if the lib was already
    >= 16 KB-aligned and copied verbatim. Inserts the minimum zero padding
    before each under-aligned LOAD segment so its file offset satisfies the
    loader's congruence rule (p_offset % page == p_vaddr % page), bumps
    p_align to 16 KB, shifts every program-header offset to track the inserted
    padding, and grows the file accordingly. Section headers (loader-irrelevant)
    are dropped so their now-stale offsets cannot trip a strict linker.

    Pure stdlib (struct) on purpose: lief 0.17 silently fails to relocate this
    gadget's bss-bearing trailing segment, producing a "p_offset past end of
    file" image that the Android linker rejects.
    """
    data = bytearray(src.read_bytes())
    # ELF64 little-endian only (every Android gadget ABI we ship). Anything
    # else: copy verbatim rather than risk a bad rewrite.
    if data[:4] != b"\x7fELF" or len(data) < 64 or data[4] != 2 or data[5] != 1:
        shutil.copy2(src, dst)
        return False
    en = "<"
    PAGE = GADGET_PAGE_ALIGN
    PT_LOAD = 1
    (e_phoff,) = struct.unpack_from(en + "Q", data, 0x20)
    (e_shoff,) = struct.unpack_from(en + "Q", data, 0x28)
    (e_phentsize,) = struct.unpack_from(en + "H", data, 0x36)
    (e_phnum,) = struct.unpack_from(en + "H", data, 0x38)
    (e_shentsize,) = struct.unpack_from(en + "H", data, 0x3A)
    (e_shnum,) = struct.unpack_from(en + "H", data, 0x3C)

    phdrs = []  # (hdr_offset, p_type, p_offset, p_vaddr, p_align)
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type = struct.unpack_from(en + "I", data, base)[0]
        p_offset, p_vaddr = struct.unpack_from(en + "QQ", data, base + 8)
        p_align = struct.unpack_from(en + "Q", data, base + 48)[0]
        phdrs.append((base, p_type, p_offset, p_vaddr, p_align))

    loads = [p for p in phdrs if p[1] == PT_LOAD]
    if not loads or all(p[4] >= PAGE for p in loads):
        shutil.copy2(src, dst)
        return False

    # Walk LOAD segments in file order, inserting just enough padding before
    # each so its new offset is page-congruent with its vaddr.
    inserts = []  # (at_old_offset, pad_bytes)
    cum = 0
    for _, _, p_offset, p_vaddr, _ in sorted(loads, key=lambda p: p[2]):
        need = (p_vaddr - (p_offset + cum)) % PAGE
        cum += need
        inserts.append((p_offset, need))

    def shift_for(off: int) -> int:
        return sum(pad for at, pad in inserts if at <= off)

    # Rebuild the file with the padding spliced in.
    out = bytearray()
    pos = 0
    for at, pad in sorted(inserts, key=lambda x: x[0]):
        out += data[pos:at]
        out += b"\x00" * pad
        pos = at
    out += data[pos:]

    # Fix up every program-header offset; bump LOAD alignment to the page size.
    for base, p_type, p_offset, _p_vaddr, _p_align in phdrs:
        struct.pack_into(en + "Q", out, base + 8, p_offset + shift_for(p_offset))
        if p_type == PT_LOAD:
            struct.pack_into(en + "Q", out, base + 48, PAGE)
    # Shift e_phoff if it moved.
    struct.pack_into(en + "Q", out, 0x20, e_phoff + shift_for(e_phoff))
    # Keep the section header table but track the padding: the Android linker
    # validates e_shstrndx, so the table must stay present and consistent
    # (zeroing it trips "invalid e_shstrndx"). Shift e_shoff and every section
    # offset by the padding inserted before them.
    if e_shoff and e_shnum:
        struct.pack_into(en + "Q", out, 0x28, e_shoff + shift_for(e_shoff))
        for i in range(e_shnum):
            old_sh = e_shoff + i * e_shentsize
            new_sh = old_sh + shift_for(old_sh)
            sh_offset = struct.unpack_from(en + "Q", data, old_sh + 24)[0]
            if sh_offset:
                struct.pack_into(en + "Q", out, new_sh + 24,
                                 sh_offset + shift_for(sh_offset))

    dst.write_bytes(out)
    return True


# --------------------------------------------------------------------------- #
#  Static Flutter TLS bypass (no gadget, no Frida)                            #
# --------------------------------------------------------------------------- #
#
# Flutter ships its own BoringSSL inside libflutter.so and verifies the server
# cert against a baked-in trust store, ignoring the system store, the NSC, and
# any user CA. The only reliable defeat is to neuter ssl_verify_peer_cert (and
# the session_verify_cert_chain helper) so it always reports success. The NVISO
# runtime hook does this with Frida, but the gadget's Interceptor SIGSEGVs on
# some new arm64 SoCs (Pixel 8 / Tensor G3, Android 16) and Frida 17's gadget
# won't run scripts at all. So we also do it STATICALLY at patch time: locate
# the function by NVISO's byte signatures and overwrite its prologue with a stub
# that returns the success value. No runtime, no Frida, device-independent.
#
# These signatures are ported verbatim from NVISO's disable-flutter-tls.js
# (the Android "libflutter.so" config). ssl_verify_peer_cert returns an
# enum ssl_verify_result_t where ssl_verify_ok == 0; that return convention has
# been stable across BoringSSL/Flutter versions for years, which is why the stub
# value lives with each signature (retval) rather than being guessed. Update
# this table from upstream when a new Flutter engine ships an unmatched layout:
#   https://github.com/NVISOsecurity/disable-flutter-tls-verification
FLUTTER_TLS_SIGS: dict[str, list[tuple[str, int]]] = {
    "arm64": [
        ("F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9", 0),
        ("F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 "
         "F4 03 00 AA 68 1A 40 F9", 0),
        ("FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 "
         "B5 00 00 B4 B6 4A 40 F9", 0),
        ("FF ?3 01 D1 F? ?? 01 A9 ?? ?? ?? 94 ?? ?? ?? 52 48 00 00 39 1A 50 40 F9 "
         "DA 02 00 B4 48 03 40 F9", 1),
    ],
    "arm": [
        ("2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8", 0),
    ],
    "x86_64": [
        ("55 41 57 41 56 41 55 41 54 53 50 49 89 F? 4? 8B ?? 4? 8B 4? 30 4C 8B ?? "
         "?? 0? 00 00 4D 85 ?? 74 1? 4D 8B", 0),
        ("55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 "
         "4C 8B A0 28 02 00 00 4D 85 E4 74", 0),
        ("55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FE 4C 8B 27 49 8B 44 24 "
         "30 48 8B 98 D0 01 00 00 48 85 DB", 0),
    ],
    "x86": [
        ("55 89 E5 53 57 56 83 E4 F0 83 EC 20 E8 00 00 00 00 5B 81 C3 2B 79 66 00 "
         "8B 7D 08 8B 17 8B 42 18 8B 80 88 01", 0),
    ],
}

# APK lib/<abi>/ directory name -> instruction-set key in FLUTTER_TLS_SIGS.
_ABI_TO_ARCH = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}


def _flutter_return_stub(arch: str, retval: int) -> bytes:
    """Machine code that does `return retval;` for the given instruction set."""
    if arch == "arm64":
        return struct.pack("<II", 0x52800000 | ((retval & 0xFFFF) << 5), 0xD65F03C0)
    if arch == "arm":  # Thumb: movs r0, #retval ; bx lr
        return struct.pack("<HH", 0x2000 | (retval & 0xFF), 0x4770)
    if arch in ("x86_64", "x86"):  # mov eax, retval ; ret
        return b"\xb8" + struct.pack("<I", retval & 0xFFFFFFFF) + b"\xc3"
    raise ValueError(f"no return stub for arch {arch}")


def _sig_to_regex(sig: str) -> "re.Pattern[bytes]":
    """Compile an NVISO-style nibble-wildcard signature to a bytes regex."""
    out = b""
    for tok in sig.split():
        hi, lo = tok[0], tok[1]
        if hi == "?" and lo == "?":
            out += b"."
        elif hi != "?" and lo != "?":
            out += re.escape(bytes([int(tok, 16)]))
        else:
            vals = [b for b in range(256)
                    if (hi == "?" or f"{b:02X}"[0] == hi.upper())
                    and (lo == "?" or f"{b:02X}"[1] == lo.upper())]
            out += b"[" + b"".join(re.escape(bytes([v])) for v in vals) + b"]"
    return re.compile(out, re.DOTALL)


def _patch_flutter_tls_bytes(data: bytes, arch: str) -> tuple[bytes, list[int]]:
    """Return (patched_data, [offsets]) with every ssl_verify_peer_cert match in
    `data` overwritten by a success-returning stub for `arch`. No-op (empty list)
    when no signature matches, so it is safe on non-Flutter libs and idempotent
    (a patched prologue no longer matches)."""
    sigs = FLUTTER_TLS_SIGS.get(arch)
    if not sigs:
        return data, []
    buf = bytearray(data)
    hits: list[int] = []
    for sig, retval in sigs:
        stub = _flutter_return_stub(arch, retval)
        for m in _sig_to_regex(sig).finditer(data):
            off = m.start()
            if off in hits:
                continue
            buf[off:off + len(stub)] = stub
            hits.append(off)
    return bytes(buf), sorted(hits)


def _static_patch_flutter_so(apk: Path) -> int:
    """Patch any Stored lib/<abi>/libflutter.so inside `apk` in place so its
    TLS verification always succeeds, fixing the entry CRC and re-writing the
    APK bytes. Returns the number of call sites patched across all ABIs. Leaves
    every other zip entry (resources.arsc, alignment, the manifest) untouched,
    so the existing sign step's zipalign still holds. Deflated libflutter.so is
    reported and skipped (rare; would need a full re-zip)."""
    raw = bytearray(apk.read_bytes())
    eocd = raw.rfind(b"PK\x05\x06")
    if eocd < 0:
        return 0
    cd_off = struct.unpack_from("<I", raw, eocd + 16)[0]
    cd_count = struct.unpack_from("<H", raw, eocd + 10)[0]
    if cd_off == 0xFFFFFFFF or cd_count == 0xFFFF:
        # zip64: real values live in the zip64 EOCD we do not parse. Bail rather
        # than walk a bogus offset. APKs almost never hit this.
        log.warning("zip64 APK %s: static libflutter patch skipped (use the "
                    "runtime hook instead)", apk.name)
        return 0
    total = 0
    p = cd_off
    for _ in range(cd_count):
        if raw[p:p + 4] != b"PK\x01\x02":
            break
        gp_flag = struct.unpack_from("<H", raw, p + 8)[0]
        method = struct.unpack_from("<H", raw, p + 10)[0]
        comp_size = struct.unpack_from("<I", raw, p + 20)[0]
        name_len = struct.unpack_from("<H", raw, p + 28)[0]
        extra_len = struct.unpack_from("<H", raw, p + 30)[0]
        comment_len = struct.unpack_from("<H", raw, p + 32)[0]
        lh_off = struct.unpack_from("<I", raw, p + 42)[0]
        name = raw[p + 46:p + 46 + name_len].decode("utf-8", "replace")
        m = re.fullmatch(r"lib/([^/]+)/libflutter\.so", name)
        if m:
            arch = _ABI_TO_ARCH.get(m.group(1))
            if arch is None:
                pass
            elif method != 0:
                log.warning("libflutter.so in %s is compressed; static TLS "
                            "patch skipped for %s", apk.name, name)
            else:
                # Local header: 30 + name_len + extra_len -> entry data.
                lname_len = struct.unpack_from("<H", raw, lh_off + 26)[0]
                lextra_len = struct.unpack_from("<H", raw, lh_off + 28)[0]
                data_off = lh_off + 30 + lname_len + lextra_len
                blob = bytes(raw[data_off:data_off + comp_size])
                patched, hits = _patch_flutter_tls_bytes(blob, arch)
                if hits:
                    raw[data_off:data_off + comp_size] = patched
                    crc = zlib.crc32(patched) & 0xFFFFFFFF
                    struct.pack_into("<I", raw, p + 16, crc)        # central dir
                    if not (gp_flag & 0x08):
                        # Only update the local CRC when there is no trailing data
                        # descriptor (bit 3). With a descriptor the local CRC is 0
                        # and the authoritative copy is the central dir entry.
                        struct.pack_into("<I", raw, lh_off + 14, crc)
                    total += len(hits)
                    log.info("Static Flutter TLS patch: %s %s -> %d site(s) at %s",
                             apk.name, name, len(hits),
                             ", ".join(hex(h) for h in hits))
        p += 46 + name_len + extra_len + comment_len
    if total:
        apk.write_bytes(raw)
    return total


def _cache_fragment(url: str, *, refresh: bool) -> str:
    """Return a bypass fragment's text, caching it per-file under utils/fragments
    so assembling a per-app bundle never re-downloads and works offline once
    each fragment has been fetched."""
    frag_dir = UTILS_DIR / "fragments"
    frag_dir.mkdir(exist_ok=True)
    cached = frag_dir / url.rsplit("/", 1)[-1]
    if cached.exists() and not refresh:
        return cached.read_text(encoding="utf-8")
    log.info("Fetching bypass fragment: %s", cached.name)
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    cached.write_text(r.text, encoding="utf-8")
    return r.text


def fetch_bypass_script(
    cert_pem: str,
    *,
    refresh: bool,
    proxy_host: str,
    proxy_port: int,
    debug_bundle: bool = False,
    frameworks: Optional[set[str]] = None,
    dest: Optional[Path] = None,
    native_only: bool = False,
) -> Path:
    """Assemble a bypass bundle tailored to the detected frameworks.

    DECLAW_BYPASS_URLS overrides selection entirely (all listed URLs, in
    order). Otherwise select_bypass_urls() picks core hooks plus, only when
    libflutter is present, the Flutter BoringSSL bypass. Fragments are cached
    individually; the bundle itself is assembled fresh each call (cheap) so it
    always reflects the current app, cert, proxy and debug flags.

    native_only drops ART-instrumenting (Java) fragments for the Frida 17.x
    gadget so the bundle stays GC-safe on Android 16+.
    """
    urls_env = os.environ.get("DECLAW_BYPASS_URLS", "").strip()
    if urls_env:
        urls = [u for u in urls_env.split(";") if u]
    else:
        urls = select_bypass_urls(frameworks or set(), native_only=native_only)

    chosen = [u.rsplit("/", 1)[-1] for u in urls]
    log.info("Bypass strategy (%s): %s",
             ", ".join(sorted(frameworks)) if frameworks else "all",
             ", ".join(chosen))

    parts = [(url, _cache_fragment(url, refresh=refresh)) for url in urls]
    out = dest or (UTILS_DIR / "universal-bypass.js")
    return _write_bypass(out, cert_pem, parts,
                         proxy_host=proxy_host, proxy_port=proxy_port,
                         debug_bundle=debug_bundle)


def _write_bypass(
    cached: Path,
    cert_pem: str,
    parts: list[tuple[str, str]],
    *,
    proxy_host: str,
    proxy_port: int,
    debug_bundle: bool = False,
) -> Path:
    header = _bypass_header(cert_pem, proxy_host, proxy_port, debug_bundle)
    with open(cached, "w", encoding="utf-8") as fh:
        fh.write(header)
        for url, body in parts:
            fh.write(f"\n// ==== {url} ====\n")
            fh.write(body)
            if not body.endswith("\n"):
                fh.write("\n")
    return cached


# --------------------------------------------------------------------------- #
#  Frida 17.x: compile the bundle so the gadget can run it on every Android    #
# --------------------------------------------------------------------------- #
#
# The 17.x gadget will not run a raw concatenated 16.x-style script: the language
# bridges were unbundled and several Module APIs moved. frida-compile bundles a
# shim that restores the `Java` global (from frida-java-bridge) and the moved
# Module APIs, plus a waitForModule polyfill, so the existing fragments run
# unchanged. Validated on Android 16/17 (Cuttlefish arm64): native fragments
# load and patch ssl_verify_peer_cert with the process staying alive.
_FC_SHIM = (
    "import Java from 'frida-java-bridge';\n"
    "globalThis.Java = Java;\n"
    "const P = Process;\n"
    "if (!Module.getExportByName) Module.getExportByName = (m, s) => m === null"
    " ? Module.getGlobalExportByName(s)"
    " : (P.findModuleByName(m)?.getExportByName(s) ?? null);\n"
    "if (!Module.findExportByName) Module.findExportByName = (m, s) => { try {"
    " return m === null ? (Module.getGlobalExportByName?.(s) ?? null)"
    " : (P.findModuleByName(m)?.findExportByName(s) ?? null); } catch (e) { return null; } };\n"
    "globalThis.waitForModule = function (name, cb) { const hit = P.findModuleByName(name);"
    " if (hit) { cb(hit); return; }"
    " const iv = setInterval(() => { const m = P.findModuleByName(name);"
    " if (m) { clearInterval(iv); cb(m); } }, 500); };\n"
)


def have_frida_compile() -> bool:
    return all(shutil.which(t) is not None for t in ("node", "npm", "npx"))


def _ensure_fc_project(*, refresh: bool = False) -> Path:
    """Create (once) and return the cached frida-compile project under utils/fc."""
    fc = UTILS_DIR / "fc"
    installed = fc / "node_modules" / "frida-compile"
    (fc / "shim.js").parent.mkdir(parents=True, exist_ok=True)
    (fc / "package.json").write_text(
        '{"name":"declaw-fc","version":"1.0.0","type":"module","private":true}\n',
        encoding="utf-8")
    (fc / "shim.js").write_text(_FC_SHIM, encoding="utf-8")
    (fc / "entry.js").write_text("import './shim.js';\nimport './declaw-bundle.js';\n",
                                 encoding="utf-8")
    if installed.exists() and not refresh:
        return fc
    log.info("Installing frida-compile + frida-java-bridge (one-time) ...")
    sp.run(["npm", "i", "--silent", "frida-compile@19", "frida-java-bridge@7"],
           cwd=fc, check=True)
    return fc


def frida_compile_bundle(bundle: Path) -> Optional[Path]:
    """Compile the raw bundle into a single script the Frida 17.x gadget runs.

    Returns the compiled .js path, or None if frida-compile is unavailable so the
    caller can fall back to the 16.x gadget + raw bundle.
    """
    if not have_frida_compile():
        log.warning("node/npx not found: cannot frida-compile for the 17.x gadget. "
                    "Falling back to Frida %s (works on Android <= 15 only). "
                    "Install Node.js for Android 16+ support.", FALLBACK_FRIDA_VERSION)
        return None
    try:
        fc = _ensure_fc_project()
        shutil.copy2(bundle, fc / "declaw-bundle.js")
        out = fc / "compiled.js"
        if out.exists():
            out.unlink()
        sp.run(["npx", "--yes", "frida-compile", "entry.js", "-o", str(out)],
               cwd=fc, check=True)
        if not out.exists():
            raise RuntimeError("frida-compile produced no output")
        log.info("frida-compiled bundle for the 17.x gadget (%d KB)",
                 out.stat().st_size // 1024)
        return out
    except Exception as exc:  # noqa: BLE001 - any failure -> fall back gracefully
        log.warning("frida-compile failed (%s). Falling back to Frida %s.",
                    exc, FALLBACK_FRIDA_VERSION)
        return None


def _bypass_header(cert_pem: str, proxy_host: str, proxy_port: int,
                   debug_bundle: bool = False) -> str:
    escaped_pem = cert_pem.strip()
    debug_flag = "true" if debug_bundle else "false"
    # When debug_bundle is on, route every console.log through android.util.Log
    # so output is visible under `adb logcat -s declaw:V`. Without this the
    # gadget's console output goes to a buffer that never reaches logcat.
    # File beacon written from the JS thread immediately, no Java needed.
    # Frida's File API is sync and always present, so this proves the script
    # actually executed. Path is the app's private files dir, world-unreadable
    # but readable via `adb shell run-as <pkg>` (works because manifest sets
    # debuggable=true).
    beacon_block = (
        "// ---- declaw debug beacon ----\n"
        "// Bridge console.log to logcat SYNCHRONOUSLY via libc __android_log_write\n"
        "// so the httptoolkit installer fragments that run on script load (before\n"
        "// any Java.perform completes) surface their messages too. Without this,\n"
        "// an installer that throws shows up later as an InvocationTargetException\n"
        "// at the call site instead of a clear [skip] line at install time.\n"
        "(function () { try {\n"
        "  const liblog = Module.findExportByName('liblog.so', '__android_log_write')\n"
        "    || Module.findExportByName(null, '__android_log_write');\n"
        "  if (liblog) {\n"
        "    const __wr = new NativeFunction(liblog, 'int', ['int', 'pointer', 'pointer']);\n"
        "    const __tag = Memory.allocUtf8String('declaw');\n"
        "    const __orig = console.log;\n"
        "    console.log = function () {\n"
        "      const m = Array.prototype.slice.call(arguments).join(' ');\n"
        "      try { __wr(3, __tag, Memory.allocUtf8String(m)); } catch (e) {}\n"
        "      try { __orig.apply(console, arguments); } catch (e) {}\n"
        "    };\n"
        "    console.warn = console.error = console.log;\n"
        "    console.log('bundle alive, proxy=' + PROXY_HOST + ':' + PROXY_PORT);\n"
        "  }\n"
        "} catch (e) {} })();\n"
        "// Java-side beacon (best effort once the VM is ready).\n"
        "setImmediate(function () { try { Java.perform(function () {\n"
        "  try { Java.use('android.util.Log').d('declaw', 'Java ready'); } catch (e) {}\n"
        "}); } catch (e) {} });\n"
        "// ---- end debug beacon ----\n"
    )
    debug_block = beacon_block if debug_bundle else ""

    # Small, high-value Java hooks the httptoolkit bundle does NOT cover.
    # All wrapped with safeHook so a missing class can never take down the
    # rest of the script (cf. "Too many hooks spoil the app", j4k0m, 2026).
    # These fire BEFORE the httptoolkit fragments via setImmediate(Java.perform).
    hardening_block = (
        "// ---- declaw hardening hooks (NetCap, WebView, anti-debug) ----\n"
        "setImmediate(function () { try { Java.perform(function () {\n"
        "  const __declawTag = 'declaw';\n"
        "  function safeHook(name, install) {\n"
        "    try {\n"
        "      install();\n"
        "      try { Java.use('android.util.Log').d(__declawTag, '[hook] ' + name); } catch (e) {}\n"
        "    } catch (error) {\n"
        "      try { Java.use('android.util.Log').d(__declawTag,\n"
        "        '[skip] ' + name + ': ' + (error.message || error)); } catch (e) {}\n"
        "    }\n"
        "  }\n"
        "\n"
        "  // 1) NetworkCapabilities.hasCapability(int), selective.\n"
        "  // An inspection proxy can leave NET_CAPABILITY_INTERNET (12) present\n"
        "  // but disturb NET_CAPABILITY_VALIDATED (16). Apps that gate requests\n"
        "  // on both report 'offline' and never make calls; the connect-hook\n"
        "  // then has nothing to redirect. Returning true for ONLY those two\n"
        "  // preserves every other capability check (VPN, metered, transport).\n"
        "  safeHook('NetworkCapabilities.hasCapability', function () {\n"
        "    const NetCap = Java.use('android.net.NetworkCapabilities');\n"
        "    const orig = NetCap.hasCapability.overload('int');\n"
        "    orig.implementation = function (cap) {\n"
        "      if (cap === 12 || cap === 16) return true;\n"
        "      return orig.call(this, cap);\n"
        "    };\n"
        "  });\n"
        "\n"
        "  // 2) WebViewClient.onReceivedSslError, handler.proceed().\n"
        "  // Covers any embedded WebView page that hits an SSL error against\n"
        "  // the Burp / mitmproxy CA. Cheap, broad, no false positives because\n"
        "  // it only runs when an SSL error already occurred.\n"
        "  safeHook('WebViewClient.onReceivedSslError', function () {\n"
        "    const WVC = Java.use('android.webkit.WebViewClient');\n"
        "    WVC.onReceivedSslError.implementation = function (view, handler, error) {\n"
        "      handler.proceed();\n"
        "    };\n"
        "  });\n"
        "\n"
        "  // 3) android.os.Debug status, suppress the reaction not the env.\n"
        "  // Setting debuggable=true in the manifest makes some apps refuse to\n"
        "  // run when isDebuggerConnected() / waitingForDebugger() return true.\n"
        "  // Returning false from both is the smallest behavioural change.\n"
        "  safeHook('Debug.isDebuggerConnected', function () {\n"
        "    Java.use('android.os.Debug').isDebuggerConnected.implementation = function () { return false; };\n"
        "  });\n"
        "  safeHook('Debug.waitingForDebugger', function () {\n"
        "    Java.use('android.os.Debug').waitingForDebugger.implementation = function () { return false; };\n"
        "  });\n"
        "}); } catch (e) {} });\n"
        "// ---- end declaw hardening ----\n"
    )

    return (
        "// declaw universal SSL-unpinning bundle\n"
        "// Generated header. Downstream hooks read these globals.\n"
        f"const CERT_PEM = `{escaped_pem}\\n`;\n"
        f"const PROXY_HOST = '{proxy_host}';\n"
        f"const PROXY_PORT = {proxy_port};\n"
        f"const DEBUG_MODE = {debug_flag};\n"
        "const IGNORED_NON_HTTP_PORTS = [];\n"
        "const BLOCK_HTTP3 = true;\n"
        "const PROXY_SUPPORTS_SOCKS5 = false;\n"
        f"{debug_block}"
        f"{hardening_block}"
        "// ---- declaw header end ----\n"
    )


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

    # Apktool sometimes fails to resolve a resource-referenced
    # `android:appComponentFactory` and writes a bare integer instead of the
    # real class name. Reinstalling such an APK leaves Android trying to load
    # `<package>.<int>` and crashing on launch. Replacing the value with the
    # platform default keeps the app loadable; a pentested APK doesn't need a
    # custom component factory.
    acf = application.get(QN_APP_COMPONENT_FACTORY)
    if acf is not None and (acf.isdigit() or "." not in acf):
        application.set(QN_APP_COMPONENT_FACTORY, "androidx.core.app.CoreComponentFactory")
        changes.append("appComponentFactory(reset)")

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
    extra_abis: Optional[set[str]] = None,
    frida_version: str = DEFAULT_FRIDA_VERSION,
) -> None:
    # Detected ABIs plus any caller-requested extras. Useful when the source
    # APK is single-arch (e.g. arm64-v8a from a Pixel) but we want to install
    # on a different-arch sandbox (e.g. x86_64 emulator). Android picks the
    # matching lib/<abi>/ at install time, so the unused gadget never loads.
    target_abis = set(inspection.abis)
    if extra_abis:
        target_abis |= extra_abis
    target_abis = sorted(target_abis) or ["arm64-v8a"]

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
        gadget_so = fetch_frida_gadget(abi, refresh=refresh, version=frida_version)
        abi_dir = lib_root / abi
        abi_dir.mkdir(parents=True, exist_ok=True)
        realigned = _align_native_lib_16k(gadget_so, abi_dir / gadget_file)
        (abi_dir / config_file).write_bytes(config_bytes)
        shutil.copy2(bypass_script, abi_dir / script_file)
        log.info(
            "Gadget + unpin script placed in lib/%s/ as %s%s",
            abi, gadget_file, " (re-aligned to 16 KB pages)" if realigned else "",
        )

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
                log.warning("Bundle has two splits named %s; keeping the later "
                            "one (%s). If install-multiple later fails, the "
                            "bundle nests distinct splits under the same name.",
                            apk.name, apk)
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
    def repl(m: "re.Match[str]") -> str:
        decl = m.group(1)
        # abstract/native methods have no body; injecting one fails apktool build.
        if re.search(r"\b(abstract|native)\b", decl):
            return m.group(0)
        return f"{decl}    .locals 0\n    return-void\n{m.group(3)}"

    new_text, n = pattern.subn(repl, text)
    if new_text != text:
        smali_path.write_text(new_text, encoding="utf-8")
        return True
    return False


# --------------------------------------------------------------------------- #
#  Application-class wrapper (fallback when we cannot patch the original)     #
# --------------------------------------------------------------------------- #

_WRAPPER_CLASS = "com/declaw/DeclawApp"
_PROVIDER_CLASS = "com/declaw/DeclawPreload"


def _apktool_min_sdk(unpacked: Path) -> int:
    """Best-effort minSdkVersion from apktool.yml. 0 if unknown."""
    yml = unpacked / "apktool.yml"
    if not yml.exists():
        return 0
    for line in yml.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = re.search(r"minSdkVersion:\s*['\"]?(\d+)", line)
        if m:
            return int(m.group(1))
    return 0


def _injection_smali_dir(unpacked: Path) -> Path:
    """Where to write an injected class.

    apktool maps `smali` -> classes.dex, `smali_classes2` -> classes2.dex, etc.
    Large apps (Signal, banking, social) fill their first dex right up to the
    64K method/field/type reference ceiling. Dropping a class into the existing
    `smali` folder then tips that dex over the limit and apktool fails the
    rebuild with "Unsigned short value out of range: 65536". Putting our class
    in a brand-new dex folder gives it a full 64K of headroom.

    But a *second* dex only loads at runtime when the app is multidex-capable:
    API 21+ loads every classesN.dex natively; older apps need the multidex
    support library, which a single-dex legacy app will not have. So only use a
    fresh dex when it is safe:
      - the app is already multidex (smali_classes2 exists), or
      - minSdkVersion >= 21.
    Otherwise fall back to `smali` (classes.dex). Single-dex legacy apps are
    small and nowhere near the 64K ceiling, so the overflow cannot happen there.
    """
    dex_dirs = sorted(
        p.name for p in unpacked.iterdir()
        if p.is_dir() and re.fullmatch(r"smali(_classes\d+)?", p.name)
    )
    already_multidex = any(d != "smali" for d in dex_dirs)
    min_sdk = _apktool_min_sdk(unpacked)

    if not (already_multidex or min_sdk >= 21):
        d = unpacked / "smali"
        d.mkdir(exist_ok=True)
        log.debug("Injecting into classes.dex (single-dex, minSdk=%d)", min_sdk)
        return d

    indices = [1]  # `smali` == dex index 1
    for name in dex_dirs:
        m = re.fullmatch(r"smali_classes(\d+)", name)
        if m:
            indices.append(int(m.group(1)))
    nxt = max(indices) + 1
    d = unpacked / f"smali_classes{nxt}"
    d.mkdir(parents=True, exist_ok=True)
    return d


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

    # Place into a fresh dex so a near-full classes.dex is never tipped over
    # the 64K reference ceiling by our injected class.
    smali_root = _injection_smali_dir(unpacked)
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

    # Fresh dex when safe (see _injection_smali_dir): the provider is a whole
    # class with a dozen method/type refs; appending it to a near-full
    # classes.dex is what overflowed the rebuild on large apps like Signal.
    smali_root = _injection_smali_dir(unpacked)
    out = smali_root / (_PROVIDER_CLASS + ".smali")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(smali, encoding="utf-8")
    log.info("Injected ContentProvider %s for early gadget load (%s)",
             _PROVIDER_CLASS.replace("/", "."), smali_root.name)


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
    cmd = _java("-jar", str(jar), "d", "-f", "-o", str(out_dir))
    if not with_sources:
        cmd.append("-s")
    cmd.append(str(apk))
    log.info("Unpacking %s (sources=%s)", apk.name, "yes" if with_sources else "no")
    _run(cmd)


def apktool_build(unpacked: Path, out_apk: Path, jar: Path) -> None:
    log.info("Repacking -> %s", out_apk.name)
    _run(_java("-jar", str(jar), "b", "-f", str(unpacked), "-o", str(out_apk)))


_SIGNED_SUFFIX_RE = re.compile(r"-aligned-(?:debugSigned|signed)\.apk$")


def sign_apk(apk: Path, signer_jar: Path) -> Path:
    log.info("Signing %s", apk.name)
    _run(_java("-jar", str(signer_jar), "-a", str(apk), "--allowResign", "--overwrite"))
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
    # Bypass bundle is assembled per app (after framework detection), so Tools
    # carries the inputs instead of a pre-built path. build_bypass is False in
    # --minimal mode.
    build_bypass: bool
    cert_pem: str = ""
    proxy_host: str = DEFAULT_PROXY_HOST
    proxy_port: int = DEFAULT_PROXY_PORT
    debug_bundle: bool = False
    refresh: bool = False
    extra_abis: set[str] = field(default_factory=set)
    frida_version: str = DEFAULT_FRIDA_VERSION


def prepare_tools(
    *,
    refresh: bool,
    minimal: bool,
    cert_pem: str,
    extra_abis: set[str],
    proxy_host: str,
    proxy_port: int,
    debug_bundle: bool = False,
    frida_version: str = DEFAULT_FRIDA_VERSION,
) -> Tools:
    apktool = _cached_jar(APKTOOL_URL, refresh=refresh)
    signer = _cached_jar(UBER_APK_SIGNER_URL, refresh=refresh)
    # The bypass bundle is assembled later, per app, once frameworks are known.
    return Tools(
        apktool, signer,
        build_bypass=not minimal,
        cert_pem=cert_pem,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        debug_bundle=debug_bundle,
        refresh=refresh,
        extra_abis=extra_abis,
        frida_version=frida_version,
    )


def abis_from_apks(apks: list[Path]) -> set[str]:
    """Union of native ABIs across a split-APK set.

    A split-bundle base.apk carries no lib/ dir (native libs live in the
    per-arch split_config.<abi>.apk). So ABI detection that only reads the
    base sees nothing and the gadget defaults to arm64-v8a, leaving every
    other arch split without lib<name>.so. Installing the x86_64 split then
    dies at System.loadLibrary with UnsatisfiedLinkError. Scanning every
    apk's lib/<abi>/ entries recovers the real ABI set so the gadget gets
    injected into the base for each arch the bundle ships.
    """
    abis: set[str] = set()
    known = set(FRIDA_ABI_MAP.keys())
    for apk in apks:
        try:
            with zipfile.ZipFile(apk) as zf:
                for name in zf.namelist():
                    if name.startswith("lib/"):
                        parts = name.split("/")
                        if len(parts) >= 3 and parts[1] in known:
                            abis.add(parts[1])
        except (zipfile.BadZipFile, OSError):
            continue
    return abis


# Native library name -> framework tag. Used to pick bypass fragments.
# libapp.so (Dart AOT) and libflutter.so (engine) both appear in release
# Flutter apps; detecting either (plus the flutter_assets dir) makes Flutter
# detection hard to miss. Over-detecting Flutter only adds NVISO, which is a
# no-op when libflutter is absent, so we err toward inclusion.
_LIB_FRAMEWORK_MARKERS = {
    "libflutter.so": "flutter",
    "libapp.so": "flutter",
    "libreactnativejni.so": "react-native",
    "libhermes.so": "react-native",
}


def frameworks_from_apks(apks: list[Path]) -> set[str]:
    """Detect cross-platform frameworks across a split-APK set by their native
    libs and asset markers. On split bundles these libs live in the per-arch
    split, not the base, so base-only detection misses them (which left Flutter
    apps without the NVISO BoringSSL bypass)."""
    found: set[str] = set()
    for apk in apks:
        try:
            with zipfile.ZipFile(apk) as zf:
                for name in zf.namelist():
                    base = name.rsplit("/", 1)[-1]
                    if base in _LIB_FRAMEWORK_MARKERS:
                        found.add(_LIB_FRAMEWORK_MARKERS[base])
                    elif name.startswith("assets/flutter_assets/"):
                        found.add("flutter")
        except (zipfile.BadZipFile, OSError):
            continue
    return found


def patch_base_apk(
    base_apk: Path,
    out_dir: Path,
    tools: Tools,
    *,
    minimal: bool,
    refresh: bool,
    bundle_abis: Optional[set[str]] = None,
    bundle_frameworks: Optional[set[str]] = None,
) -> Path:
    unpacked = out_dir / "base.unpacked"

    apktool_decode(base_apk, unpacked, tools.apktool, with_sources=not minimal)
    inspection = inspect_unpacked(unpacked)
    # Frameworks from the base plus those found in the arch splits (libflutter
    # lives in split_config.<abi>.apk, not the base, so base-only detection
    # misses Flutter on split bundles).
    frameworks = set(inspection.frameworks) | set(bundle_frameworks or set())
    if frameworks:
        log.info("Frameworks detected: %s", ", ".join(sorted(frameworks)))
    if inspection.abis:
        log.info("ABIs detected: %s", ", ".join(sorted(inspection.abis)))

    # ABIs the gadget must cover: those in the base plus those carried by the
    # sibling arch splits, plus any caller-requested extras. Whatever split
    # the user ends up installing, the base will carry the matching gadget.
    extra_abis = set(tools.extra_abis)
    if bundle_abis:
        split_only = bundle_abis - set(inspection.abis)
        if split_only:
            log.info("ABIs from arch splits: %s", ", ".join(sorted(split_only)))
        extra_abis |= bundle_abis

    manifest_info = patch_manifest(unpacked)
    add_network_security_config(unpacked)

    if not minimal:
        apply_smali_pin_patches(unpacked)
        # Static libflutter swap first; if it lands, the Frida hooks below
        # become a backstop instead of the only line of defence.
        try_patch_flutter_static(unpacked, inspection, refresh=refresh)
        # Assemble the bypass bundle for the frameworks this app actually uses.
        # On Frida 17.x (the default, works on every Android) the bundle is
        # native-only and run through frida-compile; if compile is unavailable we
        # downgrade the gadget to 16.x + the raw bundle (Android <= 15 only).
        eff_frida = tools.frida_version
        want_v17 = _frida_major(eff_frida) >= 17
        bypass_script = None
        if tools.build_bypass:
            bypass_script = fetch_bypass_script(
                tools.cert_pem,
                refresh=tools.refresh,
                proxy_host=tools.proxy_host,
                proxy_port=tools.proxy_port,
                debug_bundle=tools.debug_bundle,
                frameworks=frameworks,
                dest=out_dir / "declaw-bypass.js",
                native_only=want_v17,
            )
            if want_v17:
                compiled = frida_compile_bundle(bypass_script)
                if compiled is not None:
                    bypass_script = compiled
                else:
                    # No frida-compile: drop to the 16.x gadget, which runs raw
                    # scripts AND tolerates the Java fragments (GC-safe on the
                    # Android <= 15 devices this fallback targets). Re-assemble the
                    # full bundle so we do not ship a needlessly degraded one.
                    eff_frida = FALLBACK_FRIDA_VERSION
                    bypass_script = fetch_bypass_script(
                        tools.cert_pem,
                        refresh=tools.refresh,
                        proxy_host=tools.proxy_host,
                        proxy_port=tools.proxy_port,
                        debug_bundle=tools.debug_bundle,
                        frameworks=frameworks,
                        dest=out_dir / "declaw-bypass.js",
                        native_only=False,
                    )
        inject_frida_gadget(
            unpacked,
            inspection,
            manifest_info,
            bypass_script=bypass_script,
            refresh=refresh,
            extra_abis=extra_abis,
            frida_version=eff_frida,
        )

    repacked = out_dir / "base.repack.apk"
    apktool_build(unpacked, repacked, tools.apktool)
    # Static Flutter TLS defeat for any libflutter.so carried in the base. Runs
    # in addition to the runtime NVISO hook so the bypass survives even where the
    # Frida gadget can't (e.g. 16 KB-page / new-SoC devices). No-op if not Flutter.
    _static_patch_flutter_so(repacked)
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
        # Flutter's libflutter.so usually rides in the arch split, not the base.
        _static_patch_flutter_so(tmp)
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
    extra_abis: set[str],
    proxy_host: str,
    proxy_port: int,
    debug_bundle: bool = False,
    frida_version: str = DEFAULT_FRIDA_VERSION,
) -> int:
    target_path = Path(target)
    local_mode = target_path.exists()

    tools = prepare_tools(
        refresh=refresh,
        minimal=minimal,
        cert_pem=cert_pem,
        extra_abis=extra_abis,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        debug_bundle=debug_bundle,
        frida_version=frida_version,
    )

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

    bundle_abis = abis_from_apks(apks)
    bundle_frameworks = frameworks_from_apks(apks)
    patch_base_apk(base_apk, patched_out, tools,
                   minimal=minimal, refresh=refresh,
                   bundle_abis=bundle_abis, bundle_frameworks=bundle_frameworks)
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

    bundle_abis = abis_from_apks(apks)
    bundle_frameworks = frameworks_from_apks(apks)
    final_base = patch_base_apk(base_apk, patched_out, tools,
                                minimal=minimal, refresh=refresh,
                                bundle_abis=bundle_abis,
                                bundle_frameworks=bundle_frameworks)
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
    p.add_argument("--proxy", metavar="HOST:PORT",
                   help="Proxy address baked into the bundled hooks. Required for "
                        "Flutter and any app that ignores the system proxy (the "
                        "native-connect hook redirects TCP here). Overrides "
                        "DECLAW_PROXY env var. Default 127.0.0.1:8000.")
    p.add_argument("--debug-bundle", action="store_true",
                   help="Flip DEBUG_MODE=true in the bundled Frida script so every "
                        "connect() rewrite and pinning hook gets logged. View with "
                        "`adb logcat -s frida-gadget:*`.")
    p.add_argument("--gadget-abis", metavar="LIST", default="",
                   help="Comma-separated extra ABIs to inject the gadget into "
                        "(e.g. x86_64 when patching a Pixel arm64 APK for an "
                        "x86_64 emulator). Combined with what's in the APK.")
    p.add_argument("--frida-version", metavar="X.Y.Z", default="",
                   help=f"Pin Frida gadget version. Default {DEFAULT_FRIDA_VERSION} "
                        f"because Frida 17.x gadget script mode is broken on Android "
                        f"(silent no-op). Use 'latest' if upstream has shipped a fix. "
                        f"Overrides DECLAW_FRIDA_VERSION env var.")
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

    proxy_spec = (args.proxy or os.environ.get("DECLAW_PROXY", "")).strip()
    if not proxy_spec:
        # No explicit proxy. Try to auto-detect from a connected device so
        # the bundled connect hook actually targets a reachable address.
        auto = auto_detect_proxy_host(args.serial)
        if auto is not None:
            proxy_host, proxy_port = auto
        else:
            proxy_host, proxy_port = parse_proxy("")
    else:
        proxy_host, proxy_port = parse_proxy(proxy_spec)
    if proxy_spec:
        log.info("Bypass hooks will redirect TCP to %s:%d", proxy_host, proxy_port)
    else:
        log.debug("Using default proxy header %s:%d", proxy_host, proxy_port)

    debug_bundle = bool(args.debug_bundle) or os.environ.get("DECLAW_DEBUG_BUNDLE", "").strip() not in ("", "0", "false", "False")
    if debug_bundle:
        log.info("DEBUG_MODE enabled in bundled script. Tail `adb logcat -s declaw:V`.")

    frida_version = (args.frida_version or os.environ.get("DECLAW_FRIDA_VERSION", "")).strip() or DEFAULT_FRIDA_VERSION
    if _frida_major(frida_version) >= 17:
        if have_frida_compile():
            log.info("Frida %s gadget + frida-compile (native bundle): works on "
                     "every Android, including 16+.", frida_version)
        else:
            log.warning("Frida %s needs frida-compile (node) which is missing; will "
                        "fall back to %s (Android <= 15 only). Install Node.js for "
                        "Android 16+ support.", frida_version, FALLBACK_FRIDA_VERSION)
    else:
        log.warning("Frida %s: its Gum SIGSEGVs on Android 16+. Use the default %s "
                    "(needs node) for new devices.", frida_version, DEFAULT_FRIDA_VERSION)

    abi_src = (args.gadget_abis or os.environ.get("DECLAW_GADGET_ABIS", "")).strip()
    extra_abis = {a.strip() for a in abi_src.split(",") if a.strip()}
    if extra_abis:
        log.info("Extra gadget ABIs requested: %s", ", ".join(sorted(extra_abis)))

    try:
        return run_pipeline(
            target=args.target,
            serial=args.serial,
            output=Path(args.output) if args.output else None,
            minimal=args.minimal,
            refresh=args.refresh,
            cert_pem=cert_pem,
            extra_abis=extra_abis,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            debug_bundle=debug_bundle,
            frida_version=frida_version,
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
