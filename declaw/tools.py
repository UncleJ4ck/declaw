"""declaw.tools — Tool preparation and ABI/framework detection."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import zipfile

from declaw.config import APKTOOL_URL, DEFAULT_FRIDA_VERSION, DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT, FRIDA_ABI_MAP, UBER_APK_SIGNER_URL
from declaw.shell import _cached_jar


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
