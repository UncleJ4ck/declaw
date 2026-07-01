"""declaw.analyze — Per-APK TLS-stack analysis and strategy recommendation.

Scans an APK set (no apktool decode needed) for the networking/TLS stack and the
anti-tamper protection that decide which declaw mode actually decrypts the app:

  - cronet (libcronet*.so)          hard-pins its own bundled BoringSSL; the
                                    CA + NSC patch cannot decrypt it, friTap can.
  - flutter (libflutter/libapp)     own BoringSSL; static patch + NVISO (patch).
  - okhttp (dex marker)             native-tls hook + smali pin patch (patch).
  - anti-tamper packers (PairIP..)  re-signing is detected; friTap on the
                                    unmodified app avoids re-signing (capture).

Cheap on purpose: reads zip namelists plus a bounded byte-scan of classes*.dex.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import zipfile

from declaw.config import FRIDA_ABI_MAP, log


# Native lib basename (lowercase) -> framework tag.
_FRAMEWORK_LIBS = {
    "libflutter.so": "flutter",
    "libapp.so": "flutter",
    "libreactnativejni.so": "react-native",
    "libhermes.so": "react-native",
    "libjsc.so": "react-native",
    "libmonodroid.so": "xamarin",
    "libil2cpp.so": "unity",
}

# Native lib basename (lowercase) -> human anti-tamper / packer name. These
# packers verify the APK signature at runtime, so a re-signed (patched) APK is
# detected and killed; friTap on the unmodified app sidesteps that.
_ANTI_TAMPER_LIBS = {
    "libpairipcore.so": "PairIP",
    "libdexguard.so": "DexGuard",
    "libjiagu.so": "Qihoo Jiagu",
    "libjiagu_art.so": "Qihoo Jiagu",
    "libsecneo.so": "SecNeo",
    "libtersafe.so": "Tencent TerSafe",
    "libtersafe2.so": "Tencent TerSafe",
    "libnesec.so": "NESEC",
    "libsecshell.so": "Bangcle SecShell",
    "libdexhelper.so": "Bangcle DexHelper",
    "libmobisec.so": "Mobisec",
    "libtoolchecker.so": "tool-check",
    "libsardine-root-checker.so": "root-checker",
}

# Bytes searched inside classes*.dex (string-table markers).
_DEX_OKHTTP = b"okhttp3/"
_DEX_PIN_MARKERS = (
    b"okhttp3/CertificatePinner",
    b"com/datatheorem/android/trustkit",
    b"certificatetransparency",
)
_DEX_CONSCRYPT = b"org/conscrypt"
_DEX_CRONET = b"org/chromium/net"


@dataclass
class AppProfile:
    frameworks: set[str] = field(default_factory=set)
    abis: set[str] = field(default_factory=set)
    cronet: bool = False
    okhttp: bool = False
    conscrypt: bool = False
    java_pinning: bool = False
    anti_tamper: set[str] = field(default_factory=set)

    def strategy(self) -> tuple[str, str]:
        """Return (mode, reason). mode is 'patch' or 'capture'."""
        if self.cronet:
            return ("capture",
                    "cronet bundles its own pinned BoringSSL (libcronet); the CA/NSC "
                    "patch cannot decrypt it. friTap key extraction decrypts it.")
        if self.anti_tamper:
            return ("capture",
                    f"anti-tamper present ({', '.join(sorted(self.anti_tamper))}); re-signing "
                    "the patched APK will likely be detected. friTap on the unmodified app "
                    "avoids re-signing.")
        bits: list[str] = []
        if "flutter" in self.frameworks:
            bits.append("Flutter static BoringSSL patch + NVISO")
        if self.okhttp:
            bits.append("OkHttp native-tls hook + smali pin patch")
        if self.java_pinning:
            bits.append("Java pinning smali patch")
        return ("patch", "; ".join(bits) or "standard Java/Conscrypt TLS")

    def summary(self) -> str:
        parts = []
        if self.frameworks:
            parts.append("frameworks=" + ",".join(sorted(self.frameworks)))
        for flag in ("cronet", "okhttp", "conscrypt", "java_pinning"):
            if getattr(self, flag):
                parts.append(flag)
        if self.anti_tamper:
            parts.append("anti-tamper=" + ",".join(sorted(self.anti_tamper)))
        if self.abis:
            parts.append("abis=" + ",".join(sorted(self.abis)))
        return "; ".join(parts) or "no notable markers"


def _scan_dex(zf: zipfile.ZipFile, profile: AppProfile) -> None:
    for name in zf.namelist():
        base = name.rsplit("/", 1)[-1]
        if not (base.startswith("classes") and base.endswith(".dex")):
            continue
        try:
            data = zf.read(name)
        except (KeyError, zipfile.BadZipFile, OSError):
            continue
        low = data.lower()
        if _DEX_OKHTTP in data:
            profile.okhttp = True
        if _DEX_CONSCRYPT in low:
            profile.conscrypt = True
        if _DEX_CRONET in low:
            profile.cronet = True  # cronet sometimes ships as a play-services dep, no libcronet
        if any(m in low for m in _DEX_PIN_MARKERS):
            profile.java_pinning = True


def analyze_apks(apks: list[Path]) -> AppProfile:
    """Inspect a split-APK set and return its TLS/protection profile."""
    profile = AppProfile()
    known_abis = set(FRIDA_ABI_MAP)
    for apk in apks:
        try:
            zf = zipfile.ZipFile(apk)
        except (zipfile.BadZipFile, OSError):
            continue
        with zf:
            for name in zf.namelist():
                if name.startswith("lib/"):
                    parts = name.split("/")
                    if len(parts) >= 3 and parts[1] in known_abis:
                        profile.abis.add(parts[1])
                    base = parts[-1].lower()
                    if base.startswith("libcronet"):
                        profile.cronet = True
                    if base in _FRAMEWORK_LIBS:
                        profile.frameworks.add(_FRAMEWORK_LIBS[base])
                    if base in _ANTI_TAMPER_LIBS:
                        profile.anti_tamper.add(_ANTI_TAMPER_LIBS[base])
                elif name.startswith("assets/flutter_assets/"):
                    profile.frameworks.add("flutter")
                elif name.endswith("index.android.bundle"):
                    profile.frameworks.add("react-native")
            _scan_dex(zf, profile)
    return profile


def log_profile(profile: AppProfile) -> tuple[str, str]:
    """Log the profile + recommended strategy; return (mode, reason)."""
    mode, reason = profile.strategy()
    log.info("APK profile: %s", profile.summary())
    if mode == "capture":
        log.info("Recommended: friTap capture mode (--capture). %s", reason)
    else:
        log.info("Recommended: patch mode (default). %s", reason)
    return mode, reason
